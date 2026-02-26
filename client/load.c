// DB loading + conversion to runtime Graph (CSR + u24 edges), then free blob.

STATIC void db_fail(const char* what) {
	fprintf(stderr, "error: invalid/truncated db (%s)\n", what);
	exit(1);
}

#define DB_IO_BUF_SIZE (1u << 20)

typedef struct DbSource {
	DbStreamFillFn fill;
	void*          ctx;
} DbSource;

typedef struct DbReader {
	DbSource source;
	u8*      buf;
	size_t   cap;
	size_t   pos;
	size_t   len;
	bool     eof;
	u64      consumed;
} DbReader;

STATIC void db_reader_consume(DbReader* r, size_t n) {
	if (n > r->len - r->pos) db_fail("internal reader over-consume");
	r->pos += n;
	r->consumed += (u64)n;
}

STATIC void db_reader_init(DbReader* r, DbSource source) {
	memset(r, 0, sizeof(*r));
	r->source = source;
	r->cap    = (size_t)DB_IO_BUF_SIZE;
	r->buf    = (u8*)malloc(r->cap);
	if (!r->buf) db_fail("OOM db reader buffer");
}

STATIC void db_reader_destroy(DbReader* r) {
	free(r->buf);
	r->buf = NULL;
}

STATIC void db_reader_require(DbReader* r, size_t n, const char* what) {
	if (n == 0) return;
	if (n > r->cap) db_fail("requested read exceeds 1MB reader buffer");
	if ((r->len - r->pos) >= n) return;

	size_t rem = r->len - r->pos;
	if (rem && r->pos) memmove(r->buf, r->buf + r->pos, rem);
	r->pos = 0;
	r->len = rem;

	while (r->len < n) {
		if (r->eof) db_fail(what);

		bool   src_eof = false;
		size_t got     = r->source.fill(r->source.ctx, r->buf + r->len, r->cap - r->len, &src_eof);
		r->len += got;
		if (src_eof) r->eof = true;

		if (got == 0) {
			if (r->eof) db_fail(what);
			db_fail("reader source stalled");
		}
	}
}

STATIC void db_reader_read_exact(DbReader* r, void* dst, size_t n, const char* what) {
	u8* out = (u8*)dst;
	while (n) {
		db_reader_require(r, 1, what);
		size_t avail = r->len - r->pos;
		size_t take  = (avail < n) ? avail : n;
		memcpy(out, r->buf + r->pos, take);
		db_reader_consume(r, take);
		out += take;
		n -= take;
	}
}

STATIC void db_reader_skip(DbReader* r, size_t n, const char* what) {
	while (n) {
		db_reader_require(r, 1, what);
		size_t avail = r->len - r->pos;
		size_t take  = (avail < n) ? avail : n;
		db_reader_consume(r, take);
		n -= take;
	}
}

STATIC bool db_reader_has_more(DbReader* r) {
	if (r->len - r->pos) return true;
	if (r->eof) return false;

	r->pos = 0;
	r->len = 0;

	bool   src_eof = false;
	size_t got     = r->source.fill(r->source.ctx, r->buf, r->cap, &src_eof);
	r->len         = got;
	if (src_eof) r->eof = true;

	if (got == 0) {
		if (!r->eof) db_fail("reader source stalled");
		return false;
	}
	return true;
}

STATIC u64 db_reader_drain_remaining(DbReader* r) {
	u64 total = 0;
	if (r->len > r->pos) {
		size_t rem = r->len - r->pos;
		total += (u64)rem;
		db_reader_consume(r, rem);
	}
	while (!r->eof) {
		r->pos = 0;
		r->len = 0;

		bool   src_eof = false;
		size_t got     = r->source.fill(r->source.ctx, r->buf, r->cap, &src_eof);
		r->len         = got;
		if (src_eof) r->eof = true;
		if (got == 0) {
			if (!r->eof) db_fail("reader source stalled");
			break;
		}
		total += (u64)got;
		db_reader_consume(r, got);
	}
	return total;
}

#define DB_REQUIRE(reader, n, what) db_reader_require((reader), (size_t)(n), (what))

#define DB_READ(reader, dst, what)                                  \
	do {                                                            \
		DB_REQUIRE((reader), sizeof(dst), (what));                 \
		memcpy(&(dst), (reader)->buf + (reader)->pos, sizeof(dst)); \
		db_reader_consume((reader), sizeof(dst));                  \
	} while (0)

typedef struct MemSourceCtx {
	const u8* buf;
	size_t    len;
	size_t    pos;
} MemSourceCtx;

STATIC size_t mem_source_fill(void* ctx_ptr, u8* dst, size_t cap, bool* out_eof) {
	MemSourceCtx* ctx = (MemSourceCtx*)ctx_ptr;
	size_t        rem = ctx->len - ctx->pos;
	size_t        n   = rem < cap ? rem : cap;
	if (n) memcpy(dst, ctx->buf + ctx->pos, n);
	ctx->pos += n;
	*out_eof = (ctx->pos == ctx->len);
	return n;
}

typedef struct FileSourceCtx {
	FILE* f;
} FileSourceCtx;

STATIC size_t file_source_fill(void* ctx_ptr, u8* dst, size_t cap, bool* out_eof) {
	FileSourceCtx* ctx = (FileSourceCtx*)ctx_ptr;
	size_t         got = fread(dst, 1, cap, ctx->f);
	if (got < cap && ferror(ctx->f)) {
		fprintf(stderr, "error: could not read db file: %s\n", strerror(errno));
		exit(1);
	}
	*out_eof = feof(ctx->f) != 0;
	return got;
}

#ifndef NO_COMPRESSION
typedef struct LzmaSourceCtx {
	DbSource    upstream;
	lzma_stream strm;
	u8*         in_buf;
	bool        in_eof;
	bool        finished;
} LzmaSourceCtx;

STATIC void lzma_source_init(LzmaSourceCtx* ctx, DbSource upstream) {
	memset(ctx, 0, sizeof(*ctx));
	ctx->upstream = upstream;
	lzma_stream z = LZMA_STREAM_INIT;
	ctx->strm     = z;
	ctx->in_buf = (u8*)malloc(DB_IO_BUF_SIZE);
	if (!ctx->in_buf) {
		fprintf(stderr, "error: OOM allocating compressed reader buffer\n");
		exit(1);
	}
	lzma_ret ret = lzma_stream_decoder(&ctx->strm, UINT64_MAX, 0);
	if (ret != LZMA_OK) {
		fprintf(stderr, "error: cannot initialize lzma decoder\n");
		exit(1);
	}
}

STATIC void lzma_source_destroy(LzmaSourceCtx* ctx) {
	lzma_end(&ctx->strm);
	free(ctx->in_buf);
	ctx->in_buf = NULL;
}

STATIC size_t lzma_source_fill(void* ctx_ptr, u8* dst, size_t cap, bool* out_eof) {
	LzmaSourceCtx* ctx = (LzmaSourceCtx*)ctx_ptr;
	if (ctx->finished) {
		*out_eof = true;
		return 0;
	}

	ctx->strm.next_out  = dst;
	ctx->strm.avail_out = cap;

	while (ctx->strm.avail_out > 0) {
		if (ctx->strm.avail_in == 0 && !ctx->in_eof) {
			bool   src_eof = false;
			size_t got     = ctx->upstream.fill(ctx->upstream.ctx, ctx->in_buf, DB_IO_BUF_SIZE, &src_eof);
			ctx->strm.next_in  = ctx->in_buf;
			ctx->strm.avail_in = got;
			ctx->in_eof        = src_eof;
			if (got == 0 && !ctx->in_eof) db_fail("compressed reader source stalled");
		}

		size_t in_before  = ctx->strm.avail_in;
		size_t out_before = ctx->strm.avail_out;
		lzma_ret ret      = lzma_code(&ctx->strm, ctx->in_eof ? LZMA_FINISH : LZMA_RUN);

		if (ret == LZMA_STREAM_END) {
			ctx->finished = true;
			break;
		}
		if (ret != LZMA_OK) {
			fprintf(stderr, "error: lzma decode failed (%d)\n", (int)ret);
			exit(1);
		}
		if (ctx->strm.avail_out != out_before) break;
		if (ctx->strm.avail_in == in_before) db_fail("lzma decode made no progress");
	}

	size_t produced = cap - ctx->strm.avail_out;
	*out_eof        = ctx->finished;
	if (produced == 0 && !ctx->finished && ctx->in_eof && ctx->strm.avail_in == 0) {
		db_fail("lzma stream ended unexpectedly");
	}
	return produced;
}
#endif

enum {
	LINK_FLAG_IS_RENAME  = 1u << 0,
	LINK_FLAG_IS_INFOBOX = 1u << 1,
};

STATIC void validate_graph_fully(Graph* g) {
#if !defined(DB_NO_VALIDATE)
	if (!g->titles || !g->out_offsets || !g->out_edges24) db_fail("internal graph not initialized");

	if (g->N == 0) db_fail("N==0");
	if (g->N > 0xFFFFFFu) db_fail("N exceeds 24-bit id range");
	if (g->L == 0) db_fail("L==0");

	// Titles must be sorted
	for (u32 i = 1; i < g->N; i++) {
		if (string_cmp(g->titles[i - 1], g->titles[i]) > 0) {
			fprintf(stderr, "error: titles not sorted at %u\n", i);
			exit(1);
		}
	}

	// Offsets monotonic and consistent
	if (g->out_offsets[0] != 0) db_fail("out_offsets[0]!=0");
	if (g->out_offsets[g->N] != g->L) db_fail("out_offsets[N]!=L");
	for (u32 i = 0; i < g->N; i++) {
		if (g->out_offsets[i] > g->out_offsets[i + 1]) db_fail("out_offsets not monotonic");
	}
	// Validate adjacency lists are sorted and in range (decode u24 once at startup).
	// This is O(L) and allowed at startup.
	for (u32 u = 0; u < g->N; u++) {
		u32 beg = g->out_offsets[u];
		u32 end = g->out_offsets[u + 1];
		if (beg > end || end > g->L) db_fail("out_offsets bounds");
		if (end > beg) {
			const u8* p    = u24_cptr(g->out_edges24, beg);
			u32       prev = u24_load(p);
			if (prev >= g->N) db_fail("out edge id out of range");
			p += 3;
			for (u32 idx = beg + 1; idx < end; idx++, p += 3) {
				u32 v = u24_load(p);
				if (v >= g->N) db_fail("out edge id out of range");
				if (v < prev) db_fail("out adjacency not sorted");
				prev = v;
			}
		}
	}

	// Validate unredir table invariants
	for (u32 i = 0; i < g->nr_unredir; i++) {
		UnredirEdge* e = &g->unredir[i];
		if (e->src >= g->N || e->dest >= g->N) db_fail("unredir src/dest out of range");
		if (e->redir_idx >= g->nr_redir_titles) db_fail("unredir redir_idx out of range");
		if (i > 0) {
			UnredirEdge* p      = &g->unredir[i - 1];
			bool         sorted = (p->src < e->src) || (p->src == e->src && p->dest < e->dest) ||
						  (p->src == e->src && p->dest == e->dest && p->redir_idx <= e->redir_idx);
			if (!sorted) db_fail("unredir not sorted");
			if (p->src == e->src && p->dest == e->dest) db_fail("duplicate unredir (src,dest)");
		}
	}

	// Validate each unredir pair is a real edge in the graph (since adjacency is sorted).
	// Potentially expensive but startup-only.
	for (u32 i = 0; i < g->nr_unredir; i++) {
		UnredirEdge* e = &g->unredir[i];
		if (!graph_has_edge(g, e->src, e->dest)) {
			fprintf(stderr, "error: unredir edge (%u -> %u) not present in graph\n", e->src, e->dest);
			exit(1);
		}
	}

#endif // !defined(DB_NO_VALIDATE)

	g->validated = true;
}

STATIC void graph_load_from_reader(Graph* g, DbReader* r) {
	puts("Processing data...");

	DB_REQUIRE(r, 4, "magic");
	if (memcmp(r->buf + r->pos, "WIKI", 4) != 0) db_fail("magic");
	db_reader_consume(r, 4);

	u32 version = 0;
	DB_READ(r, version, "version");
	u8 dump_format = (u8)(version & 0xFFu);
	if (dump_format > DUMP_FORMAT_VERSION) db_fail("db newer than client");
	if (dump_format < 1) db_fail("invalid db format");

	i32 dump_date = (i32)(version >> 8);
	printf("[info] database file date: 20%02d.%02d.%02d\n", dump_date / 10000, (dump_date / 100) % 100,
		   dump_date % 100);

	i32 nr_entries = 0;
	DB_READ(r, nr_entries, "nr_entries");
	if (nr_entries <= 0) db_fail("nr_entries <= 0");

	u32 total_links = 0;
	DB_READ(r, total_links, "total_links");
	if (total_links == 0) db_fail("total_links==0");

	u32 total_title_bytes = 0;
	DB_READ(r, total_title_bytes, "total_title_bytes");
	if (total_title_bytes == 0) db_fail("total_title_bytes==0");

	g->N = (u32)nr_entries;
	g->L = total_links;

	if (g->N > 0xFFFFFFu) {
		fprintf(stderr, "error: N=%u does not fit in 24-bit ids; disable u24 or update format\n", g->N);
		exit(1);
	}

	// --- read outdegrees (u16 per node), build out_offsets
	g->out_offsets = (u32*)malloc(((size_t)g->N + 1u) * sizeof(u32));
	if (!g->out_offsets) db_fail("OOM out_offsets");
	g->out_offsets[0] = 0;

	u64 sum_deg = 0;
	for (u32 i = 0; i < g->N; i++) {
		u16 d = 0;
		DB_READ(r, d, "outdegree");
		sum_deg += (u64)d;
		g->out_offsets[i + 1] = g->out_offsets[i] + (u32)d;
	}

	u32 pad_u16 = (g->N % 4u) ? (4u - (g->N % 4u)) : 0u;
	if (pad_u16) db_reader_skip(r, (size_t)pad_u16 * sizeof(u16), "outdegree padding");

	if (sum_deg != (u64)g->L) {
		fprintf(stderr, "error: total_links mismatch (header=%u, sum_outdeg=%llu)\n", g->L,
				(unsigned long long)sum_deg);
		exit(1);
	}

	if (g->L > (u32)((SIZE_MAX - 4u) / 3u)) db_fail("edge bytes overflow");
	size_t out_bytes = (size_t)g->L * 3u + 4u;
	g->out_edges24   = (u8*)malloc(out_bytes);
	if (!g->out_edges24) db_fail("OOM out_edges24");
	memset(g->out_edges24 + (size_t)g->L * 3u, 0, 4); // padding

	g->max_out_degree = 0;

	// --- outgoing edge u32 block, streamed and packed to u24
	for (u32 u = 0; u < g->N; u++) {
		u32  beg      = g->out_offsets[u];
		u32  end2     = g->out_offsets[u + 1];
		u32  out_deg  = end2 - beg;
		u32  prev     = 0;
		bool has_prev = false;
		if (out_deg > g->max_out_degree) g->max_out_degree = out_deg;

		u32 idx = beg;
		while (idx < end2) {
			DB_REQUIRE(r, sizeof(u32), "edge block");
			size_t avail_vals = (r->len - r->pos) / sizeof(u32);
			size_t need_vals  = (size_t)(end2 - idx);
			size_t take_vals  = (avail_vals < need_vals) ? avail_vals : need_vals;
			const u8* q       = r->buf + r->pos;
			for (size_t k = 0; k < take_vals; k++, idx++, q += sizeof(u32)) {
				u32 v = 0;
				memcpy(&v, q, sizeof(u32));
				if (v >= g->N) db_fail("edge id out of range");
				if (has_prev && v < prev) db_fail("adjacency not sorted");
				has_prev = true;
				prev     = v;
				u24_store(u24_ptr(g->out_edges24, idx), v);
			}
			db_reader_consume(r, take_vals * sizeof(u32));
		}
	}

	// --- title lengths + title bytes
	size_t title_lens_bytes = (size_t)g->N * sizeof(u16);
	u16*   title_lens       = (u16*)malloc(title_lens_bytes);
	if (!title_lens) db_fail("OOM title lengths");
	db_reader_read_exact(r, title_lens, title_lens_bytes, "title lengths");

	g->titles = (string*)malloc((size_t)g->N * sizeof(string));
	if (!g->titles) db_fail("OOM titles array");
	g->titles_arena = (char*)malloc((size_t)total_title_bytes);
	if (!g->titles_arena) db_fail("OOM titles arena");
	g->titles_arena_bytes = total_title_bytes;
	db_reader_read_exact(r, g->titles_arena, (size_t)total_title_bytes, "title bytes");

	u32 off = 0;
	for (u32 i = 0; i < g->N; i++) {
		u16 len = title_lens[i];
		if ((u32)len > 65535u) db_fail("title len > 65535");
		if (off + (u32)len > total_title_bytes) db_fail("title bytes overflow");
		g->titles[i] = STR(g->titles_arena + off, (int)len);
		off += (u32)len;
	}
	if (off != total_title_bytes) db_fail("title bytes sum mismatch");
	free(title_lens);

	// --- v2 optional sections
	u32 un_n = 0, rt_n = 0, rt_bytes = 0;
	u32 rt_pad = 0;

	g->nr_unredir      = 0;
	g->unredir         = NULL;
	g->nr_redir_titles = 0;
	g->redir_titles    = NULL;
	g->redir_arena     = NULL;
	g->redir_arena_bytes = 0;
	g->edge_flags        = NULL;

	if (dump_format >= 2) {
		DB_READ(r, un_n, "unredir count");
		DB_READ(r, rt_n, "redir title count");
		DB_READ(r, rt_bytes, "redir title bytes");

		g->nr_unredir = un_n;
		if (un_n) {
			g->unredir = (UnredirEdge*)malloc((size_t)un_n * sizeof(UnredirEdge));
			if (!g->unredir) db_fail("OOM unredir");
			for (u32 i = 0; i < un_n; i++) {
				u32 src = 0, dst = 0, ridx = 0;
				DB_READ(r, src, "unredir src");
				DB_READ(r, dst, "unredir dest");
				DB_READ(r, ridx, "unredir redir_idx");
				g->unredir[i].src       = src;
				g->unredir[i].dest      = dst;
				g->unredir[i].redir_idx = ridx;
			}
		}

		g->nr_redir_titles   = rt_n;
		g->redir_arena_bytes = rt_bytes;
		if (rt_n) {
			u8* redir_lens = (u8*)malloc((size_t)rt_n);
			if (!redir_lens) db_fail("OOM redir lens");
			db_reader_read_exact(r, redir_lens, (size_t)rt_n, "redir lens");

			rt_pad = (4u - (rt_n & 3u)) & 3u;
			if (rt_pad) db_reader_skip(r, rt_pad, "redir lens pad");

			g->redir_titles = (string*)malloc((size_t)rt_n * sizeof(string));
			if (!g->redir_titles) db_fail("OOM redir_titles");
			g->redir_arena = (char*)malloc((size_t)rt_bytes);
			if (!g->redir_arena) db_fail("OOM redir_arena");
			db_reader_read_exact(r, g->redir_arena, (size_t)rt_bytes, "redir bytes");

			u32 off2 = 0;
			for (u32 i = 0; i < rt_n; i++) {
				u32 len = (u32)redir_lens[i];
				if (off2 + len > rt_bytes) db_fail("redir bytes overflow");
				g->redir_titles[i] = STR(g->redir_arena + off2, (int)len);
				off2 += len;
			}
			if (off2 != rt_bytes) db_fail("redir bytes sum mismatch");
			free(redir_lens);
		}
	}

	u32 link_flags_bytes   = 0;
	u64 link_flags_rename  = 0;
	u64 link_flags_infobox = 0;
	u64 link_flags_unknown = 0;

	if (dump_format >= 2 && db_reader_has_more(r)) {
		link_flags_bytes = g->L;
		g->edge_flags    = (u8*)malloc((size_t)link_flags_bytes);
		if (!g->edge_flags) db_fail("OOM edge_flags");
		db_reader_read_exact(r, g->edge_flags, (size_t)link_flags_bytes, "link_flags");
		for (u32 i = 0; i < link_flags_bytes; i++) {
			u8 flags = g->edge_flags[i];
			if (flags & LINK_FLAG_IS_RENAME) link_flags_rename++;
			if (flags & LINK_FLAG_IS_INFOBOX) link_flags_infobox++;
			if (flags & (u8) ~(LINK_FLAG_IS_RENAME | LINK_FLAG_IS_INFOBOX)) link_flags_unknown++;
		}
		printf("[info] link flags summary: rename=%llu infobox=%llu unknown_bitmask=%llu\n",
			   (unsigned long long)link_flags_rename, (unsigned long long)link_flags_infobox,
			   (unsigned long long)link_flags_unknown);
	}

	u64 unknown_tail_bytes = db_reader_drain_remaining(r);

	u64 header_bytes =
		4u + (u64)sizeof(version) + (u64)sizeof(nr_entries) + (u64)sizeof(total_links) + (u64)sizeof(total_title_bytes);
	u64 section1_outdegree_bytes  = (u64)g->N * (u64)sizeof(u16) + (u64)pad_u16 * (u64)sizeof(u16);
	u64 section2_edges_u32_bytes  = (u64)g->L * (u64)sizeof(u32);
	u64 section3_title_lens_bytes = (u64)g->N * (u64)sizeof(u16);
	u64 section4_title_bytes      = (u64)total_title_bytes;
	u64 section5_v2_header_bytes  = (dump_format >= 2) ? (3u * (u64)sizeof(u32)) : 0u;
	u64 section5_unredir_bytes    = (u64)un_n * 3u * (u64)sizeof(u32);
	u64 section5_redir_lens_bytes = (u64)rt_n + (u64)rt_pad;
	u64 section5_redir_text_bytes = (u64)rt_bytes;
	u64 section5_v2_total_bytes =
		section5_v2_header_bytes + section5_unredir_bytes + section5_redir_lens_bytes + section5_redir_text_bytes;
	u64 section6_link_flags_bytes = (u64)link_flags_bytes;
	u64 known_total_bytes         = header_bytes + section1_outdegree_bytes + section2_edges_u32_bytes +
							section3_title_lens_bytes + section4_title_bytes + section5_v2_total_bytes +
							section6_link_flags_bytes;
	int value_width = 1;
	for (u64 t = known_total_bytes; t >= 10; t /= 10) value_width++;

#define PRINT_DB_SIZE(label, bytes)                                                                              \
	do {                                                                                                         \
		double pct = (known_total_bytes == 0) ? 0.0 : (100.0 * (double)(bytes) / (double)known_total_bytes); \
		printf("[info]   %-32s %*llu (%.2f%%)\n", (label), value_width, (unsigned long long)(bytes), pct);   \
	} while (0)

	printf("[info] db section bytes:\n");
	PRINT_DB_SIZE("header:", header_bytes);
	PRINT_DB_SIZE("section1_outdegree_u16_plus_pad:", section1_outdegree_bytes);
	PRINT_DB_SIZE("section2_edges_u32:", section2_edges_u32_bytes);
	PRINT_DB_SIZE("section3_title_lens_u16:", section3_title_lens_bytes);
	PRINT_DB_SIZE("section4_title_bytes:", section4_title_bytes);
	PRINT_DB_SIZE("section5_v2_total:", section5_v2_total_bytes);
	PRINT_DB_SIZE("  section5_v2_header:", section5_v2_header_bytes);
	PRINT_DB_SIZE("  section5_unredir_tuples:", section5_unredir_bytes);
	PRINT_DB_SIZE("  section5_redir_lens_plus_pad:", section5_redir_lens_bytes);
	PRINT_DB_SIZE("  section5_redir_title_bytes:", section5_redir_text_bytes);
	PRINT_DB_SIZE("section6_link_flags:", section6_link_flags_bytes);
	PRINT_DB_SIZE("known_total:", known_total_bytes);
#undef PRINT_DB_SIZE
	if (unknown_tail_bytes) {
		double tail_pct = (known_total_bytes == 0) ? 0.0 : (100.0 * (double)unknown_tail_bytes / (double)known_total_bytes);
		printf("[info]   %-32s %*llu (%.2f%%) (ignored)\n", "unknown_tail_bytes:", value_width,
			   (unsigned long long)unknown_tail_bytes, tail_pct);
	}
	printf("[info] unredirect entries: %u\n", un_n);
	printf("[info] redirect titles: %u\n", rt_n);
	printf("[info] link flag bytes: %u\n", link_flags_bytes);

	log_ts("processed db file");

	validate_graph_fully(g);
	search_prepare_graph(g);

	log_ts("validated db file");
}

STATIC void graph_load_from_stream(Graph* g, DbStreamFillFn fill, void* ctx, bool is_compressed) {
	DbSource source;
	source.fill = fill;
	source.ctx  = ctx;

#ifndef NO_COMPRESSION
	LzmaSourceCtx lzma_ctx;
	if (is_compressed) {
		lzma_source_init(&lzma_ctx, source);
		source.fill = lzma_source_fill;
		source.ctx  = &lzma_ctx;
	}
#else
	(void)is_compressed;
#endif

	DbReader reader;
	db_reader_init(&reader, source);
	graph_load_from_reader(g, &reader);
	db_reader_destroy(&reader);

#ifndef NO_COMPRESSION
	if (is_compressed) lzma_source_destroy(&lzma_ctx);
#endif
}

// Load graph from a raw (decompressed) buffer. The buffer is freed after loading.
STATIC void graph_load_from_mem(Graph* g, char* raw, long raw_len) {
	if (raw_len <= 0) db_fail("empty raw db");

	MemSourceCtx mem_ctx;
	mem_ctx.buf = (const u8*)raw;
	mem_ctx.len = (size_t)raw_len;
	mem_ctx.pos = 0;
	DbSource source;
	source.fill = mem_source_fill;
	source.ctx  = &mem_ctx;
	graph_load_from_stream(g, source.fill, source.ctx, false);

	free(raw);
}

STATIC void graph_load_from_file(Graph* g, const char* path) {
	puts("streaming db file...");
	FILE* f = fopen(path, "rb");
	if (!f) {
		fprintf(stderr, "error: could not open db file: %s\n", strerror(errno));
		exit(1);
	}

	u8     probe[4] = {0};
	size_t nprobe   = fread(probe, 1, sizeof(probe), f);
	if (nprobe < sizeof(probe) && ferror(f)) {
		fprintf(stderr, "error: could not read db file: %s\n", strerror(errno));
		exit(1);
	}
	if (nprobe < sizeof(probe)) db_fail("empty db file");
	if (fseek(f, 0, SEEK_SET) != 0) {
		fprintf(stderr, "error: could not seek db file: %s\n", strerror(errno));
		exit(1);
	}

	bool is_raw = (memcmp(probe, "WIKI", 4) == 0);
	FileSourceCtx file_ctx;
	file_ctx.f = f;
	if (!is_raw) puts("decompressing db stream...");
	graph_load_from_stream(g, file_source_fill, &file_ctx, !is_raw);
	fclose(f);
}

typedef struct {
	u8     prefix[4];
	size_t prefix_pos;
	FILE*  f;
} StdinPrefixCtx;

STATIC size_t stdin_prefix_fill(void* ctx_ptr, u8* dst, size_t cap, bool* out_eof) {
	StdinPrefixCtx* c = (StdinPrefixCtx*)ctx_ptr;
	size_t total = 0;

	// drain prefix bytes first
	while (c->prefix_pos < 4 && total < cap) {
		dst[total++] = c->prefix[c->prefix_pos++];
	}

	if (total < cap) {
		size_t got = fread(dst + total, 1, cap - total, c->f);
		if (got == 0 && ferror(c->f)) {
			fprintf(stderr, "error: could not read from stdin: %s\n", strerror(errno));
			exit(1);
		}
		total += got;
	}

	*out_eof = feof(c->f) && c->prefix_pos >= 4;
	return total;
}

STATIC void graph_load_from_stdin(Graph* g) {
	puts("streaming db from stdin...");

	// Read 4-byte probe to detect compression without seeking.
	u8     probe[4] = {0};
	size_t nprobe   = fread(probe, 1, sizeof(probe), stdin);
	if (nprobe < sizeof(probe) && ferror(stdin)) {
		fprintf(stderr, "error: could not read from stdin: %s\n", strerror(errno));
		exit(1);
	}
	if (nprobe < sizeof(probe)) db_fail("stdin too short for db");

	bool is_raw = (memcmp(probe, "WIKI", 4) == 0);

	// Chain a prefix source (the 4 probe bytes) with stdin to form a
	// single contiguous stream — no seeking required.
	StdinPrefixCtx ctx;
	memcpy(ctx.prefix, probe, 4);
	ctx.prefix_pos = 0;
	ctx.f          = stdin;

	if (!is_raw) puts("decompressing stdin stream...");
	graph_load_from_stream(g, stdin_prefix_fill, &ctx, !is_raw);
}
