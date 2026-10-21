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
		DB_REQUIRE((reader), sizeof(dst), (what));                  \
		memcpy(&(dst), (reader)->buf + (reader)->pos, sizeof(dst)); \
		db_reader_consume((reader), sizeof(dst));                   \
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
	ctx->in_buf   = (u8*)malloc(DB_IO_BUF_SIZE);
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
			bool   src_eof     = false;
			size_t got         = ctx->upstream.fill(ctx->upstream.ctx, ctx->in_buf, DB_IO_BUF_SIZE, &src_eof);
			ctx->strm.next_in  = ctx->in_buf;
			ctx->strm.avail_in = got;
			ctx->in_eof        = src_eof;
			if (got == 0 && !ctx->in_eof) db_fail("compressed reader source stalled");
		}

		size_t   in_before  = ctx->strm.avail_in;
		size_t   out_before = ctx->strm.avail_out;
		lzma_ret ret        = lzma_code(&ctx->strm, ctx->in_eof ? LZMA_FINISH : LZMA_RUN);

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

typedef struct ZstdSourceCtx {
	DbSource      upstream;
	ZSTD_DStream* strm;
	ZSTD_inBuffer in;
	u8*           in_buf;
	bool          in_eof;
	bool          frame_done;
	bool          finished;
} ZstdSourceCtx;

STATIC void zstd_source_init(ZstdSourceCtx* ctx, DbSource upstream) {
	memset(ctx, 0, sizeof(*ctx));
	ctx->upstream = upstream;
	ctx->strm     = ZSTD_createDStream();
	ctx->in_buf   = (u8*)malloc(DB_IO_BUF_SIZE);
	if (!ctx->strm || !ctx->in_buf) {
		fprintf(stderr, "error: OOM allocating zstd decoder\n");
		exit(1);
	}
	ctx->in.src = ctx->in_buf;
}

STATIC void zstd_source_destroy(ZstdSourceCtx* ctx) {
	ZSTD_freeDStream(ctx->strm);
	free(ctx->in_buf);
	ctx->in_buf = NULL;
}

STATIC size_t zstd_source_fill(void* ctx_ptr, u8* dst, size_t cap, bool* out_eof) {
	ZstdSourceCtx* ctx = (ZstdSourceCtx*)ctx_ptr;
	ZSTD_outBuffer out = {dst, cap, 0};
	while (!ctx->finished && out.pos == 0) {
		if (ctx->in.pos == ctx->in.size && !ctx->in_eof) {
			ctx->in.size = ctx->upstream.fill(ctx->upstream.ctx, ctx->in_buf, DB_IO_BUF_SIZE, &ctx->in_eof);
			ctx->in.pos  = 0;
			if (ctx->in.size == 0 && !ctx->in_eof) db_fail("compressed reader source stalled");
		}
		if (ctx->in.pos == ctx->in.size && ctx->in_eof) {
			if (!ctx->frame_done) db_fail("zstd stream ended unexpectedly");
			ctx->finished = true;
			break;
		}
		size_t ret = ZSTD_decompressStream(ctx->strm, &out, &ctx->in);
		if (ZSTD_isError(ret)) {
			fprintf(stderr, "error: zstd decode failed (%s)\n", ZSTD_getErrorName(ret));
			exit(1);
		}
		ctx->frame_done = ret == 0;
	}
	*out_eof = ctx->finished;
	return out.pos;
}

// Replays a reader's buffered bytes, then continues from its source (used after sniffing a stream).
STATIC size_t db_reader_source_fill(void* ctx_ptr, u8* dst, size_t cap, bool* out_eof) {
	DbReader* r = (DbReader*)ctx_ptr;
	if (r->pos == r->len) {
		if (r->eof) return *out_eof = true, 0;
		return r->source.fill(r->source.ctx, dst, cap, out_eof);
	}
	size_t n = MIN(cap, r->len - r->pos);
	memcpy(dst, r->buf + r->pos, n);
	db_reader_consume(r, n);
	*out_eof = r->eof && r->pos == r->len;
	return n;
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

// --- v3: the v2 sections, re-encoded by db_gen/wiki_v3.h. Each section is a u32 length plus its bytes.
typedef struct V3Bytes {
	u8*       data;
	const u8 *p, *end;
	u64       acc; // bit reader state for the low-bits section
	int       nbits;
} V3Bytes;

STATIC V3Bytes v3_section(DbReader* r) {
	u32 n = 0;
	DB_READ(r, n, "v3 section length");
	V3Bytes s = {0};
	if (!(s.data = (u8*)malloc(n ? n : 1))) db_fail("OOM v3 section");
	db_reader_read_exact(r, s.data, n, "v3 section");
	s.p   = s.data;
	s.end = s.data + n;
	return s;
}

STATIC void v3_done(V3Bytes* s) {
	if (s->p != s->end || s->nbits >= 8 || (s->acc & ((1u << s->nbits) - 1))) db_fail("v3 section has trailing bytes");
	free(s->data);
}

STATIC u8 v3_byte(V3Bytes* s) {
	if (s->p == s->end) db_fail("v3 section truncated");
	return *s->p++;
}

STATIC u32 v3_varint(V3Bytes* s) {
	u32 x = 0;
	for (int shift = 0; shift < 35; shift += 7) {
		u8 b = v3_byte(s);
		x |= (u32)(b & 127) << shift;
		if (!(b & 128)) return x;
	}
	db_fail("v3 varint");
	return 0;
}

STATIC u32 v3_bits(V3Bytes* s, int k) {
	while (s->nbits < k) s->acc = s->acc << 8 | v3_byte(s), s->nbits += 8;
	s->nbits -= k;
	return (u32)(s->acc >> s->nbits) & ((1u << k) - 1);
}

// Inverse of wiki_v3::put_gap(): symbols 1..7 are values, larger symbols carry the top 3 bits.
STATIC u32 v3_gap(V3Bytes* sym, V3Bytes* low) {
	u32 s = v3_byte(sym);
	if (s < 8) {
		if (!s) db_fail("v3 zero gap");
		return s;
	}
	u32 k = (s - 8) / 4 + 3;
	if (k > 31) db_fail("v3 gap symbol");
	return (4u | ((s - 8) & 3)) << (k - 2) | v3_bits(low, (int)k - 2);
}

// Adjacency lists are short; qsort's comparator calls dominated v3 loading.
STATIC void sort_u32(u32* a, u32 n) {
	while (n > 16) {
		u32 pivot = a[n / 2], i = 0, j = n - 1;
		for (;;) {
			while (a[i] < pivot) i++;
			while (a[j] > pivot) j--;
			if (i >= j) break;
			u32 t  = a[i];
			a[i++] = a[j];
			a[j--] = t;
		}
		u32 split = j + 1; // recurse into the smaller side
		if (split < n - split) sort_u32(a, split), a += split, n -= split;
		else sort_u32(a + split, n - split), n = split;
	}
	for (u32 i = 1; i < n; i++) {
		u32 x = a[i], j = i;
		for (; j && a[j - 1] > x; j--) a[j] = a[j - 1];
		a[j] = x;
	}
}

STATIC void v3_titles(DbReader* r, u32 n, u32 bytes, string** titles, char** arena) {
	V3Bytes s = v3_section(r);
	*titles   = (string*)malloc((size_t)n * sizeof(string) + 1);
	*arena    = (char*)malloc((size_t)bytes + 1);
	if (!*titles || !*arena) db_fail("OOM v3 titles");
	u32 off = 0, prev_len = 0;
	for (u32 i = 0; i < n; i++) {
		u32 prefix = v3_byte(&s);
		if (prefix > prev_len) db_fail("v3 title prefix");
		const u8* nl = (const u8*)memchr(s.p, '\n', (size_t)(s.end - s.p));
		if (!nl) db_fail("v3 title truncated");
		u32 len = prefix + (u32)(nl - s.p);
		if (len > 65535 || len > bytes - off) db_fail("v3 title bytes");
		if (prefix) memmove(*arena + off, *arena + off - prev_len, prefix);
		memcpy(*arena + off + prefix, s.p, (size_t)(nl - s.p));
		(*titles)[i] = STR(*arena + off, (int)len);
		s.p          = nl + 1;
		off += len;
		prev_len = len;
	}
	if (off != bytes) db_fail("v3 title bytes sum mismatch");
	v3_done(&s);
}

STATIC void graph_load_v3(Graph* g, DbReader* r, u32 title_bytes) {
	u32 N = g->N, L = g->L, U = 0, R = 0, RB = 0;
	DB_READ(r, U, "unredir count");
	DB_READ(r, R, "redir title count");
	DB_READ(r, RB, "redir title bytes");

	V3Bytes degrees = v3_section(r), in_degrees = v3_section(r), ref_counts, refs, mask_syms, syms[26], low;

	g->out_offsets = (u32*)malloc(((size_t)N + 1) * sizeof(u32));
	g->out_edges24 = (u8*)calloc((size_t)L * 3 + 4, 1);
	u32* order     = (u32*)malloc((size_t)N * sizeof(u32));
	u32* indeg     = (u32*)malloc((size_t)N * sizeof(u32));
	u32* list      = (u32*)malloc(4 * 65536 * sizeof(u32)); // up to 3 copied lists plus the rest
	if (!g->out_offsets || !g->out_edges24 || !order || !indeg || !list) db_fail("OOM v3 edges");
	g->out_offsets[0] = 0;
	u64 sum = 0, insum = 0;
	u32 max_in = 0;
	for (u32 i = 0; i < N; i++) {
		u32 d = v3_byte(&degrees);
		d |= (u32)v3_byte(&degrees) << 8;
		sum += d;
		if (sum > L) db_fail("total_links mismatch");
		g->out_offsets[i + 1] = (u32)sum;
		indeg[i]              = v3_varint(&in_degrees);
		insum += indeg[i];
		if (indeg[i] > max_in) max_in = indeg[i];
	}
	if (sum != L || insum != L) db_fail("total_links mismatch");
	v3_done(&degrees);
	v3_done(&in_degrees);

	// order[rank] = node, ranked by descending in-degree (stable counting sort).
	u32* start = (u32*)calloc((size_t)max_in + 2, sizeof(u32));
	if (!start) db_fail("OOM v3 ranks");
	for (u32 i = 0; i < N; i++) start[max_in - indeg[i] + 1]++;
	for (u32 v = 1; v <= max_in + 1; v++) start[v] += start[v - 1];
	for (u32 i = 0; i < N; i++) order[start[max_in - indeg[i]]++] = i;
	free(start);

	g->max_out_degree = 0;
	for (u32 i = 0; i < N; i++) {
		if (i % 65536 == 0) { // edge sections come in blocks of 65536 nodes
			ref_counts = v3_section(r), refs = v3_section(r), mask_syms = v3_section(r);
			for (int c = 0; c < 26; c++) syms[c] = v3_section(r);
			low = v3_section(r);
		}
		u32 d = g->out_offsets[i + 1] - g->out_offsets[i], n = 0, nrefs = v3_byte(&ref_counts);
		if (d > g->max_out_degree) g->max_out_degree = d;
		if (nrefs > 3) db_fail("v3 reference count");
		for (u32 k = 0; k < nrefs; k++) {
			u32 dist = v3_varint(&refs), shared = v3_varint(&refs);
			if (!dist || dist > i) db_fail("v3 reference distance");
			u32 ref = i - dist, rbeg = g->out_offsets[ref], rd = g->out_offsets[ref + 1] - rbeg;
			if (shared > rd || shared > d) db_fail("v3 reference count");
			// The mask lists whichever side is smaller: the copied positions, or the skipped ones.
			u32 p = UINT32_MAX;
			if (shared <= rd - shared) {
				for (u32 j = 0; j < shared; j++) {
					if ((p += v3_gap(&mask_syms, &low)) >= rd) db_fail("v3 mask position");
					list[n++] = u24_load(u24_cptr(g->out_edges24, rbeg + p));
				}
			} else {
				u32 skip = rd - shared, next = skip ? p + v3_gap(&mask_syms, &low) : UINT32_MAX;
				for (p = 0; p < rd; p++) {
					if (p != next) list[n++] = u24_load(u24_cptr(g->out_edges24, rbeg + p));
					else next = --skip ? next + v3_gap(&mask_syms, &low) : UINT32_MAX;
				}
				if (next != UINT32_MAX) db_fail("v3 mask position");
			}
		}
		if (nrefs > 1) {
			sort_u32(list, n);
			u32 m = 0;
			for (u32 k = 0; k < n; k++)
				if (!m || list[k] != list[m - 1]) list[m++] = list[k];
			n = m;
		}
		if (n > d) db_fail("v3 copied links exceed degree");
		// The rest arrive in rank order: sort them and merge with the copied links.
		u32 *rest = list + n, nrest = d - n, prev = UINT32_MAX;
		for (u32 j = 0; j < nrest; j++) {
			u32 c = j ? 1 + MIN((u32)(31 - __builtin_clz(prev + 1)), 24u) : 0;
			prev += v3_gap(&syms[c], &low);
			if (prev >= N) db_fail("v3 link rank");
			rest[j] = order[prev];
		}
		sort_u32(rest, nrest);
		u8* out = u24_ptr(g->out_edges24, g->out_offsets[i]);
		for (u32 a = 0, b = 0, last = UINT32_MAX; a + b < d; out += 3) {
			u32 v = b == nrest || (a < n && list[a] < rest[b]) ? list[a++] : rest[b++];
			if (last != UINT32_MAX && v <= last) db_fail("v3 adjacency not strictly sorted");
			u24_store(out, last = v);
		}
		if ((i + 1) % 65536 == 0 || i + 1 == N) {
			v3_done(&ref_counts);
			v3_done(&refs);
			v3_done(&mask_syms);
			for (int c = 0; c < 26; c++) v3_done(&syms[c]);
			v3_done(&low);
		}
	}
	free(list);
	free(order);
	free(indeg);

	v3_titles(r, N, title_bytes, &g->titles, &g->titles_arena);
	g->titles_arena_bytes = title_bytes;

	// Redirect annotations: each target's aliases, then per link to such a target one bit, and the alias rank when set.
	V3Bytes alias_lists = v3_section(r), alias_bits = v3_section(r), alias_ranks = v3_section(r);
	u32*    alias_off = (u32*)malloc(((size_t)N + 1) * sizeof(u32));
	u32*    alias_ids = (u32*)malloc(((size_t)MIN(U, R) + 1) * sizeof(u32));
	g->unredir        = (UnredirEdge*)malloc(((size_t)U + 1) * sizeof(UnredirEdge));
	if (!alias_off || !alias_ids || !g->unredir) db_fail("OOM v3 aliases");
	alias_off[0] = 0;
	for (u32 i = 0; i < N; i++) {
		u32 n = v3_varint(&alias_lists);
		if (n > MIN(U, R) - alias_off[i]) db_fail("v3 alias count");
		for (u32 k = 0; k < n; k++)
			if ((alias_ids[alias_off[i] + k] = v3_varint(&alias_lists)) >= R) db_fail("v3 alias id");
		alias_off[i + 1] = alias_off[i] + n;
	}
	u32 u = 0;
	for (u32 s = 0; s < N; s++)
		for (u32 k = g->out_offsets[s]; k < g->out_offsets[s + 1]; k++) {
			u32 dest = u24_load(u24_cptr(g->out_edges24, k)), n = alias_off[dest + 1] - alias_off[dest];
			if (!n || !v3_bits(&alias_bits, 1)) continue;
			u32 v = v3_varint(&alias_ranks);
			if (v >= n || u == U) db_fail("v3 alias rank");
			g->unredir[u++] = (UnredirEdge){s, dest, alias_ids[alias_off[dest] + v]};
		}
	if (u != U) db_fail("v3 unredir count");
	g->nr_unredir = U;
	v3_done(&alias_lists);
	v3_done(&alias_bits);
	v3_done(&alias_ranks);
	free(alias_off);
	free(alias_ids);

	g->nr_redir_titles   = R;
	g->redir_arena_bytes = RB;
	v3_titles(r, R, RB, &g->redir_titles, &g->redir_arena);

	// Flags: each target's predicted value, then one bitmap per bit that differs anywhere.
	V3Bytes predicted = v3_section(r), planes = v3_section(r);
	if ((size_t)(predicted.end - predicted.p) != N) db_fail("v3 flag predictions");
	u8 active     = v3_byte(&planes);
	g->edge_flags = (u8*)malloc((size_t)L + 1);
	if (!g->edge_flags) db_fail("OOM edge_flags");
	for (u32 k = 0; k < L; k++) g->edge_flags[k] = predicted.p[u24_load(u24_cptr(g->out_edges24, k))];
	for (int b = 0; b < 8; b++) {
		if (!(active >> b & 1)) continue;
		if ((size_t)(planes.end - planes.p) < ((size_t)L + 7) / 8) db_fail("v3 flag planes");
		for (u32 k = 0; k < L; k++) g->edge_flags[k] ^= (u8)((planes.p[k / 8] >> (k % 8) & 1) << b);
		planes.p += ((size_t)L + 7) / 8;
	}
	predicted.p = predicted.end;
	v3_done(&predicted);
	v3_done(&planes);
	db_reader_drain_remaining(r);
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

	if (dump_format >= 3) {
		graph_load_v3(g, r, total_title_bytes);
		log_ts("processed db file");
		validate_graph_fully(g);
		search_prepare_graph(g);
		log_ts("validated db file");
		return;
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
			size_t    avail_vals = (r->len - r->pos) / sizeof(u32);
			size_t    need_vals  = (size_t)(end2 - idx);
			size_t    take_vals  = (avail_vals < need_vals) ? avail_vals : need_vals;
			const u8* q          = r->buf + r->pos;
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

	g->nr_unredir        = 0;
	g->unredir           = NULL;
	g->nr_redir_titles   = 0;
	g->redir_titles      = NULL;
	g->redir_arena       = NULL;
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

#define PRINT_DB_SIZE(label, bytes)                                                                          \
	do {                                                                                                     \
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
		double tail_pct = 100.0 * (double)unknown_tail_bytes / (double)known_total_bytes;
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
	ZstdSourceCtx zstd_ctx;
	DbReader      probe;
	bool          zstd = false;
	if (is_compressed) {
		// Sniff xz vs zstd, then replay the probed bytes into the decoder.
		db_reader_init(&probe, source);
		DB_REQUIRE(&probe, 4, "compressed db signature");
		zstd        = !memcmp(probe.buf + probe.pos, "\x28\xb5\x2f\xfd", 4);
		source.fill = db_reader_source_fill;
		source.ctx  = &probe;
		if (zstd) {
			zstd_source_init(&zstd_ctx, source);
			source.fill = zstd_source_fill;
			source.ctx  = &zstd_ctx;
		} else {
			lzma_source_init(&lzma_ctx, source);
			source.fill = lzma_source_fill;
			source.ctx  = &lzma_ctx;
		}
	}
#else
	(void)is_compressed;
#endif

	DbReader reader;
	db_reader_init(&reader, source);
	graph_load_from_reader(g, &reader);
	db_reader_destroy(&reader);

#ifndef NO_COMPRESSION
	if (is_compressed) {
		if (zstd) zstd_source_destroy(&zstd_ctx);
		else lzma_source_destroy(&lzma_ctx);
		db_reader_destroy(&probe);
	}
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

	bool          is_raw = (memcmp(probe, "WIKI", 4) == 0);
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
	StdinPrefixCtx* c     = (StdinPrefixCtx*)ctx_ptr;
	size_t          total = 0;

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
