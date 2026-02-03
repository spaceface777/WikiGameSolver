// DB loading + conversion to runtime Graph (CSR + u24 edges), then free blob.

STATIC void db_fail(const char* what) {
	fprintf(stderr, "error: invalid/truncated db (%s)\n", what);
	exit(1);
}

#define DB_REQUIRE(p, end, n, what)                                            \
	do {                                                                       \
		if ((p) > (end) || (size_t)((end) - (p)) < (size_t)(n)) db_fail(what); \
	} while (0)

#define DB_READ(p, end, dst, what)                 \
	do {                                           \
		DB_REQUIRE((p), (end), sizeof(dst), what); \
		memcpy(&(dst), (p), sizeof(dst));          \
		(p) += sizeof(dst);                        \
	} while (0)

STATIC char* read_file_all(const char* path, long* out_len) {
	FILE* f = fopen(path, "rb");
	if (!f) {
		fprintf(stderr, "error: could not open db file: %s\n", strerror(errno));
		exit(1);
	}
	fseek(f, 0, SEEK_END);
	long len = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (len <= 0) {
		fprintf(stderr, "error: empty db file\n");
		exit(1);
	}
	char* buf = (char*)malloc((size_t)len);
	if (!buf) {
		fprintf(stderr, "error: OOM reading db\n");
		exit(1);
	}
	if ((long)fread(buf, 1, (size_t)len, f) != len) {
		fprintf(stderr, "error: could not read db file: %s\n", strerror(errno));
		exit(1);
	}
	fclose(f);
	*out_len = len;
	return buf;
}

#ifndef NO_COMPRESSION
STATIC char* lzma_decompress_alloc(const char* in, long in_len, long* out_len) {
	puts("decompressing db file...");
	lzma_stream strm = LZMA_STREAM_INIT;
	lzma_ret	ret	 = lzma_stream_decoder(&strm, UINT64_MAX, 0);
	if (ret != LZMA_OK) {
		fprintf(stderr, "error: cannot initialize lzma decoder\n");
		exit(1);
	}

	char*		 out	  = NULL;
	size_t		 out_size = 0;
	size_t		 in_pos	  = 0;
	const size_t CHUNK	  = 1u << 24;

	while (1) {
		strm.next_in  = (const uint8_t*)(in + in_pos);
		strm.avail_in = (size_t)in_len - in_pos;

		out = (char*)realloc(out, out_size + CHUNK);
		if (!out) {
			fprintf(stderr, "error: OOM during decompression\n");
			exit(1);
		}
		strm.next_out  = (uint8_t*)(out + out_size);
		strm.avail_out = CHUNK;

		ret = lzma_code(&strm, LZMA_RUN);
		if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
			fprintf(stderr, "error: lzma decode failed (%d)\n", (int)ret);
			exit(1);
		}

		out_size += CHUNK - strm.avail_out;
		in_pos += (size_t)(strm.next_in - (const uint8_t*)(in + in_pos));

		if (ret == LZMA_STREAM_END) break;
	}

	lzma_end(&strm);
	*out_len = (long)out_size;
	return out;
}
#endif

STATIC void validate_graph_fully(Graph* g) {
#if !defined(DB_NO_VALIDATE)
	if (!g->titles || !g->out_offsets || !g->out_edges24 || !g->in_offsets || !g->in_edges24)
		db_fail("internal graph not initialized");

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
	if (g->in_offsets[0] != 0) db_fail("in_offsets[0]!=0");
	if (g->in_offsets[g->N] != g->L) db_fail("in_offsets[N]!=L");
	for (u32 i = 0; i < g->N; i++) {
		if (g->in_offsets[i] > g->in_offsets[i + 1]) db_fail("in_offsets not monotonic");
	}

	// Validate adjacency lists are sorted and in range (decode u24 once at startup).
	// This is O(L) and allowed at startup.
	for (u32 u = 0; u < g->N; u++) {
		u32 beg = g->out_offsets[u];
		u32 end = g->out_offsets[u + 1];
		if (beg > end || end > g->L) db_fail("out_offsets bounds");
		if (end > beg) {
			const u8* p	   = u24_cptr(g->out_edges24, beg);
			u32		  prev = u24_load(p);
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

	// Incoming edges in range (decode once).
	for (u32 v = 0; v < g->N; v++) {
		u32 beg = g->in_offsets[v];
		u32 end = g->in_offsets[v + 1];
		if (beg > end || end > g->L) db_fail("in_offsets bounds");
		const u8* p = u24_cptr(g->in_edges24, beg);
		for (u32 idx = beg; idx < end; idx++, p += 3) {
			u32 src = u24_load(p);
			if (src >= g->N) db_fail("in edge src out of range");
		}
	}

	// Validate unredir table invariants
	for (u32 i = 0; i < g->nr_unredir; i++) {
		UnredirEdge* e = &g->unredir[i];
		if (e->src >= g->N || e->dest >= g->N) db_fail("unredir src/dest out of range");
		if (e->redir_idx >= g->nr_redir_titles) db_fail("unredir redir_idx out of range");
		if (i > 0) {
			UnredirEdge* p		= &g->unredir[i - 1];
			bool		 sorted = (p->src < e->src) || (p->src == e->src && p->dest < e->dest) ||
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

// Load graph from a raw (decompressed) buffer. The buffer is freed after loading.
STATIC void graph_load_from_mem(Graph* g, char* raw, long raw_len) {
	puts("Processing data...");
	char* p	  = raw;
	char* end = raw + raw_len;

	DB_REQUIRE(p, end, 4, "magic");
	if (memcmp(p, "WIKI", 4) != 0) db_fail("magic");
	p += 4;

	u32 version = 0;
	DB_READ(p, end, version, "version");
	u8 dump_format = (u8)(version & 0xFFu);
	if (dump_format > DUMP_FORMAT_VERSION) db_fail("db newer than client");
	if (dump_format < 1) db_fail("invalid db format");

	i32 dump_date = (i32)(version >> 8);
	printf("[info] database file date: 20%02d.%02d.%02d\n", dump_date / 10000, (dump_date / 100) % 100,
		   dump_date % 100);

	i32 nr_entries = 0;
	DB_READ(p, end, nr_entries, "nr_entries");
	if (nr_entries <= 0) db_fail("nr_entries <= 0");

	u32 total_links = 0;
	DB_READ(p, end, total_links, "total_links");
	if (total_links == 0) db_fail("total_links==0");

	u32 total_title_bytes = 0;
	DB_READ(p, end, total_title_bytes, "total_title_bytes");
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
		DB_READ(p, end, d, "outdegree");
		sum_deg += (u64)d;
		g->out_offsets[i + 1] = g->out_offsets[i] + (u32)d;
	}

	// padding to 4-byte boundary (as in your original format)
	u32 pad_u16 = (g->N % 4u) ? (4u - (g->N % 4u)) : 0u;
	if (pad_u16) {
		DB_REQUIRE(p, end, pad_u16 * sizeof(u16), "outdegree padding");
		p += pad_u16 * (u32)sizeof(u16);
	}

	if (sum_deg != (u64)g->L) {
		fprintf(stderr, "error: total_links mismatch (header=%u, sum_outdeg=%llu)\n", g->L,
				(unsigned long long)sum_deg);
		exit(1);
	}

	// --- outgoing edge u32 block
	DB_REQUIRE(p, end, (size_t)g->L * sizeof(u32), "edge block");
	// edges start should be aligned due to padding, but validate before casting
	if (((uintptr_t)p & 3u) != 0) db_fail("edge block alignment");
	const u32* edges_u32 = (const u32*)p;
	p += (u32)sizeof(u32) * g->L;

	// --- title lengths (u16[N])
	DB_REQUIRE(p, end, (size_t)g->N * sizeof(u16), "title lengths");
	const u16* title_lens = (const u16*)p;
	p += (u32)sizeof(u16) * g->N;

	// --- title bytes
	DB_REQUIRE(p, end, total_title_bytes, "title bytes");
	const char* title_bytes = p;
	p += total_title_bytes;

	// --- v2 footer (optional)
	u32			un_n = 0, rt_n = 0, rt_bytes = 0;
	const u32*	unredir_srcdestidx = NULL;
	const u8*	redir_lens		   = NULL;
	const char* redir_bytes		   = NULL;

	if (dump_format >= 2) {
		DB_REQUIRE(p, end, 12u, "v2 footer");
		DB_READ(p, end, un_n, "unredir count");
		DB_READ(p, end, rt_n, "redir title count");
		DB_READ(p, end, rt_bytes, "redir title bytes");

		if (un_n) {
			DB_REQUIRE(p, end, (size_t)un_n * 12u, "unredir table");
			unredir_srcdestidx = (const u32*)p;
			p += (u32)(un_n * 12u);
		}
		if (rt_n) {
			DB_REQUIRE(p, end, (size_t)rt_n, "redir lens");
			redir_lens = (const u8*)p;
			p += rt_n;

			u32 pad = (4u - (rt_n & 3u)) & 3u;
			DB_REQUIRE(p, end, pad, "redir lens pad");
			p += pad;

			DB_REQUIRE(p, end, rt_bytes, "redir bytes");
			redir_bytes = p;
			p += rt_bytes;
		}
		printf("[info] unredirect entries: %u\n", un_n);
		printf("[info] redirect titles: %u\n", rt_n);
	}

	// ------------------------------------------------------------------------
	// Allocate & copy runtime structures (free blob afterward)
	// ------------------------------------------------------------------------

	// Titles
	g->titles = (string*)malloc((size_t)g->N * sizeof(string));
	if (!g->titles) db_fail("OOM titles array");
	g->titles_arena = (char*)malloc((size_t)total_title_bytes);
	if (!g->titles_arena) db_fail("OOM titles arena");
	g->titles_arena_bytes = total_title_bytes;

	memcpy(g->titles_arena, title_bytes, total_title_bytes);

	// Build string descriptors and validate sortedness + total bytes
	u32 off = 0;
	for (u32 i = 0; i < g->N; i++) {
		u16 len = title_lens[i];
		if ((u32)len > 65535u) db_fail("title len > 65535");
		if (off + (u32)len > total_title_bytes) db_fail("title bytes overflow");
		g->titles[i] = STR(g->titles_arena + off, (int)len);
		off += (u32)len;
	}
	if (off != total_title_bytes) db_fail("title bytes sum mismatch");

	// Out edges (u24)
	size_t out_bytes = (size_t)g->L * 3u + 4u;
	if (g->L > (u32)((SIZE_MAX - 4u) / 3u)) db_fail("edge bytes overflow");
	g->out_edges24 = (u8*)malloc(out_bytes);
	if (!g->out_edges24) db_fail("OOM out_edges24");
	memset(g->out_edges24 + (size_t)g->L * 3u, 0, 4); // padding

	// In offsets counts, then prefix sum
	g->in_offsets = (u32*)calloc(((size_t)g->N + 1u), sizeof(u32));
	if (!g->in_offsets) db_fail("OOM in_offsets");

	// Pack outgoing edges + indegree counts + validate adjacency sorted/range
	for (u32 u = 0; u < g->N; u++) {
		u32	 beg	  = g->out_offsets[u];
		u32	 end2	  = g->out_offsets[u + 1];
		u32	 prev	  = 0;
		bool has_prev = false;

		for (u32 idx = beg; idx < end2; idx++) {
			u32 v = edges_u32[idx];
			if (v >= g->N) db_fail("edge id out of range");
			// adjacency should be sorted (generator assumption) => assert now
			if (has_prev && v < prev) db_fail("adjacency not sorted");
			has_prev = true;
			prev	 = v;

			u24_store(u24_ptr(g->out_edges24, idx), v);
			g->in_offsets[v + 1]++; // indegree count
		}
	}

	// prefix sum indegree counts -> offsets
	for (u32 i = 1; i <= g->N; i++) {
		g->in_offsets[i] += g->in_offsets[i - 1];
	}
	if (g->in_offsets[g->N] != g->L) db_fail("in_offsets sum != L");

	// In edges (u24)
	size_t in_bytes = (size_t)g->L * 3u + 4u;
	g->in_edges24	= (u8*)malloc(in_bytes);
	if (!g->in_edges24) db_fail("OOM in_edges24");
	memset(g->in_edges24 + (size_t)g->L * 3u, 0, 4); // padding

	u32* cur = (u32*)malloc(((size_t)g->N + 1u) * sizeof(u32));
	if (!cur) db_fail("OOM cur");
	memcpy(cur, g->in_offsets, ((size_t)g->N + 1u) * sizeof(u32));

	// Fill incoming edges by reusing edges_u32 (still in blob)
	for (u32 src = 0; src < g->N; src++) {
		u32 beg	 = g->out_offsets[src];
		u32 end2 = g->out_offsets[src + 1];
		for (u32 idx = beg; idx < end2; idx++) {
			u32 dst = edges_u32[idx];
			u32 pos = cur[dst]++;
			u24_store(u24_ptr(g->in_edges24, pos), src);
		}
	}
	free(cur);

	// v2: unredir + redirect titles copied out
	g->nr_unredir = un_n;
	g->unredir	  = NULL;
	if (un_n) {
		g->unredir = (UnredirEdge*)malloc((size_t)un_n * sizeof(UnredirEdge));
		if (!g->unredir) db_fail("OOM unredir");
		// unredir_srcdestidx points into raw as u32 triples
		const u32* q = unredir_srcdestidx;
		for (u32 i = 0; i < un_n; i++) {
			UnredirEdge* e = &g->unredir[i];
			// stored as src,dest,redir_idx each u32
			u32 src = 0, dst = 0, ridx = 0;
			memcpy(&src, q + 0, sizeof(u32));
			memcpy(&dst, q + 1, sizeof(u32));
			memcpy(&ridx, q + 2, sizeof(u32));
			q += 3;
			e->src		 = src;
			e->dest		 = dst;
			e->redir_idx = ridx;
		}
	}

	g->nr_redir_titles	 = rt_n;
	g->redir_titles		 = NULL;
	g->redir_arena		 = NULL;
	g->redir_arena_bytes = rt_bytes;

	if (rt_n) {
		g->redir_titles = (string*)malloc((size_t)rt_n * sizeof(string));
		if (!g->redir_titles) db_fail("OOM redir_titles");
		g->redir_arena = (char*)malloc((size_t)rt_bytes);
		if (!g->redir_arena) db_fail("OOM redir_arena");
		memcpy(g->redir_arena, redir_bytes, rt_bytes);

		u32 off2 = 0;
		for (u32 i = 0; i < rt_n; i++) {
			u32 len = (u32)redir_lens[i];
			if (off2 + len > rt_bytes) db_fail("redir bytes overflow");
			g->redir_titles[i] = STR(g->redir_arena + off2, (int)len);
			off2 += len;
		}
		if (off2 != rt_bytes) db_fail("redir bytes sum mismatch");
	}

	// Now we can free the decompressed blob (per your plan)
	free(raw);

	log_ts("processed db file");

	// Full validation after conversion and copies
	validate_graph_fully(g);

	log_ts("validated db file");
}

STATIC void graph_load_from_file(Graph* g, const char* path) {
	puts("reading db file into memory...");
	long  comp_len = 0;
	char* comp	   = read_file_all(path, &comp_len);
	log_ts("read db file");

	char* raw	  = NULL;
	long  raw_len = 0;

#ifdef NO_COMPRESSION
	raw		= comp;
	raw_len = comp_len;
#else
	bool is_raw = (comp_len >= 4) && (memcmp(comp, "WIKI", 4) == 0);
	if (is_raw) {
		raw		= comp;
		raw_len = comp_len;
	} else {
		raw = lzma_decompress_alloc(comp, comp_len, &raw_len);
		free(comp);
		log_ts("decompressed db file");
	}
#endif

	graph_load_from_mem(g, raw, raw_len);
}
