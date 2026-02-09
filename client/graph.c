// u24 packed edge helpers + string comparisons

STATIC inline void u24_store(u8* p, u32 v) {
	// v must fit in 24 bits
	p[0] = (u8)(v & 0xFFu);
	p[1] = (u8)((v >> 8) & 0xFFu);
	p[2] = (u8)((v >> 16) & 0xFFu);
}

STATIC inline u32 u24_load(const u8* p) {
	return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16);
}

STATIC inline u8* u24_ptr(u8* base, u32 idx) {
	return base + (size_t)idx * 3u;
}

STATIC inline const u8* u24_cptr(const u8* base, u32 idx) {
	return base + (size_t)idx * 3u;
}

STATIC inline int string_cmp_raw(const char* a, int al, const char* b, int bl) {
	int m = MIN(al, bl);
	int c = memcmp(a, b, (size_t)m);
	if (c != 0) return c;
	if (al < bl) return -1;
	if (al > bl) return 1;
	return 0;
}

STATIC inline int string_cmp(string a, string b) {
	return string_cmp_raw(STR_PTR(a), STR_LEN(a), STR_PTR(b), STR_LEN(b));
}

STATIC inline unsigned char ascii_lower(unsigned char c) {
	if (c >= 'A' && c <= 'Z') return (unsigned char)(c + ('a' - 'A'));
	return c;
}

STATIC bool string_eq_ascii_ci_raw(const char* a, int al, const char* b, int bl) {
	if (al != bl) return false;
	for (int i = 0; i < al; i++) {
		unsigned char ca = ascii_lower((unsigned char)a[i]);
		unsigned char cb = ascii_lower((unsigned char)b[i]);
		if (ca != cb) return false;
	}
	return true;
}

// Binary search for exact title match in sorted titles array.
// Returns UINT32_MAX if not found.
STATIC u32 graph_find_id(const Graph* g, string title) {
	const char* key	   = STR_PTR(title);
	int			keylen = STR_LEN(title);

	u32 l = 0, r = (g->N == 0 ? 0 : g->N - 1);
	while (g->N && l <= r) {
		u32	   m = l + (r - l) / 2;
		string t = g->titles[m];

		int c = string_cmp_raw(key, keylen, STR_PTR(t), STR_LEN(t));
		if (c == 0) return m;
		if (c > 0) l = m + 1;
		else {
			if (m == 0) break;
			r = m - 1;
		}
	}
	return UINT32_MAX;
}

// Linear scan fallback for case-insensitive exact match.
// Returns the unique matching ID, or UINT32_MAX for none/ambiguous.
STATIC u32 graph_find_id_case_insensitive_unique(const Graph* g, string title) {
	const char* key	   = STR_PTR(title);
	int			keylen = STR_LEN(title);
	u32			found  = UINT32_MAX;
	for (u32 i = 0; i < g->N; i++) {
		string t = g->titles[i];
		if (!string_eq_ascii_ci_raw(key, keylen, STR_PTR(t), STR_LEN(t))) continue;
		if (found != UINT32_MAX) return UINT32_MAX;
		found = i;
	}
	return found;
}

// Outgoing adjacency membership check using binary search.
// Requires adjacency lists are sorted (asserted at startup).
STATIC bool graph_has_edge(const Graph* g, u32 src, u32 dst) {
	u32 beg = g->out_offsets[src];
	u32 end = g->out_offsets[src + 1];
	// binary search over [beg, end)
	u32 l = beg, r = end;
	while (l < r) {
		u32 m = l + (r - l) / 2;
		u32 v = u24_load(u24_cptr(g->out_edges24, m));
		if (v < dst) l = m + 1;
		else r = m;
	}
	if (l >= end) return false;
	return u24_load(u24_cptr(g->out_edges24, l)) == dst;
}
