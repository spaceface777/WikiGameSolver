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

// Redirect title index the edge's link went through, or -1 for a direct link.
STATIC inline int graph_edge_redirect(const Graph* g, u32 edge) {
	u64 word = g->unredir_bits ? g->unredir_bits[edge >> 6] : 0, below = (1ull << (edge & 63)) - 1;
	if (!(word >> (edge & 63) & 1)) return -1;
	u32 i = g->unredir_rank[edge >> 6] + (u32)__builtin_popcountll(word & below);
	return (int)u24_load(g->unredir_alias24 + (size_t)i * 3u);
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
	const char* key    = STR_PTR(title);
	int         keylen = STR_LEN(title);

	u32 l = 0, r = (g->N == 0 ? 0 : g->N - 1);
	while (g->N && l <= r) {
		u32    m = l + (r - l) / 2;
		string t = graph_title(g, m);

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
// ambiguous=true indicates multiple matches.
STATIC u32 graph_find_id_case_insensitive_unique(const Graph* g, string title, bool* ambiguous) {
	if (ambiguous) *ambiguous = false;
	const char* key    = STR_PTR(title);
	int         keylen = STR_LEN(title);
	u32         found  = UINT32_MAX;
	for (u32 i = 0; i < g->N; i++) {
		string t = graph_title(g, i);
		if (!string_eq_ascii_ci_raw(key, keylen, STR_PTR(t), STR_LEN(t))) continue;
		if (found != UINT32_MAX) {
			if (ambiguous) *ambiguous = true;
			return UINT32_MAX;
		}
		found = i;
	}
	return found;
}

// Index of edge src->dst in out_edges24 (binary search; adjacency is sorted), or UINT32_MAX.
STATIC u32 graph_edge_index(const Graph* g, u32 src, u32 dst) {
	u32 l = g->out_offsets[src], r = g->out_offsets[src + 1];
	while (l < r) {
		u32 m = l + (r - l) / 2;
		if (u24_load(u24_cptr(g->out_edges24, m)) < dst) l = m + 1;
		else r = m;
	}
	return l < g->out_offsets[src + 1] && u24_load(u24_cptr(g->out_edges24, l)) == dst ? l : UINT32_MAX;
}

// Resolve a redirect title index into a canonical page ID.
// Returns UINT32_MAX for none/ambiguous. ambiguous=true means conflicting destinations.
STATIC u32 graph_find_redirect_dest_by_index_unique(const Graph* g, u32 redir_idx, bool* ambiguous) {
	if (ambiguous) *ambiguous = false;
	u32  found = UINT32_MAX;
	bool have  = false;
	for (u32 w = 0, i = 0; g->nr_unredir && w < (g->L + 63) / 64; w++)
		for (u64 bits = g->unredir_bits[w]; bits; bits &= bits - 1, i++) {
			if (u24_load(g->unredir_alias24 + (size_t)i * 3u) != redir_idx) continue;
			u32 dest = u24_load(u24_cptr(g->out_edges24, w * 64 + (u32)__builtin_ctzll(bits)));
			if (!have) {
				found = dest;
				have  = true;
				continue;
			}
			if (found != dest) {
				if (ambiguous) *ambiguous = true;
				return UINT32_MAX;
			}
		}
	return have ? found : UINT32_MAX;
}

// Search redirect title table for an exact match (case-sensitive or ASCII case-insensitive).
// Returns resolved canonical page ID when one or more matching redirect titles all map uniquely
// to the same canonical destination. If multiple redirect titles match, the lexicographically
// first title is retained via out_redir_idx. Returns UINT32_MAX for none/ambiguous.
STATIC u32 graph_find_id_in_redirect_titles_unique(const Graph* g, string title, bool case_insensitive, bool* ambiguous,
												   u32* out_redir_idx) {
	if (ambiguous) *ambiguous = false;
	if (out_redir_idx) *out_redir_idx = UINT32_MAX;

	u32  matched_dest = UINT32_MAX;
	u32  matched_idx  = UINT32_MAX;
	bool have_match   = false;
	for (u32 i = 0; i < g->nr_redir_titles; i++) {
		string rt = graph_redir_title(g, i);
		bool   ok = case_insensitive ? string_eq_ascii_ci_raw(STR_PTR(title), STR_LEN(title), STR_PTR(rt), STR_LEN(rt))
									 : string_eq(title, rt);
		if (!ok) continue;

		bool dest_ambiguous = false;
		u32  dest           = graph_find_redirect_dest_by_index_unique(g, i, &dest_ambiguous);
		if (dest_ambiguous) {
			if (ambiguous) *ambiguous = true;
			return UINT32_MAX;
		}
		if (dest == UINT32_MAX) continue;

		if (have_match && matched_dest != dest) {
			if (ambiguous) *ambiguous = true;
			return UINT32_MAX;
		}
		if (!have_match) {
			have_match   = true;
			matched_dest = dest;
			matched_idx  = i;
		}
	}
	if (!have_match) return UINT32_MAX;
	if (out_redir_idx) *out_redir_idx = matched_idx;
	return matched_dest;
}

// Resolution order:
// 1) exact canonical title
// 2) case-insensitive canonical title (must be unique)
// 3) exact redirect title (must be unique and map uniquely)
// 4) case-insensitive redirect title (must be unique and map uniquely)
//
// Redirect fallback is only attempted when canonical case-insensitive lookup found zero matches.
// ambiguous=true indicates a disambiguation failure; caller should stop fallback attempts.
STATIC u32 graph_find_id_fuzzy(const Graph* g, string title, bool* ambiguous, u32* out_redir_idx) {
	if (ambiguous) *ambiguous = false;
	if (out_redir_idx) *out_redir_idx = UINT32_MAX;

	u32 id = graph_find_id(g, title);
	if (id != UINT32_MAX) return id;

	bool ci_ambiguous = false;
	id                = graph_find_id_case_insensitive_unique(g, title, &ci_ambiguous);
	if (id != UINT32_MAX) return id;
	if (ci_ambiguous) {
		if (ambiguous) *ambiguous = true;
		return UINT32_MAX;
	}

	bool redir_exact_ambiguous = false;
	id = graph_find_id_in_redirect_titles_unique(g, title, false, &redir_exact_ambiguous, out_redir_idx);
	if (id != UINT32_MAX) return id;
	if (redir_exact_ambiguous) {
		if (ambiguous) *ambiguous = true;
		return UINT32_MAX;
	}

	bool redir_ci_ambiguous = false;
	id = graph_find_id_in_redirect_titles_unique(g, title, true, &redir_ci_ambiguous, out_redir_idx);
	if (id != UINT32_MAX) return id;
	if (redir_ci_ambiguous && ambiguous) *ambiguous = true;
	return UINT32_MAX;
}

