#ifdef ENABLE_PRETTY_INPUT

#include "input.h"

typedef struct Range {
	int start, end;
} Range;

STATIC inline int cmp_title_key(string t, const char* key, int keylen) {
	const char* tp = STR_PTR(t);
	int         tl = STR_LEN(t);
	int         m  = MIN(tl, keylen);
	int         c  = memcmp(tp, key, (size_t)m);
	if (c != 0) return c;
	if (tl < keylen) return -1;
	if (tl > keylen) return 1;
	return 0;
}

STATIC u32 lower_bound_titles(const Graph* g, const char* key, int keylen) {
	u32 l = 0, r = g->N; // [l,r)
	while (l < r) {
		u32 m = l + (r - l) / 2;
		if (cmp_title_key(g->titles[m], key, keylen) < 0) l = m + 1;
		else r = m;
	}
	return l;
}

// Returns the inclusive [start,end] range of titles that start with prefix.
STATIC Range prefix_range_titles(const Graph* g, const char* prefix, int plen) {
	Range ans = {-1, -1};
	if (!g || g->N == 0) return ans;
	if (!prefix || plen <= 0) return ans; // don't autocomplete empty prefix

	u32 lo = lower_bound_titles(g, prefix, plen);

	// Build prefix_hi = prefix + 0xFF, so all strings with this prefix are < prefix_hi.
	// Safe for UTF-8 titles (0xFF is not a valid UTF-8 byte).
	char* hi = (char*)alloca((size_t)plen + 1u);
	memcpy(hi, prefix, (size_t)plen);
	hi[plen] = (char)0xFF;

	u32 up = lower_bound_titles(g, hi, plen + 1);
	if (lo >= up) return ans;

	ans.start = (int)lo;
	ans.end   = (int)up - 1;
	return ans;
}

STATIC const Graph* pretty_g = NULL;

STATIC void completion_cb(const char* buf, linenoiseCompletions* lc) {
	if (!buf || !pretty_g) return;

	int   blen = (int)strlen(buf);
	Range p    = prefix_range_titles(pretty_g, buf, blen);
	if (p.start == -1) return;

	int count = p.end - p.start + 1;
	if (count <= 0) return;

	int limit = count;
	if (limit > 100) limit = 100;

	u32 ids[100];
	int n = pagerank_topk_in_title_range(pretty_g, (u32)p.start, (u32)p.end, limit, ids);

	for (int j = 0; j < n; j++) {
		string t = pretty_g->titles[ids[j]];
		linenoiseAddCompletionN(lc, STR_PTR(t), STR_LEN(t));
	}
}

STATIC char* hints_cb(const char* buf, int* color, int* bold) {
	if (!buf || !pretty_g) return NULL;

	int   blen = (int)strlen(buf);
	Range p    = prefix_range_titles(pretty_g, buf, blen);
	if (p.start == -1) {
		return strdup("\x1b[31m (not found)\x1b[0m");
	}

	int count = p.end - p.start + 1;
	if (count < 1) return strdup("\x1b[31m (not found)\x1b[0m");

	*color = 34;
	*bold  = 0;

	u32 best[1];
	if (pagerank_topk_in_title_range(pretty_g, (u32)p.start, (u32)p.end, 1, best) != 1) {
		return NULL;
	}

	string t = pretty_g->titles[best[0]];
	if (STR_LEN(t) <= blen) {
		// exact match or prefix longer than title; no hint
		return NULL;
	}

	const char* s    = STR_PTR(t) + blen;
	int         slen = STR_LEN(t) - blen;
	char*       out  = (char*)malloc((size_t)slen + 1);
	memcpy(out, s, (size_t)slen);
	out[slen] = '\0';
	return out;
}

STATIC void pretty_init(Graph* g) {
	pagerank_build(g, 20, 0.85, 0.0001);

	pretty_g = g;
	linenoiseSetCompletionCallback(completion_cb);
	linenoiseSetHintsCallback(hints_cb);
	linenoiseSetFreeHintsCallback(free);
}

#else
STATIC void pretty_init(const Graph* g) {
	(void)g;
}
#endif
