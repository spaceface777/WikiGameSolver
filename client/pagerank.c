#include <float.h>
#include <math.h>

#define PR_ALPHA_DEFAULT 1.6

typedef struct {
	u32    id;
	double score;
} PRTop;

STATIC inline void pr_swap(PRTop* a, PRTop* b) {
	PRTop t = *a;
	*a      = *b;
	*b      = t;
}

// min-heap by score (keep best K by evicting smallest)
STATIC void pr_heap_sift_down(PRTop* h, int n, int i) {
	while (1) {
		int l = 2 * i + 1, r = l + 1, s = i;
		if (l < n && h[l].score < h[s].score) s = l;
		if (r < n && h[r].score < h[s].score) s = r;
		if (s == i) break;
		pr_swap(&h[i], &h[s]);
		i = s;
	}
}

STATIC void pr_heap_sift_up(PRTop* h, int i) {
	while (i > 0) {
		int p = (i - 1) / 2;
		if (h[p].score <= h[i].score) break;
		pr_swap(&h[p], &h[i]);
		i = p;
	}
}

STATIC void pr_topk_push(PRTop* h, int* sz, int k, u32 id, double score) {
	if (k <= 0) return;
	if (*sz < k) {
		h[*sz].id    = id;
		h[*sz].score = score;
		pr_heap_sift_up(h, *sz);
		(*sz)++;
	} else if (score > h[0].score) {
		h[0].id    = id;
		h[0].score = score;
		pr_heap_sift_down(h, *sz, 0);
	}
}

STATIC int pr_cmp_desc(const void* a, const void* b) {
	const PRTop* x = (const PRTop*)a;
	const PRTop* y = (const PRTop*)b;
	if (x->score < y->score) return 1;
	if (x->score > y->score) return -1;
	// tie-breaker: lower id first (stable-ish)
	if (x->id < y->id) return -1;
	if (x->id > y->id) return 1;
	return 0;
}

// Build PageRank once. Stores result in g->pagerank (double[N]).
// iters: number of iterations (e.g., 10..30)
// damp: typical 0.85
// eps: if >0, stop early when L1 diff < eps
// alpha: bias exponent for high-PR nodes
STATIC void pagerank_build(Graph* g, int iters, double damp, double eps, double alpha) {
	if (!g || !g->validated) {
		fprintf(stderr, "error: pagerank_build requires validated graph\n");
		exit(1);
	}
	if (g->pagerank) return; // already computed

	printf("Building PageRank with %d iterations, damp=%f, eps=%f\n", iters, damp, eps);

	if (iters < 1) iters = 1;
	if (!(damp > 0.0f && damp < 1.0f)) damp = 0.85f;

	u32     N   = g->N;
	double* r   = (double*)malloc((size_t)N * sizeof(double));
	double* nxt = (double*)malloc((size_t)N * sizeof(double));
	if (!r || !nxt) {
		fprintf(stderr, "error: OOM in pagerank\n");
		exit(1);
	}

	// init uniform
	double init = 1.0f / (double)N;
	for (u32 i = 0; i < N; i++) r[i] = init;

	for (int it = 0; it < iters; it++) {
		memset(nxt, 0, (size_t)N * sizeof(double));

		double dangling = 0.0;

		// stream edges
		for (u32 u = 0; u < N; u++) {
			u32 beg = g->out_offsets[u];
			u32 end = g->out_offsets[u + 1];
			u32 deg = end - beg;

			if (deg == 0) {
				dangling += (double)r[u];
				continue;
			}

			double    share = r[u] / (double)deg;
			const u8* p     = u24_cptr(g->out_edges24, beg);
			for (u32 idx = beg; idx < end; idx++, p += 3) {
				u32 v = u24_load(p); // no checks here; validated at startup
				nxt[v] += share;
			}
		}

		double base     = (1.0f - damp) / (double)N;
		double add_dang = (double)(dangling / (double)N);

		double diff = 0.0;
		for (u32 i = 0; i < N; i++) {
			double nr = base + damp * (nxt[i] + add_dang);
			diff += fabs((double)nr - (double)r[i]);
			r[i] = nr;
		}

		if (eps > 0.0f && (double)diff < eps) break;
	}

	free(nxt);

	// Apply an in-place alpha bias to favor high-PR nodes. The biased scores are
	// normalized so they still form a proper probability distribution for the
	// sampler.
	double sum = 0.0;

	if (alpha == 1.0f) {
		for (u32 i = 0; i < N; i++) {
			sum += r[i];
		}
	} else {
		for (u32 i = 0; i < N; i++) {
			double biased = pow(r[i], alpha);
			if (biased == 0.0) biased = DBL_MIN;
			r[i] = biased;
			sum += biased;
		}
	}
	if (sum > 0.0) {
		double inv = 1.0 / sum;
		for (u32 i = 0; i < N; i++) r[i] *= inv;
	}

	g->pagerank = r;
}

// Select top-k nodes by PageRank within a contiguous title-range [lo, hi] inclusive.
// Writes up to k node IDs to out_ids, sorted by descending PR score.
// Returns count written.
STATIC int pagerank_topk_in_title_range(const Graph* g, u32 lo, u32 hi, int k, u32* out_ids) {
	if (!g || !g->pagerank || !out_ids || k <= 0) return 0;
	if (lo > hi || hi >= g->N) return 0;

	if (k > 1000) k = 1000; // keep it sane for interactive use

	PRTop* heap = (PRTop*)malloc((size_t)k * sizeof(PRTop));
	if (!heap) {
		fprintf(stderr, "error: OOM in pagerank_topk\n");
		exit(1);
	}
	int sz = 0;

	for (u32 id = lo; id <= hi; id++) {
		pr_topk_push(heap, &sz, k, id, g->pagerank[id]);
	}

	qsort(heap, (size_t)sz, sizeof(PRTop), pr_cmp_desc);
	for (int i = 0; i < sz; i++) out_ids[i] = heap[i].id;

	free(heap);
	return sz;
}

// Convenience getter
STATIC inline double pagerank_score(const Graph* g, u32 id) {
	return (g && g->pagerank) ? g->pagerank[id] : 0.0f;
}
