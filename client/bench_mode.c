#include <float.h>

typedef struct {
	u32      n;
	u32*     gid;
	u32*     alias;
	float*   prob;
	uint64_t rng;
} PRSampler;

STATIC uint64_t rng64(uint64_t* s) {
	uint64_t x = *s;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	*s = x;
	return x * 2685821657736338717ULL;
}

STATIC double rng_double01(uint64_t* s) {
	uint64_t r = rng64(s);
	return (double)((r >> 11) & ((1ULL << 53) - 1)) * (1.0 / 9007199254740992.0);
}

STATIC void prsampler_free(PRSampler* S) {
	if (!S) return;
	free(S->gid);
	free(S->alias);
	free(S->prob);
	memset(S, 0, sizeof(*S));
}

STATIC bool prsampler_build(PRSampler* S, const double* pr, u32 N, uint64_t seed) {
	if (!S || !pr || N == 0) return false;

	memset(S, 0, sizeof(*S));
	S->rng = seed ? seed : 0x9e3779b97f4a7c15ULL;
	S->n   = N;

	S->gid   = (u32*)malloc((size_t)N * sizeof(u32));
	S->alias = (u32*)malloc((size_t)N * sizeof(u32));
	S->prob  = (float*)malloc((size_t)N * sizeof(float));
	if (!S->gid || !S->alias || !S->prob) {
		prsampler_free(S);
		return false;
	}

	double* q     = (double*)malloc((size_t)N * sizeof(double));
	u32*    small = (u32*)malloc((size_t)N * sizeof(u32));
	u32*    large = (u32*)malloc((size_t)N * sizeof(u32));
	if (!q || !small || !large) {
		free(q);
		free(small);
		free(large);
		prsampler_free(S);
		return false;
	}

	double sum = 0.0;
	for (u32 i = 0; i < N; i++) {
		S->gid[i] = i;
		double w  = pr[i];
		if (w <= 0.0) w = DBL_MIN;
		q[i] = w;
		sum += w;
	}

	if (!(sum > 0.0)) {
		free(q);
		free(small);
		free(large);
		prsampler_free(S);
		return false;
	}

	double scale = (double)N / sum;
	u32    ns = 0, nl = 0;
	for (u32 i = 0; i < N; i++) {
		q[i] *= scale;
		if (q[i] < 1.0) small[ns++] = i;
		else large[nl++] = i;
	}

	while (ns && nl) {
		u32 s = small[--ns];
		u32 l = large[--nl];

		double ps = q[s];
		if (ps < 0.0) ps = 0.0;
		if (ps > 1.0) ps = 1.0;
		S->prob[s]  = (float)ps;
		S->alias[s] = l;

		q[l] = (q[l] + q[s]) - 1.0;
		if (q[l] < 1.0) small[ns++] = l;
		else large[nl++] = l;
	}

	while (nl) {
		u32 i       = large[--nl];
		S->prob[i]  = 1.0f;
		S->alias[i] = i;
	}
	while (ns) {
		u32 i       = small[--ns];
		S->prob[i]  = 1.0f;
		S->alias[i] = i;
	}

	free(q);
	free(small);
	free(large);
	return true;
}

STATIC u32 prsampler_next(PRSampler* S) {
	u32    i = (u32)(rng64(&S->rng) % (uint64_t)S->n);
	double u = rng_double01(&S->rng);
	u32    j = (u < (double)S->prob[i]) ? i : S->alias[i];
	return S->gid[j];
}

STATIC void bench_run(const Graph* g, u32 iters, u8 max_depth) {
	if (!g || iters == 0) return;

	pagerank_build((Graph*)g, 20, 0.85, 0.0001);

	PRSampler samp;
	if (!prsampler_build(&samp, g->pagerank, g->N, 1234567ULL)) {
		fprintf(stderr, "error: failed to build pagerank sampler\n");
		return;
	}

	fprintf(stdout, "[bench] iters=%u max_depth=%u (pagerank alpha=1.6)\n", iters, (unsigned)max_depth);

	u64     bench_start = get_monotonic_time();
	u32     found       = 0;
	PathIDs path        = {0};

	for (u32 i = 0; i < iters; i++) {
		u32 s = prsampler_next(&samp);
		u32 t = prsampler_next(&samp);
		while (t == s) t = prsampler_next(&samp);

		string start  = g->titles[s];
		string target = g->titles[t];

		u64  t0 = get_monotonic_time();
		bool ok = graph_find_path_titles(g, start, target, max_depth, &path);
		u64  t1 = get_monotonic_time();

		if (ok) found++;
		fprintf(stdout, "[bench %u/%u] %.3f ms %.*s -> %.*s %s\n", i + 1, iters, (double)(t1 - t0) / 1e6,
				STR_LEN(start), STR_PTR(start), STR_LEN(target), STR_PTR(target), ok ? "FOUND" : "MISS");
	}

	u64    bench_end = get_monotonic_time();
	double wall      = (double)(bench_end - bench_start) / 1e9;
	double qps       = wall > 0.0 ? (double)iters / wall : 0.0;
	fprintf(stdout, "[bench] wall=%.3fs qps=%.2f found=%u/%u\n", wall, qps, found, iters);

	prsampler_free(&samp);
}
