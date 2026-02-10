#include <float.h>
#include <math.h>

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

typedef struct {
	u64        pick_pair_ns;
	u64        query_wall_ns;
	SearchPerf perf;
} BenchSample;

typedef struct {
	bool valid;
	u32  n;

	double min;
	double max;
	double mean;
	double stddev;
	double cv;

	double p01;
	double p10;
	double p25;
	double p50;
	double p75;
	double p90;
	double p95;
	double p99;

	double iqr;
	double mad;
	double trimmed_mean_10;
	double skewness;
	double ci95_lo;
	double ci95_hi;
	u32    tukey_outliers;
	u32    sigma3_outliers;
} DistStats;

typedef enum {
	BM_PICK_PAIR_NS = 0,
	BM_QUERY_WALL_NS,
	BM_QUERY_TOTAL_NS,
	BM_SOLVER_NS,
	BM_LOOKUP_NS,
	BM_SP_BFS_NS,
	BM_SP_RESET_NS,
	BM_MP_FWD_BFS_NS,
	BM_MP_REV_BFS_NS,
	BM_MEMO_RESET_NS,
	BM_ZERO_DFS_NS,
	BM_COST_DFS_NS,
	BM_PATH_BUILD_NS,
	BM_CLEANUP_NS,
	BM_VERIFY_NS,
	BM_PATH_LEN,
	BM_VIS_SP,
	BM_VIS_FWD,
	BM_VIS_REV,
	BM_SHORTEST_DIST,
} BenchMetric;

typedef struct {
	const char* label;
	BenchMetric metric;
} StageMetricRow;

STATIC void* bench_xmalloc(size_t bytes, const char* what) {
	void* p = malloc(bytes);
	if (!p) {
		fprintf(stderr, "error: OOM allocating %s (%zu bytes)\n", what, bytes);
		exit(1);
	}
	return p;
}

STATIC int cmp_u64_asc(const void* a, const void* b) {
	u64 x = *(const u64*)a;
	u64 y = *(const u64*)b;
	if (x < y) return -1;
	if (x > y) return 1;
	return 0;
}

STATIC int cmp_f64_asc(const void* a, const void* b) {
	double x = *(const double*)a;
	double y = *(const double*)b;
	if (x < y) return -1;
	if (x > y) return 1;
	return 0;
}

STATIC double percentile_sorted_u64(const u64* sorted, u32 n, double pct) {
	if (!sorted || n == 0) return 0.0;
	if (pct <= 0.0) return (double)sorted[0];
	if (pct >= 100.0) return (double)sorted[n - 1];
	double rank = (pct / 100.0) * (double)(n - 1);
	u32    lo   = (u32)rank;
	u32    hi   = (lo + 1u < n) ? (lo + 1u) : lo;
	double frac = rank - (double)lo;
	return (double)sorted[lo] + ((double)sorted[hi] - (double)sorted[lo]) * frac;
}

STATIC double percentile_sorted_f64(const double* sorted, u32 n, double pct) {
	if (!sorted || n == 0) return 0.0;
	if (pct <= 0.0) return sorted[0];
	if (pct >= 100.0) return sorted[n - 1];
	double rank = (pct / 100.0) * (double)(n - 1);
	u32    lo   = (u32)rank;
	u32    hi   = (lo + 1u < n) ? (lo + 1u) : lo;
	double frac = rank - (double)lo;
	return sorted[lo] + (sorted[hi] - sorted[lo]) * frac;
}

STATIC void diststats_compute(const u64* values, u32 n, DistStats* out) {
	memset(out, 0, sizeof(*out));
	if (!values || n == 0) return;

	u64* sorted = (u64*)bench_xmalloc((size_t)n * sizeof(u64), "diststats sorted");
	memcpy(sorted, values, (size_t)n * sizeof(u64));
	qsort(sorted, (size_t)n, sizeof(u64), cmp_u64_asc);

	out->valid = true;
	out->n     = n;
	out->min   = (double)sorted[0];
	out->max   = (double)sorted[n - 1];

	long double sum = 0.0;
	for (u32 i = 0; i < n; i++) sum += (long double)sorted[i];
	out->mean = (double)(sum / (long double)n);

	long double var_sum = 0.0;
	for (u32 i = 0; i < n; i++) {
		long double d = (long double)sorted[i] - (long double)out->mean;
		var_sum += d * d;
	}
	if (n > 1) out->stddev = sqrt((double)(var_sum / (long double)(n - 1)));
	else out->stddev = 0.0;
	out->cv = (out->mean > 0.0) ? (out->stddev / out->mean) : 0.0;

	out->p01 = percentile_sorted_u64(sorted, n, 1.0);
	out->p10 = percentile_sorted_u64(sorted, n, 10.0);
	out->p25 = percentile_sorted_u64(sorted, n, 25.0);
	out->p50 = percentile_sorted_u64(sorted, n, 50.0);
	out->p75 = percentile_sorted_u64(sorted, n, 75.0);
	out->p90 = percentile_sorted_u64(sorted, n, 90.0);
	out->p95 = percentile_sorted_u64(sorted, n, 95.0);
	out->p99 = percentile_sorted_u64(sorted, n, 99.0);

	out->iqr = out->p75 - out->p25;

	u32 trim = n / 10u;
	if (trim * 2u >= n) {
		out->trimmed_mean_10 = out->mean;
	} else {
		long double tsum = 0.0;
		u32         cnt  = 0;
		for (u32 i = trim; i < n - trim; i++) {
			tsum += (long double)sorted[i];
			cnt++;
		}
		out->trimmed_mean_10 = (cnt > 0) ? (double)(tsum / (long double)cnt) : out->mean;
	}

	double* abs_dev = (double*)bench_xmalloc((size_t)n * sizeof(double), "diststats abs_dev");
	for (u32 i = 0; i < n; i++) abs_dev[i] = fabs((double)sorted[i] - out->p50);
	qsort(abs_dev, (size_t)n, sizeof(double), cmp_f64_asc);
	out->mad = percentile_sorted_f64(abs_dev, n, 50.0);
	free(abs_dev);

	if (out->stddev > 0.0) {
		long double skew_sum = 0.0;
		for (u32 i = 0; i < n; i++) {
			double z = ((double)sorted[i] - out->mean) / out->stddev;
			skew_sum += (long double)z * (long double)z * (long double)z;
		}
		out->skewness = (double)(skew_sum / (long double)n);
	}

	double lo = out->p25 - 1.5 * out->iqr;
	double hi = out->p75 + 1.5 * out->iqr;
	double z3 = 3.0 * out->stddev;
	for (u32 i = 0; i < n; i++) {
		double x = (double)sorted[i];
		if (x < lo || x > hi) out->tukey_outliers++;
		if (out->stddev > 0.0 && fabs(x - out->mean) > z3) out->sigma3_outliers++;
	}

	if (n > 1) {
		double sem = out->stddev / sqrt((double)n);
		double d95 = 1.96 * sem;
		out->ci95_lo = out->mean - d95;
		out->ci95_hi = out->mean + d95;
	} else {
		out->ci95_lo = out->mean;
		out->ci95_hi = out->mean;
	}

	free(sorted);
}

STATIC u64 bench_metric_get(const BenchSample* s, BenchMetric metric) {
	switch (metric) {
		case BM_PICK_PAIR_NS: return s->pick_pair_ns;
		case BM_QUERY_WALL_NS: return s->query_wall_ns;
		case BM_QUERY_TOTAL_NS: return s->perf.total_ns;
		case BM_SOLVER_NS: return s->perf.solver_ns;
		case BM_LOOKUP_NS: return s->perf.lookup_ns;
		case BM_SP_BFS_NS: return s->perf.sp_bfs_ns;
		case BM_SP_RESET_NS: return s->perf.sp_reset_ns;
		case BM_MP_FWD_BFS_NS: return s->perf.mp_fwd_bfs_ns;
		case BM_MP_REV_BFS_NS: return s->perf.mp_rev_bfs_ns;
		case BM_MEMO_RESET_NS: return s->perf.memo_reset_ns;
		case BM_ZERO_DFS_NS: return s->perf.zero_dfs_ns;
		case BM_COST_DFS_NS: return s->perf.cost_dfs_ns;
		case BM_PATH_BUILD_NS: return s->perf.path_build_ns;
		case BM_CLEANUP_NS: return s->perf.cleanup_ns;
		case BM_VERIFY_NS: return s->perf.verify_ns;
		case BM_PATH_LEN: return s->perf.path_len;
		case BM_VIS_SP: return s->perf.vis_sp;
		case BM_VIS_FWD: return s->perf.vis_fwd;
		case BM_VIS_REV: return s->perf.vis_rev;
		case BM_SHORTEST_DIST: return s->perf.shortest_dist;
	}
	return 0;
}

STATIC void bench_metric_stats(const BenchSample* samples, u32 n, BenchMetric metric, bool found_only, u64* scratch,
							   DistStats* out) {
	u32 cnt = 0;
	for (u32 i = 0; i < n; i++) {
		if (found_only && !samples[i].perf.found) continue;
		scratch[cnt++] = bench_metric_get(&samples[i], metric);
	}
	diststats_compute(scratch, cnt, out);
}

STATIC double ns_to_ms(double ns) {
	return ns / 1e6;
}

STATIC const char* strategy_name(u8 strategy) {
	switch (strategy) {
		case 1: return "zero-special";
		case 2: return "min-cost";
		default: return "none";
	}
}

STATIC void print_time_dist(const char* label, const DistStats* st) {
	if (!st->valid) {
		fprintf(stdout, "[bench][time] %-16s n=0\n", label);
		return;
	}
	fprintf(stdout,
			"[bench][time] %-16s n=%u mean=%.3fms p50=%.3fms p90=%.3fms p95=%.3fms p99=%.3fms min=%.3fms max=%.3fms sd=%.3fms cv=%.2f%%\n",
			label, st->n, ns_to_ms(st->mean), ns_to_ms(st->p50), ns_to_ms(st->p90), ns_to_ms(st->p95),
			ns_to_ms(st->p99), ns_to_ms(st->min), ns_to_ms(st->max), ns_to_ms(st->stddev), st->cv * 100.0);
}

STATIC void print_diag_dist(const char* label, const DistStats* st, bool is_ns) {
	if (!st->valid) {
		fprintf(stdout, "[bench][diag] %-16s n=0\n", label);
		return;
	}
	double scale = is_ns ? 1e6 : 1.0;
	fprintf(stdout,
			"[bench][diag] %-16s trim10=%.3f mad=%.3f iqr=%.3f skew=%.3f tukey=%u(%.2f%%) 3sigma=%u(%.2f%%) mean95=[%.3f, %.3f]\n",
			label, st->trimmed_mean_10 / scale, st->mad / scale, st->iqr / scale, st->skewness, st->tukey_outliers,
			100.0 * (double)st->tukey_outliers / (double)st->n, st->sigma3_outliers,
			100.0 * (double)st->sigma3_outliers / (double)st->n, st->ci95_lo / scale, st->ci95_hi / scale);
}

STATIC void print_u64_dist(const char* label, const DistStats* st) {
	if (!st->valid) {
		fprintf(stdout, "[bench][count] %-16s n=0\n", label);
		return;
	}
	fprintf(stdout,
			"[bench][count] %-16s n=%u mean=%.2f p50=%.0f p90=%.0f p99=%.0f min=%.0f max=%.0f sd=%.2f\n",
			label, st->n, st->mean, st->p50, st->p90, st->p99, st->min, st->max, st->stddev);
}

STATIC void bench_run(const Graph* g, u32 iters, u8 max_depth) {
	if (!g || iters == 0) return;

	pagerank_build((Graph*)g, 20, 0.85, 0.0001);

	PRSampler samp;
	if (!prsampler_build(&samp, g->pagerank, g->N, 1234567ULL)) {
		fprintf(stderr, "error: failed to build pagerank sampler\n");
		return;
	}

	BenchSample* samples = (BenchSample*)calloc((size_t)iters, sizeof(BenchSample));
	u64*         scratch = (u64*)bench_xmalloc((size_t)iters * sizeof(u64), "bench scratch");
	if (!samples) {
		fprintf(stderr, "error: OOM allocating bench samples\n");
		prsampler_free(&samp);
		free(scratch);
		return;
	}

	fprintf(stdout, "\n[bench] iters=%u max_depth=%u (pagerank alpha=1.6)\n", iters, (unsigned)max_depth);

	u64     bench_start        = get_monotonic_time();
	u32     found              = 0;
	u32     zero_special_found = 0;
	u32     min_cost_found     = 0;
	u32     misses             = 0;
	PathIDs path               = {0};

	u32 progress_step = 0;
	if (iters > 200) {
		progress_step = iters / 20u;
		if (progress_step == 0) progress_step = 1;
	}

	for (u32 i = 0; i < iters; i++) {
		u64 pick_t0 = get_monotonic_time();
		u32 s       = prsampler_next(&samp);
		u32 t       = prsampler_next(&samp);
		while (t == s) t = prsampler_next(&samp);
		samples[i].pick_pair_ns = get_monotonic_time() - pick_t0;

		string start  = g->titles[s];
		string target = g->titles[t];

		u64  t0 = get_monotonic_time();
		bool ok = graph_find_path_titles(g, start, target, max_depth, &path);
		u64  t1 = get_monotonic_time();

		samples[i].query_wall_ns = t1 - t0;
		const SearchPerf* perf   = search_perf_get_last();
		if (perf) samples[i].perf = *perf;
		if (samples[i].perf.total_ns == 0) samples[i].perf.total_ns = samples[i].query_wall_ns;
		if (samples[i].perf.solver_ns == 0 && samples[i].perf.total_ns >= samples[i].perf.lookup_ns) {
			samples[i].perf.solver_ns = samples[i].perf.total_ns - samples[i].perf.lookup_ns;
		}
		samples[i].perf.found = ok;

		if (ok) {
			found++;
			if (samples[i].perf.strategy == 1) zero_special_found++;
			else if (samples[i].perf.strategy == 2) min_cost_found++;
		} else {
			misses++;
		}

		bool print_line = (iters <= 200) || (i < 5) || (i + 1 == iters) || (progress_step && ((i + 1) % progress_step == 0));
		if (print_line) {
			if (samples[i].perf.shortest_dist == 0xFF) {
				fprintf(stdout,
						"[bench %6u/%u] q=%.3fms solve=%.3fms lookup=%.3fms strat=%s D=NA path=%u vis=%u/%u/%u %s\n",
						i + 1, iters, ns_to_ms((double)samples[i].perf.total_ns), ns_to_ms((double)samples[i].perf.solver_ns),
						ns_to_ms((double)samples[i].perf.lookup_ns), strategy_name(samples[i].perf.strategy),
						samples[i].perf.path_len, samples[i].perf.vis_sp, samples[i].perf.vis_fwd, samples[i].perf.vis_rev,
						ok ? "FOUND" : "MISS");
			} else {
				fprintf(stdout,
						"[bench %6u/%u] q=%.3fms solve=%.3fms lookup=%.3fms strat=%s D=%u path=%u vis=%u/%u/%u %s\n",
						i + 1, iters, ns_to_ms((double)samples[i].perf.total_ns), ns_to_ms((double)samples[i].perf.solver_ns),
						ns_to_ms((double)samples[i].perf.lookup_ns), strategy_name(samples[i].perf.strategy),
						(unsigned)samples[i].perf.shortest_dist, samples[i].perf.path_len, samples[i].perf.vis_sp,
						samples[i].perf.vis_fwd, samples[i].perf.vis_rev, ok ? "FOUND" : "MISS");
			}
		}
	}

	u64    bench_end = get_monotonic_time();
	double wall      = (double)(bench_end - bench_start) / 1e9;
	double qps       = wall > 0.0 ? (double)iters / wall : 0.0;
	double found_pct = (iters > 0) ? (100.0 * (double)found / (double)iters) : 0.0;

	fprintf(stdout,
			"\n[bench] wall=%.3fs qps=%.2f found=%u/%u (%.2f%%) zero-special=%u (%.2f%% of found) min-cost=%u (%.2f%% of found) miss=%u\n",
			wall, qps, found, iters, found_pct, zero_special_found,
			(found > 0) ? (100.0 * (double)zero_special_found / (double)found) : 0.0, min_cost_found,
			(found > 0) ? (100.0 * (double)min_cost_found / (double)found) : 0.0, misses);

	DistStats st_total = {0}, st_wall = {0}, st_solver = {0}, st_lookup = {0}, st_pick = {0};
	bench_metric_stats(samples, iters, BM_QUERY_TOTAL_NS, false, scratch, &st_total);
	bench_metric_stats(samples, iters, BM_QUERY_WALL_NS, false, scratch, &st_wall);
	bench_metric_stats(samples, iters, BM_SOLVER_NS, false, scratch, &st_solver);
	bench_metric_stats(samples, iters, BM_LOOKUP_NS, false, scratch, &st_lookup);
	bench_metric_stats(samples, iters, BM_PICK_PAIR_NS, false, scratch, &st_pick);

	fprintf(stdout, "\n[bench] latency distributions\n");
	print_time_dist("query_total", &st_total);
	print_time_dist("query_wall", &st_wall);
	print_time_dist("solver", &st_solver);
	print_time_dist("lookup", &st_lookup);
	print_time_dist("pair_pick", &st_pick);

	fprintf(stdout, "\n[bench] diagnostics\n");
	print_diag_dist("query_total", &st_total, true);
	print_diag_dist("solver", &st_solver, true);
	if (st_total.valid && st_total.p50 > 0.0) {
		fprintf(stdout, "[bench][diag] %-16s p99/p50=%.2fx p95/p50=%.2fx p90/p50=%.2fx\n", "tail_ratios",
				st_total.p99 / st_total.p50, st_total.p95 / st_total.p50, st_total.p90 / st_total.p50);
	}

	fprintf(stdout, "\n[bench] stage breakdown (per query mean)\n");
	static const StageMetricRow rows[] = {
		{"lookup", BM_LOOKUP_NS},
		{"sp_bfs", BM_SP_BFS_NS},
		{"sp_reset", BM_SP_RESET_NS},
		{"mp_fwd_bfs", BM_MP_FWD_BFS_NS},
		{"mp_rev_bfs", BM_MP_REV_BFS_NS},
		{"memo_reset", BM_MEMO_RESET_NS},
		{"zero_dfs", BM_ZERO_DFS_NS},
		{"cost_dfs", BM_COST_DFS_NS},
		{"path_build", BM_PATH_BUILD_NS},
		{"cleanup", BM_CLEANUP_NS},
		{"verify", BM_VERIFY_NS},
	};
	for (u32 i = 0; i < (u32)(sizeof(rows) / sizeof(rows[0])); i++) {
		DistStats st = {0};
		bench_metric_stats(samples, iters, rows[i].metric, false, scratch, &st);
		if (!st.valid) continue;
		double pct_total  = (st_total.valid && st_total.mean > 0.0) ? (100.0 * st.mean / st_total.mean) : 0.0;
		double pct_solver = (st_solver.valid && st_solver.mean > 0.0) ? (100.0 * st.mean / st_solver.mean) : 0.0;
		fprintf(stdout,
				"[bench][stage] %-12s mean=%.3fms p90=%.3fms p99=%.3fms share_total=%.2f%% share_solver=%.2f%%\n",
				rows[i].label, ns_to_ms(st.mean), ns_to_ms(st.p90), ns_to_ms(st.p99), pct_total, pct_solver);
	}

	fprintf(stdout, "\n[bench] workload distributions\n");
	DistStats st_depth = {0}, st_path = {0}, st_vis_sp = {0}, st_vis_f = {0}, st_vis_r = {0};
	bench_metric_stats(samples, iters, BM_SHORTEST_DIST, true, scratch, &st_depth);
	bench_metric_stats(samples, iters, BM_PATH_LEN, true, scratch, &st_path);
	bench_metric_stats(samples, iters, BM_VIS_SP, false, scratch, &st_vis_sp);
	bench_metric_stats(samples, iters, BM_VIS_FWD, false, scratch, &st_vis_f);
	bench_metric_stats(samples, iters, BM_VIS_REV, false, scratch, &st_vis_r);
	print_u64_dist("shortest_dist", &st_depth);
	print_u64_dist("path_len", &st_path);
	print_u64_dist("vis_sp", &st_vis_sp);
	print_u64_dist("vis_fwd", &st_vis_f);
	print_u64_dist("vis_rev", &st_vis_r);

	prsampler_free(&samp);
	free(samples);
	free(scratch);
}
