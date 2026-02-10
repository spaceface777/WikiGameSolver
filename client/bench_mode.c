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
	u32        cost_best;
	u32        cost_worst;
	u32        cost_spread;
	u64        cost_sum;
	u64        cost_avg_milli;
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
	BM_DP_NS,
	BM_ENUM_NS,
	BM_FALLBACK_DP_NS,
	BM_PATH_BUILD_NS,
	BM_CLEANUP_NS,
	BM_VERIFY_NS,
	BM_PATH_LEN,
	BM_VIS_SP,
	BM_VIS_LAYERS,
	BM_SHORTEST_DIST,
	BM_PATHS_RETURNED,
	BM_ENUM_STATES_USED,
	BM_DAG_EDGES_USED,
	BM_SIDETRACK_NODES_USED,
	BM_SIDETRACK_STATES_USED,
	BM_COST_BEST,
	BM_COST_WORST,
	BM_COST_SPREAD,
	BM_COST_AVG_MILLI,
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
		double sem   = out->stddev / sqrt((double)n);
		double d95   = 1.96 * sem;
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
	case BM_PICK_PAIR_NS:          return s->pick_pair_ns;
	case BM_QUERY_WALL_NS:         return s->query_wall_ns;
	case BM_QUERY_TOTAL_NS:        return s->perf.total_ns;
	case BM_SOLVER_NS:             return s->perf.solver_ns;
	case BM_LOOKUP_NS:             return s->perf.lookup_ns;
	case BM_SP_BFS_NS:             return s->perf.sp_bfs_ns;
	case BM_SP_RESET_NS:           return s->perf.sp_reset_ns;
	case BM_DP_NS:                 return s->perf.dp_ns;
	case BM_ENUM_NS:               return s->perf.enum_ns;
	case BM_FALLBACK_DP_NS:        return s->perf.fallback_dp_ns;
	case BM_PATH_BUILD_NS:         return s->perf.path_build_ns;
	case BM_CLEANUP_NS:            return s->perf.cleanup_ns;
	case BM_VERIFY_NS:             return s->perf.verify_ns;
	case BM_PATH_LEN:              return s->perf.path_len;
	case BM_VIS_SP:                return s->perf.vis_sp;
	case BM_VIS_LAYERS:            return s->perf.vis_layers;
	case BM_SHORTEST_DIST:         return s->perf.shortest_dist;
	case BM_PATHS_RETURNED:        return s->perf.paths_returned;
	case BM_ENUM_STATES_USED:      return s->perf.enum_states_used;
	case BM_DAG_EDGES_USED:        return s->perf.dag_edges_used;
	case BM_SIDETRACK_NODES_USED:  return s->perf.sidetrack_nodes_used;
	case BM_SIDETRACK_STATES_USED: return s->perf.sidetrack_states_used;
	case BM_COST_BEST:             return s->cost_best;
	case BM_COST_WORST:            return s->cost_worst;
	case BM_COST_SPREAD:           return s->cost_spread;
	case BM_COST_AVG_MILLI:        return s->cost_avg_milli;
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
	case 1:  return "k1-fast";
	case 2:  return "sidetrack";
	case 3:  return "enum-k";
	default: return "none";
	}
}

STATIC void print_time_dist(const char* label, const DistStats* st) {
	if (!st->valid) {
		fprintf(stdout, "[bench][time] %-16s n=0\n", label);
		return;
	}
	fprintf(stdout,
			"[bench][time] %-16s n=%u mean=%.3fms p50=%.3fms p90=%.3fms p95=%.3fms p99=%.3fms min=%.3fms max=%.3fms "
			"sd=%.3fms cv=%.2f%%\n",
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
			"[bench][diag] %-16s trim10=%.3f mad=%.3f iqr=%.3f skew=%.3f tukey=%u(%.2f%%) 3sigma=%u(%.2f%%) "
			"mean95=[%.3f, %.3f]\n",
			label, st->trimmed_mean_10 / scale, st->mad / scale, st->iqr / scale, st->skewness, st->tukey_outliers,
			100.0 * (double)st->tukey_outliers / (double)st->n, st->sigma3_outliers,
			100.0 * (double)st->sigma3_outliers / (double)st->n, st->ci95_lo / scale, st->ci95_hi / scale);
}

STATIC void print_u64_dist(const char* label, const DistStats* st) {
	if (!st->valid) {
		fprintf(stdout, "[bench][count] %-16s n=0\n", label);
		return;
	}
	fprintf(stdout, "[bench][count] %-16s n=%u mean=%.2f p50=%.0f p90=%.0f p99=%.0f min=%.0f max=%.0f sd=%.2f\n", label,
			st->n, st->mean, st->p50, st->p90, st->p99, st->min, st->max, st->stddev);
}

STATIC bool bench_find_edge_cost(const Graph* g, u32 src, u32 dst, u32* out_cost) {
	u32 beg = g->out_offsets[src];
	u32 end = g->out_offsets[src + 1];
	u32 l   = beg;
	u32 r   = end;
	while (l < r) {
		u32 m = l + (r - l) / 2u;
		u32 v = u24_load(u24_cptr(g->out_edges24, m));
		if (v < dst) l = m + 1u;
		else r = m;
	}
	if (l >= end) return false;
	if (u24_load(u24_cptr(g->out_edges24, l)) != dst) return false;
	if (out_cost) *out_cost = edge_special_cost(edge_flags_or_zero(g, l));
	return true;
}

STATIC bool bench_path_cost(const Graph* g, const PathIDs* p, u32* out_cost) {
	if (!p || p->len == 0) return false;
	u64 sum = 0;
	for (u32 i = 1; i < p->len; i++) {
		u32 ec = 0;
		if (!bench_find_edge_cost(g, p->ids[i - 1], p->ids[i], &ec)) return false;
		sum += (u64)ec;
	}
	if (out_cost) *out_cost = (u32)sum;
	return true;
}

STATIC void bench_collect_costs(const Graph* g, const PathSet* set, BenchSample* sample, u32 k_paths, u32* rank_hits,
								u64* rank_cost_sum, u32* rank_cost_min, u32* rank_cost_max) {
	if (!set || set->count == 0) return;

	u64 sum   = 0;
	u32 best  = 0;
	u32 worst = 0;
	for (u32 i = 0; i < set->count; i++) {
		u32 c = 0;
		if (!bench_path_cost(g, &set->paths[i], &c)) continue;
		if (i == 0 || c < best) best = c;
		if (i == 0 || c > worst) worst = c;
		sum += (u64)c;

		if (i < k_paths) {
			rank_hits[i]++;
			rank_cost_sum[i] += (u64)c;
			if (rank_hits[i] == 1 || c < rank_cost_min[i]) rank_cost_min[i] = c;
			if (rank_hits[i] == 1 || c > rank_cost_max[i]) rank_cost_max[i] = c;
		}
	}

	sample->cost_best      = best;
	sample->cost_worst     = worst;
	sample->cost_spread    = worst - best;
	sample->cost_sum       = sum;
	sample->cost_avg_milli = (set->count > 0) ? (((sum * 1000ull) + (u64)(set->count / 2u)) / (u64)set->count) : 0ull;
}

STATIC void bench_run(const Graph* g, u32 iters, u8 max_depth, u32 k_paths) {
	if (!g || iters == 0) return;
	if (k_paths < 1 || k_paths > SEARCH_MAX_K) {
		fprintf(stderr, "error: bench k must be in 1..%u\n", (unsigned)SEARCH_MAX_K);
		return;
	}

	pagerank_build((Graph*)g, 20, 0.85, 0.0001);

	PRSampler samp;
	if (!prsampler_build(&samp, g->pagerank, g->N, 1234567ULL)) {
		fprintf(stderr, "error: failed to build pagerank sampler\n");
		return;
	}

	BenchSample* samples       = (BenchSample*)calloc((size_t)iters, sizeof(BenchSample));
	u64*         scratch       = (u64*)bench_xmalloc((size_t)iters * sizeof(u64), "bench scratch");
	u32*         rank_hits     = (u32*)calloc((size_t)k_paths, sizeof(u32));
	u64*         rank_cost_sum = (u64*)calloc((size_t)k_paths, sizeof(u64));
	u32*         rank_cost_min = (u32*)calloc((size_t)k_paths, sizeof(u32));
	u32*         rank_cost_max = (u32*)calloc((size_t)k_paths, sizeof(u32));
	if (!samples || !rank_hits || !rank_cost_sum || !rank_cost_min || !rank_cost_max) {
		fprintf(stderr, "error: OOM allocating bench buffers\n");
		prsampler_free(&samp);
		free(samples);
		free(scratch);
		free(rank_hits);
		free(rank_cost_sum);
		free(rank_cost_min);
		free(rank_cost_max);
		return;
	}

	fprintf(stdout, "\n[bench] iters=%u max_depth=%u k=%u (pagerank alpha=1.6)\n", iters, (unsigned)max_depth,
			(unsigned)k_paths);

	u64 bench_start  = get_monotonic_time();
	u32 found        = 0;
	u32 full_k_hit   = 0;
	u32 k1_fast_hit  = 0;
	u32 enum_k_hit   = 0;
	u32 fallback_hit = 0;
	u32 misses       = 0;

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

		string  start  = g->titles[s];
		string  target = g->titles[t];
		PathSet set    = {0};

		u64  t0 = get_monotonic_time();
		bool ok = graph_find_path_titles_k(g, start, target, max_depth, k_paths, &set);
		u64  t1 = get_monotonic_time();

		samples[i].query_wall_ns = t1 - t0;
		const SearchPerf* perf   = search_perf_get_last();
		if (perf) samples[i].perf = *perf;
		if (samples[i].perf.total_ns == 0) samples[i].perf.total_ns = samples[i].query_wall_ns;
		if (samples[i].perf.solver_ns == 0 && samples[i].perf.total_ns >= samples[i].perf.lookup_ns) {
			samples[i].perf.solver_ns = samples[i].perf.total_ns - samples[i].perf.lookup_ns;
		}
		samples[i].perf.found = ok;
		if (ok && samples[i].perf.paths_returned == 0) samples[i].perf.paths_returned = set.count;
		if (ok && samples[i].perf.path_len == 0 && set.count > 0) samples[i].perf.path_len = set.paths[0].len;

		if (ok) {
			found++;
			if (set.count == k_paths) full_k_hit++;
			if (samples[i].perf.strategy == 1) k1_fast_hit++;
			if (samples[i].perf.strategy == 3) enum_k_hit++;
			if (samples[i].perf.fallback_used) fallback_hit++;
			bench_collect_costs(g, &set, &samples[i], k_paths, rank_hits, rank_cost_sum, rank_cost_min, rank_cost_max);
		} else {
			misses++;
		}

		bool print_line =
			(iters <= 200) || (i < 5) || (i + 1 == iters) || (progress_step && ((i + 1) % progress_step == 0));
		if (print_line) {
			double avg_cost = (double)samples[i].cost_avg_milli / 1000.0;
			if (samples[i].perf.shortest_dist == 0xFF) {
				fprintf(stdout,
						"[bench %6u/%u] q=%.3fms solve=%.3fms lookup=%.3fms strat=%s D=NA len=%u ret=%u cost=[%u..%u] "
						"avg=%.3f vis=%u/%u enum_states=%u %s\n",
						i + 1, iters, ns_to_ms((double)samples[i].perf.total_ns),
						ns_to_ms((double)samples[i].perf.solver_ns), ns_to_ms((double)samples[i].perf.lookup_ns),
						strategy_name(samples[i].perf.strategy), samples[i].perf.path_len,
						samples[i].perf.paths_returned, samples[i].cost_best, samples[i].cost_worst, avg_cost,
						samples[i].perf.vis_sp, samples[i].perf.vis_layers, samples[i].perf.enum_states_used,
						ok ? "FOUND" : "MISS");
			} else {
				fprintf(stdout,
						"[bench %6u/%u] q=%.3fms solve=%.3fms lookup=%.3fms strat=%s D=%u len=%u ret=%u cost=[%u..%u] "
						"avg=%.3f vis=%u/%u enum_states=%u %s\n",
						i + 1, iters, ns_to_ms((double)samples[i].perf.total_ns),
						ns_to_ms((double)samples[i].perf.solver_ns), ns_to_ms((double)samples[i].perf.lookup_ns),
						strategy_name(samples[i].perf.strategy), (unsigned)samples[i].perf.shortest_dist,
						samples[i].perf.path_len, samples[i].perf.paths_returned, samples[i].cost_best,
						samples[i].cost_worst, avg_cost, samples[i].perf.vis_sp, samples[i].perf.vis_layers,
						samples[i].perf.enum_states_used, ok ? "FOUND" : "MISS");
			}
		}
	}

	u64    bench_end = get_monotonic_time();
	double wall      = (double)(bench_end - bench_start) / 1e9;
	double qps       = wall > 0.0 ? (double)iters / wall : 0.0;
	double found_pct = (iters > 0) ? (100.0 * (double)found / (double)iters) : 0.0;

	fprintf(stdout,
			"\n[bench] wall=%.3fs qps=%.2f found=%u/%u (%.2f%%) full_k=%u (%.2f%%) k1-fast=%u (%.2f%%) enum-k=%u "
			"(%.2f%%) fallback=%u (%.2f%%) miss=%u\n",
			wall, qps, found, iters, found_pct, full_k_hit,
			(found > 0) ? (100.0 * (double)full_k_hit / (double)found) : 0.0, k1_fast_hit,
			(found > 0) ? (100.0 * (double)k1_fast_hit / (double)found) : 0.0, enum_k_hit,
			(found > 0) ? (100.0 * (double)enum_k_hit / (double)found) : 0.0, fallback_hit,
			(found > 0) ? (100.0 * (double)fallback_hit / (double)found) : 0.0, misses);

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
		{"dp", BM_DP_NS},
		{"enum", BM_ENUM_NS},
		{"fallback_dp", BM_FALLBACK_DP_NS},
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
	DistStats st_depth = {0}, st_path = {0}, st_vis_sp = {0}, st_vis_layers = {0}, st_paths_returned = {0},
			  st_enum_states = {0}, st_dag_edges = {0}, st_sidetrack_nodes = {0}, st_sidetrack_states = {0},
			  st_cost_best = {0}, st_cost_worst = {0}, st_cost_spread = {0}, st_cost_avg = {0};
	bench_metric_stats(samples, iters, BM_SHORTEST_DIST, true, scratch, &st_depth);
	bench_metric_stats(samples, iters, BM_PATH_LEN, true, scratch, &st_path);
	bench_metric_stats(samples, iters, BM_VIS_SP, false, scratch, &st_vis_sp);
	bench_metric_stats(samples, iters, BM_VIS_LAYERS, false, scratch, &st_vis_layers);
	bench_metric_stats(samples, iters, BM_PATHS_RETURNED, false, scratch, &st_paths_returned);
	bench_metric_stats(samples, iters, BM_ENUM_STATES_USED, false, scratch, &st_enum_states);
	bench_metric_stats(samples, iters, BM_DAG_EDGES_USED, false, scratch, &st_dag_edges);
	bench_metric_stats(samples, iters, BM_SIDETRACK_NODES_USED, false, scratch, &st_sidetrack_nodes);
	bench_metric_stats(samples, iters, BM_SIDETRACK_STATES_USED, false, scratch, &st_sidetrack_states);
	bench_metric_stats(samples, iters, BM_COST_BEST, true, scratch, &st_cost_best);
	bench_metric_stats(samples, iters, BM_COST_WORST, true, scratch, &st_cost_worst);
	bench_metric_stats(samples, iters, BM_COST_SPREAD, true, scratch, &st_cost_spread);
	bench_metric_stats(samples, iters, BM_COST_AVG_MILLI, true, scratch, &st_cost_avg);
	print_u64_dist("shortest_dist", &st_depth);
	print_u64_dist("path_len", &st_path);
	print_u64_dist("vis_sp", &st_vis_sp);
	print_u64_dist("vis_layers", &st_vis_layers);
	print_u64_dist("paths_returned", &st_paths_returned);
	print_u64_dist("enum_states_used", &st_enum_states);
	print_u64_dist("dag_edges_used", &st_dag_edges);
	print_u64_dist("sidetrack_nodes", &st_sidetrack_nodes);
	print_u64_dist("sidetrack_states", &st_sidetrack_states);
	print_u64_dist("cost_best", &st_cost_best);
	print_u64_dist("cost_worst", &st_cost_worst);
	print_u64_dist("cost_spread", &st_cost_spread);
	if (st_cost_avg.valid) {
		fprintf(stdout, "[bench][cost] avg_cost         n=%u mean=%.3f p50=%.3f p90=%.3f p99=%.3f min=%.3f max=%.3f\n",
				st_cost_avg.n, st_cost_avg.mean / 1000.0, st_cost_avg.p50 / 1000.0, st_cost_avg.p90 / 1000.0,
				st_cost_avg.p99 / 1000.0, st_cost_avg.min / 1000.0, st_cost_avg.max / 1000.0);
	}

	fprintf(stdout, "\n[bench] rank cost summary (k=%u)\n", (unsigned)k_paths);
	for (u32 r = 0; r < k_paths; r++) {
		if (rank_hits[r] == 0) {
			fprintf(stdout, "[bench][rank %2u] hits=0\n", (unsigned)(r + 1u));
			continue;
		}
		double mean    = (double)rank_cost_sum[r] / (double)rank_hits[r];
		double hit_pct = (found > 0) ? (100.0 * (double)rank_hits[r] / (double)found) : 0.0;
		fprintf(stdout, "[bench][rank %2u] hits=%u/%u (%.2f%%) mean=%.2f min=%u max=%u\n", (unsigned)(r + 1u),
				(unsigned)rank_hits[r], (unsigned)found, hit_pct, mean, (unsigned)rank_cost_min[r],
				(unsigned)rank_cost_max[r]);
	}

	prsampler_free(&samp);
	free(samples);
	free(scratch);
	free(rank_hits);
	free(rank_cost_sum);
	free(rank_cost_min);
	free(rank_cost_max);
}
