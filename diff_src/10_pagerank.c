/************ Forward decls ************/

static uint64_t rng64(uint64_t* s);

/************ PageRank (snapshot-local, normalized IDs) ************/

typedef struct {
	uint32_t n_active;
	uint32_t n_cheese;
	uint64_t m_active; // edges considered (to active nodes, after no-cheese handling)
} PRMeta;

static uint8_t* build_active_mask_for_snapshotB(const CombinedMap* cm) {
	uint8_t* active = (uint8_t*)xmalloc((size_t)cm->n);
	for (uint32_t g = 0; g < cm->n; g++) active[g] = (cm->locB_of_g[g] >= 0) ? 1 : 0;
	return active;
}

static uint8_t* build_cheese_mask(const CombinedMap* cm) {
	uint8_t* cheese = (uint8_t*)xmalloc((size_t)cm->n);
	for (uint32_t g = 0; g < cm->n; g++) cheese[g] = title_is_cheese_like(cm->titles[g]) ? 1 : 0;
	return cheese;
}

static void pagerank_compute_B(const WikiDB* B, const CombinedMap* cm, const uint8_t* active, const uint8_t* cheese,
							   int no_cheese_edges, // if 1: cheese nodes do NOT distribute along outgoing edges
							   int iters, double damp, double eps,
							   double** out_rank, // malloc'd length cm->n
							   PRMeta*	meta_out) {
	if (damp <= 0.0 || damp >= 1.0) damp = 0.85;
	if (iters < 1) iters = 1;

	PRMeta meta;
	memset(&meta, 0, sizeof(meta));

	// Count active nodes and cheese nodes (among active).
	for (uint32_t g = 0; g < cm->n; g++) {
		if (active[g]) {
			meta.n_active++;
			if (cheese && cheese[g]) meta.n_cheese++;
		}
	}
	if (meta.n_active == 0) die("pagerank: no active nodes in snapshot B");

	// Precompute effective outdegree (counting only edges to active nodes),
	// and optionally zeroing out "cheese" sources.
	uint32_t* out_eff = (uint32_t*)xmalloc((size_t)cm->n * sizeof(uint32_t));
	memset(out_eff, 0, (size_t)cm->n * sizeof(uint32_t));

	for (int32_t li = 0; li < B->nr_entries; li++) {
		uint32_t src = cm->mapB[li];
		if (!active[src]) continue; // shouldn't happen
		if (no_cheese_edges && cheese && cheese[src]) {
			out_eff[src] = 0;
			continue;
		}
		uint32_t		cnt = 0;
		const uint32_t* L	= B->entries[li].links;
		uint16_t		nl	= B->entries[li].nr_links;
		for (uint16_t t = 0; t < nl; t++) {
			uint32_t dst = L[t];
			if (dst < cm->n && active[dst]) cnt++;
		}
		out_eff[src] = cnt;
		meta.m_active += cnt;
	}

	double* r	= (double*)xmalloc((size_t)cm->n * sizeof(double));
	double* nxt = (double*)xmalloc((size_t)cm->n * sizeof(double));

	// Initialize uniformly over active nodes.
	double init = 1.0 / (double)meta.n_active;
	for (uint32_t g = 0; g < cm->n; g++) r[g] = active[g] ? init : 0.0;

	for (int it = 0; it < iters; it++) {
		memset(nxt, 0, (size_t)cm->n * sizeof(double));

		double dangling = 0.0;

		// Stream edges: src via local index in B.
		for (int32_t li = 0; li < B->nr_entries; li++) {
			uint32_t src = cm->mapB[li];
			if (!active[src]) continue;

			uint32_t oe = out_eff[src];
			if (oe == 0) {
				dangling += r[src];
				continue;
			}

			double			share = r[src] / (double)oe;
			const uint32_t* L	  = B->entries[li].links;
			uint16_t		nl	  = B->entries[li].nr_links;
			for (uint16_t t = 0; t < nl; t++) {
				uint32_t dst = L[t];
				if (dst < cm->n && active[dst]) nxt[dst] += share;
			}
		}

		double base		= (1.0 - damp) / (double)meta.n_active;
		double add_dang = dangling / (double)meta.n_active;

		double diff = 0.0;
		for (uint32_t g = 0; g < cm->n; g++) {
			if (!active[g]) {
				r[g] = 0.0;
				continue;
			}
			double ng = base + damp * (nxt[g] + add_dang);
			diff += fabs(ng - r[g]);
			r[g] = ng;
		}

		if (eps > 0.0 && diff < eps) break;
	}

	free(nxt);
	free(out_eff);

	*out_rank = r;
	if (meta_out) *meta_out = meta;
}

static void pagerank_print_top(const char* label, const CombinedMap* cm, const uint8_t* active, const uint8_t* cheese,
							   const double* r, int topk, int exclude_cheese_from_print) {
	TopD* top = (TopD*)xmalloc((size_t)topk * sizeof(TopD));
	int	  sz  = 0;

	double	 sum	  = 0.0;
	uint32_t n_active = 0;
	for (uint32_t g = 0; g < cm->n; g++) {
		if (!active[g]) continue;
		n_active++;
		sum += r[g];
		if (exclude_cheese_from_print && cheese && cheese[g]) continue;
		topk_d_push(top, &sz, topk, g, r[g], 0);
	}

	qsort(top, (size_t)sz, sizeof(TopD), cmp_topd_desc);

	printf("\n[pagerank] %s\n", label);
	printf("  active_nodes=%u  rank_sum=%.6f\n", n_active, sum);
	printf("  Top %d:\n", sz);
	for (int i = 0; i < sz; i++) {
		uint32_t g = top[i].node;
		printf("  %2d) pr=%.10g title=", i + 1, top[i].val);
		fprint_title(stdout, cm->titles[g]);
		if (cheese && cheese[g]) printf("  [cheese]");
		printf("\n");
	}

	free(top);
}
