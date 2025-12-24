/************ Build indegree/outdegree + optional inverse adjacency ************/

static void csr_free(CSRInv* inv) {
	if (inv->off) free(inv->off);
	if (inv->nbr) free(inv->nbr);
	memset(inv, 0, sizeof(*inv));
}

static NormGraph build_graph(const WikiDB* db, const CombinedMap* cm, const uint32_t* local_to_global,
							 int build_inverse) {
	NormGraph g;
	memset(&g, 0, sizeof(g));
	g.n = cm->n;

	g.outdeg = (uint32_t*)xmalloc((size_t)g.n * sizeof(uint32_t));
	g.indeg	 = (uint32_t*)xmalloc((size_t)g.n * sizeof(uint32_t));
	memset(g.outdeg, 0, (size_t)g.n * sizeof(uint32_t));
	memset(g.indeg, 0, (size_t)g.n * sizeof(uint32_t));

	// outdegree + indegree counts
	uint64_t m = 0;
	for (int32_t i = 0; i < db->nr_entries; i++) {
		uint32_t src	  = local_to_global[i];
		uint16_t nl		  = db->entries[i].nr_links;
		g.outdeg[src]	  = nl;
		const uint32_t* L = db->entries[i].links;
		for (uint16_t t = 0; t < nl; t++) {
			uint32_t dst = L[t];
			g.indeg[dst]++;
		}
		m += nl;
	}
	g.m = m;

	if (!build_inverse) return g;

	// Build CSR inverse adjacency: for each node v, list incoming neighbors (sources).
	g.inv.m	  = m;
	g.inv.off = (uint32_t*)xmalloc((size_t)(g.n + 1) * sizeof(uint32_t));
	memset(g.inv.off, 0, (size_t)(g.n + 1) * sizeof(uint32_t));

	// Prefix sums from indegree
	// off[0]=0; off[v+1]=off[v]+indeg[v]
	uint64_t run = 0;
	g.inv.off[0] = 0;
	for (uint32_t v = 0; v < g.n; v++) {
		run += g.indeg[v];
		if (run > UINT32_MAX) die("inverse offsets exceed 32-bit");
		g.inv.off[v + 1] = (uint32_t)run;
	}
	if (run != m) die("inverse prefix sum mismatch");

	g.inv.nbr	  = (uint32_t*)xmalloc((size_t)m * sizeof(uint32_t));
	uint32_t* cur = (uint32_t*)xmalloc((size_t)g.n * sizeof(uint32_t));
	memcpy(cur, g.inv.off, (size_t)g.n * sizeof(uint32_t));

	for (int32_t i = 0; i < db->nr_entries; i++) {
		uint32_t		src = local_to_global[i];
		uint16_t		nl	= db->entries[i].nr_links;
		const uint32_t* L	= db->entries[i].links;
		for (uint16_t t = 0; t < nl; t++) {
			uint32_t dst   = L[t];
			uint32_t pos   = cur[dst]++;
			g.inv.nbr[pos] = src;
		}
	}

	free(cur);
	return g;
}

static void graph_free(NormGraph* g) {
	if (g->outdeg) free(g->outdeg);
	if (g->indeg) free(g->indeg);
	csr_free(&g->inv);
	memset(g, 0, sizeof(*g));
}
