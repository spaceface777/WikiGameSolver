/************ Added / removed relevance ************/

typedef struct {
	uint32_t node; // global id
	uint64_t val;  // score
	uint32_t indeg;
	uint32_t outdeg;
} TopU64;

static void heap_u64_sift_down(TopU64* h, int n, int i) {
	while (1) {
		int l = 2 * i + 1, r = l + 1, s = i;
		if (l < n && h[l].val < h[s].val) s = l;
		if (r < n && h[r].val < h[s].val) s = r;
		if (s == i) break;
		TopU64 tmp = h[i];
		h[i]	   = h[s];
		h[s]	   = tmp;
		i		   = s;
	}
}
static void heap_u64_sift_up(TopU64* h, int i) {
	while (i > 0) {
		int p = (i - 1) / 2;
		if (h[p].val <= h[i].val) break;
		TopU64 tmp = h[i];
		h[i]	   = h[p];
		h[p]	   = tmp;
		i		   = p;
	}
}
static void topk_u64_push(TopU64* h, int* sz, int k, uint32_t node, uint64_t val, uint32_t indeg, uint32_t outdeg) {
	if (*sz < k) {
		h[*sz].node	  = node;
		h[*sz].val	  = val;
		h[*sz].indeg  = indeg;
		h[*sz].outdeg = outdeg;
		heap_u64_sift_up(h, *sz);
		(*sz)++;
	} else if (k > 0 && val > h[0].val) {
		h[0].node	= node;
		h[0].val	= val;
		h[0].indeg	= indeg;
		h[0].outdeg = outdeg;
		heap_u64_sift_down(h, *sz, 0);
	}
}
static int cmp_topu64_desc(const void* a, const void* b) {
	const TopU64* x = (const TopU64*)a;
	const TopU64* y = (const TopU64*)b;
	if (x->val < y->val) return 1;
	if (x->val > y->val) return -1;
	// tie-break: higher indegree first
	if (x->indeg < y->indeg) return 1;
	if (x->indeg > y->indeg) return -1;
	return 0;
}

static void analyze_added_removed_relevance(const CombinedMap* cm, const NormGraph* GA, const NormGraph* GB, int topk) {
	TopU64* top_added	= (TopU64*)xmalloc((size_t)topk * sizeof(TopU64));
	TopU64* top_removed = (TopU64*)xmalloc((size_t)topk * sizeof(TopU64));
	int		sa = 0, sr = 0;

	for (uint32_t g = 0; g < cm->n; g++) {
		int inA = (cm->locA_of_g[g] >= 0);
		int inB = (cm->locB_of_g[g] >= 0);

		if (!inA && inB) {
			uint32_t indeg	= GB->indeg[g];
			uint32_t outdeg = GB->outdeg[g];
			uint64_t score	= (uint64_t)indeg * 5ULL + (uint64_t)outdeg;
			if (score) topk_u64_push(top_added, &sa, topk, g, score, indeg, outdeg);
		} else if (inA && !inB) {
			uint32_t indeg	= GA->indeg[g];
			uint32_t outdeg = GA->outdeg[g];
			uint64_t score	= (uint64_t)indeg * 5ULL + (uint64_t)outdeg;
			if (score) topk_u64_push(top_removed, &sr, topk, g, score, indeg, outdeg);
		}
	}

	qsort(top_added, (size_t)sa, sizeof(TopU64), cmp_topu64_desc);
	qsort(top_removed, (size_t)sr, sizeof(TopU64), cmp_topu64_desc);

	printf("\nTop %d most 'relevant' ADDED pages (B-only) by score=indeg*5+outdeg:\n", sa);
	for (int i = 0; i < sa; i++) {
		uint32_t g = top_added[i].node;
		printf("  %2d) score=%" PRIu64 " indeg=%u outdeg=%u title=", i + 1, top_added[i].val, top_added[i].indeg,
			   top_added[i].outdeg);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	printf("\nTop %d most 'relevant' REMOVED pages (A-only) by score=indeg*5+outdeg:\n", sr);
	for (int i = 0; i < sr; i++) {
		uint32_t g = top_removed[i].node;
		printf("  %2d) score=%" PRIu64 " indeg=%u outdeg=%u title=", i + 1, top_removed[i].val, top_removed[i].indeg,
			   top_removed[i].outdeg);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	free(top_added);
	free(top_removed);
}
