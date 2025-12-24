/************ Top-K heaps (min-heap) ************/

typedef struct {
	uint32_t node;
	uint32_t val;
} TopU32;
typedef struct {
	uint32_t node;
	int64_t	 val;
} TopI64;
typedef struct {
	uint32_t node;
	double	 val;
	uint32_t aux;
} TopD; // aux can store abs-changed edges

static void heap_u32_sift_down(TopU32* h, int n, int i) {
	while (1) {
		int l = 2 * i + 1, r = l + 1, s = i;
		if (l < n && h[l].val < h[s].val) s = l;
		if (r < n && h[r].val < h[s].val) s = r;
		if (s == i) break;
		TopU32 tmp = h[i];
		h[i]	   = h[s];
		h[s]	   = tmp;
		i		   = s;
	}
}
static void heap_u32_sift_up(TopU32* h, int i) {
	while (i > 0) {
		int p = (i - 1) / 2;
		if (h[p].val <= h[i].val) break;
		TopU32 tmp = h[i];
		h[i]	   = h[p];
		h[p]	   = tmp;
		i		   = p;
	}
}
static void topk_u32_push(TopU32* h, int* sz, int k, uint32_t node, uint32_t val) {
	if (*sz < k) {
		h[*sz].node = node;
		h[*sz].val	= val;
		heap_u32_sift_up(h, *sz);
		(*sz)++;
	} else if (k > 0 && val > h[0].val) {
		h[0].node = node;
		h[0].val  = val;
		heap_u32_sift_down(h, *sz, 0);
	}
}

static void heap_i64_sift_down(TopI64* h, int n, int i) {
	while (1) {
		int l = 2 * i + 1, r = l + 1, s = i;
		if (l < n && h[l].val < h[s].val) s = l;
		if (r < n && h[r].val < h[s].val) s = r;
		if (s == i) break;
		TopI64 tmp = h[i];
		h[i]	   = h[s];
		h[s]	   = tmp;
		i		   = s;
	}
}
static void heap_i64_sift_up(TopI64* h, int i) {
	while (i > 0) {
		int p = (i - 1) / 2;
		if (h[p].val <= h[i].val) break;
		TopI64 tmp = h[i];
		h[i]	   = h[p];
		h[p]	   = tmp;
		i		   = p;
	}
}
static void topk_i64_push(TopI64* h, int* sz, int k, uint32_t node, int64_t val) {
	if (*sz < k) {
		h[*sz].node = node;
		h[*sz].val	= val;
		heap_i64_sift_up(h, *sz);
		(*sz)++;
	} else if (k > 0 && val > h[0].val) {
		h[0].node = node;
		h[0].val  = val;
		heap_i64_sift_down(h, *sz, 0);
	}
}

static void heap_d_sift_down(TopD* h, int n, int i) {
	while (1) {
		int l = 2 * i + 1, r = l + 1, s = i;
		if (l < n && h[l].val < h[s].val) s = l;
		if (r < n && h[r].val < h[s].val) s = r;
		if (s == i) break;
		TopD tmp = h[i];
		h[i]	 = h[s];
		h[s]	 = tmp;
		i		 = s;
	}
}
static void heap_d_sift_up(TopD* h, int i) {
	while (i > 0) {
		int p = (i - 1) / 2;
		if (h[p].val <= h[i].val) break;
		TopD tmp = h[i];
		h[i]	 = h[p];
		h[p]	 = tmp;
		i		 = p;
	}
}
static void topk_d_push(TopD* h, int* sz, int k, uint32_t node, double val, uint32_t aux) {
	if (*sz < k) {
		h[*sz].node = node;
		h[*sz].val	= val;
		h[*sz].aux	= aux;
		heap_d_sift_up(h, *sz);
		(*sz)++;
	} else if (k > 0 && val > h[0].val) {
		h[0].node = node;
		h[0].val  = val;
		h[0].aux  = aux;
		heap_d_sift_down(h, *sz, 0);
	}
}

static int cmp_topu32_desc(const void* a, const void* b) {
	const TopU32* x = (const TopU32*)a;
	const TopU32* y = (const TopU32*)b;
	if (x->val < y->val) return 1;
	if (x->val > y->val) return -1;
	return 0;
}
static int cmp_topi64_desc(const void* a, const void* b) {
	const TopI64* x = (const TopI64*)a;
	const TopI64* y = (const TopI64*)b;
	if (x->val < y->val) return 1;
	if (x->val > y->val) return -1;
	return 0;
}
static int cmp_topd_desc(const void* a, const void* b) {
	const TopD* x = (const TopD*)a;
	const TopD* y = (const TopD*)b;
	if (x->val < y->val) return 1;
	if (x->val > y->val) return -1;
	if (x->aux < y->aux) return 1;
	if (x->aux > y->aux) return -1;
	return 0;
}
