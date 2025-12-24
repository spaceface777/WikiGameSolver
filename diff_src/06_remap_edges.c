/************ Remap edges in-place ************/

static uint64_t remap_edges_in_place(WikiDB* db, const uint32_t* local_to_global) {
	uint64_t m = 0;
	for (int32_t i = 0; i < db->nr_entries; i++) {
		Entry*	  e	 = &db->entries[i];
		uint16_t  nl = e->nr_links;
		uint32_t* L	 = e->links;
		for (uint16_t t = 0; t < nl; t++) {
			uint32_t old = L[t];
			L[t]		 = local_to_global[old];
		}
		m += nl;
	}
	return m;
}

static int is_sorted_u32(const uint32_t* a, uint32_t n) {
	if (n <= 1) return 1;
	for (uint32_t i = 1; i < n; i++)
		if (a[i - 1] > a[i]) return 0;
	return 1;
}

static int cmp_u32_qsort(const void* pa, const void* pb) {
	uint32_t a = *(const uint32_t*)pa;
	uint32_t b = *(const uint32_t*)pb;
	if (a < b) return -1;
	if (a > b) return 1;
	return 0;
}

static void force_sort_all(WikiDB* db) {
	for (int32_t i = 0; i < db->nr_entries; i++) {
		Entry* e = &db->entries[i];
		if (e->nr_links > 1) qsort(e->links, e->nr_links, sizeof(uint32_t), cmp_u32_qsort);
	}
}
