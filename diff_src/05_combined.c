/************ Combined title universe + remaps ************/

static CombinedMap build_combined(const WikiDB* A, const WikiDB* B) {
	CombinedMap cm;
	memset(&cm, 0, sizeof(cm));

	int32_t nA = A->nr_entries;
	int32_t nB = B->nr_entries;

	cm.mapA = (uint32_t*)xmalloc((size_t)nA * sizeof(uint32_t));
	cm.mapB = (uint32_t*)xmalloc((size_t)nB * sizeof(uint32_t));

	// Upper bound on combined size: nA + nB
	cm.titles = (TitleRef*)xmalloc((size_t)(nA + nB) * sizeof(TitleRef));

	int32_t	 i = 0, j = 0;
	uint32_t k = 0;

	while (i < nA || j < nB) {
		if (i < nA && j < nB) {
			TitleRef ta = db_title_ref(A, i);
			TitleRef tb = db_title_ref(B, j);
			int		 c	= title_cmp(ta, tb);
			if (c == 0) {
				cm.titles[k] = ta; // keep A's pointer
				cm.mapA[i]	 = k;
				cm.mapB[j]	 = k;
				i++;
				j++;
				k++;
				cm.common_titles++;
			} else if (c < 0) {
				cm.titles[k] = ta;
				cm.mapA[i]	 = k;
				i++;
				k++;
				cm.removed_titles++; // in A not in B
			} else {
				cm.titles[k] = tb;
				cm.mapB[j]	 = k;
				j++;
				k++;
				cm.added_titles++; // in B not in A
			}
		} else if (i < nA) {
			TitleRef ta	 = db_title_ref(A, i);
			cm.titles[k] = ta;
			cm.mapA[i]	 = k;
			i++;
			k++;
			cm.removed_titles++;
		} else {
			TitleRef tb	 = db_title_ref(B, j);
			cm.titles[k] = tb;
			cm.mapB[j]	 = k;
			j++;
			k++;
			cm.added_titles++;
		}
	}

	cm.n	  = k;
	cm.titles = (TitleRef*)xrealloc(cm.titles, (size_t)cm.n * sizeof(TitleRef));

	cm.locA_of_g = (int32_t*)xmalloc((size_t)cm.n * sizeof(int32_t));
	cm.locB_of_g = (int32_t*)xmalloc((size_t)cm.n * sizeof(int32_t));
	for (uint32_t g = 0; g < cm.n; g++) {
		cm.locA_of_g[g] = -1;
		cm.locB_of_g[g] = -1;
	}
	for (int32_t a = 0; a < nA; a++) cm.locA_of_g[cm.mapA[a]] = a;
	for (int32_t b = 0; b < nB; b++) cm.locB_of_g[cm.mapB[b]] = b;

	return cm;
}

static void combined_free(CombinedMap* cm) {
	if (cm->titles) free(cm->titles);
	if (cm->mapA) free(cm->mapA);
	if (cm->mapB) free(cm->mapB);
	if (cm->locA_of_g) free(cm->locA_of_g);
	if (cm->locB_of_g) free(cm->locB_of_g);
	memset(cm, 0, sizeof(*cm));
}
