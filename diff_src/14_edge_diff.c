/************ Edge overlap + churn (assumes outgoing lists sorted by global id) ************/

static uint32_t intersect_sorted_count(const uint32_t* a, uint32_t na, const uint32_t* b, uint32_t nb) {
	uint32_t i = 0, j = 0, c = 0;
	while (i < na && j < nb) {
		uint32_t x = a[i], y = b[j];
		if (x == y) {
			c++;
			i++;
			j++;
		} else if (x < y) i++;
		else j++;
	}
	return c;
}

static uint32_t intersect_by_sorting_copies(const uint32_t* a, uint32_t na, const uint32_t* b, uint32_t nb) {
	if (na == 0 || nb == 0) return 0;
	uint32_t* aa = (uint32_t*)xmalloc((size_t)na * sizeof(uint32_t));
	uint32_t* bb = (uint32_t*)xmalloc((size_t)nb * sizeof(uint32_t));
	memcpy(aa, a, (size_t)na * sizeof(uint32_t));
	memcpy(bb, b, (size_t)nb * sizeof(uint32_t));
	qsort(aa, na, sizeof(uint32_t), cmp_u32_qsort);
	qsort(bb, nb, sizeof(uint32_t), cmp_u32_qsort);
	uint32_t inter = intersect_sorted_count(aa, na, bb, nb);
	free(aa);
	free(bb);
	return inter;
}

static void print_edge_row_details(const WikiDB* A, const WikiDB* B, const CombinedMap* cm, uint32_t g,
								   uint32_t changed, double churn_or_neg1) {
	int32_t la = cm->locA_of_g[g];
	int32_t lb = cm->locB_of_g[g];

	uint32_t		na = 0, nb = 0;
	const uint32_t *a = NULL, *b = NULL;

	if (la >= 0) {
		na = A->entries[la].nr_links;
		a  = A->entries[la].links;
	}
	if (lb >= 0) {
		nb = B->entries[lb].nr_links;
		b  = B->entries[lb].links;
	}

	uint32_t inter = 0;
	if (na && nb) inter = intersect_sorted_count(a, na, b, nb);
	uint32_t uni = na + nb - inter;

	// If it looks pathological (no overlap), verify by sorting copies (top rows only).
	uint32_t inter2	  = 0;
	int		 verified = 0;
	if (inter == 0 && na && nb) {
		inter2	 = intersect_by_sorting_copies(a, na, b, nb);
		verified = 1;
	}

	double churn = churn_or_neg1;
	if (churn < 0.0) churn = (uni > 0) ? ((double)changed / (double)uni) : 0.0;

	// Columns:
	// churn changed outA outB inter union gid [verify_inter] title
	printf("    %7.4f %8u %6u %6u %6u %6u %8" PRIu32, churn, changed, na, nb, inter, uni, g);
	// if (verified) printf(" verify=%u", inter2);
	printf("  ");
	fprint_title(stdout, cm->titles[g]);
	printf("\n");
}

static void print_edge_table_header(void) {
	printf("    churn    changed   outA   outB  inter  union      gid  title\n");
	printf("    ------  --------  -----  -----  -----  -----  --------  -----\n");
}

static int is_type_change(uint32_t outA, uint32_t outB) {
	uint32_t mn = outA < outB ? outA : outB;
	uint32_t mx = outA > outB ? outA : outB;
	// Heuristic: one side looks like a redirect/disamb stub; the other looks like a real article
	return (mn <= 2 && mx >= 30);
}

static int is_content_pair(uint32_t outA, uint32_t outB) {
	// Heuristic: both sides are “article-y”.
	return (outA >= 30 && outB >= 30);
}

static void analyze_edge_diff(const WikiDB* A, const WikiDB* B, const CombinedMap* cm, int topk, int show_progress) {
	uint64_t common = 0;
	uint64_t edgesA = 0;
	uint64_t edgesB = 0;

	uint64_t nodes_both				= 0;
	uint64_t nodes_both_union_ge_50 = 0;
	uint64_t nodes_both_content		= 0;
	uint64_t nodes_both_typechg		= 0;

	TopD*	top_ratio_all	  = (TopD*)xmalloc((size_t)topk * sizeof(TopD));
	TopD*	top_ratio_content = (TopD*)xmalloc((size_t)topk * sizeof(TopD));
	TopD*	top_ratio_typechg = (TopD*)xmalloc((size_t)topk * sizeof(TopD));
	TopU32* top_abs			  = (TopU32*)xmalloc((size_t)topk * sizeof(TopU32));

	int sz_all = 0, sz_c = 0, sz_t = 0, sz_abs = 0;

	for (uint32_t g = 0; g < cm->n; g++) {
		int32_t la = cm->locA_of_g[g];
		int32_t lb = cm->locB_of_g[g];

		uint32_t		na = 0, nb = 0;
		const uint32_t *a = NULL, *b = NULL;

		if (la >= 0) {
			na = A->entries[la].nr_links;
			a  = A->entries[la].links;
			edgesA += na;
		}
		if (lb >= 0) {
			nb = B->entries[lb].nr_links;
			b  = B->entries[lb].links;
			edgesB += nb;
		}

		// Churn leaderboards consider only pages present in BOTH snapshots:
		if (!(la >= 0 && lb >= 0)) {
			if (show_progress && (g % 1000000u) == 0u && g > 0)
				fprintf(stderr, "[progress] edge-diff processed %" PRIu32 " / %" PRIu32 " nodes\n", g, cm->n);
			continue;
		}

		nodes_both++;

		uint32_t inter = 0;
		if (na && nb) inter = intersect_sorted_count(a, na, b, nb);
		common += inter;

		uint32_t uni	 = na + nb - inter;
		uint32_t changed = (na - inter) + (nb - inter);

		// Absolute change leaderboard (no union filter)
		topk_u32_push(top_abs, &sz_abs, topk, g, changed);

		// Ratio leaderboards (avoid tiny unions)
		if (uni >= 50) {
			nodes_both_union_ge_50++;
			double churn = (double)changed / (double)uni;
			topk_d_push(top_ratio_all, &sz_all, topk, g, churn, changed);

			if (is_content_pair(na, nb)) {
				nodes_both_content++;
				topk_d_push(top_ratio_content, &sz_c, topk, g, churn, changed);
			}
			if (is_type_change(na, nb)) {
				nodes_both_typechg++;
				topk_d_push(top_ratio_typechg, &sz_t, topk, g, churn, changed);
			}
		}

		if (show_progress && (g % 1000000u) == 0u && g > 0)
			fprintf(stderr, "[progress] edge-diff processed %" PRIu32 " / %" PRIu32 " nodes\n", g, cm->n);
	}

	uint64_t removed = edgesA - common;
	uint64_t added	 = edgesB - common;

	printf("\nEdge overlap / churn (directed edges):\n");
	printf("  edges(A) = %" PRIu64 "\n", edgesA);
	printf("  edges(B) = %" PRIu64 "\n", edgesB);
	printf("  common   = %" PRIu64 "\n", common);
	printf("  removed  = %" PRIu64 "  (in A not in B)\n", removed);
	printf("  added    = %" PRIu64 "  (in B not in A)\n", added);

	if ((edgesA + edgesB - common) > 0) {
		double global_jacc = (double)common / (double)(edgesA + edgesB - common);
		printf("  global Jaccard(edge set) = %.6f\n", global_jacc);
	}

	printf("  churn leaderboards (common pages only):\n");
	printf("    nodes_both=%" PRIu64 "\n", nodes_both);
	printf("    nodes_both_union>=50=%" PRIu64 "\n", nodes_both_union_ge_50);
	printf("    nodes_both_content(outA>=50 && outB>=50)=%" PRIu64 "\n", nodes_both_content);
	printf("    nodes_both_type_change(min<=2 && max>=50)=%" PRIu64 "\n", nodes_both_typechg);

	qsort(top_ratio_all, (size_t)sz_all, sizeof(TopD), cmp_topd_desc);
	qsort(top_ratio_content, (size_t)sz_c, sizeof(TopD), cmp_topd_desc);
	qsort(top_ratio_typechg, (size_t)sz_t, sizeof(TopD), cmp_topd_desc);
	qsort(top_abs, (size_t)sz_abs, sizeof(TopU32), cmp_topu32_desc);

	printf("\n[churn] Top %d by outgoing-link churn ratio (union>=50, common pages):\n", sz_all);
	print_edge_table_header();
	for (int i = 0; i < sz_all; i++) {
		uint32_t g = top_ratio_all[i].node;
		print_edge_row_details(A, B, cm, g, top_ratio_all[i].aux, top_ratio_all[i].val);
	}

	printf("\n[churn] Top %d by churn ratio (CONTENT-CHANGE only):\n", sz_c);
	print_edge_table_header();
	for (int i = 0; i < sz_c; i++) {
		uint32_t g = top_ratio_content[i].node;
		print_edge_row_details(A, B, cm, g, top_ratio_content[i].aux, top_ratio_content[i].val);
	}

	printf("\n[churn] Top %d by churn ratio (TYPE-CHANGE only):\n", sz_t);
	print_edge_table_header();
	for (int i = 0; i < sz_t; i++) {
		uint32_t g = top_ratio_typechg[i].node;
		print_edge_row_details(A, B, cm, g, top_ratio_typechg[i].aux, top_ratio_typechg[i].val);
	}

	printf("\n[churn] Top %d by ABSOLUTE outgoing-link changes (common pages):\n", sz_abs);
	print_edge_table_header();
	for (int i = 0; i < sz_abs; i++) {
		uint32_t g = top_abs[i].node;
		// churn computed inside printer when churn_or_neg1 < 0
		print_edge_row_details(A, B, cm, g, top_abs[i].val, -1.0);
	}

	free(top_ratio_all);
	free(top_ratio_content);
	free(top_ratio_typechg);
	free(top_abs);
}
