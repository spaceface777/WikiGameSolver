/************ Main analysis ************/

static void analyze_degrees(const CombinedMap* cm, const NormGraph* GA, const NormGraph* GB, int topk,
							uint32_t sample_n) {
	printf("\nDegree summaries (normalized title universe n=%" PRIu32 "):\n", cm->n);
	printf("  A: m=%" PRIu64 " mean_out=%.4f mean_in=%.4f\n", GA->m, (double)GA->m / (double)cm->n,
		   (double)GA->m / (double)cm->n);
	printf("  B: m=%" PRIu64 " mean_out=%.4f mean_in=%.4f\n", GB->m, (double)GB->m / (double)cm->n,
		   (double)GB->m / (double)cm->n);

	// Presence + zero-degree counts (both "all nodes" and "present only")
	uint32_t presentA = 0, presentB = 0, presentBoth = 0;
	uint32_t absentA = 0, absentB = 0; // absent from snapshot

	uint32_t z_outA_all = 0, z_inA_all = 0, z_outB_all = 0, z_inB_all = 0;
	uint32_t z_outA_pres = 0, z_inA_pres = 0, z_outB_pres = 0, z_inB_pres = 0;
	for (uint32_t g = 0; g < cm->n; g++) {
		int a = (cm->locA_of_g[g] >= 0);
		int b = (cm->locB_of_g[g] >= 0);
		if (a) presentA++;
		else absentA++;
		if (b) presentB++;
		else absentB++;
		if (a && b) presentBoth++;

		// "all nodes" (includes absences => will count missing as zeros)
		if (GA->outdeg[g] == 0) z_outA_all++;
		if (GA->indeg[g] == 0) z_inA_all++;
		if (GB->outdeg[g] == 0) z_outB_all++;
		if (GB->indeg[g] == 0) z_inB_all++;

		// "present only" (the meaningful zero-degree numbers)
		if (a) {
			if (GA->outdeg[g] == 0) z_outA_pres++;
			if (GA->indeg[g] == 0) z_inA_pres++;
		}
		if (b) {
			if (GB->outdeg[g] == 0) z_outB_pres++;
			if (GB->indeg[g] == 0) z_inB_pres++;
		}
	}
	printf("  Presence: presentA=%u presentB=%u presentBoth=%u\n", presentA, presentB, presentBoth);
	printf("  Absences: absentA=%u absentB=%u (combined n=%" PRIu32 ")\n", absentA, absentB, cm->n);

	printf("  Zero outdegree (ALL nodes): A=%u (%.2f%%)  B=%u (%.2f%%)\n", z_outA_all,
		   100.0 * (double)z_outA_all / (double)cm->n, z_outB_all, 100.0 * (double)z_outB_all / (double)cm->n);
	printf("  Zero indegree  (ALL nodes): A=%u (%.2f%%)  B=%u (%.2f%%)\n", z_inA_all,
		   100.0 * (double)z_inA_all / (double)cm->n, z_inB_all, 100.0 * (double)z_inB_all / (double)cm->n);

	if (presentA) {
		printf("  Zero outdegree (PRESENT only): A=%u (%.2f%% of presentA)\n", z_outA_pres,
			   100.0 * (double)z_outA_pres / (double)presentA);
		printf("  Zero indegree  (PRESENT only): A=%u (%.2f%% of presentA)\n", z_inA_pres,
			   100.0 * (double)z_inA_pres / (double)presentA);
	}
	if (presentB) {
		printf("  Zero outdegree (PRESENT only): B=%u (%.2f%% of presentB)\n", z_outB_pres,
			   100.0 * (double)z_outB_pres / (double)presentB);
		printf("  Zero indegree  (PRESENT only): B=%u (%.2f%% of presentB)\n", z_inB_pres,
			   100.0 * (double)z_inB_pres / (double)presentB);
	}

	print_quantiles("A outdegree", GA->outdeg, cm->n, sample_n);
	print_quantiles("A indegree ", GA->indeg, cm->n, sample_n);
	print_quantiles("B outdegree", GB->outdeg, cm->n, sample_n);
	print_quantiles("B indegree ", GB->indeg, cm->n, sample_n);

	// top hubs and gainers/losers
	TopU32* top_inA	 = (TopU32*)xmalloc((size_t)topk * sizeof(TopU32));
	TopU32* top_inB	 = (TopU32*)xmalloc((size_t)topk * sizeof(TopU32));
	TopU32* top_outA = (TopU32*)xmalloc((size_t)topk * sizeof(TopU32));
	TopU32* top_outB = (TopU32*)xmalloc((size_t)topk * sizeof(TopU32));

	TopI64* gain_in	 = (TopI64*)xmalloc((size_t)topk * sizeof(TopI64));
	TopI64* loss_in	 = (TopI64*)xmalloc((size_t)topk * sizeof(TopI64));
	TopI64* gain_out = (TopI64*)xmalloc((size_t)topk * sizeof(TopI64));
	TopI64* loss_out = (TopI64*)xmalloc((size_t)topk * sizeof(TopI64));

	int s_inA = 0, s_inB = 0, s_outA = 0, s_outB = 0;
	int s_gi = 0, s_li = 0, s_go = 0, s_lo = 0;

	// Correlations (log1p to tame hubs)
	double	 sx = 0, sy = 0, sxx = 0, syy = 0, sxy = 0;
	double	 sx2 = 0, sy2 = 0, sxx2 = 0, syy2 = 0, sxy2 = 0;
	uint64_t cnt = 0;

	for (uint32_t g = 0; g < cm->n; g++) {
		uint32_t ia = GA->indeg[g];
		uint32_t ib = GB->indeg[g];
		uint32_t oa = GA->outdeg[g];
		uint32_t ob = GB->outdeg[g];

		topk_u32_push(top_inA, &s_inA, topk, g, ia);
		topk_u32_push(top_inB, &s_inB, topk, g, ib);
		topk_u32_push(top_outA, &s_outA, topk, g, oa);
		topk_u32_push(top_outB, &s_outB, topk, g, ob);

		int64_t di	= (int64_t)ib - (int64_t)ia;
		int64_t do_ = (int64_t)ob - (int64_t)oa;
		if (di > 0) topk_i64_push(gain_in, &s_gi, topk, g, di);
		if (-di > 0) topk_i64_push(loss_in, &s_li, topk, g, -di); // store abs for losers
		if (do_ > 0) topk_i64_push(gain_out, &s_go, topk, g, do_);
		if (-do_ > 0) topk_i64_push(loss_out, &s_lo, topk, g, -do_);

		// correlations only for pages present in both
		if (cm->locA_of_g[g] >= 0 && cm->locB_of_g[g] >= 0) {
			double x = log1p((double)ia);
			double y = log1p((double)ib);
			sx += x;
			sy += y;
			sxx += x * x;
			syy += y * y;
			sxy += x * y;

			double x2 = log1p((double)oa);
			double y2 = log1p((double)ob);
			sx2 += x2;
			sy2 += y2;
			sxx2 += x2 * x2;
			syy2 += y2 * y2;
			sxy2 += x2 * y2;

			cnt++;
		}
	}

	qsort(top_inA, (size_t)s_inA, sizeof(TopU32), cmp_topu32_desc);
	qsort(top_inB, (size_t)s_inB, sizeof(TopU32), cmp_topu32_desc);
	qsort(top_outA, (size_t)s_outA, sizeof(TopU32), cmp_topu32_desc);
	qsort(top_outB, (size_t)s_outB, sizeof(TopU32), cmp_topu32_desc);

	qsort(gain_in, (size_t)s_gi, sizeof(TopI64), cmp_topi64_desc);
	qsort(loss_in, (size_t)s_li, sizeof(TopI64), cmp_topi64_desc);
	qsort(gain_out, (size_t)s_go, sizeof(TopI64), cmp_topi64_desc);
	qsort(loss_out, (size_t)s_lo, sizeof(TopI64), cmp_topi64_desc);

	printf("\nTop %d indegree hubs (A):\n", s_inA);
	for (int i = 0; i < s_inA; i++) {
		uint32_t g = top_inA[i].node;
		printf("  %2d) indeg=%u title=", i + 1, top_inA[i].val);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	printf("\nTop %d indegree hubs (B):\n", s_inB);
	for (int i = 0; i < s_inB; i++) {
		uint32_t g = top_inB[i].node;
		printf("  %2d) indeg=%u title=", i + 1, top_inB[i].val);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	printf("\nTop %d outdegree hubs (A):\n", s_outA);
	for (int i = 0; i < s_outA; i++) {
		uint32_t g = top_outA[i].node;
		printf("  %2d) outdeg=%u title=", i + 1, top_outA[i].val);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	printf("\nTop %d outdegree hubs (B):\n", s_outB);
	for (int i = 0; i < s_outB; i++) {
		uint32_t g = top_outB[i].node;
		printf("  %2d) outdeg=%u title=", i + 1, top_outB[i].val);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	printf("\nTop %d indegree gainers (B - A):\n", s_gi);
	for (int i = 0; i < s_gi; i++) {
		uint32_t g = gain_in[i].node;
		printf("  %2d) +%" PRIi64 " title=", i + 1, gain_in[i].val);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	printf("\nTop %d indegree losers (A - B):\n", s_li);
	for (int i = 0; i < s_li; i++) {
		uint32_t g = loss_in[i].node;
		printf("  %2d) -%" PRIi64 " title=", i + 1, loss_in[i].val);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	printf("\nTop %d outdegree gainers (B - A):\n", s_go);
	for (int i = 0; i < s_go; i++) {
		uint32_t g = gain_out[i].node;
		printf("  %2d) +%" PRIi64 " title=", i + 1, gain_out[i].val);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	printf("\nTop %d outdegree losers (A - B):\n", s_lo);
	for (int i = 0; i < s_lo; i++) {
		uint32_t g = loss_out[i].node;
		printf("  %2d) -%" PRIi64 " title=", i + 1, loss_out[i].val);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	if (cnt > 2) {
		double mx = sx / (double)cnt, my = sy / (double)cnt;
		double vx  = sxx / (double)cnt - mx * mx;
		double vy  = syy / (double)cnt - my * my;
		double cov = sxy / (double)cnt - mx * my;
		double r   = (vx > 0 && vy > 0) ? cov / sqrt(vx * vy) : 0.0;

		double mx2 = sx2 / (double)cnt, my2 = sy2 / (double)cnt;
		double vx2	= sxx2 / (double)cnt - mx2 * mx2;
		double vy2	= syy2 / (double)cnt - my2 * my2;
		double cov2 = sxy2 / (double)cnt - mx2 * my2;
		double r2	= (vx2 > 0 && vy2 > 0) ? cov2 / sqrt(vx2 * vy2) : 0.0;

		printf("\nSimilarity (common pages only, log1p degrees):\n");
		printf("  corr(log1p indegree A, log1p indegree B) = %.6f\n", r);
		printf("  corr(log1p outdegree A, log1p outdegree B) = %.6f\n", r2);
	}

	free(top_inA);
	free(top_inB);
	free(top_outA);
	free(top_outB);
	free(gain_in);
	free(loss_in);
	free(gain_out);
	free(loss_out);
}
