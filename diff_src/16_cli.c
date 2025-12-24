/************ CLI ************/

static void usage(const char* argv0) {
	fprintf(stderr,
			"usage: %s old.db.xz new.db.xz [options]\n"
			"options:\n"
			"  --top K               top-k to print (default 30)\n"
			"  --sample N            reservoir sample for degree quantiles (default 1000000)\n"
			"  --no-edge-diff        skip edge overlap/churn pass\n"
			"  --no-inverse          do not build full inverse adjacency (still counts indegree)\n"
			"  --force-sort          qsort every outgoing list after remap (expensive)\n"
			"\n"
			"  --pagerank            compute PageRank on snapshot B (power iteration)\n"
			"  --pagerank-no-cheese  also compute PageRank where cheese pages don't distribute\n"
			"  --pr-iters N          PageRank iterations (default 30)\n"
			"  --pr-damp D           PageRank damping factor (default 0.85)\n"
			"  --pr-eps E            PageRank early-stop L1 threshold (default 0 disables)\n"
			"  --pr-exclude-cheese   exclude cheese pages from printed top list\n"
			"\n"
			"  --diameter            run directed longest-shortest-path heuristic on snapshot B\n"
			"  --diam-sweeps N       number of double-sweeps (default 8)\n"
			"  --diam-min-visited N  ignore BFS results visiting <N nodes (default 250000)\n"
			"  --diam-min-out N      seed nodes must have outdeg>=N (default 30)\n",
			argv0);
	exit(2);
}

int main(int argc, char** argv) {
	if (argc < 3) usage(argv[0]);

	// make stdout line buffered
	setvbuf(stdout, NULL, _IOLBF, 0);

	Timer total, step;
	timer_start(&total);

	const char* pathA = argv[1];
	const char* pathB = argv[2];

	int		 topk		  = 30;
	uint32_t sample_n	  = 1000000;
	int		 do_edge_diff = 1;
	int		 do_inverse	  = 1;
	int		 force_sort	  = 0;

	int	   do_pagerank			   = 0;
	int	   do_pagerank_no_cheese   = 0;
	int	   pr_exclude_cheese_print = 0;
	int	   pr_iters				   = 30;
	double pr_damp				   = 0.85;
	double pr_eps				   = 0.0; // 0 => disabled

	int		 do_diameter	  = 0;
	int		 diam_sweeps	  = 8;
	uint32_t diam_min_visited = 250000;
	uint32_t diam_min_out	  = 30;

	for (int i = 3; i < argc; i++) {
		if (strcmp(argv[i], "--top") == 0) {
			if (i + 1 >= argc) usage(argv[0]);
			topk = atoi(argv[++i]);
			if (topk <= 0) topk = 30;
		} else if (strcmp(argv[i], "--sample") == 0) {
			if (i + 1 >= argc) usage(argv[0]);
			long long v = atoll(argv[++i]);
			if (v < 1000) v = 1000;
			if (v > 5000000) v = 5000000; // keep sane by default
			sample_n = (uint32_t)v;
		} else if (strcmp(argv[i], "--no-edge-diff") == 0) {
			do_edge_diff = 0;
		} else if (strcmp(argv[i], "--no-inverse") == 0) {
			do_inverse = 0;
		} else if (strcmp(argv[i], "--force-sort") == 0) {
			force_sort = 1;
		} else if (strcmp(argv[i], "--pagerank") == 0) {
			do_pagerank = 1;
		} else if (strcmp(argv[i], "--pagerank-no-cheese") == 0) {
			do_pagerank			  = 1;
			do_pagerank_no_cheese = 1;
		} else if (strcmp(argv[i], "--pr-iters") == 0) {
			if (i + 1 >= argc) usage(argv[0]);
			pr_iters = atoi(argv[++i]);
			if (pr_iters < 1) pr_iters = 1;
			if (pr_iters > 200) pr_iters = 200;
		} else if (strcmp(argv[i], "--pr-damp") == 0) {
			if (i + 1 >= argc) usage(argv[0]);
			pr_damp = atof(argv[++i]);
		} else if (strcmp(argv[i], "--pr-eps") == 0) {
			if (i + 1 >= argc) usage(argv[0]);
			pr_eps = atof(argv[++i]);
			if (pr_eps < 0.0) pr_eps = 0.0;
		} else if (strcmp(argv[i], "--pr-exclude-cheese") == 0) {
			pr_exclude_cheese_print = 1;
		} else if (strcmp(argv[i], "--diameter") == 0) {
			do_diameter = 1;
		} else if (strcmp(argv[i], "--diam-sweeps") == 0) {
			if (i + 1 >= argc) usage(argv[0]);
			diam_sweeps = atoi(argv[++i]);
			if (diam_sweeps < 1) diam_sweeps = 1;
			if (diam_sweeps > 100) diam_sweeps = 100;
		} else if (strcmp(argv[i], "--diam-min-visited") == 0) {
			if (i + 1 >= argc) usage(argv[0]);
			long long v = atoll(argv[++i]);
			if (v < 0) v = 0;
			if (v > 7000000LL) v = 7000000LL;
			diam_min_visited = (uint32_t)v;
		} else if (strcmp(argv[i], "--diam-min-out") == 0) {
			if (i + 1 >= argc) usage(argv[0]);
			long long v = atoll(argv[++i]);
			if (v < 0) v = 0;
			if (v > 1000000LL) v = 1000000LL;
			diam_min_out = (uint32_t)v;
		} else {
			usage(argv[0]);
		}
	}

	WikiDB A, B;
	printf("[load] %s\n", pathA);
	timer_start(&step);
	if (!db_load_xz(&A, pathA)) die("failed loading A");
	printf("  date=");
	print_dump_date(A.dump_date_yymmdd);
	printf(" entries=%d links=%u title_bytes=%u\n", A.nr_entries, A.total_links, A.total_title_bytes);
	print_step_time("load A", &step);

	printf("[load] %s\n", pathB);
	timer_start(&step);
	if (!db_load_xz(&B, pathB)) die("failed loading B");
	printf("  date=");
	print_dump_date(B.dump_date_yymmdd);
	printf(" entries=%d links=%u title_bytes=%u\n", B.nr_entries, B.total_links, B.total_title_bytes);
	print_step_time("load B", &step);

	printf("\n[normalize] building combined title universe (merge of sorted title lists)\n");
	timer_start(&step);
	CombinedMap cm = build_combined(&A, &B);

	printf("  combined n=%" PRIu32 "\n", cm.n);
	printf("  common=%" PRIu32 " added(B-only)=%" PRIu32 " removed(A-only)=%" PRIu32 "\n", cm.common_titles,
		   cm.added_titles, cm.removed_titles);
	print_step_time("build combined titles", &step);

	printf("\n[normalize] remapping edges in-place to combined global IDs\n");
	timer_start(&step);
	uint64_t mA = remap_edges_in_place(&A, cm.mapA);
	uint64_t mB = remap_edges_in_place(&B, cm.mapB);
	printf("  remapped edges: A=%" PRIu64 " B=%" PRIu64 "\n", mA, mB);
	print_step_time("remap edges", &step);

	// Optional: force-sort all outgoing lists (heavy), else sanity-check a small sample.
	timer_start(&step);
	if (force_sort) {
		printf("[normalize] --force-sort enabled: sorting all outgoing lists (both DBs)\n");
		force_sort_all(&A);
		force_sort_all(&B);
	} else {
		// quick sanity check first ~50k nodes
		int		badA = 0, badB = 0;
		int32_t limA = A.nr_entries < 50000 ? A.nr_entries : 50000;
		int32_t limB = B.nr_entries < 50000 ? B.nr_entries : 50000;
		for (int32_t i = 0; i < limA; i++)
			if (!is_sorted_u32(A.entries[i].links, A.entries[i].nr_links)) {
				badA = 1;
				break;
			}
		for (int32_t i = 0; i < limB; i++)
			if (!is_sorted_u32(B.entries[i].links, B.entries[i].nr_links)) {
				badB = 1;
				break;
			}
		if (badA || badB) {
			fprintf(stderr,
					"warning: detected unsorted outgoing lists in %s.\n"
					"         edge-diff/churn assumes sorted lists.\n"
					"         rerun with --force-sort (expensive) or ensure DB builder sorts adjacency.\n",
					(badA && badB) ? "A and B" : (badA ? "A" : "B"));
		}
	}
	print_step_time(force_sort ? "force-sort outgoing lists" : "sort/sanity check", &step);

	printf("\n[build] computing degrees%s\n", do_inverse ? " and inverse graphs" : "");
	timer_start(&step);
	NormGraph GA = build_graph(&A, &cm, cm.mapA, do_inverse);
	NormGraph GB = build_graph(&B, &cm, cm.mapB, do_inverse);
	print_step_time(do_inverse ? "build degrees+inverse" : "build degrees", &step);

	timer_start(&step);
	analyze_degrees(&cm, &GA, &GB, topk, sample_n);
	print_step_time("analyze degrees", &step);

	timer_start(&step);
	analyze_added_removed_relevance(&cm, &GA, &GB, topk);
	print_step_time("analyze added/removed", &step);

	// Optional: PageRank + "no-cheese" PageRank (snapshot B).
	if (do_pagerank || do_diameter) {
		// Build masks once if either feature is used.
		timer_start(&step);
		uint8_t* activeB = build_active_mask_for_snapshotB(&cm);
		uint8_t* cheese	 = build_cheese_mask(&cm);
		print_step_time("build masks (active/cheese)", &step);

		if (do_pagerank) {
			timer_start(&step);
			double* pr = NULL;
			PRMeta	meta;
			pagerank_compute_B(&B, &cm, activeB, cheese, 0, pr_iters, pr_damp, pr_eps, &pr, &meta);
			printf("\n[pagerank] raw (snapshot B)\n");
			printf("  iters=%d damp=%.4f eps=%g  active=%u  cheese(active)=%u  edges_considered=%" PRIu64 "\n",
				   pr_iters, pr_damp, pr_eps, meta.n_active, meta.n_cheese, meta.m_active);
			pagerank_print_top("raw PageRank (B)", &cm, activeB, cheese, pr, topk, pr_exclude_cheese_print);
			print_step_time("pagerank raw", &step);

			timer_start(&step);
			printf("\n[pagerank] sampler (snapshot B)\n");
			PRSampler samp;
			if (!prsampler_build(&samp, pr, activeB, cm.n, 2.0 /*alpha*/, 1234567ULL)) {
				die("failed to build PRSampler");
			}
			for (int k = 0; k < 10; k++) {
				uint32_t g = random_biased(&samp);
				printf("biased pick %d: ", k);
				fprint_title(stdout, cm.titles[g]);
				printf("\n");
			}
			prsampler_free(&samp);
			print_step_time("pagerank sampler", &step);

			free(pr);

			if (do_pagerank_no_cheese) {
				timer_start(&step);
				double* pr2 = NULL;
				PRMeta	meta2;
				pagerank_compute_B(&B, &cm, activeB, cheese, 1, pr_iters, pr_damp, pr_eps, &pr2, &meta2);
				printf("\n[pagerank] no-cheese (snapshot B)\n");
				printf("  iters=%d damp=%.4f eps=%g  active=%u  cheese(active)=%u  edges_considered=%" PRIu64 "\n",
					   pr_iters, pr_damp, pr_eps, meta2.n_active, meta2.n_cheese, meta2.m_active);
				pagerank_print_top("no-cheese PageRank (B) [cheese sources don't distribute]", &cm, activeB, cheese,
								   pr2, topk, pr_exclude_cheese_print);
				free(pr2);
				print_step_time("pagerank no-cheese", &step);
			}
		}

		if (do_diameter) {
			timer_start(&step);
			analyze_directed_longest_shortest_path_B(&B, &cm, activeB, diam_sweeps, diam_min_visited, diam_min_out);
			print_step_time("diameter heuristic", &step);
		}

		free(activeB);
		free(cheese);
	}

	if (do_edge_diff) {
		printf("\n[diff] edge overlap + churn (this pass is bandwidth-heavy on big DBs)\n");
		timer_start(&step);
		analyze_edge_diff(&A, &B, &cm, topk, 1);
		print_step_time("edge diff", &step);
	} else {
		printf("\n[diff] edge overlap/churn skipped (--no-edge-diff)\n");
	}

	// Future extension hooks:
	// - PageRank (power iteration) using outgoing lists + dangling handling.
	// - Approx PageRank / personalization.
	// - Strong components / reachability sampling.
	// - Per-page MinHash sketches for fast churn at scale.

	timer_start(&step);
	graph_free(&GA);
	graph_free(&GB);
	combined_free(&cm);
	db_free(&A);
	db_free(&B);
	print_step_time("cleanup", &step);
	print_step_time("overall", &total);

	return 0;
}
