// Simple min-heap for keeping top-K items by score
typedef struct {
	u32    id;
	double score;
} DiffTop;

STATIC void diff_top_swap(DiffTop* a, DiffTop* b) {
	DiffTop t = *a;
	*a        = *b;
	*b        = t;
}

STATIC void diff_top_sift_down(DiffTop* h, int n, int i) {
	while (1) {
		int l = 2 * i + 1;
		int r = l + 1;
		int s = i;
		if (l < n && h[l].score < h[s].score) s = l;
		if (r < n && h[r].score < h[s].score) s = r;
		if (s == i) break;
		diff_top_swap(&h[i], &h[s]);
		i = s;
	}
}

STATIC void diff_top_sift_up(DiffTop* h, int i) {
	while (i > 0) {
		int p = (i - 1) / 2;
		if (h[p].score <= h[i].score) break;
		diff_top_swap(&h[p], &h[i]);
		i = p;
	}
}

STATIC void diff_top_push(DiffTop* h, int* sz, int k, u32 id, double score) {
	if (k <= 0) return;
	if (*sz < k) {
		h[*sz].id    = id;
		h[*sz].score = score;
		diff_top_sift_up(h, *sz);
		(*sz)++;
	} else if (score > h[0].score) {
		h[0].id    = id;
		h[0].score = score;
		diff_top_sift_down(h, *sz, 0);
	}
}

STATIC int diff_top_cmp_desc(const void* a, const void* b) {
	const DiffTop* x = (const DiffTop*)a;
	const DiffTop* y = (const DiffTop*)b;
	if (x->score < y->score) return 1;
	if (x->score > y->score) return -1;
	if (x->id < y->id) return -1;
	if (x->id > y->id) return 1;
	return 0;
}

typedef struct {
	string title;
	u32    ridx;
} RedirTitleIdx;

STATIC int redir_title_cmp(const void* a, const void* b) {
	const RedirTitleIdx* x = (const RedirTitleIdx*)a;
	const RedirTitleIdx* y = (const RedirTitleIdx*)b;
	return string_cmp(x->title, y->title);
}

STATIC void diff_run(const char* old_path, const char* new_path, int topk) {
	Graph old_g = {0};
	Graph new_g = {0};

	printf("[diff] loading old db: %s\n", old_path);
	graph_load_from_file(&old_g, old_path);
	printf("[diff] loading new db: %s\n", new_path);
	graph_load_from_file(&new_g, new_path);

	// Build PageRank once per graph for relevance ordering.
	pagerank_build(&old_g, 20, 0.85, 0.0);
	pagerank_build(&new_g, 20, 0.85, 0.0);

	// Mark targets that have an incoming redirect whose title existed as a canonical
	// page in the old snapshot (heuristic for renames).
	bool* new_dest_has_old_redirect = NULL;
	if (new_g.N > 0) {
		new_dest_has_old_redirect = (bool*)calloc((size_t)new_g.N, sizeof(bool));
		if (!new_dest_has_old_redirect) {
			fprintf(stderr, "error: OOM new_dest_has_old_redirect\n");
			exit(1);
		}
	}
	for (u32 i = 0; i < new_g.nr_unredir; i++) {
		UnredirEdge* e = &new_g.unredir[i];
		if (e->redir_idx >= new_g.nr_redir_titles) continue;
		string rt = new_g.redir_titles[e->redir_idx];
		if (graph_find_id(&old_g, rt) != UINT32_MAX) new_dest_has_old_redirect[e->dest] = true;
	}

	// Build a sorted index of redirect titles in the new snapshot for quick lookup
	// when testing whether an old title has become a redirect.
	RedirTitleIdx* new_redir_index = NULL;
	int            new_redir_n     = 0;
	if (new_g.nr_redir_titles) {
		new_redir_n     = (int)new_g.nr_redir_titles;
		new_redir_index = (RedirTitleIdx*)malloc((size_t)new_redir_n * sizeof(RedirTitleIdx));
		if (!new_redir_index) {
			fprintf(stderr, "error: OOM new_redir_index\n");
			exit(1);
		}
		for (int i = 0; i < new_redir_n; i++) {
			new_redir_index[i].title = new_g.redir_titles[i];
			new_redir_index[i].ridx  = (u32)i;
		}
		qsort(new_redir_index, (size_t)new_redir_n, sizeof(RedirTitleIdx), redir_title_cmp);
	}

	bool* old_titles_redirected = NULL;
	if (old_g.N > 0) {
		old_titles_redirected = (bool*)calloc((size_t)old_g.N, sizeof(bool));
		if (!old_titles_redirected) {
			fprintf(stderr, "error: OOM old_titles_redirected\n");
			exit(1);
		}
	}
	if (new_redir_index) {
		for (int i = 0; i < new_redir_n; i++) {
			string rt     = new_redir_index[i].title;
			u32    old_id = graph_find_id(&old_g, rt);
			if (old_titles_redirected && old_id != UINT32_MAX) old_titles_redirected[old_id] = true;
		}
	}

	DiffTop* add_heap = (DiffTop*)malloc((size_t)topk * sizeof(DiffTop));
	DiffTop* del_heap = (DiffTop*)malloc((size_t)topk * sizeof(DiffTop));
	int      add_sz   = 0;
	int      del_sz   = 0;
	if ((!add_heap && topk > 0) || (!del_heap && topk > 0)) {
		fprintf(stderr, "error: OOM diff heaps\n");
		exit(1);
	}

	// Collect top additions: canonical titles absent in old graph and not explained by
	// old titles being turned into redirects.
	for (u32 id = 0; id < new_g.N; id++) {
		string t = new_g.titles[id];
		if (graph_find_id(&old_g, t) != UINT32_MAX) continue;
		if (new_dest_has_old_redirect && new_dest_has_old_redirect[id]) continue;
		double pr = pagerank_score(&new_g, id);
		diff_top_push(add_heap, &add_sz, topk, id, pr);
	}

	// Collect top deletions: canonical titles missing in new graph and not preserved
	// as redirects.
	for (u32 id = 0; id < old_g.N; id++) {
		string t = old_g.titles[id];
		if (graph_find_id(&new_g, t) != UINT32_MAX) continue;
		if (old_titles_redirected && old_titles_redirected[id]) continue;
		double pr = pagerank_score(&old_g, id);
		diff_top_push(del_heap, &del_sz, topk, id, pr);
	}

	qsort(add_heap, (size_t)add_sz, sizeof(DiffTop), diff_top_cmp_desc);
	qsort(del_heap, (size_t)del_sz, sizeof(DiffTop), diff_top_cmp_desc);

	printf("\nTop %d new articles (PageRank-biased, excluding renames):\n", topk);
	for (int i = 0; i < add_sz; i++) {
		DiffTop* d = &add_heap[i];
		string   t = new_g.titles[d->id];
		printf("  %2d. %.*s (PR=%.6g)\n", i + 1, STR_LEN(t), STR_PTR(t), d->score);
	}

	printf("\nTop %d deletions (PageRank-biased, excluding renames):\n", topk);
	for (int i = 0; i < del_sz; i++) {
		DiffTop* d = &del_heap[i];
		string   t = old_g.titles[d->id];
		printf("  %2d. %.*s (PR=%.6g)\n", i + 1, STR_LEN(t), STR_PTR(t), d->score);
	}

	free(new_dest_has_old_redirect);
	free(new_redir_index);
	free(old_titles_redirected);
	free(add_heap);
	free(del_heap);
}
