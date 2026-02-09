// Search backend: shortest distance BFS + split forward/backward layers + constrained DFS
// Hot BFS loops contain no bounds checks (DB validated at startup).

#ifdef ENABLE_SERVER
#define MAYBE_THREAD_LOCAL _Thread_local
#else
#define MAYBE_THREAD_LOCAL
#endif

MAYBE_THREAD_LOCAL STATIC u8*  sp_ds = NULL;
MAYBE_THREAD_LOCAL STATIC u32* sp_qs = NULL;

MAYBE_THREAD_LOCAL STATIC u8*  mp_df		= NULL;
MAYBE_THREAD_LOCAL STATIC u8*  mp_db		= NULL;
MAYBE_THREAD_LOCAL STATIC u32* mp_qf		= NULL;
MAYBE_THREAD_LOCAL STATIC u32* mp_qb		= NULL;
MAYBE_THREAD_LOCAL STATIC u8*  mp_zero_memo = NULL;
MAYBE_THREAD_LOCAL STATIC u32* mp_zero_next = NULL;
MAYBE_THREAD_LOCAL STATIC u8*  mp_cost_done = NULL;
MAYBE_THREAD_LOCAL STATIC u32* mp_cost_best = NULL;
MAYBE_THREAD_LOCAL STATIC u32* mp_cost_next = NULL;

STATIC void sp_init(u32 N) {
	if (!sp_ds) {
		sp_ds = (u8*)malloc((size_t)N);
		if (!sp_ds) {
			fprintf(stderr, "error: OOM sp_ds\n");
			exit(1);
		}
		memset(sp_ds, 0xFF, (size_t)N);
	}
	if (!sp_qs) {
		sp_qs = (u32*)malloc((size_t)N * sizeof(u32));
		if (!sp_qs) {
			fprintf(stderr, "error: OOM sp_qs\n");
			exit(1);
		}
	}
}

STATIC void mp_init(u32 N) {
	if (!mp_df) {
		mp_df = (u8*)malloc((size_t)N);
		if (!mp_df) {
			fprintf(stderr, "error: OOM mp_df\n");
			exit(1);
		}
		memset(mp_df, 0xFF, (size_t)N);
	}
	if (!mp_db) {
		mp_db = (u8*)malloc((size_t)N);
		if (!mp_db) {
			fprintf(stderr, "error: OOM mp_db\n");
			exit(1);
		}
		memset(mp_db, 0xFF, (size_t)N);
	}
	if (!mp_qf) {
		mp_qf = (u32*)malloc((size_t)N * sizeof(u32));
		if (!mp_qf) {
			fprintf(stderr, "error: OOM mp_qf\n");
			exit(1);
		}
	}
	if (!mp_qb) {
		mp_qb = (u32*)malloc((size_t)N * sizeof(u32));
		if (!mp_qb) {
			fprintf(stderr, "error: OOM mp_qb\n");
			exit(1);
		}
	}
	if (!mp_zero_memo) {
		mp_zero_memo = (u8*)malloc((size_t)N);
		if (!mp_zero_memo) {
			fprintf(stderr, "error: OOM mp_zero_memo\n");
			exit(1);
		}
		memset(mp_zero_memo, 0, (size_t)N);
	}
	if (!mp_zero_next) {
		mp_zero_next = (u32*)malloc((size_t)N * sizeof(u32));
		if (!mp_zero_next) {
			fprintf(stderr, "error: OOM mp_zero_next\n");
			exit(1);
		}
	}
	if (!mp_cost_done) {
		mp_cost_done = (u8*)malloc((size_t)N);
		if (!mp_cost_done) {
			fprintf(stderr, "error: OOM mp_cost_done\n");
			exit(1);
		}
		memset(mp_cost_done, 0, (size_t)N);
	}
	if (!mp_cost_best) {
		mp_cost_best = (u32*)malloc((size_t)N * sizeof(u32));
		if (!mp_cost_best) {
			fprintf(stderr, "error: OOM mp_cost_best\n");
			exit(1);
		}
	}
	if (!mp_cost_next) {
		mp_cost_next = (u32*)malloc((size_t)N * sizeof(u32));
		if (!mp_cost_next) {
			fprintf(stderr, "error: OOM mp_cost_next\n");
			exit(1);
		}
	}
}

STATIC u8 sp_bfs_distance(const Graph* g, u32 s, u32 t, u8 max_depth, u32* out_vis) {
	u32 head = 0, tail = 0;
	sp_qs[tail++] = s;
	sp_ds[s]	  = 0;

	while (head < tail) {
		u32 v  = sp_qs[head++];
		u8	dv = sp_ds[v];
		if (v == t) break;
		if (dv >= max_depth) continue;

		u32		  beg = g->out_offsets[v];
		u32		  end = g->out_offsets[v + 1];
		const u8* p	  = u24_cptr(g->out_edges24, beg);

		for (u32 idx = beg; idx < end; idx++, p += 3) {
			u32 u = u24_load(p);
			if (sp_ds[u] != 0xFF) continue;
			sp_ds[u]	  = (u8)(dv + 1);
			sp_qs[tail++] = u;
			if (u == t) {
				head = tail;
				break;
			}
		}
	}

	if (out_vis) *out_vis = tail;
	return sp_ds[t];
}

STATIC void sp_reset(u32 vis) {
	for (u32 i = 0; i < vis; i++) sp_ds[sp_qs[i]] = 0xFF;
}

STATIC u32 mp_bfs_prefix(const Graph* g, u32 s, u8 split) {
	u32 head = 0, tail = 0;
	mp_qf[tail++] = s;
	mp_df[s]	  = 0;

	while (head < tail) {
		u32 u  = mp_qf[head++];
		u8	du = mp_df[u];
		if (du >= split) continue;

		u32		  beg = g->out_offsets[u];
		u32		  end = g->out_offsets[u + 1];
		const u8* p	  = u24_cptr(g->out_edges24, beg);

		for (u32 idx = beg; idx < end; idx++, p += 3) {
			u32 v = u24_load(p);
			if (mp_df[v] != 0xFF) continue;
			mp_df[v]	  = (u8)(du + 1);
			mp_qf[tail++] = v;
		}
	}
	return tail;
}

STATIC u32 mp_rbfs_suffix(const Graph* g, u32 t, u8 suffix) {
	u32 head = 0, tail = 0;
	mp_qb[tail++] = t;
	mp_db[t]	  = 0;

	while (head < tail) {
		u32 v  = mp_qb[head++];
		u8	dv = mp_db[v];
		if (dv >= suffix) continue;

		u32		  beg = g->in_offsets[v];
		u32		  end = g->in_offsets[v + 1];
		const u8* p	  = u24_cptr(g->in_edges24, beg);

		for (u32 idx = beg; idx < end; idx++, p += 3) {
			u32 pred = u24_load(p);
			if (mp_db[pred] != 0xFF) continue;
			mp_db[pred]	  = (u8)(dv + 1);
			mp_qb[tail++] = pred;
		}
	}
	return tail;
}

STATIC void mp_reset_df(u32 vis) {
	for (u32 i = 0; i < vis; i++) mp_df[mp_qf[i]] = 0xFF;
}

STATIC void mp_reset_db(u32 vis) {
	for (u32 i = 0; i < vis; i++) mp_db[mp_qb[i]] = 0xFF;
}

STATIC inline u8 edge_flags_or_zero(const Graph* g, u32 edge_idx) {
	return g->edge_flags ? g->edge_flags[edge_idx] : 0u;
}

STATIC inline u32 edge_special_cost(u8 flags) {
	return flags ? (1000u + (u32)flags) : 0u;
}

STATIC inline bool edge_in_shortest_dag(u8 D, u32 u, u32 v) {
	u8 du = mp_df[u];
	if (du == 0xFF || mp_df[v] != (u8)(du + 1) || mp_db[v] == 0xFF) return false;
	return (u8)(du + 1 + mp_db[v]) == D;
}

// mp_zero_memo states: 0=unknown, 1=no path, 2=path exists.
STATIC bool mp_shortest_zero_dfs(const Graph* g, u32 u, u32 t, u8 D) {
	u8 state = mp_zero_memo[u];
	if (state == 1) return false;
	if (state == 2) return true;

	if (u == t) {
		mp_zero_memo[u] = 2;
		mp_zero_next[u] = UINT32_MAX;
		return true;
	}

	u32		  beg = g->out_offsets[u];
	u32		  end = g->out_offsets[u + 1];
	const u8* p	  = u24_cptr(g->out_edges24, beg);

	for (u32 idx = beg; idx < end; idx++, p += 3) {
		u32 v = u24_load(p);
		if (!edge_in_shortest_dag(D, u, v)) continue;
		if (edge_flags_or_zero(g, idx) != 0) continue;
		if (mp_shortest_zero_dfs(g, v, t, D)) {
			mp_zero_memo[u] = 2;
			mp_zero_next[u] = v;
			return true;
		}
	}

	mp_zero_memo[u] = 1;
	return false;
}

STATIC const u32 MP_INF_COST = 0x3FFFFFFFu;

// Computes exact minimum special_cost over all shortest-length paths from u->t.
STATIC u32 mp_shortest_min_cost_dfs(const Graph* g, u32 u, u32 t, u8 D) {
	if (mp_cost_done[u]) return mp_cost_best[u];
	mp_cost_done[u] = 1;

	if (u == t) {
		mp_cost_best[u] = 0;
		mp_cost_next[u] = UINT32_MAX;
		return 0;
	}

	u32		  best_cost = MP_INF_COST;
	u32		  best_next = UINT32_MAX;
	u32		  beg		= g->out_offsets[u];
	u32		  end		= g->out_offsets[u + 1];
	const u8* p			= u24_cptr(g->out_edges24, beg);

	for (u32 idx = beg; idx < end; idx++, p += 3) {
		u32 v = u24_load(p);
		if (!edge_in_shortest_dag(D, u, v)) continue;

		u32 tail_cost = mp_shortest_min_cost_dfs(g, v, t, D);
		if (tail_cost == MP_INF_COST) continue;

		u8	flags	  = edge_flags_or_zero(g, idx);
		u32 cand_cost = tail_cost + edge_special_cost(flags);
		if (cand_cost < best_cost || (cand_cost == best_cost && v < best_next)) {
			best_cost = cand_cost;
			best_next = v;
		}
	}

	mp_cost_best[u] = best_cost;
	mp_cost_next[u] = best_next;
	return best_cost;
}

STATIC bool mp_build_path_from_next(u32 s, u32 t, u8 D, const u32* next_arr, PathIDs* out) {
	u32 cur			= s;
	u32 len			= 0;
	out->ids[len++] = s;

	for (u8 step = 0; step < D; step++) {
		u32 nxt = next_arr[cur];
		if (nxt == UINT32_MAX) return false;
		out->ids[len++] = nxt;
		cur				= nxt;
	}
	if (cur != t) return false;
	out->len = len;
	return true;
}

STATIC bool bikpaths_find_one(const Graph* g, u32 s, u32 t, u8 max_depth, PathIDs* out) {
	assert(g && g->validated);
	assert(g->N <= 0xFFFFFFu);
	assert(PATH_CAP <= 256);
	assert(max_depth < (PATH_CAP - 1));

	if (s == t) {
		out->len	= 1;
		out->ids[0] = s;
		return true;
	}

	u32 N = g->N;
	sp_init(N);
	mp_init(N);

	// 1) provable shortest distance D (bounded by max_depth)
	u32 vis_s = 0;
	u8	D	  = sp_bfs_distance(g, s, t, max_depth, &vis_s);
	sp_reset(vis_s);
	if (D == 0xFF) return false;

	// 2) build complete shortest-path layering from both sides
	u32 vis_f = mp_bfs_prefix(g, s, D);
	u32 vis_b = mp_rbfs_suffix(g, t, D);

	// Reset DP memo states only for touched forward nodes.
	for (u32 i = 0; i < vis_f; i++) {
		u32 v			= mp_qf[i];
		mp_zero_memo[v] = 0;
		mp_zero_next[v] = UINT32_MAX;
		mp_cost_done[v] = 0;
		mp_cost_best[v] = MP_INF_COST;
		mp_cost_next[v] = UINT32_MAX;
	}

	// 3) First choice: shortest path that uses only non-special edges.
	bool found = false;
	if (mp_shortest_zero_dfs(g, s, t, D)) {
		found = mp_build_path_from_next(s, t, D, mp_zero_next, out);
	}

	// 4) Fallback: among ALL shortest paths, pick minimum special_cost.
	if (!found) {
		u32 best_cost = mp_shortest_min_cost_dfs(g, s, t, D);
		if (best_cost != MP_INF_COST) found = mp_build_path_from_next(s, t, D, mp_cost_next, out);
	}

	mp_reset_db(vis_b);
	mp_reset_df(vis_f);

	return found;
}

#if VERIFY_RESULT_PATH
STATIC void verify_path_or_die(const Graph* g, const PathIDs* p) {
	if (!p || p->len == 0) return;
	if (p->len >= PATH_CAP) {
		fprintf(stderr, "error: invalid path length %u\n", p->len);
		exit(1);
	}
	for (u32 i = 1; i < p->len; i++) {
		u32 a = p->ids[i - 1];
		u32 b = p->ids[i];
		if (!graph_has_edge(g, a, b)) {
			fprintf(stderr, "error: returned path contains non-edge %u -> %u\n", a, b);
			exit(1);
		}
	}
}
#endif

STATIC bool graph_find_path_titles(const Graph* g, string start, string target, u8 max_depth, PathIDs* out) {
	if (!g || !g->validated) {
		fprintf(stderr, "error: graph not loaded/validated\n");
		exit(1);
	}
	if (max_depth > 254) {
		fprintf(stderr, "error: max_depth must be <= 254\n");
		exit(2);
	}

	u32 s = graph_find_id(g, start);
	if (s == UINT32_MAX) s = graph_find_id_case_insensitive_unique(g, start);
	if (s == UINT32_MAX) {
		printf("start page `%.*s` not in the database\n", STR_LEN(start), STR_PTR(start));
		return false;
	}
	u32 t = graph_find_id(g, target);
	if (t == UINT32_MAX) t = graph_find_id_case_insensitive_unique(g, target);
	if (t == UINT32_MAX) {
		printf("target page `%.*s` not in the database\n", STR_LEN(target), STR_PTR(target));
		return false;
	}

	out->len = 0;
	bool ok	 = bikpaths_find_one(g, s, t, max_depth, out);

#if VERIFY_RESULT_PATH
	if (ok) verify_path_or_die(g, out);
#endif
	return ok;
}
