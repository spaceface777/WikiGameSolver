// Search backend: shortest distance BFS + split forward/backward layers + constrained DFS
// Hot BFS loops contain no bounds checks (DB validated at startup).

#ifdef ENABLE_SERVER
#define MAYBE_THREAD_LOCAL _Thread_local
#else
#define MAYBE_THREAD_LOCAL
#endif

MAYBE_THREAD_LOCAL STATIC u8*  sp_ds = NULL;
MAYBE_THREAD_LOCAL STATIC u32* sp_qs = NULL;

MAYBE_THREAD_LOCAL STATIC u8*  mp_df = NULL;
MAYBE_THREAD_LOCAL STATIC u8*  mp_db = NULL;
MAYBE_THREAD_LOCAL STATIC u32* mp_qf = NULL;
MAYBE_THREAD_LOCAL STATIC u32* mp_qb = NULL;

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

typedef struct {
	const Graph* g;
	u32			 s, t;
	u8			 D, split, suffix;
	u32			 max_paths;
	u32			 npaths;

	u32 pre[PATH_CAP];
	u32 suf[PATH_CAP];

	PathIDs* out; // write first path here
	bool	 found;
} MPEnum;

STATIC void mp_suffix_dfs(MPEnum* E, u32 u, u8 rem, u8 idx) {
	if (E->found) return;
	if (E->npaths >= E->max_paths) return;

	if (rem == 0) {
		if (u != E->t) return;

		// build final ids = pre[0..split] + suf[1..suffix]
		u32 len = 0;
		for (u32 i = 0; i <= (u32)E->split; i++) E->out->ids[len++] = E->pre[i];
		for (u32 i = 1; i <= (u32)E->suffix; i++) E->out->ids[len++] = E->suf[i];

		E->out->len = len;
		E->npaths++;
		E->found = true;
		return;
	}

	// Walk forward while decreasing mp_db by 1
	u32		  beg = E->g->out_offsets[u];
	u32		  end = E->g->out_offsets[u + 1];
	const u8* p	  = u24_cptr(E->g->out_edges24, beg);

	for (u32 i = beg; i < end; i++, p += 3) {
		u32 v = u24_load(p);
		if (mp_db[v] == (u8)(rem - 1)) {
			E->suf[idx + 1] = v;
			mp_suffix_dfs(E, v, (u8)(rem - 1), (u8)(idx + 1));
			if (E->found) return;
		}
	}
}

STATIC void mp_prefix_dfs(MPEnum* E, u32 u, u8 depth) {
	if (E->found) return;
	if (E->npaths >= E->max_paths) return;

	if (depth == E->split) {
		// midpoint must be exactly suffix away from t
		if (mp_db[u] == E->suffix) {
			E->suf[0] = u;
			mp_suffix_dfs(E, u, E->suffix, 0);
		}
		return;
	}

	// Follow layer-respecting edges where mp_df[next] = depth+1
	u32		  beg = E->g->out_offsets[u];
	u32		  end = E->g->out_offsets[u + 1];
	const u8* p	  = u24_cptr(E->g->out_edges24, beg);

	for (u32 i = beg; i < end; i++, p += 3) {
		u32 v = u24_load(p);
		if (mp_df[v] == (u8)(depth + 1)) {
			E->pre[depth + 1] = v;
			mp_prefix_dfs(E, v, (u8)(depth + 1));
			if (E->found) return;
		}
	}
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

	u8 split  = (u8)((D + 1) / 2);
	u8 suffix = (u8)(D - split);

	// 2) build forward and backward distance layers
	u32 vis_f = mp_bfs_prefix(g, s, split);
	u32 vis_b = mp_rbfs_suffix(g, t, suffix);

	// 3) enumerate a shortest path (max_paths=1)
	MPEnum E	= {0};
	E.g			= g;
	E.s			= s;
	E.t			= t;
	E.D			= D;
	E.split		= split;
	E.suffix	= suffix;
	E.max_paths = 1;
	E.npaths	= 0;
	E.pre[0]	= s;
	E.out		= out;
	E.found		= false;

	mp_prefix_dfs(&E, s, 0);

	mp_reset_db(vis_b);
	mp_reset_df(vis_f);

	return E.found;
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
	if (s == UINT32_MAX) {
		printf("start page `%.*s` not in the database\n", STR_LEN(start), STR_PTR(start));
		return false;
	}
	u32 t = graph_find_id(g, target);
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
