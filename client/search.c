// Search backend: shortest-hop BFS + forward-layer DP + K-best shortest-hop enumeration.
// Hot BFS/edge loops contain no bounds checks (DB validated at startup).

#ifdef ENABLE_SERVER
#define MAYBE_THREAD_LOCAL _Thread_local
#else
#define MAYBE_THREAD_LOCAL
#endif

typedef struct SearchPerf {
	u64 lookup_ns;
	u64 sp_bfs_ns;
	u64 sp_reset_ns;
	u64 dp_ns;
	u64 enum_ns;
	u64 fallback_dp_ns;
	u64 path_build_ns;
	u64 cleanup_ns;
	u64 solver_ns;
	u64 verify_ns;
	u64 total_ns;

	u32  vis_sp;
	u32  vis_layers;
	u32  path_len;
	u32  paths_returned;
	u32  enum_states_used;
	u32  dag_edges_used;
	u32  sidetrack_nodes_used;
	u32  sidetrack_states_used;
	u8   shortest_dist;
	u8   strategy; // 0=none, 1=K==1 BFS, 2=sidetrack fallback, 3=K>1 enum
	bool fallback_used;
	bool found;
} SearchPerf;

typedef struct State {
	u32 node;
	u32 parent_idx;
	u32 g;
	u8  depth;
	u8  _pad[3];
} State;

typedef struct SidetrackNode {
	u32 from;
	u32 to;
	u32 delta;
	u32 left;
	u32 right;
	u8  npl;
} SidetrackNode;

typedef struct SidetrackState {
	u32 prev_idx;
	u32 node_idx;
	u32 delta_sum;
} SidetrackState;

typedef struct DagEdge {
	u32 to;
	u16 cost;
	u32 next;
} DagEdge;

typedef struct SearchScratch {
	u8*  dist;           // N
	u32* q;              // N (BFS queue + visited list)
	u32* best_cost;      // N (K==1 fast path)
	u32* parent;         // N (K==1 fast path)
	u32* dag_head;       // N (per-node linked-list head for recorded shortest-layer edges)
	u32* layer_nodes;    // N (stable layer buckets)
	u32* h;              // N (exact remaining cost in shortest-hop DAG)
	u64* can_bits;       // (N+63)/64
	u8*  best_child_u24; // 3*N

	State* states;
	u32*   heap_idx;
	u32    states_cap;

	DagEdge* dag_edges;
	u32      dag_edge_cap;
	u32      dag_edges_len; // per-query

	u32*            sidetrack_roots; // N
	SidetrackNode*  sidetrack_nodes;
	u32             sidetrack_nodes_cap;
	u32             sidetrack_nodes_len;
	SidetrackState* sidetrack_states;
	u32*            sidetrack_heap_idx;
	u32             sidetrack_states_cap;

	u32 N;
} SearchScratch;

MAYBE_THREAD_LOCAL STATIC SearchScratch g_search_scratch   = {0};
MAYBE_THREAD_LOCAL STATIC SearchPerf    g_search_perf_last = {0};

STATIC const SearchPerf* search_perf_get_last(void) {
	return &g_search_perf_last;
}

STATIC const u32 SEARCH_INF_COST = 0x3FFFFFFFu;
STATIC const u32 U24_NONE        = 0xFFFFFFu;

INLINE bool bit_test(const u64* bits, u32 i) {
	return (bits[i >> 6] >> (i & 63u)) & 1u;
}

INLINE void bit_set(u64* bits, u32 i) {
	bits[i >> 6] |= (1ull << (i & 63u));
}

INLINE void bit_clear(u64* bits, u32 i) {
	bits[i >> 6] &= ~(1ull << (i & 63u));
}

INLINE u8 edge_flags_or_zero(const Graph* g, u32 edge_idx) {
	return g->edge_flags ? g->edge_flags[edge_idx] : 0u;
}

INLINE u32 edge_special_cost(u8 flags) {
	return flags ? (1000u + (u32)flags) : 0u;
}

INLINE void u24_store_at(u8* base, u32 idx, u32 v) {
	u24_store(base + (size_t)idx * 3u, v);
}

INLINE u32 u24_load_at(const u8* base, u32 idx) {
	return u24_load(base + (size_t)idx * 3u);
}

INLINE void best_child_set(SearchScratch* sc, u32 node, u32 child) {
	u24_store_at(sc->best_child_u24, node, child);
}

INLINE u32 best_child_get(const SearchScratch* sc, u32 node) {
	return u24_load_at(sc->best_child_u24, node);
}

STATIC void* search_xmalloc(size_t bytes, const char* what) {
	void* p = malloc(bytes);
	if (!p) {
		fprintf(stderr, "error: OOM allocating %s (%zu bytes)\n", what, bytes);
		exit(1);
	}
	return p;
}

STATIC u32 search_grow_cap_15(u32 cur, u32 need) {
	u64 cap = (cur > 0) ? (u64)cur : 1ull;
	if (cap < 16ull) cap = 16ull;
	while (cap < (u64)need) {
		u64 next = cap + (cap >> 1); // x1.5
		if (next <= cap) next = (u64)need;
		cap = next;
		if (cap > (u64)UINT32_MAX) {
			cap = (u64)UINT32_MAX;
			break;
		}
	}
	if (cap < (u64)need) return 0;
	return (u32)cap;
}

STATIC bool search_reserve_enum(SearchScratch* sc, u32 need) {
	if (need <= sc->states_cap) return true;
	u32 new_cap = search_grow_cap_15(sc->states_cap ? sc->states_cap : ENUM_STATE_INIT_CAP, need);
	if (new_cap == 0) return false;

	State* new_states = (State*)malloc((size_t)new_cap * sizeof(State));
	u32*   new_heap   = (u32*)malloc((size_t)new_cap * sizeof(u32));
	if (!new_states || !new_heap) {
		free(new_states);
		free(new_heap);
		return false;
	}
	if (sc->states) {
		memcpy(new_states, sc->states, (size_t)sc->states_cap * sizeof(State));
		free(sc->states);
	}
	if (sc->heap_idx) {
		memcpy(new_heap, sc->heap_idx, (size_t)sc->states_cap * sizeof(u32));
		free(sc->heap_idx);
	}
	sc->states     = new_states;
	sc->heap_idx   = new_heap;
	sc->states_cap = new_cap;
	return true;
}

STATIC bool search_reserve_dag_edges(SearchScratch* sc, u32 need) {
	if (need <= sc->dag_edge_cap) return true;
	u32 new_cap = search_grow_cap_15(sc->dag_edge_cap ? sc->dag_edge_cap : DAG_EDGE_INIT_CAP, need);
	if (new_cap == 0) return false;
	DagEdge* p = (DagEdge*)realloc(sc->dag_edges, (size_t)new_cap * sizeof(DagEdge));
	if (!p) return false;
	sc->dag_edges    = p;
	sc->dag_edge_cap = new_cap;
	return true;
}

STATIC bool search_reserve_sidetrack_nodes(SearchScratch* sc, u32 need) {
	if (need <= sc->sidetrack_nodes_cap) return true;
	u32 new_cap = search_grow_cap_15(sc->sidetrack_nodes_cap ? sc->sidetrack_nodes_cap : SIDETRACK_NODE_INIT_CAP, need);
	if (new_cap == 0) return false;
	SidetrackNode* nodes = (SidetrackNode*)malloc((size_t)new_cap * sizeof(SidetrackNode));
	if (!nodes) return false;
	if (sc->sidetrack_nodes) {
		memcpy(nodes, sc->sidetrack_nodes, (size_t)sc->sidetrack_nodes_cap * sizeof(SidetrackNode));
		free(sc->sidetrack_nodes);
	}
	sc->sidetrack_nodes     = nodes;
	sc->sidetrack_nodes_cap = new_cap;
	return true;
}

STATIC bool search_reserve_sidetrack_states(SearchScratch* sc, u32 need) {
	if (need <= sc->sidetrack_states_cap) return true;
	u32 new_cap =
		search_grow_cap_15(sc->sidetrack_states_cap ? sc->sidetrack_states_cap : SIDETRACK_STATE_INIT_CAP, need);
	if (new_cap == 0) return false;

	SidetrackState* states = (SidetrackState*)malloc((size_t)new_cap * sizeof(SidetrackState));
	u32*            heap   = (u32*)malloc((size_t)new_cap * sizeof(u32));
	if (!states || !heap) {
		free(states);
		free(heap);
		return false;
	}
	if (sc->sidetrack_states) {
		memcpy(states, sc->sidetrack_states, (size_t)sc->sidetrack_states_cap * sizeof(SidetrackState));
		free(sc->sidetrack_states);
	}
	if (sc->sidetrack_heap_idx) {
		memcpy(heap, sc->sidetrack_heap_idx, (size_t)sc->sidetrack_states_cap * sizeof(u32));
		free(sc->sidetrack_heap_idx);
	}
	sc->sidetrack_states     = states;
	sc->sidetrack_heap_idx   = heap;
	sc->sidetrack_states_cap = new_cap;
	return true;
}

STATIC void search_ensure_scratch(const Graph* g) {
	SearchScratch* sc = &g_search_scratch;
	if (sc->N == g->N && sc->dist && sc->q && sc->best_cost && sc->parent && sc->dag_head && sc->layer_nodes && sc->h &&
		sc->can_bits && sc->best_child_u24 && sc->states && sc->heap_idx && sc->dag_edges && sc->sidetrack_roots &&
		sc->sidetrack_nodes && sc->sidetrack_states && sc->sidetrack_heap_idx)
		return;

	if (sc->N != 0 && sc->N != g->N) {
		fprintf(stderr, "error: search scratch graph size mismatch (%u vs %u)\n", (unsigned)sc->N, (unsigned)g->N);
		exit(1);
	}

	u32 N = g->N;
	if (!sc->dist) {
		sc->dist = (u8*)search_xmalloc((size_t)N, "dist");
		memset(sc->dist, 0xFF, (size_t)N);
	}
	if (!sc->q) sc->q = (u32*)search_xmalloc((size_t)N * sizeof(u32), "q");
	if (!sc->best_cost) sc->best_cost = (u32*)search_xmalloc((size_t)N * sizeof(u32), "best_cost");
	if (!sc->parent) sc->parent = (u32*)search_xmalloc((size_t)N * sizeof(u32), "parent");
	if (!sc->dag_head) {
		sc->dag_head = (u32*)search_xmalloc((size_t)N * sizeof(u32), "dag_head");
		for (u32 i = 0; i < N; i++) sc->dag_head[i] = UINT32_MAX;
	}
	if (!sc->layer_nodes) sc->layer_nodes = (u32*)search_xmalloc((size_t)N * sizeof(u32), "layer_nodes");
	if (!sc->h) sc->h = (u32*)search_xmalloc((size_t)N * sizeof(u32), "h");
	if (!sc->can_bits) {
		size_t can_words = ((size_t)N + 63u) >> 6;
		sc->can_bits     = (u64*)search_xmalloc(can_words * sizeof(u64), "can_bits");
		memset(sc->can_bits, 0, can_words * sizeof(u64));
	}
	if (!sc->best_child_u24) {
		sc->best_child_u24 = (u8*)search_xmalloc((size_t)N * 3u, "best_child_u24");
		memset(sc->best_child_u24, 0xFF, (size_t)N * 3u);
	}
	if (!sc->sidetrack_roots) {
		sc->sidetrack_roots = (u32*)search_xmalloc((size_t)N * sizeof(u32), "sidetrack_roots");
		memset(sc->sidetrack_roots, 0xFF, (size_t)N * sizeof(u32));
	}
	if (!search_reserve_enum(sc, ENUM_STATE_INIT_CAP)) {
		fprintf(stderr, "error: OOM allocating enum buffers\n");
		exit(1);
	}
	if (!search_reserve_dag_edges(sc, DAG_EDGE_INIT_CAP)) {
		fprintf(stderr, "error: OOM allocating dag_edges buffer\n");
		exit(1);
	}
	if (!search_reserve_sidetrack_nodes(sc, SIDETRACK_NODE_INIT_CAP)) {
		fprintf(stderr, "error: OOM allocating sidetrack_nodes buffer\n");
		exit(1);
	}
	if (!search_reserve_sidetrack_states(sc, SIDETRACK_STATE_INIT_CAP)) {
		fprintf(stderr, "error: OOM allocating sidetrack_states buffer\n");
		exit(1);
	}

	sc->N = N;
}

STATIC void search_prepare_graph(const Graph* g) {
	if (!g || !g->validated) return;
	search_ensure_scratch(g);
}

STATIC void search_reset_dist(const SearchScratch* sc, u32 vis) {
	for (u32 i = 0; i < vis; i++) sc->dist[sc->q[i]] = 0xFF;
}

STATIC void search_clear_can_for_nodes(SearchScratch* sc, const u32* nodes, u32 n) {
	for (u32 i = 0; i < n; i++) bit_clear(sc->can_bits, nodes[i]);
}

// Out adjacency is sorted; probe one destination edge cost without scanning the whole list.
STATIC bool graph_get_edge_cost_to(const Graph* g, u32 src, u32 dst, u32* out_cost) {
	u32 beg = g->out_offsets[src];
	u32 end = g->out_offsets[src + 1];
	u32 l   = beg;
	u32 r   = end;
	while (l < r) {
		u32 m = l + (r - l) / 2;
		u32 v = u24_load(u24_cptr(g->out_edges24, m));
		if (v < dst) l = m + 1;
		else r = m;
	}
	if (l >= end) return false;
	if (u24_load(u24_cptr(g->out_edges24, l)) != dst) return false;
	if (out_cost) *out_cost = edge_special_cost(edge_flags_or_zero(g, l));
	return true;
}

// Finds bounded shortest-hop distance and records all visited nodes in sc->q[0..vis).
// If t is discovered at distance D, BFS still finishes expanding the rest of layer D-1.
STATIC u8 sp_bfs_distance_record_dag(const Graph* g, SearchScratch* sc, u32 s, u32 t, u8 max_depth, u32* out_vis,
									 bool* out_dag_overflow) {
	u32  tail         = 0;
	u8   D            = 0xFF;
	bool dag_overflow = false;
	sc->dag_edges_len = 0;
	sc->q[tail++]     = s;
	sc->dist[s]       = 0;
	sc->dag_head[s]   = UINT32_MAX;

	u32 layer_begin = 0;
	while (layer_begin < tail) {
		u32 layer_end = tail;
		u8  dv        = sc->dist[sc->q[layer_begin]];
		if (dv >= max_depth) break;

		for (u32 qi = layer_begin; qi < layer_end; qi++) {
			u32       u   = sc->q[qi];
			u8        d   = sc->dist[u];
			u8        nd  = (u8)(d + 1);
			u32       beg = g->out_offsets[u];
			u32       end = g->out_offsets[u + 1];
			const u8* p   = u24_cptr(g->out_edges24, beg);

			for (u32 idx = beg; idx < end; idx++, p += 3) {
				u32 v   = u24_load(p);
				u8  dv2 = sc->dist[v];
				if (dv2 == 0xFF) {
					sc->dist[v]     = nd;
					sc->q[tail++]   = v;
					sc->dag_head[v] = UINT32_MAX;
					dv2             = nd;
					if (v == t && D == 0xFF) D = nd;
				}
				if (dv2 != nd) continue;

				if (!dag_overflow) {
					if (sc->dag_edges_len >= sc->dag_edge_cap &&
						!search_reserve_dag_edges(sc, sc->dag_edges_len + 1u)) {
						dag_overflow = true;
					}
					if (!dag_overflow) {
						u32 ei                 = sc->dag_edges_len++;
						sc->dag_edges[ei].to   = v;
						sc->dag_edges[ei].cost = (u16)edge_special_cost(edge_flags_or_zero(g, idx));
						sc->dag_edges[ei].next = sc->dag_head[u];
						sc->dag_head[u]        = ei;
					}
				}
			}
		}
		if (D != 0xFF && (u8)(dv + 1) >= D) break;
		layer_begin = layer_end;
	}

	if (out_vis) *out_vis = tail;
	if (out_dag_overflow) *out_dag_overflow = dag_overflow;
	return D;
}

// K==1 fast path: compute minimum special_cost among shortest-hop paths during BFS.
STATIC u8 sp_bfs_k1_min_cost(const Graph* g, SearchScratch* sc, u32 s, u32 t, u8 max_depth, u32* out_vis) {
	u32 tail         = 0;
	u8  D            = 0xFF;
	u32 Cbest        = SEARCH_INF_COST;
	sc->q[tail++]    = s;
	sc->dist[s]      = 0;
	sc->best_cost[s] = 0;
	sc->parent[s]    = UINT32_MAX;

	u32 layer_begin = 0;
	while (layer_begin < tail) {
		u32 layer_end = tail;
		u8  d         = sc->dist[sc->q[layer_begin]];
		if (d >= max_depth) break;
		u8 nd = (u8)(d + 1);

		for (u32 qi = layer_begin; qi < layer_end; qi++) {
			u32 u    = sc->q[qi];
			u32 base = sc->best_cost[u];
			if (base >= Cbest) continue; // branch-and-bound (edge costs are nonnegative)

			bool only_t_edge = (D != 0xFF && nd == D);
			if (only_t_edge) {
				u32 ec = 0;
				if (graph_get_edge_cost_to(g, u, t, &ec)) {
					u32 cand = base + ec;
					u32 cur  = Cbest;
					u32 pu   = sc->parent[t];
					if (cand < cur || (cand == cur && u < pu)) {
						sc->best_cost[t] = cand;
						sc->parent[t]    = u;
						Cbest            = cand;
						if (cand == 0) {
							if (out_vis) *out_vis = tail;
							return D;
						}
					}
				}
			} else {
				u32       beg = g->out_offsets[u];
				u32       end = g->out_offsets[u + 1];
				const u8* p   = u24_cptr(g->out_edges24, beg);

				for (u32 idx = beg; idx < end; idx++, p += 3) {
					u32 v    = u24_load(p);
					u32 cand = base + edge_special_cost(edge_flags_or_zero(g, idx));
					u8  dv   = sc->dist[v];
					if (dv == 0xFF) {
						if (D != 0xFF && nd == D && v != t) continue;
						sc->dist[v]      = nd;
						sc->best_cost[v] = cand;
						sc->parent[v]    = u;
						if (v == t) {
							if (D == 0xFF) D = nd;
							sc->q[tail++] = v; // keep reset list complete; t is never expanded afterward
							if (cand < Cbest) Cbest = cand;
							if (cand == 0) {
								if (out_vis) *out_vis = tail;
								return D;
							}
							break; // once D is known for this layer, non-t edges are irrelevant
						}
						sc->q[tail++] = v;
						continue;
					}
					if (dv != nd) continue;
					u32 cur = sc->best_cost[v];
					u32 pu  = sc->parent[v];
					if (cand < cur || (cand == cur && u < pu)) {
						sc->best_cost[v] = cand;
						sc->parent[v]    = u;
						if (v == t) {
							Cbest = cand;
							if (cand == 0) {
								if (out_vis) *out_vis = tail;
								return D;
							}
						}
					}
					if (D != 0xFF && nd == D && v == t) break;
				}
			}
		}

		if (D != 0xFF && nd >= D) break;
		layer_begin = layer_end;
	}

	if (out_vis) *out_vis = tail;
	return D;
}

INLINE bool enum_state_less(const SearchScratch* sc, u32 a_idx, u32 b_idx) {
	const State* a  = &sc->states[a_idx];
	const State* b  = &sc->states[b_idx];
	u64          fa = (u64)a->g + (u64)sc->h[a->node];
	u64          fb = (u64)b->g + (u64)sc->h[b->node];
	if (fa != fb) return fa < fb;
	if (a->g != b->g) return a->g < b->g;
	if (a->node != b->node) return a->node < b->node;
	return a->parent_idx < b->parent_idx;
}

STATIC void enum_heap_push(SearchScratch* sc, u32* heap_len, u32 state_idx) {
	u32 i           = (*heap_len)++;
	sc->heap_idx[i] = state_idx;
	while (i > 0) {
		u32 p = (i - 1u) >> 1;
		if (!enum_state_less(sc, sc->heap_idx[i], sc->heap_idx[p])) break;
		u32 tmp         = sc->heap_idx[i];
		sc->heap_idx[i] = sc->heap_idx[p];
		sc->heap_idx[p] = tmp;
		i               = p;
	}
}

STATIC u32 enum_heap_pop(SearchScratch* sc, u32* heap_len) {
	u32 out = sc->heap_idx[0];
	u32 n   = --(*heap_len);
	if (n == 0) return out;
	sc->heap_idx[0] = sc->heap_idx[n];

	u32 i = 0;
	while (1) {
		u32 l = i * 2u + 1u;
		u32 r = l + 1u;
		if (l >= n) break;
		u32 m = l;
		if (r < n && enum_state_less(sc, sc->heap_idx[r], sc->heap_idx[l])) m = r;
		if (!enum_state_less(sc, sc->heap_idx[m], sc->heap_idx[i])) break;
		u32 tmp         = sc->heap_idx[i];
		sc->heap_idx[i] = sc->heap_idx[m];
		sc->heap_idx[m] = tmp;
		i               = m;
	}
	return out;
}

STATIC bool enum_path_reconstruct(const SearchScratch* sc, u32 state_idx, PathIDs* out) {
	u32 len = 0;
	for (u32 cur = state_idx; cur != UINT32_MAX; cur = sc->states[cur].parent_idx) len++;
	if (len == 0 || len > PATH_CAP) return false;

	u32 cur = state_idx;
	for (u32 pos = len; pos > 0; pos--) {
		out->ids[pos - 1] = sc->states[cur].node;
		cur               = sc->states[cur].parent_idx;
	}
	out->len             = len;
	out->start_redir_idx = UINT32_MAX;
	return true;
}

INLINE bool sidetrack_node_less(const SearchScratch* sc, u32 a, u32 b) {
	const SidetrackNode* na = &sc->sidetrack_nodes[a];
	const SidetrackNode* nb = &sc->sidetrack_nodes[b];
	if (na->delta != nb->delta) return na->delta < nb->delta;
	if (na->from != nb->from) return na->from < nb->from;
	if (na->to != nb->to) return na->to < nb->to;
	return a < b;
}

INLINE u8 sidetrack_npl(const SearchScratch* sc, u32 idx) {
	return idx == UINT32_MAX ? 0u : sc->sidetrack_nodes[idx].npl;
}

STATIC const u32 SIDETRACK_MELD_DEPTH_GUARD = 4096u;

STATIC u32 sidetrack_heap_meld_rec(SearchScratch* sc, u32 a, u32 b, u32 depth, bool* depth_fail) {
	if (a == UINT32_MAX) return b;
	if (b == UINT32_MAX) return a;
	if (depth >= SIDETRACK_MELD_DEPTH_GUARD) {
		*depth_fail = true;
		return a;
	}
	if (sidetrack_node_less(sc, b, a)) {
		u32 tmp = a;
		a       = b;
		b       = tmp;
	}

	SidetrackNode* na = &sc->sidetrack_nodes[a];
	na->right         = sidetrack_heap_meld_rec(sc, na->right, b, depth + 1u, depth_fail);
	if (sidetrack_npl(sc, na->left) < sidetrack_npl(sc, na->right)) {
		u32 tmp   = na->left;
		na->left  = na->right;
		na->right = tmp;
	}
	na->npl = (u8)(sidetrack_npl(sc, na->right) + 1u);
	return a;
}

STATIC u32 sidetrack_heap_meld(SearchScratch* sc, u32 a, u32 b, bool* depth_fail) {
	return sidetrack_heap_meld_rec(sc, a, b, 0u, depth_fail);
}

INLINE bool sidetrack_state_less(const SearchScratch* sc, u32 a_idx, u32 b_idx) {
	const SidetrackState* a = &sc->sidetrack_states[a_idx];
	const SidetrackState* b = &sc->sidetrack_states[b_idx];
	if (a->delta_sum != b->delta_sum) return a->delta_sum < b->delta_sum;
	if (a->node_idx != b->node_idx) return sidetrack_node_less(sc, a->node_idx, b->node_idx);
	return a->prev_idx < b->prev_idx;
}

STATIC void sidetrack_heap_push(SearchScratch* sc, u32* heap_len, u32 st_idx) {
	u32 i                     = (*heap_len)++;
	sc->sidetrack_heap_idx[i] = st_idx;
	while (i > 0) {
		u32 p = (i - 1u) >> 1;
		if (!sidetrack_state_less(sc, sc->sidetrack_heap_idx[i], sc->sidetrack_heap_idx[p])) break;
		u32 tmp                   = sc->sidetrack_heap_idx[i];
		sc->sidetrack_heap_idx[i] = sc->sidetrack_heap_idx[p];
		sc->sidetrack_heap_idx[p] = tmp;
		i                         = p;
	}
}

STATIC u32 sidetrack_heap_pop(SearchScratch* sc, u32* heap_len) {
	u32 out = sc->sidetrack_heap_idx[0];
	u32 n   = --(*heap_len);
	if (n == 0) return out;
	sc->sidetrack_heap_idx[0] = sc->sidetrack_heap_idx[n];
	u32 i                     = 0;
	while (1) {
		u32 l = i * 2u + 1u;
		u32 r = l + 1u;
		if (l >= n) break;
		u32 m = l;
		if (r < n && sidetrack_state_less(sc, sc->sidetrack_heap_idx[r], sc->sidetrack_heap_idx[l])) m = r;
		if (!sidetrack_state_less(sc, sc->sidetrack_heap_idx[m], sc->sidetrack_heap_idx[i])) break;
		u32 tmp                   = sc->sidetrack_heap_idx[i];
		sc->sidetrack_heap_idx[i] = sc->sidetrack_heap_idx[m];
		sc->sidetrack_heap_idx[m] = tmp;
		i                         = m;
	}
	return out;
}

STATIC bool sidetrack_push_state(SearchScratch* sc, u32* states_len, u32* heap_len, SidetrackState st) {
	u32 need  = *states_len + 1u;
	u32 hneed = *heap_len + 1u;
	if ((need > sc->sidetrack_states_cap || hneed > sc->sidetrack_states_cap) &&
		!search_reserve_sidetrack_states(sc, need > hneed ? need : hneed))
		return false;
	u32 idx                   = (*states_len)++;
	sc->sidetrack_states[idx] = st;
	sidetrack_heap_push(sc, heap_len, idx);
	return true;
}

STATIC bool build_tree_path_from_best(const SearchScratch* sc, u32 s, u32 t, u8 D, PathIDs* out) {
	out->start_redir_idx = UINT32_MAX;
	out->len             = 1;
	out->ids[0]          = s;
	u32 cur              = s;
	for (u32 step = 0; step < D; step++) {
		u32 nxt = best_child_get(sc, cur);
		if (nxt == U24_NONE || out->len >= PATH_CAP) return false;
		out->ids[out->len++] = nxt;
		cur                  = nxt;
	}
	return cur == t && out->len == (u32)(D + 1u);
}

STATIC bool build_sidetrack_path(const SearchScratch* sc, u32 s, u32 t, u8 D, u32 st_idx, PathIDs* out) {
	u32 seq[PATH_CAP];
	u32 seq_len = 0;
	for (u32 cur = st_idx; cur != UINT32_MAX; cur = sc->sidetrack_states[cur].prev_idx) {
		if (seq_len >= PATH_CAP) return false;
		seq[seq_len++] = sc->sidetrack_states[cur].node_idx;
	}
	for (u32 i = 0, j = seq_len ? (seq_len - 1u) : 0u; i < j; i++, j--) {
		u32 tmp = seq[i];
		seq[i]  = seq[j];
		seq[j]  = tmp;
	}

	out->start_redir_idx = UINT32_MAX;
	out->len             = 1;
	out->ids[0]          = s;
	u32 cur              = s;

	for (u32 i = 0; i < seq_len; i++) {
		const SidetrackNode* sn    = &sc->sidetrack_nodes[seq[i]];
		u32                  guard = 0;
		while (cur != sn->from) {
			u32 nxt = best_child_get(sc, cur);
			if (nxt == U24_NONE || out->len >= PATH_CAP) return false;
			out->ids[out->len++] = nxt;
			cur                  = nxt;
			if (++guard > (u32)(D + 1u)) return false;
		}
		if (out->len >= PATH_CAP) return false;
		out->ids[out->len++] = sn->to;
		cur                  = sn->to;
	}

	u32 guard = 0;
	while (cur != t) {
		u32 nxt = best_child_get(sc, cur);
		if (nxt == U24_NONE || out->len >= PATH_CAP) return false;
		out->ids[out->len++] = nxt;
		cur                  = nxt;
		if (++guard > (u32)(D + 1u)) return false;
	}
	return out->len == (u32)(D + 1u);
}

// Exact fallback using Eppstein sidetracks on the shortest-hop DAG.
STATIC u32 sidetrack_exact_k_shortest(const Graph* g, SearchScratch* sc, u32 s, u32 t, u8 D, u32 K,
									  const u32* layer_nodes, const u32* layer_offsets, const u32* layer_counts,
									  bool dag_overflow, u32* out_states_used, u32* out_nodes_used, PathSet* out) {
	if (out_states_used) *out_states_used = 0;
	if (out_nodes_used) *out_nodes_used = 0;
	u32 layer_total = layer_offsets[D] + layer_counts[D];
	if (layer_total == 0) return 0;

	for (u32 i = 0; i < layer_total; i++) sc->sidetrack_roots[layer_nodes[i]] = UINT32_MAX;
	sc->sidetrack_nodes_len = 0;
	bool build_truncated    = false;
	bool meld_depth_fail    = false;

	for (i32 d = (i32)D - 1; d >= 0; d--) {
		u32 begin = layer_offsets[(u32)d];
		u32 n     = layer_counts[(u32)d];
		for (u32 i = 0; i < n; i++) {
			u32 u = layer_nodes[begin + i];
			if (!bit_test(sc->can_bits, u)) {
				sc->sidetrack_roots[u] = UINT32_MAX;
				continue;
			}

			u32 own_root = UINT32_MAX;
			u32 best_v   = best_child_get(sc, u);
			u32 hu       = sc->h[u];

			if (!dag_overflow) {
				for (u32 ei = sc->dag_head[u]; ei != UINT32_MAX; ei = sc->dag_edges[ei].next) {
					u32 v = sc->dag_edges[ei].to;
					if (!bit_test(sc->can_bits, v)) continue;
					if (v == best_v) continue;
					u32 hv = sc->h[v];
					if (hu == SEARCH_INF_COST || hv == SEARCH_INF_COST) continue;

					u64 sum = (u64)sc->dag_edges[ei].cost + (u64)hv;
					if (sum < (u64)hu) {
#if !defined(NDEBUG)
						assert(sum >= (u64)hu);
#endif
						continue;
					}
					u32 delta = (u32)(sum - (u64)hu);
					if (sc->sidetrack_nodes_len >= sc->sidetrack_nodes_cap &&
						!search_reserve_sidetrack_nodes(sc, sc->sidetrack_nodes_len + 1u)) {
						build_truncated = true;
						break;
					}
					u32            sn_idx = sc->sidetrack_nodes_len++;
					SidetrackNode* sn     = &sc->sidetrack_nodes[sn_idx];
					sn->from              = u;
					sn->to                = v;
					sn->delta             = delta;
					sn->left              = UINT32_MAX;
					sn->right             = UINT32_MAX;
					sn->npl               = 1;
					own_root              = sidetrack_heap_meld(sc, own_root, sn_idx, &meld_depth_fail);
					if (meld_depth_fail) {
						build_truncated = true;
						break;
					}
				}
			} else {
				u32       beg = g->out_offsets[u];
				u32       end = g->out_offsets[u + 1];
				const u8* p   = u24_cptr(g->out_edges24, beg);
				for (u32 idx = beg; idx < end; idx++, p += 3) {
					u32 v = u24_load(p);
					if (sc->dist[v] != (u8)(d + 1)) continue;
					if (!bit_test(sc->can_bits, v)) continue;
					if (v == best_v) continue;
					u32 hv = sc->h[v];
					if (hu == SEARCH_INF_COST || hv == SEARCH_INF_COST) continue;

					u64 sum = (u64)edge_special_cost(edge_flags_or_zero(g, idx)) + (u64)hv;
					if (sum < (u64)hu) {
#if !defined(NDEBUG)
						assert(sum >= (u64)hu);
#endif
						continue;
					}
					u32 delta = (u32)(sum - (u64)hu);
					if (sc->sidetrack_nodes_len >= sc->sidetrack_nodes_cap &&
						!search_reserve_sidetrack_nodes(sc, sc->sidetrack_nodes_len + 1u)) {
						build_truncated = true;
						break;
					}
					u32            sn_idx = sc->sidetrack_nodes_len++;
					SidetrackNode* sn     = &sc->sidetrack_nodes[sn_idx];
					sn->from              = u;
					sn->to                = v;
					sn->delta             = delta;
					sn->left              = UINT32_MAX;
					sn->right             = UINT32_MAX;
					sn->npl               = 1;
					own_root              = sidetrack_heap_meld(sc, own_root, sn_idx, &meld_depth_fail);
					if (meld_depth_fail) {
						build_truncated = true;
						break;
					}
				}
			}
			if (build_truncated) break;

			u32 child_root         = (best_v == U24_NONE) ? UINT32_MAX : sc->sidetrack_roots[best_v];
			sc->sidetrack_roots[u] = sidetrack_heap_meld(sc, own_root, child_root, &meld_depth_fail);
			if (meld_depth_fail) {
				build_truncated = true;
				break;
			}
		}
		if (build_truncated) break;
	}

	if (!build_tree_path_from_best(sc, s, t, D, &out->paths[0])) return 0;
	u32 out_n = 1;
	if (K == 1 || build_truncated) return out_n;

	u32 states_len = 0;
	u32 heap_len   = 0;
	u32 root       = sc->sidetrack_roots[s];
	if (root != UINT32_MAX) {
		SidetrackState init;
		init.prev_idx  = UINT32_MAX;
		init.node_idx  = root;
		init.delta_sum = sc->sidetrack_nodes[root].delta;
		if (!sidetrack_push_state(sc, &states_len, &heap_len, init)) {
			if (out_states_used) *out_states_used = states_len;
			return out_n;
		}
	}

	while (heap_len > 0 && out_n < K) {
		u32 st_i = sidetrack_heap_pop(sc, &heap_len);
		if (build_sidetrack_path(sc, s, t, D, st_i, &out->paths[out_n])) {
			out_n++;
		}

		const SidetrackState st = sc->sidetrack_states[st_i];
		const SidetrackNode* sn = &sc->sidetrack_nodes[st.node_idx];

		if (sn->left != UINT32_MAX) {
			SidetrackState rep;
			rep.prev_idx  = st.prev_idx;
			rep.node_idx  = sn->left;
			rep.delta_sum = st.delta_sum - sn->delta + sc->sidetrack_nodes[sn->left].delta;
			if (!sidetrack_push_state(sc, &states_len, &heap_len, rep)) break;
		}
		if (sn->right != UINT32_MAX) {
			SidetrackState rep;
			rep.prev_idx  = st.prev_idx;
			rep.node_idx  = sn->right;
			rep.delta_sum = st.delta_sum - sn->delta + sc->sidetrack_nodes[sn->right].delta;
			if (!sidetrack_push_state(sc, &states_len, &heap_len, rep)) break;
		}

		u32 append_root = sc->sidetrack_roots[sn->to];
		if (append_root != UINT32_MAX) {
			SidetrackState app;
			app.prev_idx  = st_i;
			app.node_idx  = append_root;
			app.delta_sum = st.delta_sum + sc->sidetrack_nodes[append_root].delta;
			if (!sidetrack_push_state(sc, &states_len, &heap_len, app)) break;
		}
	}

	if (out_states_used) *out_states_used = states_len;
	if (out_nodes_used) *out_nodes_used = sc->sidetrack_nodes_len;
	return out_n;
}

STATIC u32 bikpaths_find_k(const Graph* g, u32 s, u32 t, u8 max_depth, u32 K, PathSet* out, SearchPerf* perf) {
	assert(g && g->validated);
	assert(g->N <= 0xFFFFFFu);
	assert(PATH_CAP <= 256);
	assert(max_depth < (PATH_CAP - 1));
	assert(K >= 1 && K <= SEARCH_MAX_K);

	SearchScratch* sc = &g_search_scratch;
	search_ensure_scratch(g);

	out->count = 0;
	if (s == t) {
		out->count                    = 1;
		out->paths[0].len             = 1;
		out->paths[0].ids[0]          = s;
		out->paths[0].start_redir_idx = UINT32_MAX;
		if (perf) {
			perf->shortest_dist  = 0;
			perf->paths_returned = 1;
			perf->path_len       = 1;
			perf->found          = true;
			perf->strategy       = 1;
		}
		return 1;
	}

	u64 phase_t0 = get_monotonic_time();
	u32 vis_sp   = 0;

	// Common case fast path (K==1): shortest-hop min-special-cost path during BFS.
	if (K == 1) {
		u8 D = sp_bfs_k1_min_cost(g, sc, s, t, max_depth, &vis_sp);
		if (perf) {
			perf->sp_bfs_ns += (get_monotonic_time() - phase_t0);
			perf->vis_sp                = vis_sp;
			perf->shortest_dist         = D;
			perf->dag_edges_used        = 0;
			perf->sidetrack_nodes_used  = 0;
			perf->sidetrack_states_used = 0;
		}
		u32 paths_found = 0;
		if (D != 0xFF) {
			phase_t0           = get_monotonic_time();
			PathIDs* p         = &out->paths[0];
			p->start_redir_idx = UINT32_MAX;
			p->len             = (u32)D + 1u;
			u32 cur            = t;
			for (i32 pos = (i32)D; pos >= 0; pos--) {
				p->ids[pos] = cur;
				if (pos == 0) break;
				cur = sc->parent[cur];
				if (cur == UINT32_MAX) {
					p->len = 0;
					break;
				}
			}
			if (p->len == (u32)D + 1u && p->ids[0] == s && p->ids[D] == t) {
				out->count  = 1;
				paths_found = 1;
			}
			if (perf) perf->path_build_ns += (get_monotonic_time() - phase_t0);
		}
		phase_t0 = get_monotonic_time();
		search_reset_dist(sc, vis_sp);
		if (perf) perf->sp_reset_ns += (get_monotonic_time() - phase_t0);
		if (perf) {
			perf->paths_returned = paths_found;
			perf->path_len       = paths_found ? out->paths[0].len : 0;
			perf->found          = (paths_found != 0);
			perf->strategy       = 1; // K==1 fast BFS path
		}
		return paths_found;
	}

	bool dag_overflow = false;
	u8   D            = sp_bfs_distance_record_dag(g, sc, s, t, max_depth, &vis_sp, &dag_overflow);
	if (perf) {
		perf->sp_bfs_ns += (get_monotonic_time() - phase_t0);
		perf->vis_sp                = vis_sp;
		perf->shortest_dist         = D;
		perf->dag_edges_used        = sc->dag_edges_len;
		perf->sidetrack_nodes_used  = 0;
		perf->sidetrack_states_used = 0;
	}
	if (D == 0xFF) {
		phase_t0 = get_monotonic_time();
		search_reset_dist(sc, vis_sp);
		if (perf) perf->sp_reset_ns += (get_monotonic_time() - phase_t0);
		return 0;
	}

	u32 layer_counts[PATH_CAP]  = {0};
	u32 layer_offsets[PATH_CAP] = {0};
	u32 layer_cursor[PATH_CAP]  = {0};

	phase_t0 = get_monotonic_time();
	search_clear_can_for_nodes(sc, sc->q, vis_sp);
	for (u32 i = 0; i < vis_sp; i++) {
		u32 v = sc->q[i];
		u8  d = sc->dist[v];
		if (d <= D) layer_counts[d]++;
	}
	for (u32 d = 1; d <= D; d++) layer_offsets[d] = layer_offsets[d - 1] + layer_counts[d - 1];
	for (u32 d = 0; d <= D; d++) layer_cursor[d] = layer_offsets[d];

	u32 layer_total = layer_offsets[D] + layer_counts[D];
	for (u32 i = 0; i < vis_sp; i++) {
		u32 v = sc->q[i];
		u8  d = sc->dist[v];
		if (d > D) continue;
		u32 pos              = layer_cursor[d]++;
		sc->layer_nodes[pos] = v;
		sc->h[v]             = SEARCH_INF_COST;
		best_child_set(sc, v, U24_NONE);
	}

	for (u32 i = 0; i < layer_counts[D]; i++) {
		u32 v = sc->layer_nodes[layer_offsets[D] + i];
		if (v == t) {
			bit_set(sc->can_bits, v);
			sc->h[v] = 0;
		}
	}

	for (i32 d = (i32)D - 1; d >= 0; d--) {
		u32 begin = layer_offsets[(u32)d];
		u32 n     = layer_counts[(u32)d];
		for (u32 i = 0; i < n; i++) {
			u32 u         = sc->layer_nodes[begin + i];
			u32 best      = SEARCH_INF_COST;
			u32 best_next = U24_NONE;

			if (!dag_overflow) {
				for (u32 ei = sc->dag_head[u]; ei != UINT32_MAX; ei = sc->dag_edges[ei].next) {
					u32 v = sc->dag_edges[ei].to;
					if (!bit_test(sc->can_bits, v)) continue;
					u32 hv = sc->h[v];
					if (hv == SEARCH_INF_COST) continue;
					u32 cand = hv + (u32)sc->dag_edges[ei].cost;
					if (cand < best || (cand == best && v < best_next)) {
						best      = cand;
						best_next = v;
					}
				}
			} else {
				u32       beg = g->out_offsets[u];
				u32       end = g->out_offsets[u + 1];
				const u8* p   = u24_cptr(g->out_edges24, beg);
				for (u32 idx = beg; idx < end; idx++, p += 3) {
					u32 v = u24_load(p);
					if (sc->dist[v] != (u8)(d + 1)) continue;
					if (!bit_test(sc->can_bits, v)) continue;
					u32 hv = sc->h[v];
					if (hv == SEARCH_INF_COST) continue;
					u32 cand = hv + edge_special_cost(edge_flags_or_zero(g, idx));
					if (cand < best || (cand == best && v < best_next)) {
						best      = cand;
						best_next = v;
					}
				}
			}

			if (best_next != U24_NONE) {
				bit_set(sc->can_bits, u);
				sc->h[u] = best;
				best_child_set(sc, u, best_next);
			}
		}
	}
	if (perf) {
		perf->dp_ns += (get_monotonic_time() - phase_t0);
		perf->vis_layers = layer_total;
	}

	u32 paths_found = 0;
	if (bit_test(sc->can_bits, s)) {
		phase_t0        = get_monotonic_time();
		u32  states_len = 0;
		u32  heap_len   = 0;
		bool overflow   = false;

		State root;
		root.node              = s;
		root.parent_idx        = UINT32_MAX;
		root.g                 = 0;
		root.depth             = 0;
		sc->states[states_len] = root;
		enum_heap_push(sc, &heap_len, states_len);
		states_len++;

		while (heap_len > 0 && paths_found < K) {
			u32   st_idx = enum_heap_pop(sc, &heap_len);
			State st     = sc->states[st_idx];

			if (st.node == t && st.depth == D) {
				u64 pb_t0 = get_monotonic_time();
				if (enum_path_reconstruct(sc, st_idx, &out->paths[paths_found])) {
					paths_found++;
				}
				if (perf) perf->path_build_ns += (get_monotonic_time() - pb_t0);
				continue;
			}
			if (st.depth >= D) continue;

			if (!dag_overflow) {
				for (u32 ei = sc->dag_head[st.node]; ei != UINT32_MAX; ei = sc->dag_edges[ei].next) {
					u32 v = sc->dag_edges[ei].to;
					if (!bit_test(sc->can_bits, v)) continue;
					u32 need  = states_len + 1u;
					u32 hneed = heap_len + 1u;
					if ((need > sc->states_cap || hneed > sc->states_cap) &&
						!search_reserve_enum(sc, need > hneed ? need : hneed)) {
						overflow = true;
						break;
					}
					State child;
					child.node             = v;
					child.parent_idx       = st_idx;
					child.g                = st.g + (u32)sc->dag_edges[ei].cost;
					child.depth            = (u8)(st.depth + 1);
					sc->states[states_len] = child;
					enum_heap_push(sc, &heap_len, states_len);
					states_len++;
				}
			} else {
				u32       beg = g->out_offsets[st.node];
				u32       end = g->out_offsets[st.node + 1];
				const u8* p   = u24_cptr(g->out_edges24, beg);
				for (u32 idx = beg; idx < end; idx++, p += 3) {
					u32 v = u24_load(p);
					if (sc->dist[v] != (u8)(st.depth + 1)) continue;
					if (!bit_test(sc->can_bits, v)) continue;

					u32 need  = states_len + 1u;
					u32 hneed = heap_len + 1u;
					if ((need > sc->states_cap || hneed > sc->states_cap) &&
						!search_reserve_enum(sc, need > hneed ? need : hneed)) {
						overflow = true;
						break;
					}
					State child;
					child.node             = v;
					child.parent_idx       = st_idx;
					child.g                = st.g + edge_special_cost(edge_flags_or_zero(g, idx));
					child.depth            = (u8)(st.depth + 1);
					sc->states[states_len] = child;
					enum_heap_push(sc, &heap_len, states_len);
					states_len++;
				}
			}
			if (overflow) break;
		}

		if (perf) {
			perf->enum_ns += (get_monotonic_time() - phase_t0);
			perf->enum_states_used = states_len;
		}

		if (overflow && paths_found < K) {
			if (perf) {
				perf->fallback_used = true;
				perf->strategy      = 2;
			}
			u32 sidetrack_states_used = 0;
			u32 sidetrack_nodes_used  = 0;
			phase_t0                  = get_monotonic_time();
			paths_found = sidetrack_exact_k_shortest(g, sc, s, t, D, K, sc->layer_nodes, layer_offsets, layer_counts,
													 dag_overflow, &sidetrack_states_used, &sidetrack_nodes_used, out);
			if (perf) perf->fallback_dp_ns += (get_monotonic_time() - phase_t0);
			if (perf) {
				perf->enum_states_used      = sidetrack_states_used;
				perf->sidetrack_states_used = sidetrack_states_used;
				perf->sidetrack_nodes_used  = sidetrack_nodes_used;
			}
		} else {
			if (perf) perf->strategy = 3; // K>1 enum path
		}
	}

	out->count = paths_found;

	phase_t0 = get_monotonic_time();
	search_reset_dist(sc, vis_sp);
	if (perf) perf->sp_reset_ns += (get_monotonic_time() - phase_t0);

	phase_t0 = get_monotonic_time();
	if (layer_total) search_clear_can_for_nodes(sc, sc->layer_nodes, layer_total);
	if (perf) {
		perf->cleanup_ns += (get_monotonic_time() - phase_t0);
		perf->paths_returned = paths_found;
		perf->path_len       = paths_found ? out->paths[0].len : 0;
		perf->found          = (paths_found != 0);
	}

	return paths_found;
}

#if VERIFY_RESULT_PATH
STATIC bool graph_find_edge_index(const Graph* g, u32 src, u32 dst, u32* out_edge_idx) {
	u32 beg = g->out_offsets[src];
	u32 end = g->out_offsets[src + 1];
	u32 l   = beg;
	u32 r   = end;
	while (l < r) {
		u32 m = l + (r - l) / 2;
		u32 v = u24_load(u24_cptr(g->out_edges24, m));
		if (v < dst) l = m + 1;
		else r = m;
	}
	if (l >= end) return false;
	if (u24_load(u24_cptr(g->out_edges24, l)) != dst) return false;
	if (out_edge_idx) *out_edge_idx = l;
	return true;
}

STATIC void verify_pathset_or_die(const Graph* g, const PathSet* set, u8 D) {
	if (!set || set->count == 0) return;
	u32 prev_cost = 0;
	for (u32 i = 0; i < set->count; i++) {
		const PathIDs* p = &set->paths[i];
		if (p->len != (u32)(D + 1u)) {
			fprintf(stderr, "error: path[%u] length %u != shortest-hop length %u\n", (unsigned)i, (unsigned)p->len,
					(unsigned)(D + 1u));
			exit(1);
		}
		u32 cost = 0;
		for (u32 j = 1; j < p->len; j++) {
			u32 a   = p->ids[j - 1];
			u32 b   = p->ids[j];
			u32 eix = 0;
			if (!graph_find_edge_index(g, a, b, &eix)) {
				fprintf(stderr, "error: returned path contains non-edge %u -> %u\n", a, b);
				exit(1);
			}
			cost += edge_special_cost(edge_flags_or_zero(g, eix));
		}
		if (i > 0 && cost < prev_cost) {
			fprintf(stderr, "error: returned path costs are not nondecreasing (%u then %u)\n", prev_cost, cost);
			exit(1);
		}
		prev_cost = cost;
	}
}
#endif

STATIC bool graph_find_path_titles_k(const Graph* g, string start, string target, u8 max_depth, u32 K, PathSet* out) {
	if (!g || !g->validated) {
		fprintf(stderr, "error: graph not loaded/validated\n");
		exit(1);
	}
	if (max_depth > 254) {
		fprintf(stderr, "error: max_depth must be <= 254\n");
		exit(2);
	}
	if (K == 0 || K > SEARCH_MAX_K) {
		fprintf(stderr, "error: K must be in 1..%u\n", (unsigned)SEARCH_MAX_K);
		exit(2);
	}

	SearchPerf* perf = &g_search_perf_last;
	memset(perf, 0, sizeof(*perf));
	perf->shortest_dist = 0xFF;
	u64 total_t0        = get_monotonic_time();

	out->count = 0;

	u32  start_redir_idx = UINT32_MAX;
	bool start_ambiguous = false;
	u64  lookup_t0       = get_monotonic_time();
	u32  s               = graph_find_id_fuzzy(g, start, &start_ambiguous, &start_redir_idx);
	perf->lookup_ns += (get_monotonic_time() - lookup_t0);
	if (s == UINT32_MAX) {
		if (start_ambiguous) {
			printf("start page `%.*s` is ambiguous; cannot disambiguate uniquely\n", STR_LEN(start), STR_PTR(start));
		} else {
			printf("start page `%.*s` not in the database\n", STR_LEN(start), STR_PTR(start));
		}
		perf->total_ns = (get_monotonic_time() - total_t0);
		return false;
	}

	bool target_ambiguous = false;
	lookup_t0             = get_monotonic_time();
	u32 t                 = graph_find_id_fuzzy(g, target, &target_ambiguous, NULL);
	perf->lookup_ns += (get_monotonic_time() - lookup_t0);
	if (t == UINT32_MAX) {
		if (target_ambiguous) {
			printf("target page `%.*s` is ambiguous; cannot disambiguate uniquely\n", STR_LEN(target), STR_PTR(target));
		} else {
			printf("target page `%.*s` not in the database\n", STR_LEN(target), STR_PTR(target));
		}
		perf->total_ns = (get_monotonic_time() - total_t0);
		return false;
	}

	u64 solver_t0 = get_monotonic_time();
	u32 npaths    = bikpaths_find_k(g, s, t, max_depth, K, out, perf);
	perf->solver_ns += (get_monotonic_time() - solver_t0);

	if (npaths) {
		for (u32 i = 0; i < npaths; i++) out->paths[i].start_redir_idx = start_redir_idx;
	}

#if VERIFY_RESULT_PATH
	if (npaths) {
		u64 verify_t0 = get_monotonic_time();
		verify_pathset_or_die(g, out, perf->shortest_dist);
		perf->verify_ns += (get_monotonic_time() - verify_t0);
	}
#endif

	perf->found          = (npaths != 0);
	perf->paths_returned = npaths;
	perf->path_len       = npaths ? out->paths[0].len : 0;
	perf->total_ns       = (get_monotonic_time() - total_t0);
	return npaths != 0;
}

STATIC bool graph_find_path_titles(const Graph* g, string start, string target, u8 max_depth, PathIDs* out) {
	PathSet set = {0};
	bool    ok  = graph_find_path_titles_k(g, start, target, max_depth, 1, &set);
	if (!ok || set.count == 0) {
		out->len             = 0;
		out->start_redir_idx = UINT32_MAX;
		return false;
	}
	*out = set.paths[0];
	return true;
}
