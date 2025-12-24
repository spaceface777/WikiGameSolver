/************ Directed longest-shortest-path heuristic (snapshot B) ************/

typedef struct {
	uint32_t far;
	uint32_t dist;
	uint32_t visited;
} BFSOut;

static BFSOut bfs_farthest_B(const WikiDB* B, const CombinedMap* cm, const uint8_t* active, uint32_t start,
							 uint32_t* queue,  // size cm->n
							 uint32_t* parent, // size cm->n
							 int32_t*  dist,   // size cm->n
							 uint32_t* seen,   // size cm->n
							 uint32_t  seen_id) {
	BFSOut out;
	out.far		= start;
	out.dist	= 0;
	out.visited = 0;

	if (start >= cm->n || !active[start]) return out;

	uint32_t head = 0, tail = 0;
	queue[tail++] = start;
	seen[start]	  = seen_id;
	dist[start]	  = 0;
	parent[start] = start;
	out.visited	  = 1;

	while (head < tail) {
		uint32_t u	= queue[head++];
		int32_t	 du = dist[u];
		if ((uint32_t)du > out.dist) {
			out.dist = (uint32_t)du;
			out.far	 = u;
		}

		int32_t lu = cm->locB_of_g[u];
		if (lu < 0) continue;
		const Entry*	e  = &B->entries[lu];
		const uint32_t* L  = e->links;
		uint16_t		nl = e->nr_links;

		for (uint16_t t = 0; t < nl; t++) {
			uint32_t v = L[t];
			if (v >= cm->n || !active[v]) continue;
			if (seen[v] == seen_id) continue;
			seen[v]		  = seen_id;
			dist[v]		  = du + 1;
			parent[v]	  = u;
			queue[tail++] = v;
			out.visited++;
		}
	}

	return out;
}

static uint32_t pick_random_active_node_B(const WikiDB* B, const CombinedMap* cm, const uint8_t* active,
										  uint64_t* rng_state, uint32_t min_outdeg) {
	// Try random picks; fall back to first active.
	for (int tries = 0; tries < 200000; tries++) {
		uint32_t g = (uint32_t)(rng64(rng_state) % (uint64_t)cm->n);
		if (!active[g]) continue;
		int32_t lg = cm->locB_of_g[g];
		if (lg < 0) continue;
		if ((uint32_t)B->entries[lg].nr_links < min_outdeg) continue;
		return g;
	}
	for (uint32_t g = 0; g < cm->n; g++) {
		if (!active[g]) continue;
		int32_t lg = cm->locB_of_g[g];
		if (lg < 0) continue;
		if ((uint32_t)B->entries[lg].nr_links < min_outdeg) continue;
		return g;
	}
	return 0;
}

static void print_path_B(const CombinedMap* cm, const uint32_t* path, uint32_t len) {
	for (uint32_t i = 0; i < len; i++) {
		printf("  %3u) ", i);
		fprint_title(stdout, cm->titles[path[i]]);
		printf("\n");
	}
}

static void analyze_directed_longest_shortest_path_B(const WikiDB* B, const CombinedMap* cm, const uint8_t* active,
													 int	  sweeps,	   // number of "double sweeps"
													 uint32_t min_visited, // ignore tiny reachable regions
													 uint32_t seed_min_outdeg) {
	if (sweeps < 1) sweeps = 1;

	printf("\n[diameter] Directed longest-shortest-path heuristic (snapshot B)\n");
	printf("  sweeps=%d  min_visited=%u  seed_min_outdeg=%u\n", sweeps, min_visited, seed_min_outdeg);

	// BFS work buffers.
	uint32_t* queue	 = (uint32_t*)xmalloc((size_t)cm->n * sizeof(uint32_t));
	uint32_t* parent = (uint32_t*)xmalloc((size_t)cm->n * sizeof(uint32_t));
	int32_t*  dist	 = (int32_t*)xmalloc((size_t)cm->n * sizeof(int32_t));
	uint32_t* seen	 = (uint32_t*)xmalloc((size_t)cm->n * sizeof(uint32_t));
	memset(seen, 0, (size_t)cm->n * sizeof(uint32_t));
	uint32_t seen_id = 1;

	uint64_t rng_state = 0x9e3779b97f4a7c15ULL ^ (uint64_t)time(NULL);

	uint32_t  best_a = 0, best_b = 0;
	uint32_t  best_dist		= 0;
	uint32_t* best_path		= NULL;
	uint32_t  best_path_len = 0;
	uint32_t  best_vis		= 0;

	uint32_t cur = pick_random_active_node_B(B, cm, active, &rng_state, seed_min_outdeg);

	for (int s = 0; s < sweeps; s++) {
		// Prevent seen_id wrap.
		if (seen_id == 0) {
			memset(seen, 0, (size_t)cm->n * sizeof(uint32_t));
			seen_id = 1;
		}

		BFSOut	 r1 = bfs_farthest_B(B, cm, active, cur, queue, parent, dist, seen, seen_id++);
		uint32_t a	= r1.far;

		if (seen_id == 0) {
			memset(seen, 0, (size_t)cm->n * sizeof(uint32_t));
			seen_id = 1;
		}

		BFSOut	 r2 = bfs_farthest_B(B, cm, active, a, queue, parent, dist, seen, seen_id++);
		uint32_t b	= r2.far;

		// Only consider reasonably large reachable regions.
		if (r2.visited >= min_visited && r2.dist >= best_dist) {
			if (r2.dist > best_dist) {
				// Reconstruct path a -> b using parent pointers from the BFS rooted at a.
				uint32_t  len  = r2.dist + 1;
				uint32_t* path = (uint32_t*)xmalloc((size_t)len * sizeof(uint32_t));
				uint32_t  v	   = b;
				for (uint32_t i = 0; i < len; i++) {
					path[len - 1 - i] = v;
					if (v == a) break;
					uint32_t pv = parent[v];
					if (pv == v) break; // safety
					v = pv;
				}

				if (best_path) free(best_path);
				best_path	  = path;
				best_path_len = len;
				best_a		  = a;
				best_b		  = b;
				best_dist	  = r2.dist;
				best_vis	  = r2.visited;
			}
		}

		// Mix exploration/exploitation: alternate between continuing from b and a fresh random seed.
		if ((s & 1) == 0) cur = b;
		else cur = pick_random_active_node_B(B, cm, active, &rng_state, seed_min_outdeg);
	}

	if (best_path) {
		printf("  best_dist=%u  visited=%u\n", best_dist, best_vis);
		printf("  endpoint A: ");
		fprint_title(stdout, cm->titles[best_a]);
		printf("\n");
		printf("  endpoint B: ");
		fprint_title(stdout, cm->titles[best_b]);
		printf("\n");
		printf("  path (len=%u):\n", best_path_len);
		print_path_B(cm, best_path, best_path_len);
		free(best_path);
	} else {
		printf("  no candidate path found (try lowering min_visited or increasing sweeps)\n");
	}

	free(queue);
	free(parent);
	free(dist);
	free(seen);
}
