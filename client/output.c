STATIC int unredir_lookup(const Graph* g, u32 src, u32 dest) {
	if (!g->nr_unredir || src >= g->N) return -1;
	u32 edge = graph_edge_index(g, src, dest);
	return edge == UINT32_MAX ? -1 : graph_edge_redirect(g, edge);
}

STATIC void graph_print_path(const Graph* g, const PathIDs* path) {
	if (!path || path->len == 0) {
		println(SLIT("\n\nNo path found."));
		return;
	}

	println(SLIT("\n\nShortest path:"));

	// First line shows the start title
	u32 start = path->ids[0];
	if (path->start_redir_idx < g->nr_redir_titles) {
		println(SLIT(" -> "), graph_redir_title(g, path->start_redir_idx), SLIT(" (redirects to "),
				graph_title(g, start), SLIT(")"));
	} else {
		println(SLIT(" -> "), graph_title(g, start));
	}

	// Subsequent lines show what to click (dest title, or redirect title annotation)
	for (u32 i = 1; i < path->len; i++) {
		u32 a = path->ids[i - 1];
		u32 b = path->ids[i];

		int ridx = unredir_lookup(g, a, b);
		if (ridx >= 0 && (u32)ridx < g->nr_redir_titles) {
			println(SLIT(" -> "), graph_redir_title(g, ridx), SLIT(" (redirects to "), graph_title(g, b), SLIT(")"));
		} else {
			println(SLIT(" -> "), graph_title(g, b));
		}
	}
}

STATIC void graph_write_pathset_fd(const Graph* g, int fd, const PathSet* set) {
#ifndef _WIN32
	if (!set || set->count == 0) {
		write(fd, "No path found", (int)strlen("No path found"));
		write(fd, "\0", 1);
		return;
	}

	for (u32 pi = 0; pi < set->count; pi++) {
		const PathIDs* path = &set->paths[pi];
		if (set->count > 1) {
			char hdr[64];
			int  n = snprintf(hdr, sizeof(hdr), "Path #%u\n", (unsigned)(pi + 1));
			if (n > 0) write(fd, hdr, (size_t)n);
		}

		// First line: start title
		{
			u32 start = path->ids[0];
			if (path->start_redir_idx < g->nr_redir_titles) {
				string rt = graph_redir_title(g, path->start_redir_idx);
				write(fd, STR_PTR(rt), STR_LEN(rt));
				write(fd, " (redirects to ", (int)sizeof(" (redirects to ") - 1);
				string bt = graph_title(g, start);
				write(fd, STR_PTR(bt), STR_LEN(bt));
				write(fd, ")", 1);
			} else {
				string s = graph_title(g, start);
				write(fd, STR_PTR(s), STR_LEN(s));
			}
			write(fd, "\n", 1);
		}

		for (u32 i = 1; i < path->len; i++) {
			u32 a = path->ids[i - 1];
			u32 b = path->ids[i];

			int ridx = unredir_lookup(g, a, b);
			if (ridx >= 0 && (u32)ridx < g->nr_redir_titles) {
				string rt = graph_redir_title(g, ridx);
				write(fd, STR_PTR(rt), STR_LEN(rt));
				write(fd, " (redirects to ", (int)sizeof(" (redirects to ") - 1);
				string bt = graph_title(g, b);
				write(fd, STR_PTR(bt), STR_LEN(bt));
				write(fd, ")\n", 2);
			} else {
				string bt = graph_title(g, b);
				write(fd, STR_PTR(bt), STR_LEN(bt));
				write(fd, "\n", 1);
			}
		}

		if (pi + 1 < set->count) write(fd, "\n", 1);
	}

	write(fd, "\0", 1);
#else
	(void)g;
	(void)fd;
	(void)set;
#endif
}
