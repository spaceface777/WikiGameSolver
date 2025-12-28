STATIC int unredir_lookup(const Graph* g, u32 src, u32 dest) {
	if (!g->unredir || g->nr_unredir == 0) return -1;

	int l = 0;
	int r = (int)g->nr_unredir - 1;
	while (l <= r) {
		int			 m = (l + r) / 2;
		UnredirEdge* e = g->unredir + m;

		if (e->src < src) l = m + 1;
		else if (e->src > src) r = m - 1;
		else {
			if (e->dest < dest) l = m + 1;
			else if (e->dest > dest) r = m - 1;
			else return (int)e->redir_idx;
		}
	}
	return -1;
}

STATIC void graph_print_path(const Graph* g, const PathIDs* path) {
	if (!path || path->len == 0) {
		println(SLIT("\n\nNo path found."));
		return;
	}

	println(SLIT("\n\nShortest path:"));

	// First line shows the start title
	u32 start = path->ids[0];
	println(SLIT(" -> "), g->titles[start]);

	// Subsequent lines show what to click (dest title, or redirect title annotation)
	for (u32 i = 1; i < path->len; i++) {
		u32 a = path->ids[i - 1];
		u32 b = path->ids[i];

		int ridx = unredir_lookup(g, a, b);
		if (ridx >= 0 && (u32)ridx < g->nr_redir_titles) {
			println(SLIT(" -> "), g->redir_titles[ridx], SLIT(" (redirects to "), g->titles[b], SLIT(")"));
		} else {
			println(SLIT(" -> "), g->titles[b]);
		}
	}
}

STATIC void graph_write_path_fd(const Graph* g, int fd, const PathIDs* path) {
#ifndef _WIN32
	if (!path || path->len == 0) {
		write(fd, "No path found", (int)strlen("No path found"));
		write(fd, "\0", 1);
		return;
	}

	// First line: start title
	{
		string s = g->titles[path->ids[0]];
		write(fd, STR_PTR(s), STR_LEN(s));
		write(fd, "\n", 1);
	}

	// Subsequent lines: "what to click"
	for (u32 i = 1; i < path->len; i++) {
		u32 a = path->ids[i - 1];
		u32 b = path->ids[i];

		int ridx = unredir_lookup(g, a, b);
		if (ridx >= 0 && (u32)ridx < g->nr_redir_titles) {
			string rt = g->redir_titles[ridx];
			write(fd, STR_PTR(rt), STR_LEN(rt));
			write(fd, " (redirects to ", (int)sizeof(" (redirects to ") - 1);
			string bt = g->titles[b];
			write(fd, STR_PTR(bt), STR_LEN(bt));
			write(fd, ")\n", 2);
		} else {
			string bt = g->titles[b];
			write(fd, STR_PTR(bt), STR_LEN(bt));
			write(fd, "\n", 1);
		}
	}

	// signal end
	write(fd, "\0", 1);
#else
	(void)g;
	(void)fd;
	(void)path;
#endif
}
