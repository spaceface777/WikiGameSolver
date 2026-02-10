#ifdef ENABLE_SERVER

typedef struct ThreadData {
	const Graph* g;
	string       start;
	string       target;
	u32          k_paths;
	int          connfd;

	bool    found;
	PathSet paths;
} ThreadData;

STATIC _Atomic int nr_jobs = 0;

STATIC void* worker_main(void* ptr) {
	ThreadData* d = (ThreadData*)ptr;
	d->found      = graph_find_path_titles_k(d->g, d->start, d->target, (u8)MAX_DEPTH, d->k_paths, &d->paths);
	return NULL;
}

STATIC void worker_send_and_free(void* ptr) {
	ThreadData* d = (ThreadData*)ptr;

	worker_main(ptr);

	printf("finished a job; %d remaining\n", --nr_jobs);

	// Always clean up, even on early exits.
	if (d->connfd != -1) {
		graph_write_pathset_fd(d->g, d->connfd, d->found ? &d->paths : NULL);
		close(d->connfd);
		d->connfd = -1;
	}

	// PROVEN LEAK FIX:
	// start/target were string_clone'd per request; previously never freed.
	string_free(&d->start);
	string_free(&d->target);
	free(d);
}

STATIC void server_listen(const Graph* g, int port) {
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		perror("socket");
		exit(1);
	}

	struct sockaddr_in servaddr = {0};
	servaddr.sin_family         = AF_INET;
	servaddr.sin_addr.s_addr    = htonl(INADDR_ANY);
	servaddr.sin_port           = htons((u16)port);

	if (bind(sockfd, (void*)&servaddr, sizeof(servaddr)) != 0) {
		perror("bind");
		exit(1);
	}
	if (listen(sockfd, 100) != 0) {
		perror("listen");
		exit(1);
	}
	printf("Listening on port %d...\n", port);

	threadpool pool = thpool_init(sysconf(_SC_NPROCESSORS_ONLN));
	char       buf_data[65536];

	while (1) {
		struct sockaddr_in cli;
		socklen_t          len = sizeof(cli);

		int connfd = accept(sockfd, (void*)&cli, &len);
		if (connfd < 0) {
			perror("accept");
			continue;
		}

		const int buf_size = (int)sizeof(buf_data) - 1;
		char*     buf      = buf_data;
		memset(buf, 0, (size_t)buf_size);

		int nread = (int)read(connfd, buf, (size_t)buf_size);
		if (nread < 1) {
			perror("read");
			close(connfd);
			continue;
		}

		// Parse with strict error handling; free any partially allocated strings.
		string start  = (string){0};
		string target = (string){0};

		// signature
		if (nread < (int)sizeof(key) || memcmp(buf, key, sizeof(key) - 1) != 0) goto err;

		int used = (int)(sizeof(key) - 1);
		buf += used;
		nread -= used;

		int slen = 0;
		int t    = 0;
		if (sscanf(buf, "%d%n", &slen, &t) != 1) goto err;
		if (slen < 0 || slen > (buf_size >> 1)) goto err;
		buf += t;
		nread -= t;

		if (nread <= 0 || *buf != ' ') goto err;
		buf++;
		nread--;

		if (nread < slen) goto err;
		start = string_clone(STR(buf, slen));
		buf += slen;
		nread -= slen;

		if (sscanf(buf, "%d%n", &slen, &t) != 1) goto err;
		if (slen < 0 || slen > (buf_size >> 1)) goto err;
		buf += t;
		nread -= t;

		if (nread <= 0 || *buf != ' ') goto err;
		buf++;
		nread--;

		if (nread < slen) goto err;
		target = string_clone(STR(buf, slen));
		buf += slen;
		nread -= slen;

		u32 req_k = 1;
		while (nread > 0 && (*buf == ' ' || *buf == '\n' || *buf == '\r' || *buf == '\t')) {
			buf++;
			nread--;
		}
		if (nread > 0) {
			int kval = 0;
			if (sscanf(buf, "%d%n", &kval, &t) != 1) goto err;
			if (kval < 1 || kval > (int)SEARCH_MAX_K) goto err;
			req_k = (u32)kval;
			buf += t;
			nread -= t;
			while (nread > 0 && (*buf == ' ' || *buf == '\n' || *buf == '\r' || *buf == '\t')) {
				buf++;
				nread--;
			}
			if (nread != 0) goto err;
		}

		ThreadData td = {
			.g       = g,
			.start   = start,
			.target  = target,
			.k_paths = req_k,
			.connfd  = connfd,
			.found   = false,
			.paths   = {0},
		};

		thpool_add_work(pool, (void*)worker_send_and_free, memdup(&td, sizeof(td)));
		printf("launched job #%d:\t%.*s -> %.*s (k=%u)\n", ++nr_jobs, STR_LEN(start), STR_PTR(start), STR_LEN(target),
			   STR_PTR(target), (unsigned)req_k);
		continue;

	err:
		if (!IS_NIL(start)) string_free(&start);
		if (!IS_NIL(target)) string_free(&target);
		write(connfd, "NO\n", 3);
		close(connfd);
	}
}

#else
STATIC void server_listen(const Graph* g, int port) {
	(void)g;
	(void)port;
}
#endif
