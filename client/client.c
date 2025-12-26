#if !defined(_WIN32) && !defined(ENABLE_SERVER) && !defined(__EMSCRIPTEN__)
#define ENABLE_PRETTY_INPUT
#endif

// #ifndef __COSMOPOLITAN__
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif
// #endif

#include "util.h"

#include "array.h"
#include "string.h"

#include "input.h"
#include "time.h"

#ifndef NO_COMPRESSION
// #include "minlzma.h"
#include "lzma.h"
#endif

#ifdef ENABLE_SERVER
#include "thread_pool.h"

#if __has_include("keys.h")
#include "keys.h"
#else
#warning "No keys.h found, using default keys; this is insecure."
#include "keys_default.h"
#endif
#endif

#define MAX_DEPTH 20

#ifdef __EMSCRIPTEN__
#define STATIC
#else
#define STATIC static
#endif

typedef struct Path	 Path;
typedef struct Node	 Node;
typedef struct Link	 Link;
typedef struct Entry Entry;

STATIC void load_mem(const char* path);
STATIC void load_mem2(char* compressed_buf, long compressed_len);
STATIC void load_mem3(char* buf);

STATIC Entry* find_entry(string name);
STATIC Path	  find_path(string start, string target);
STATIC Path	  path_from_ids(const u32* ids, u32 len);
STATIC void	  build_reverse_csr(u32 N);
STATIC Path	  find_paths_bikpaths(string start, string target, u32 max_depth_u32, u32 max_paths);
STATIC void	  print_path(Path path);
STATIC void	  path_free(Path* head);

struct Path {
	Node* node;
};

struct Node {
	string data;
	Node*  next;
};

struct Entry {
	string title;
	array  links;
};

STATIC u32	  total_links = 0;
STATIC int	  nr_entries  = 0;
STATIC Entry* entries;

// --- Reverse CSR (incoming edges) -------------------------------------------
STATIC u32* in_offsets = NULL; // size N+1
STATIC u32* in_edges   = NULL; // size total_links
STATIC bool rev_inited = false;

#ifdef ENABLE_SERVER
#define MAYBE_THREAD_LOCAL _Thread_local
#else
#define MAYBE_THREAD_LOCAL
#endif

// --- Shortest-path primitives used by bikpaths ------------------------------
MAYBE_THREAD_LOCAL STATIC u8*  sp_ds = NULL;
MAYBE_THREAD_LOCAL STATIC u32* sp_qs = NULL;
MAYBE_THREAD_LOCAL STATIC u8*  mp_df = NULL;
MAYBE_THREAD_LOCAL STATIC u8*  mp_db = NULL;
MAYBE_THREAD_LOCAL STATIC u32* mp_qf = NULL;
MAYBE_THREAD_LOCAL STATIC u32* mp_qb = NULL;

#ifdef ENABLE_PRETTY_INPUT
typedef struct Range {
	int start, end;
} Range;

Range bsearch_ranged(string name) {
	const int	len = STR_LEN(name);
	const char* ptr = STR_PTR(name);

	Range ans = {-1, -1};

	int l = 0, m, r = nr_entries - 1;

	while (l < r) {
		m					  = (l + r) / 2;
		Entry*		e		  = entries + m;
		const int	entry_len = STR_LEN(e->title);
		const char* entry_ptr = STR_PTR(e->title);
		const int	cmp		  = strncmp(entry_ptr, ptr, MIN(entry_len, len));
		if (cmp < 0) l = m + 1;
		else r = m;
	}

	ans.start = l;
	r		  = nr_entries - 1;

	while (l < r) {
		m					  = (l + r) / 2 + 1;
		Entry*		e		  = entries + m;
		const int	entry_len = STR_LEN(e->title);
		const char* entry_ptr = STR_PTR(e->title);
		const int	cmp		  = strncmp(entry_ptr, ptr, MIN(entry_len, len));
		if (cmp > 0) r = m - 1;
		else l = m;
	}
	ans.end = r;

	if ((ans.end < ans.start) || (ans.end >= nr_entries) || (ans.start < 0) ||
		(ans.start == ans.end &&
		 strncmp(STR_PTR(entries[ans.start].title), ptr, MIN(STR_LEN(entries[ans.start].title), len)) != 0)) {
		ans.start = -1;
		ans.end	  = -1;
	}
	return ans;
}

void completion(const char* buf, linenoiseCompletions* lc) {
	if (buf == 0) return;

	int	  blen = strlen(buf);
	Range p	   = bsearch_ranged(STR((char*)buf, blen));

	if (p.start == -1) return;

	int count = p.end - p.start + 1;

	int	   i		   = 0;
	Entry* first_match = entries + p.start;
	if ((count != 1) && (STR_LEN(first_match->title) - blen) <= 1) i = 1;

	for (/* i */; i < MAX(count, 100); i++) {
		Entry* e = entries + (p.start + i);
		linenoiseAddCompletionN(lc, STR_PTR(e->title), STR_LEN(e->title));
	}
}

char* hints(const char* buf, int* color, int* bold) {
	if (buf == 0) return 0;

	int	  blen = strlen(buf);
	Range p	   = bsearch_ranged(STR((char*)buf, blen));

	int count = p.end - p.start + 1;
	if (count < 1 || p.start == -1) {
		// char tbuf[1024];
		// *color = 31;
		// snprintf(tbuf, sizeof(tbuf), "%*s (not found)", blen, buf);
		// return strdup(tbuf);
		return strdup("\x1b[31m (not found)\x1b[0m");
	}

	*color = 34;
	*bold  = 0;

	Entry* first_match = entries + p.start;
	if ((count == 1) || (STR_LEN(first_match->title) - blen) > 1) {
		const char* s		= STR_PTR(first_match->title) + strlen(buf);
		int			slen	= STR_LEN(first_match->title) - blen;
		char*		new_buf = malloc(slen + 1);
		memcpy((void*)new_buf, s, slen);
		new_buf[slen] = '\0';
		return new_buf;
	}

	const char* s		= STR_PTR(entries[p.start + 1].title) + strlen(buf);
	int			slen	= STR_LEN(entries[p.start + 1].title) - blen;
	char*		new_buf = malloc(slen + 1);
	memcpy((void*)new_buf, s, slen);
	new_buf[slen] = '\0';
	return new_buf;
}

#endif

void atexit_handler(void) {
	// array_free(entries[0].links);
	// string_free(entries[0].title);
	// free(entries);
}

#ifdef ENABLE_SERVER
typedef struct ThreadData {
	string start;
	string target;
	Path   path;
	int	   connfd;
} ThreadData;

_Atomic int nr_jobs = 0;

void* thread_main(void* ptr) {
	ThreadData* data = (ThreadData*)ptr;
	Path		path = find_path(data->start, data->target);
	data->path		 = path;

	return 0;
}

void threadpool_main(void* ptr) {
	ThreadData* data = (ThreadData*)ptr;

	thread_main(ptr);
	
	printf("finished a job; %d remaining\n", --nr_jobs);

	Path path = data->path;
	if (data->connfd != -1) {
		Node* node = path.node;
		if (!node) {
			write(data->connfd, "No path found", strlen("No path found"));
			write(data->connfd, "\0", 1);
			close(data->connfd);
			return;
		}

		while (node != null) {
			write(data->connfd, STR_PTR(node->data), STR_LEN(node->data));
			write(data->connfd, "\n", 1);
			node = node->next;
		}
		// send null byte to signal end of transmission
		write(data->connfd, "\0", 1);
		close(data->connfd);
	}

	path_free(&path);
	free(ptr);
}
#endif

#ifndef __EMSCRIPTEN__
int main(int argc, char** argv) {
#ifdef NO_COMPRESSION
	const char* path = "db.unc";
#else
	const char* path = "db.bin";
#endif

	TIME_INIT();
	load_mem(path);
	atexit(atexit_handler);
	// Build reverse CSR once on the main thread (avoids races in server mode).
	build_reverse_csr((u32)nr_entries);

	if (argc < 3) {
#ifdef ENABLE_PRETTY_INPUT
		linenoiseSetCompletionCallback(completion);
		linenoiseSetHintsCallback(hints);
		linenoiseSetFreeHintsCallback(free);
#endif
		while (1) {
			putchar('\n');
			putchar('\n');
			string start  = input(SLIT("enter a starting entry: "));
			string target = input(SLIT("enter a target entry: "));

			if (IS_NIL(start) || IS_NIL(target)) break;

			u64 start_time = get_monotonic_time();

			Path path = find_path(start, target);

			u64 end_time = get_monotonic_time();

			print_path(path);

			println(SLIT("\nSearch took"), format_time(end_time - start_time));

			path_free(&path);
			string_free(&start);
			string_free(&target);
		}
#ifdef ENABLE_SERVER
	} else if (argc == 3 && (strcmp(argv[1], "-l") == 0 || strcmp(argv[1], "--listen") == 0)) {
		int port = atoi(argv[2]);
		if (port < 1 || port > 65535) {
			puts("invalid port");
			return 1;
		}

		int sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd < 0) {
			puts("socket creation failed...");
			exit(1);
		}

		struct sockaddr_in servaddr = {0};
		servaddr.sin_family			= AF_INET;
		servaddr.sin_addr.s_addr	= htonl(INADDR_ANY);
		servaddr.sin_port			= htons(port);

		if ((bind(sockfd, (void*)&servaddr, sizeof(servaddr))) != 0) {
			perror("socket bind failed");
			exit(1);
		}

		if ((listen(sockfd, 100)) != 0) {
			perror("Listen failed");
			exit(1);
		}
		printf("Listening on port %d...\n", port);
		char buf_data[65536];

		threadpool pool = thpool_init(sysconf(_SC_NPROCESSORS_ONLN));

		while (1) {
			struct sockaddr_in cli;
			socklen_t		   len = sizeof(cli);

			int connfd = accept(sockfd, (void*)&cli, &len);
			if (connfd < 0) {
				perror("server accept failed");
				continue;
			}

			const int buf_size = sizeof(buf_data) - 1;
			char*	  buf	   = buf_data;
			memset(buf, 0, buf_size);

			int nread = read(connfd, buf, buf_size);
			if (nread < 1) {
				perror("read failed");
				close(connfd);
				continue;
			}

			if ((nread < (int)sizeof(key)) || memcmp(buf, key, sizeof(key) - 1) != 0) {
				puts("received invalid signature");
				goto err;
			}

			nread = sizeof(key) - 1;
			buf += sizeof(key) - 1;

			int slen;
			int t = 0;
			if (sscanf(buf, "%d%n", &slen, &t) < 0) goto err;
			if (slen < 0 || slen > (buf_size >> 1)) {
				fprintf(stderr, "got invalid len A\n");
				goto err;
			}
			nread += t;
			buf += t;

			if (*buf != ' ') {
				puts("received invalid message");
				goto err;
			}
			nread++;
			buf++;

			string start = string_clone(STR(buf, slen));
			nread += slen;
			buf += slen;

			if (sscanf(buf, "%d%n", &slen, &t) < 0) goto err;
			if (slen < 0 || slen + nread > (buf_size >> 1)) {
				fprintf(stderr, "got invalid len B\n");
				goto err;
			}

			nread += t;
			buf += t;

			if (*buf != ' ') {
				puts("received invalid message");
				goto err;
			}
			nread++;
			buf++;

			string target = string_clone(STR(buf, slen));
			nread += slen;
			buf += slen;

			ThreadData data = {.start = start, .target = target, .path = {0}, .connfd = connfd};
			thpool_add_work(pool, (void*)threadpool_main, memdup(&data, sizeof(data)));

			printf("launched job #%d:\t%.*s -> %.*s\n", ++nr_jobs, STR_LEN(start), STR_PTR(start), STR_LEN(target),
				   STR_PTR(target));

			continue;
		err:
			buf[0] = 'N';
			buf[1] = 'O';
			buf[2] = '\n';
			buf[3] = '\0';
			write(connfd, buf, 3);
			close(connfd);
			continue;
		}
#endif
	} else {
		string start  = string_clone(STR(argv[1], strlen(argv[1])));
		string target = string_clone(STR(argv[2], strlen(argv[2])));

		Path path = find_path(start, target);
		if (path.node) {
			print_path(path);
		} else {
			println(SLIT("No path found"));
		}
	}

	return 0;
}
#endif

#define DUMP_FORMAT_VERSION 1
STATIC void load_mem(const char* path) {
	puts("reading db file into memory...");

	FILE* compressed = fopen(path, "rb");
	if (compressed == NULL) {
		fprintf(stderr, "error: could not open db file: %s\n", strerror(errno));
		exit(1);
	}

	fseek(compressed, 0, SEEK_END);
	long compressed_len = ftell(compressed);
	fseek(compressed, 0, SEEK_SET);

	char* compressed_buf = malloc(compressed_len);
	if ((long)fread(compressed_buf, 1, compressed_len, compressed) != compressed_len) {
		fprintf(stderr, "error: could not read db file: %s\n", strerror(errno));
		exit(1);
	}
	fclose(compressed);

	load_mem2(compressed_buf, compressed_len);
}

STATIC void load_mem2(char* compressed_buf, long compressed_len) {
	char* buf = 0;
#ifndef NO_COMPRESSION
	{
		unsigned int magic = *(unsigned int*)compressed_buf;
		if (magic != *(unsigned int*)"WIKI") {
			puts("decompressing db file...");
			lzma_stream strm = LZMA_STREAM_INIT;
			lzma_ret	ret	 = lzma_stream_decoder(&strm, UINT64_MAX, 0);
			if (ret != LZMA_OK) {
				printf("Error: Cannot initialize decoder\n");
				exit(1);
			}

			char*  output_buffer = NULL;
			size_t output_size	 = 0;
			size_t input_pos	 = 0;

			const int LZMA_OUT_BUF_SIZE = 1 << 24;

			do {
				strm.next_in  = (uint8_t*)(compressed_buf + input_pos);
				strm.avail_in = compressed_len - input_pos;

				output_buffer  = (char*)realloc(output_buffer, output_size + LZMA_OUT_BUF_SIZE);
				strm.next_out  = (uint8_t*)(output_buffer + output_size);
				strm.avail_out = LZMA_OUT_BUF_SIZE;

				ret = lzma_code(&strm, LZMA_RUN);
				if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
					printf("Error: Decoding failed: %d\n", ret);
					exit(1);
				}

				output_size += LZMA_OUT_BUF_SIZE - strm.avail_out;
				input_pos += strm.next_in - (uint8_t*)(compressed_buf + input_pos);
			} while (ret != LZMA_STREAM_END);

			lzma_end(&strm);

			buf = output_buffer;
			free(compressed_buf);
		} else {
#endif
			buf = compressed_buf;
#ifndef NO_COMPRESSION
		}
	}
	load_mem3(buf);
#endif
}
STATIC void load_mem3(char* buf) {
	puts("Processing data...");

	char* p = buf;

	unsigned int magic = *(unsigned int*)p;
	p += sizeof(magic);
	if (magic != *(unsigned int*)"WIKI") {
		fputs("error: invalid magic\n", stderr);
		exit(1);
	}

	unsigned int version = *(unsigned int*)p;
	p += sizeof(version);
	u8 dump_format = version & 0xff;
	if (dump_format != DUMP_FORMAT_VERSION) {
		if (dump_format > DUMP_FORMAT_VERSION) {
			fputs("error: database file is newer than this program; update your client.\n", stderr);
		} else {
			fputs("error: database file is older than this program; update your database.\n", stderr);
		}
		exit(1);
	}
	i32 dump_date = version >> 8;
	printf("[info] database file date: 20%02d.%02d.%02d\n", dump_date / 10000, (dump_date / 100) % 100,
		   dump_date % 100);
	memcpy(&nr_entries, p, sizeof(i32));
	entries = malloc(sizeof(Entry) * nr_entries);
	p += sizeof(i32);

	memcpy(&total_links, p, sizeof(u32));
	p += sizeof(u32);
	// u32 total_title_bytes;
	p += sizeof(u32);

	for (int i = 0; i < nr_entries; i++) {
		Entry* e = &entries[i];

		u16 nr_links;
		memcpy(&nr_links, p, sizeof(u16));
		e->links = ARR(0, nr_links);
		p += sizeof(u16);
	}

	int padding_needed = nr_entries % 4;
	if (padding_needed) {
		p += sizeof(u16) * (4 - padding_needed);
	}

	for (int i = 0; i < nr_entries; i++) {
		Entry* e		= &entries[i];
		u16	   nr_links = ARR_LEN(e->links);
		e->links		= ARR(p, nr_links);
		p += nr_links * sizeof(u32);
	}
	for (int i = 0; i < nr_entries; i++) {
		Entry* e = &entries[i];

		u16 l;
		memcpy(&l, p, sizeof(u16));
		p += sizeof(u16);
		e->title = STR(0, l);
	}
	for (int i = 0; i < nr_entries; i++) {
		Entry* e = &entries[i];

		u16 l	 = STR_LEN(e->title);
		e->title = STR(p, l);
		p += l;
	}
}

STATIC Entry* find_entry(string name) {
	const int	len = STR_LEN(name);
	const char* ptr = STR_PTR(name);

	int l = 0, r = nr_entries - 1;
	while (l <= r) {
		int	   m = l + (r - l) / 2;
		Entry* e = entries + m;

		const int	entry_len = STR_LEN(e->title);
		const char* entry_ptr = STR_PTR(e->title);

		int cmp = memcmp(ptr, entry_ptr, MIN(len, entry_len));
		if (cmp == 0) cmp = (len < entry_len) ? -1 : (len > entry_len);
		if (cmp == 0) return e;
		else if (cmp > 0) l = m + 1;
		else if (cmp < 0) r = m - 1;
	}
	return null;
}

STATIC Path path_from_ids(const u32* ids, u32 len) {
	if (!ids || len == 0) return (Path){0};

	Node* head = NULL;
	Node* cur  = NULL;

	for (u32 i = 0; i < len; i++) {
		Node* n = (Node*)calloc(1, sizeof(Node));
		if (!n) {
			fprintf(stderr, "error: out of memory building path\n");
			exit(1);
		}
		if (ids[i] >= (u32)nr_entries) {
			fprintf(stderr, "error: invalid node id %u in path\n", ids[i]);
			exit(1);
		}
		n->data = string_clone(entries[ids[i]].title);

		if (!head) head = n;
		else cur->next = n;
		cur = n;
	}

	return (Path){.node = head};
}

STATIC void build_reverse_csr(u32 N) {
	if (rev_inited) return;
	if (total_links == 0) {
		fprintf(stderr, "error: total_links missing from db header\n");
		exit(1);
	}

	in_offsets = (u32*)calloc((size_t)N + 1u, sizeof(u32));
	in_edges   = (u32*)malloc((size_t)total_links * sizeof(u32));
	if (!in_offsets || !in_edges) {
		fprintf(stderr, "error: out of memory building reverse CSR\n");
		exit(1);
	}

	for (u32 src = 0; src < N; src++) {
		u16	 outdeg = ARR_LEN(entries[src].links);
		u32* L		= (u32*)ARR_PTR(entries[src].links);
		for (u16 j = 0; j < outdeg; j++) {
			u32 dst = L[j];
			if (dst < N) in_offsets[dst + 1]++;
		}
	}

	for (u32 i = 1; i <= N; i++) {
		in_offsets[i] += in_offsets[i - 1];
	}

	u32* cur = (u32*)malloc(((size_t)N + 1u) * sizeof(u32));
	if (!cur) {
		fprintf(stderr, "error: out of memory\n");
		exit(1);
	}
	memcpy(cur, in_offsets, ((size_t)N + 1u) * sizeof(u32));

	for (u32 src = 0; src < N; src++) {
		u16	 outdeg = ARR_LEN(entries[src].links);
		u32* L		= (u32*)ARR_PTR(entries[src].links);
		for (u16 j = 0; j < outdeg; j++) {
			u32 dst = L[j];
			if (dst >= N) continue;
			u32 pos		  = cur[dst]++;
			in_edges[pos] = src;
		}
	}

	free(cur);
	rev_inited = true;
}

STATIC void sp_init(u32 N) {
	if (!sp_ds) {
		sp_ds = (u8*)malloc((size_t)N * sizeof(u8));
		if (!sp_ds) {
			fprintf(stderr, "error: out of memory initializing sp_ds\n");
			exit(1);
		}
		memset(sp_ds, 0xFF, (size_t)N);
	}
	if (!sp_qs) {
		sp_qs = (u32*)malloc((size_t)N * sizeof(u32));
		if (!sp_qs) {
			fprintf(stderr, "error: out of memory initializing sp_qs\n");
			exit(1);
		}
	}
}

STATIC u8 sp_bfs_ds(u32 s, u32 t, u8 max_depth, u32* out_vis) {
	u32 head = 0, tail = 0;
	sp_qs[tail++] = s;
	sp_ds[s]	  = 0;

	while (head < tail) {
		u32 v  = sp_qs[head++];
		u8	dv = sp_ds[v];
		if (v == t) break;
		if (dv >= max_depth) continue;

		u16	 outdeg = ARR_LEN(entries[v].links);
		u32* L		= (u32*)ARR_PTR(entries[v].links);
		for (u16 j = 0; j < outdeg; j++) {
			u32 u = L[j];
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

STATIC void sp_reset_ds(u32 vis) {
	for (u32 i = 0; i < vis; i++) sp_ds[sp_qs[i]] = 0xFF;
}

STATIC void mp_init(u32 N) {
	if (!mp_df) {
		mp_df = (u8*)malloc((size_t)N * sizeof(u8));
		if (!mp_df) {
			fprintf(stderr, "error: out of memory initializing mp_df\n");
			exit(1);
		}
		memset(mp_df, 0xFF, (size_t)N);
	}
	if (!mp_db) {
		mp_db = (u8*)malloc((size_t)N * sizeof(u8));
		if (!mp_db) {
			fprintf(stderr, "error: out of memory initializing mp_db\n");
			exit(1);
		}
		memset(mp_db, 0xFF, (size_t)N);
	}
	if (!mp_qf) {
		mp_qf = (u32*)malloc((size_t)N * sizeof(u32));
		if (!mp_qf) {
			fprintf(stderr, "error: out of memory initializing mp_qf\n");
			exit(1);
		}
	}
	if (!mp_qb) {
		mp_qb = (u32*)malloc((size_t)N * sizeof(u32));
		if (!mp_qb) {
			fprintf(stderr, "error: out of memory initializing mp_qb\n");
			exit(1);
		}
	}
}

STATIC u32 mp_bfs_prefix(u32 s, u8 split) {
	u32 head = 0, tail = 0;
	mp_qf[tail++] = s;
	mp_df[s]	  = 0;

	while (head < tail) {
		u32 u  = mp_qf[head++];
		u8	du = mp_df[u];
		if (du >= split) continue;
		u16	 outdeg = ARR_LEN(entries[u].links);
		u32* L		= (u32*)ARR_PTR(entries[u].links);
		for (u16 j = 0; j < outdeg; j++) {
			u32 v = L[j];
			if (mp_df[v] != 0xFF) continue;
			mp_df[v]	  = (u8)(du + 1);
			mp_qf[tail++] = v;
		}
	}
	return tail;
}

STATIC u32 mp_rbfs_suffix(u32 t, u8 suffix) {
	u32 head = 0, tail = 0;
	mp_qb[tail++] = t;
	mp_db[t]	  = 0;

	while (head < tail) {
		u32 v  = mp_qb[head++];
		u8	dv = mp_db[v];
		if (dv >= suffix) continue;

		u32 beg = in_offsets[v];
		u32 end = in_offsets[v + 1];
		for (u32 pos = beg; pos < end; pos++) {
			u32 pred = in_edges[pos];
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
	u32	 s, t;
	u8	 D, split, suffix;
	u32	 max_paths;
	u32	 npaths;
	Path first;
	u32	 pre[256];
	u32	 suf[256];
} MPEnum;

STATIC void mp_suffix_dfs(MPEnum* E, u32 u, u8 rem, u8 idx) {
	if (E->npaths >= E->max_paths) return;
	if (rem == 0) {
		if (u != E->t) return;
		u32 ids[256];
		u32 len = 0;
		for (u32 i = 0; i <= (u32)E->split; i++) ids[len++] = E->pre[i];
		for (u32 i = 1; i <= (u32)E->suffix; i++) ids[len++] = E->suf[i];

		E->npaths++;
		if (!E->first.node) E->first = path_from_ids(ids, len);
		return;
	}

	u16	 outdeg = ARR_LEN(entries[u].links);
	u32* L		= (u32*)ARR_PTR(entries[u].links);
	for (u16 j = 0; j < outdeg; j++) {
		u32 v = L[j];
		if (mp_db[v] == (u8)(rem - 1)) {
			E->suf[idx + 1] = v;
			mp_suffix_dfs(E, v, (u8)(rem - 1), (u8)(idx + 1));
			if (E->npaths >= E->max_paths) return;
		}
	}
}

STATIC void mp_prefix_dfs(MPEnum* E, u32 u, u8 depth) {
	if (E->npaths >= E->max_paths) return;
	if (depth == E->split) {
		if (mp_db[u] == E->suffix) {
			E->suf[0] = u;
			mp_suffix_dfs(E, u, E->suffix, 0);
		}
		return;
	}
	u16	 outdeg = ARR_LEN(entries[u].links);
	u32* L		= (u32*)ARR_PTR(entries[u].links);
	for (u16 j = 0; j < outdeg; j++) {
		u32 v = L[j];
		if (mp_df[v] == (u8)(depth + 1)) {
			E->pre[depth + 1] = v;
			mp_prefix_dfs(E, v, (u8)(depth + 1));
			if (E->npaths >= E->max_paths) return;
		}
	}
}

STATIC Path find_paths_bikpaths(string start, string target, u32 max_depth_u32, u32 max_paths) {
	if (max_paths == 0) max_paths = 1;
	if (max_depth_u32 > 254) {
		fprintf(stderr, "error: maxdepth must be <= 254\n");
		exit(2);
	}
	u8 max_depth = (u8)max_depth_u32;

	Entry* se = find_entry(start);
	Entry* te = find_entry(target);
	if (!se || !te) return (Path){0};

	u32 s = (u32)(se - entries);
	u32 t = (u32)(te - entries);
	if (s == t) {
		u32 ids[1] = {s};
		return path_from_ids(ids, 1);
	}

	u32 N = (u32)nr_entries;
	sp_init(N);
	mp_init(N);
	build_reverse_csr(N);

	// 1) provable shortest distance D (via BFS distances)
	u32 vis_s = 0;
	u8	D	  = sp_bfs_ds(s, t, max_depth, &vis_s);
	sp_reset_ds(vis_s);
	if (D == 0xFF) return (Path){0};

	u8 split  = (u8)((D + 1) / 2);
	u8 suffix = (u8)(D - split);

	u32 vis_f = mp_bfs_prefix(s, split);
	u32 vis_b = mp_rbfs_suffix(t, suffix);

	MPEnum E	= {0};
	E.s			= s;
	E.t			= t;
	E.D			= D;
	E.split		= split;
	E.suffix	= suffix;
	E.max_paths = max_paths;
	E.npaths	= 0;
	E.first		= (Path){0};
	E.pre[0]	= s;

	mp_prefix_dfs(&E, s, 0);

	mp_reset_db(vis_b);
	mp_reset_df(vis_f);
	return E.first;
}

STATIC Path find_path(string start, string target) {
	Entry* start_entry	= find_entry(start);
	Entry* target_entry = find_entry(target);
	if (!start_entry) {
		printf("start page `%.*s` not in the database\n", STR_LEN(start), STR_PTR(start));
		return (Path){0};
	}
	if (!target_entry) {
		printf("target page `%.*s` not in the database\n", STR_LEN(target), STR_PTR(target));
		return (Path){0};
	}

	// Use bikpaths backend; keep max depth consistent with bench default.
	return find_paths_bikpaths(start, target, MAX_DEPTH, 1);
}

STATIC inline void print_path(Path path) {
	Node* node = path.node;
	if (!node) {
		println(SLIT("\n\nNo path found."));
		return;
	}

	println(SLIT("\n\nShortest path:"));

	while (node != null) {
		println(SLIT(" -> "), node->data);
		node = node->next;
	}
}

STATIC inline void path_free(Path* path) {
	Node* tmp;
	Node* node = path->node;
	while (node != null) {
		tmp	 = node;
		node = node->next;
		string_free(&tmp->data);
		free(tmp);
	}
	path->node = 0;
}

#if UINTPTR_MAX != 0xffffffffffffffff && !defined(__EMSCRIPTEN__)
#warning "This program is designed for 64-bit architectures."
#endif
