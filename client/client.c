#if !defined(_WIN32) && !defined(ENABLE_SERVER)
#define ENABLE_PRETTY_INPUT
#endif

#ifndef __COSMOPOLITAN__
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stddef.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <unistd.h>
#endif
#endif

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

typedef struct Path Path;
typedef struct Node Node;
typedef struct Link Link;
typedef struct Entry Entry;

static void load_mem(char* path);
static Entry* find_entry(string name);
static Path find_path(string start, string target);
static void print_path(Path path);
static void path_free(Path* head);

typedef struct DFSState {
	int idx;
	u8 depth;
	u8 limit;
} DFSState;
static bool dfs(Entry* entry, string target, DFSState state, Node* path);

struct Path {
	Node* node;
};

struct Node {
	string data;
	Node* next;
};

struct Entry {
	string title;
	array  links;
};

static int nr_entries = 0;
static Entry* entries;

#ifdef ENABLE_SERVER
_Thread_local
#endif
static u8* depths;

#ifdef DEBUG_CACHE
_Thread_local static int cache_hits = 0;
_Thread_local static int cache_misses = 0;
#endif

#ifdef ENABLE_PRETTY_INPUT
typedef struct Range {
	int start, end;
} Range;

Range bsearch_ranged(string name) {
	const int len = STR_LEN(name);
	const char* ptr = STR_PTR(name);

	Range ans = { -1, -1 };

	int l = 0, m, r = nr_entries - 1;

	while (l < r) {
		m = (l + r) / 2;
		Entry* e = entries + m;
		const int entry_len = STR_LEN(e->title);
		const char* entry_ptr = STR_PTR(e->title);
		const int cmp = strncmp(entry_ptr, ptr, MIN(entry_len, len));
		if (cmp < 0) l = m + 1;
		else r = m;
	}

	ans.start = l;
	r = nr_entries - 1;

	while (l < r) {
		m = (l + r) / 2 + 1;
		Entry* e = entries + m;
		const int entry_len = STR_LEN(e->title);
		const char* entry_ptr = STR_PTR(e->title);
		const int cmp = strncmp(entry_ptr, ptr, MIN(entry_len, len));
		if (cmp > 0) r = m - 1;
		else l = m;
	}
	ans.end = r;

	if ((ans.end < ans.start) || (ans.end >= nr_entries) || (ans.start < 0) || (ans.start == ans.end && strncmp(STR_PTR(entries[ans.start].title), ptr, MIN(STR_LEN(entries[ans.start].title), len)) != 0)) {
		ans.start = -1;
		ans.end = -1;
	}
	return ans;
}

void completion(const char *buf, linenoiseCompletions *lc) {
	if (buf == 0) return;

	int blen = strlen(buf);
	Range p = bsearch_ranged(STR((char*)buf, blen));

	if (p.start == -1) return;

	int count = p.end - p.start + 1;

	int i = 0;
	Entry* first_match = entries + p.start;
	if ((count != 1) && (STR_LEN(first_match->title) - blen) <= 1) i = 1;

	for (/* i */; i < MAX(count, 100); i++) {
		Entry* e = entries + (p.start + i);
		linenoiseAddCompletionN(lc, STR_PTR(e->title), STR_LEN(e->title));
	}
}

char* hints(const char* buf, int* color, int* bold) {
	if (buf == 0) return 0;

	int blen = strlen(buf);
	Range p = bsearch_ranged(STR((char*)buf, blen));

	int count = p.end - p.start + 1;
	if (count < 1 || p.start == -1) {
		// char tbuf[1024];
		// *color = 31;
		// snprintf(tbuf, sizeof(tbuf), "%*s (not found)", blen, buf);
		// return strdup(tbuf);
		return strdup("\x1b[31m (not found)\x1b[0m");
	}

	*color = 34;
	*bold = 0;

	Entry* first_match = entries + p.start;
	if ((count == 1) || (STR_LEN(first_match->title) - blen) > 1) {
		return STR_PTR(first_match->title) + strlen(buf);
	}

	return STR_PTR(entries[p.start+1].title) + strlen(buf);
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
	int    connfd;
} ThreadData;

_Atomic int nr_jobs = 0;

void* thread_main(void* ptr) {
	ThreadData* data = (ThreadData*)ptr;
	depths = calloc(nr_entries, sizeof(u8));

	Path path = find_path(data->start, data->target);
	data->path = path;

	free(depths);

	return 0;
}

void threadpool_main(void* ptr) {
	ThreadData* data = (ThreadData*)ptr;

	thread_main(ptr);

	Path path = data->path;

	if (data->connfd != -1) {
		Node* node = path.node;
		if (!node) {
			write(data->connfd, "No path found", sizeof("No path found")-1);
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

	printf("finished a job; %d remaining\n", --nr_jobs);
}
#endif

int main(int argc, char** argv) {
	TIME_INIT();
	#ifdef NO_COMPRESSION
	load_mem("db.unc");
	#else
	load_mem("db.bin");
	#endif
	atexit(atexit_handler);

	if (argc < 3) {
#ifdef ENABLE_PRETTY_INPUT
		linenoiseSetCompletionCallback(completion);
		linenoiseSetHintsCallback(hints);
#endif
		depths = calloc(nr_entries, sizeof(u8));

		while(1) {
			#ifdef DEBUG_CACHE
			cache_hits = cache_misses = 0;
			#endif
			putchar('\n');
			putchar('\n');
			string start = input(SLIT("enter a starting entry: "));
			string target = input(SLIT("enter a target entry: "));

			if (start==0 || target==0) break;
			
			u64 start_time = get_monotonic_time();

			Path path = find_path(start, target);

			u64 end_time = get_monotonic_time();

			print_path(path);

			println(SLIT("\nSearch took"), format_time(end_time - start_time));

			path_free(&path);
			string_free(&start);
			string_free(&target);

			#ifdef DEBUG_CACHE
			printf("%dh | %dm = %.1f%% \n\n", cache_hits, cache_misses, (double)cache_hits/(cache_hits+cache_misses)*100);
			#endif

			memset(depths, 0, nr_entries);
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
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
		servaddr.sin_port = htons(port);
	
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

		while(1) {
			struct sockaddr_in cli;
			socklen_t len = sizeof(cli);
		
			int connfd = accept(sockfd, (void*)&cli, &len);
			if (connfd < 0) {
				perror("server accept failed");
				continue;
			}

			const int buf_size = sizeof(buf_data)-1;
			char* buf = buf_data;
			memset(buf, 0, buf_size);
	
			int nread = read(connfd, buf, buf_size);
			if (nread < 1) {
				perror("read failed");
				close(connfd);
				continue;
			}

			if ((nread < (int)sizeof(key)) || memcmp(buf, key, sizeof(key)-1) != 0) {
				puts("received invalid signature");
				goto err;
			}
			nread = sizeof(key)-1;
			buf += sizeof(key)-1;

			int slen;
			int t = 0;
			if (sscanf(buf, "%d%n", &slen, &t) < 0) goto err;
			if (slen < 0 || slen > (buf_size>>1)) {
				fprintf(stderr, "got invalid len\n");
				goto err;
			}
			nread += t;
			buf += t;
			string start = string_clone(STR(buf, slen));
			nread += slen;
			buf += slen;

			if (sscanf(buf, "%d%n", &slen, &t) < 0) goto err;
			if (slen < 0 || slen+nread > (buf_size>>1)) {
				fprintf(stderr, "got invalid len\n");
				goto err;
			}

			nread += t;
			buf += t;
			string target = string_clone(STR(buf, slen));
			nread += slen;
			buf += slen;

			ThreadData data = { .start=start, .target=target, .path={0}, .connfd=connfd };			
			thpool_add_work(pool, (void*)threadpool_main, memdup(&data, sizeof(data)));

			printf("launched job #%d:\t%.*s -> %.*s\n", ++nr_jobs, STR_LEN(start), STR_PTR(start), STR_LEN(target), STR_PTR(target));

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
		depths = calloc(nr_entries, sizeof(u8));

		string start = string_clone(STR(argv[1], strlen(argv[1])));
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

#define DUMP_FORMAT_VERSION 1
static void load_mem(char* path) {
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

	char* buf = 0;
#ifndef NO_COMPRESSION
	{
		unsigned int magic = *(unsigned int*)compressed_buf;
		if (magic != *(unsigned int*)"WIKI") {
			puts("decompressing db file...");
			lzma_stream strm = LZMA_STREAM_INIT;
			lzma_ret ret = lzma_stream_decoder(&strm, UINT64_MAX, 0);
			if (ret != LZMA_OK) {
				printf("Error: Cannot initialize decoder\n");
				exit(1);
			}

			char* output_buffer = NULL;
			size_t output_size = 0;
			size_t input_pos = 0;

			const int LZMA_OUT_BUF_SIZE = 1 << 24;

			do {
				strm.next_in = (uint8_t*)(compressed_buf + input_pos);
				strm.avail_in = compressed_len - input_pos;

				output_buffer = (char*)realloc(output_buffer, output_size + LZMA_OUT_BUF_SIZE);
				strm.next_out = (uint8_t*)(output_buffer + output_size);
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
#endif
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
	int dump_date = version >> 8;
	printf("[info] database file date: 20%02d.%02d.%02d\n", dump_date/10000, (dump_date/100)%100, dump_date%100);

	memcpy(&nr_entries, p, sizeof(int));
	entries = malloc(sizeof(Entry) * nr_entries);
	p += sizeof(int);

	uint32_t total_links;
	memcpy(&total_links, p, sizeof(uint32_t));
	p += sizeof(uint32_t);
	u32* link_buf = malloc(sizeof(u32) * total_links);

	uint32_t total_title_bytes;
	memcpy(&total_title_bytes, p, sizeof(uint32_t));
	p += sizeof(uint32_t);
	total_title_bytes += nr_entries; // for null terminators
	char* title_buf = malloc(total_title_bytes);

	for (int i = 0; i < nr_entries; i++) {
		Entry* e = &entries[i];

		u16 nr_links;
		memcpy(&nr_links, p, sizeof(u16));
		e->links = ARR(link_buf, nr_links);
		link_buf += nr_links;
		p += sizeof(u16);
	}
	for (int i = 0; i < nr_entries; i++) {
		Entry* e = &entries[i];
		if (e->links == 0) continue;
		u16 nr_links = ARR_LEN(e->links);
		memcpy(ARR_PTR(e->links), p, nr_links*sizeof(u32));
		p += nr_links*sizeof(u32);
	}
	for (int i = 0; i < nr_entries; i++) {
		Entry* e = &entries[i];

		u16 l;
		memcpy(&l, p, sizeof(u16));
		p += sizeof(u16);
		e->title = (void*)(ptrdiff_t)l;
	}
	for (int i = 0; i < nr_entries; i++) {
		Entry* e = &entries[i];

		u16 l = (u16)(ptrdiff_t)e->title;

		char* buf = title_buf;
		memcpy(buf, p, l);
		buf[l] = '\0';
		p += l;
		e->title = ARR(buf, l);
		title_buf += l + 1;
	}

	free(buf);
}

Entry* find_entry(string name) {
	const int len = STR_LEN(name);
	const char* ptr = STR_PTR(name);

	int l = 0, r = nr_entries - 1;
	while (l <= r) {
        int m = l + (r - l) / 2;
		Entry* e = entries + m;

		const int entry_len = STR_LEN(e->title);
		const char* entry_ptr = STR_PTR(e->title);

		const int cmp = strncmp(ptr, entry_ptr, MAX(len, entry_len));
        if (cmp == 0) return e;
        else if (cmp > 0) l = m + 1;
        else if (cmp < 0) r = m - 1;
    }
	return null;
}

static Path find_path(string start, string target) {
	Entry* start_entry = find_entry(start);
	Entry* target_entry = find_entry(target);
	if (!start_entry) {
		printf("start page `%.*s` not in the database\n", STR_LEN(start), STR_PTR(start));
		return (Path){0};
	}
	if (!target_entry) {
		printf("target page `%.*s` not in the database\n", STR_LEN(target), STR_PTR(target));
		return (Path){0};
	}

	Path path = (Path){ HEAP((Node){ .data = string_clone(start) }) };
	for (int depth = 0; depth < 12; depth++) {
		DFSState state = (DFSState){ .depth = 0, .limit = depth, .idx = (start_entry - entries) };
		if (dfs(start_entry, target, state, path.node))
			return path;
	}
	path_free(&path);
	return path;
}

static inline void print_path(Path path) {
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

static inline void path_free(Path* path) {
	Node* tmp;
	Node* node = path->node;
	while (node != null) {
		tmp = node;
		node = node->next;
		string_free(&tmp->data);
		free(tmp);
	}
	path->node = 0;
}

static bool dfs(Entry* entry, string target, DFSState state, Node* path) {
	string node = entry->title;
	if (string_eq(node, target)) {
		path->data = node;
		return true;
	}

	if (state.limit > state.depth+1) {
		int d = state.limit - state.depth;
		u8* checked_depth = depths+state.idx;
		if (*checked_depth >= d) {
			#ifdef DEBUG_CACHE
			++cache_hits;
			#endif
			return false;
		}
		#ifdef DEBUG_CACHE
		++cache_misses;
		#endif
		*checked_depth = d;

		if (!path->next) path->next = HEAP((Node){});

		u16 nr_links = ARR_LEN(entry->links);
		int* links = ARR_PTR(entry->links);
		for (int i = 0; i < nr_links; i++) {
			int newi = links[i];
			Entry* child = entries + newi;
			DFSState new_state = (DFSState){ .depth = state.depth + 1, .limit = state.limit, .idx = newi };
			if (dfs(child, target, new_state, path->next)) {
				string str = string_clone(child->title);
				path->next->data = str;
				return true;
			}
		}
	}
	return false;
}

#if UINTPTR_MAX != 0xffffffffffffffff
#error "This program only supports 64-bit architectures."
#endif
