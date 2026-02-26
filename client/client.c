#if !defined(_WIN32) && !defined(ENABLE_SERVER) && !defined(__EMSCRIPTEN__)
#define ENABLE_PRETTY_INPUT
#endif

#include <assert.h>
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

#include "util.h"

#include "array.h"
#include "string.h"
#include "time.h"

// ----------------------------------------------------------------------------
// Configuration
// ----------------------------------------------------------------------------
#define DUMP_FORMAT_VERSION 2

#define MAX_DEPTH    200
#define PATH_CAP     256 // hard cap for internal arrays; must be > max_depth and <= 255+1
#define SEARCH_MAX_K 64
// Dynamic search buffers start small and grow by 1.5x as needed.
#define ENUM_STATE_INIT_CAP      1000u     // bench p90(enum_states_used)=183
#define SIDETRACK_STATE_INIT_CAP 1000u     // fallback-only; grow x1.5 on demand
#define DAG_EDGE_INIT_CAP        10000000u // bench p90(dag_edges_used)=5,002,769
#define SIDETRACK_NODE_INIT_CAP  10000u    // fallback-only; keep small at startup
#define BENCH_K32_VALUE          32u

// Toggle expensive validation of unredir edges (binary search in adjacency).
// Kept ON by default per your "validate absolutely everything" requirement.
#ifndef VALIDATE_UNREDIR_EDGES
#define VALIDATE_UNREDIR_EDGES 1
#endif

// Verify the returned path is a valid walk in the graph (binary search per hop).
// This is outside hot loops and very cheap for MAX_DEPTH<=100.
#ifndef VERIFY_RESULT_PATH
#define VERIFY_RESULT_PATH 1
#endif

#ifdef __EMSCRIPTEN__
#define STATIC
#else
#define STATIC static
#endif

// ----------------------------------------------------------------------------
// Types
// ----------------------------------------------------------------------------
typedef struct UnredirEdge {
	u32 src;
	u32 dest;
	u32 redir_idx;
} UnredirEdge;

typedef struct Graph {
	u32 N; // nodes
	u32 L; // edges

	// Titles are sorted lexicographically (required for binary search and pretty input).
	string* titles;
	char*   titles_arena;
	u32     titles_arena_bytes;

	// v2 redirect helpers
	u32          nr_unredir;
	UnredirEdge* unredir;

	// Outgoing CSR
	u32* out_offsets; // N+1
	u8*  out_edges24; // 3*L + 4 padding

	u32 max_out_degree;

	string* redir_titles;
	u32     nr_redir_titles;
	u32     redir_arena_bytes;
	char*   redir_arena;

	// Optional trailing section in newer v2 dumps: one u8 flag byte per edge.
	u8* edge_flags; // length L when present, else NULL

	double* pagerank; // length N, NULL if not computed

	bool validated;
} Graph;

typedef struct PathIDs {
	u32 len;             // number of nodes in path
	u32 ids[PATH_CAP];   // node IDs
	u32 start_redir_idx; // UINT32_MAX when start was resolved as canonical title
} PathIDs;

typedef struct PathSet {
	u32     count; // number of returned paths
	PathIDs paths[SEARCH_MAX_K];
} PathSet;

typedef size_t (*DbStreamFillFn)(void* ctx, u8* dst, size_t cap, bool* out_eof);

// ----------------------------------------------------------------------------
// Shared helpers (declared here, defined in included .c files)
// ----------------------------------------------------------------------------
STATIC void graph_load_from_mem(Graph* g, char* raw, long raw_len);
STATIC void graph_load_from_file(Graph* g, const char* path);
STATIC void graph_load_from_stdin(Graph* g);
STATIC void graph_load_from_stream(Graph* g, DbStreamFillFn fill, void* ctx, bool is_compressed);
STATIC u32  graph_find_id(const Graph* g, string title); // returns UINT32_MAX if not found
STATIC void graph_print_path(const Graph* g, const PathIDs* path);
STATIC void graph_write_pathset_fd(const Graph* g, int fd, const PathSet* set);
STATIC bool graph_find_path_titles(const Graph* g, string start, string target, u8 max_depth, PathIDs* out);
STATIC bool graph_find_path_titles_k(const Graph* g, string start, string target, u8 max_depth, u32 K, PathSet* out);
STATIC int  unredir_lookup(const Graph* g, u32 src, u32 dest);
STATIC void pagerank_build(Graph* g, int iters, double damp, double eps);
STATIC void bench_run(const Graph* g, u32 iters, u8 max_depth, u32 k_paths);
STATIC void diff_run(const char* old_path, const char* new_path, int topk);
STATIC void search_prepare_graph(const Graph* g);

#if !defined(CLIENT_HEADER_ONLY)

// Global immutable graph after load.
STATIC Graph G = {0};

#ifndef NO_COMPRESSION
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

#include "graph.c"
#include "load.c"
#include "output.c"
#include "pagerank.c"
#include "search.c"
#include "server.c"

#include "bench_mode.c"
#include "diff_mode.c"
#include "pagerank_dump.c"
#include "input.c"

STATIC void atexit_handler(void) {
	// Intentionally empty. The process exits and OS reclaims memory.
}

#ifndef __EMSCRIPTEN__

STATIC void usage(const char* prog) {
	fprintf(stderr,
			"Usage:\n"
			"  %s [options]                  Interactive mode\n"
			"  %s [options] START TARGET     Single query\n"
			"  %s [options] --bench N       Benchmark mode\n"
			"  %s [options] --bench-k32 --bench N  Benchmark with K=32 shortest-hop paths\n"
			"  %s --diff OLD_DB NEW_DB      Snapshot diff mode\n"
			"  %s --dump-pagerank OUT       Dump pagerank alias table for mmap sampling\n"
#ifdef ENABLE_SERVER
			"  %s [options] --listen PORT    Server mode\n"
#endif
			"\n"
			"Options:\n"
			"  -d, --db PATH           Database file to load (default: db.bin or db.unc)\n"
			"  -m, --max-depth N       Max search depth (1..254). Default: %d\n"
			"  -k, --k-paths N         Return up to N shortest-hop paths (1..%d). Default: 1\n"
			"      --bench-k N         Bench only: request up to N paths (1..%d). Default: 1\n"
			"      --bench-k32         Bench only: shorthand for --bench-k %u\n"
#ifdef ENABLE_SERVER
			"  -l, --listen PORT        Listen on PORT (1..65535)\n"
#endif
#ifdef ENABLE_PRETTY_INPUT
			"      --no-pretty          Disable interactive completion/hints\n"
#endif
			"  -h, --help              Show this help\n"
			"\n"
			"Notes:\n"
			"  - Options may be given as --opt=value or --opt value.\n",
			prog, prog, prog, prog, prog, prog,
#ifdef ENABLE_SERVER
			prog,
#endif
			(int)MAX_DEPTH, (int)SEARCH_MAX_K, (int)SEARCH_MAX_K, (unsigned)BENCH_K32_VALUE);
}

STATIC bool parse_u32(const char* s, u32* out) {
	if (!s || !*s) return false;
	char* end       = NULL;
	errno           = 0;
	unsigned long v = strtoul(s, &end, 10);
	if (errno != 0 || end == s || *end != '\0') return false;
	if (v > 0xFFFFFFFFul) return false;
	*out = (u32)v;
	return true;
}

STATIC const char* take_opt_value(int* i, int argc, char** argv, const char* opt, const char* eq) {
	if (eq && eq[0] == '=') {
		// --opt=value form
		return eq + 1;
	}
	// --opt value form
	if (*i + 1 >= argc) {
		fprintf(stderr, "error: missing value for %s\n", opt);
		exit(2);
	}
	(*i)++;
	return argv[*i];
}

int main(int argc, char** argv) {
#ifdef NO_COMPRESSION
	const char* default_db = "db.unc";
#else
	const char* default_db = "db.bin";
#endif

	const char* db_path       = default_db;
	u32         max_depth_u32 = (u32)MAX_DEPTH;
	u32         k_paths       = 1;
	bool        bench_mode    = false;
	u32         bench_k_paths = 1;
	u32         bench_iters   = 0;
	bool        diff_mode     = false;
	const char* diff_old_path = NULL;
	const char* diff_new_path = NULL;
	bool        dump_pr_mode  = false;
	const char* dump_pr_path  = NULL;

#ifdef ENABLE_SERVER
	bool server_mode = false;
	u32  listen_port = 0;
#endif

#ifdef ENABLE_PRETTY_INPUT
	bool enable_pretty = true;
#endif

	log_ts("starting wiki game solver");

	// Collect positional args after options
	const char* pos[2] = {0, 0};
	int         pos_n  = 0;

	// Parse argv
	for (int i = 1; i < argc; i++) {
		const char* a = argv[i];

		if (!a || !*a) continue;

		// Stop parsing options after "--"
		if (strcmp(a, "--") == 0) {
			for (i = i + 1; i < argc; i++) {
				if (pos_n < 2) pos[pos_n++] = argv[i];
				else {
					fprintf(stderr, "error: too many positional arguments\n");
					usage(argv[0]);
					return 2;
				}
			}
			break;
		}

		if (a[0] == '-') {
			// Options
			if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
				usage(argv[0]);
				return 0;
			}

			if (strcmp(a, "--bench-k32") == 0) {
				if (BENCH_K32_VALUE > SEARCH_MAX_K) {
					fprintf(stderr, "error: --bench-k32 requires SEARCH_MAX_K >= %u\n", (unsigned)BENCH_K32_VALUE);
					return 2;
				}
				bench_k_paths = BENCH_K32_VALUE;
				continue;
			}

			if (strncmp(a, "--bench-k", 9) == 0) {
				const char* eq  = a + 9;
				const char* v   = take_opt_value(&i, argc, argv, "--bench-k", eq);
				u32         tmp = 0;
				if (!parse_u32(v, &tmp) || tmp < 1 || tmp > SEARCH_MAX_K) {
					fprintf(stderr, "error: invalid --bench-k '%s' (must be 1..%u)\n", v, (unsigned)SEARCH_MAX_K);
					return 2;
				}
				bench_k_paths = tmp;
				continue;
			}

			if (strcmp(a, "-b") == 0 || strcmp(a, "--bench") == 0 || strncmp(a, "--bench=", 8) == 0) {
				const char* eq = NULL;
				if (strncmp(a, "--bench=", 8) == 0) eq = a + 7;
				const char* v   = take_opt_value(&i, argc, argv, "--bench", eq);
				u32         tmp = 0;
				if (!parse_u32(v, &tmp) || tmp == 0) {
					fprintf(stderr, "error: invalid --bench '%s' (must be >=1)\n", v);
					return 2;
				}
				bench_mode  = true;
				bench_iters = tmp;
				continue;
			}

			if (strcmp(a, "--diff") == 0) {
				if (diff_mode) {
					fprintf(stderr, "error: --diff already specified\n");
					return 2;
				}
				if (i + 2 >= argc) {
					fprintf(stderr, "error: --diff requires OLD_DB and NEW_DB paths\n");
					return 2;
				}
				diff_mode     = true;
				diff_old_path = argv[++i];
				diff_new_path = argv[++i];
				continue;
			}

			if (strcmp(a, "--dump-pagerank") == 0 || strncmp(a, "--dump-pagerank=", 16) == 0) {
				const char* eq = NULL;
				if (strncmp(a, "--dump-pagerank=", 16) == 0) eq = a + 15;
				const char* v = take_opt_value(&i, argc, argv, "--dump-pagerank", eq);
				dump_pr_mode = true;
				dump_pr_path = v;
				continue;
			}

			// --db or --db=PATH
			if (strcmp(a, "-d") == 0 || strncmp(a, "--db", 4) == 0) {
				const char* eq = NULL;
				if (strncmp(a, "--db", 4) == 0) eq = a + 4; // may be "" or "=..."
				const char* v = take_opt_value(&i, argc, argv, "--db", eq);
				db_path       = v;
				continue;
			}

			// --max-depth or --max-depth=N
			if (strcmp(a, "-m") == 0 || strncmp(a, "--max-depth", 11) == 0) {
				const char* eq = NULL;
				if (strncmp(a, "--max-depth", 11) == 0) eq = a + 11;
				const char* v   = take_opt_value(&i, argc, argv, "--max-depth", eq);
				u32         tmp = 0;
				if (!parse_u32(v, &tmp) || tmp < 1 || tmp > 254) {
					fprintf(stderr, "error: invalid --max-depth '%s' (must be 1..254)\n", v);
					return 2;
				}
				max_depth_u32 = tmp;
				continue;
			}

			// --k-paths or --k-paths=N
			if (strcmp(a, "-k") == 0 || strncmp(a, "--k-paths", 9) == 0) {
				const char* eq = NULL;
				if (strncmp(a, "--k-paths", 9) == 0) eq = a + 9;
				const char* v   = take_opt_value(&i, argc, argv, "--k-paths", eq);
				u32         tmp = 0;
				if (!parse_u32(v, &tmp) || tmp < 1 || tmp > SEARCH_MAX_K) {
					fprintf(stderr, "error: invalid --k-paths '%s' (must be 1..%u)\n", v, (unsigned)SEARCH_MAX_K);
					return 2;
				}
				k_paths = tmp;
				continue;
			}

#ifdef ENABLE_SERVER
			// --listen or --listen=PORT
			if (strcmp(a, "-l") == 0 || strncmp(a, "--listen", 8) == 0) {
				const char* eq = NULL;
				if (strncmp(a, "--listen", 8) == 0) eq = a + 8;
				const char* v   = take_opt_value(&i, argc, argv, "--listen", eq);
				u32         tmp = 0;
				if (!parse_u32(v, &tmp) || tmp < 1 || tmp > 65535) {
					fprintf(stderr, "error: invalid port '%s' (must be 1..65535)\n", v);
					return 2;
				}
				server_mode = true;
				listen_port = tmp;
				continue;
			}
#endif

#ifdef ENABLE_PRETTY_INPUT
			if (strcmp(a, "--no-pretty") == 0) {
				enable_pretty = false;
				continue;
			}
#endif

			fprintf(stderr, "error: unknown option '%s'\n", a);
			usage(argv[0]);
			return 2;
		}

		// Positional argument
		if (pos_n < 2) pos[pos_n++] = a;
		else {
			fprintf(stderr, "error: too many positional arguments\n");
			usage(argv[0]);
			return 2;
		}
	}

	if (diff_mode && bench_mode) {
		fprintf(stderr, "error: --diff cannot be combined with --bench\n");
		return 2;
	}
	if (dump_pr_mode && (bench_mode || diff_mode)) {
		fprintf(stderr, "error: --dump-pagerank cannot be combined with --bench or --diff\n");
		return 2;
	}
	if (!bench_mode && bench_k_paths != 1) {
		fprintf(stderr, "error: --bench-k/--bench-k32 requires --bench\n");
		return 2;
	}

	if (diff_mode) {
		if (pos_n != 0) {
			fprintf(stderr, "error: START/TARGET not allowed in diff mode\n");
			usage(argv[0]);
			return 2;
		}
		diff_run(diff_old_path, diff_new_path, 10);
		return 0;
	}

	// Load DB (always exactly once)
	TIME_INIT();
	if (strcmp(db_path, "-") == 0)
		graph_load_from_stdin(&G);
	else
		graph_load_from_file(&G, db_path);
	atexit(atexit_handler);

	if (dump_pr_mode) {
		if (pos_n != 0) {
			fprintf(stderr, "error: START/TARGET not allowed with --dump-pagerank\n");
			usage(argv[0]);
			return 2;
		}
		pagerank_dump(&G, dump_pr_path);
		return 0;
	}

#ifdef ENABLE_SERVER
	if (server_mode) {
		if (pos_n != 0) {
			fprintf(stderr, "error: START/TARGET not allowed with --listen\n");
			usage(argv[0]);
			return 2;
		}
		// Server mode uses max_depth_u32 as well.
		server_listen(&G, (int)listen_port);
		return 0;
	}
#endif

	if (bench_mode) {
		if (pos_n != 0) {
			fprintf(stderr, "error: no START/TARGET allowed in bench mode\n");
			usage(argv[0]);
			return 2;
		}
		bench_run(&G, bench_iters, (u8)max_depth_u32, bench_k_paths);
		return 0;
	}

	// Single query mode
	if (pos_n == 2) {
		string start  = string_clone(STR((char*)pos[0], (int)strlen(pos[0])));
		string target = string_clone(STR((char*)pos[1], (int)strlen(pos[1])));

		bool ok = false;
		if (k_paths == 1) {
			PathIDs path_ids = {0};
			ok               = graph_find_path_titles(&G, start, target, (u8)max_depth_u32, &path_ids);
			if (ok) graph_print_path(&G, &path_ids);
		} else {
			PathSet set = {0};
			ok          = graph_find_path_titles_k(&G, start, target, (u8)max_depth_u32, k_paths, &set);
			if (ok) {
				printf("\n\nReturned %u path(s):\n", (unsigned)set.count);
				for (u32 i = 0; i < set.count; i++) {
					printf("\nPath #%u:\n", (unsigned)(i + 1));
					graph_print_path(&G, &set.paths[i]);
				}
			}
		}
		if (!ok) println(SLIT("No path found"));

		string_free(&start);
		string_free(&target);
		return ok ? 0 : 1;
	}

	if (pos_n != 0) {
		fprintf(stderr, "error: expected either 0 or 2 positional args (START TARGET)\n");
		usage(argv[0]);
		return 2;
	}

	// Interactive mode
#ifdef ENABLE_PRETTY_INPUT
	if (enable_pretty) pretty_init(&G);
	log_ts("pretty input initialized");
#endif

	while (1) {
		putchar('\n');
		putchar('\n');

		string start  = input(SLIT("enter a starting entry: "));
		string target = input(SLIT("enter a target entry: "));

		if (IS_NIL(start) || IS_NIL(target)) break;

		Timer t = timer_begin("search");

		bool ok = false;
		if (k_paths == 1) {
			PathIDs path_ids = {0};
			ok               = graph_find_path_titles(&G, start, target, (u8)max_depth_u32, &path_ids);
			if (ok) graph_print_path(&G, &path_ids);
			else println(SLIT("\n\nNo path found."));
		} else {
			PathSet set = {0};
			ok          = graph_find_path_titles_k(&G, start, target, (u8)max_depth_u32, k_paths, &set);
			if (ok) {
				printf("\n\nReturned %u path(s):\n", (unsigned)set.count);
				for (u32 i = 0; i < set.count; i++) {
					printf("\nPath #%u:\n", (unsigned)(i + 1));
					graph_print_path(&G, &set.paths[i]);
				}
			} else {
				println(SLIT("\n\nNo path found."));
			}
		}

		println("");
		timer_end(t);

		string_free(&start);
		string_free(&target);
	}

	return 0;
}
#endif // !defined(__EMSCRIPTEN__)

#endif // !defined(CLIENT_HEADER_ONLY)

#if UINTPTR_MAX != 0xffffffffffffffff && !defined(__EMSCRIPTEN__)
#warning "This program is designed for 64-bit architectures."
#endif
