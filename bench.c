#include <errno.h>
#include <float.h>
#include <inttypes.h>
#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if !defined(_WIN32)
#include <unistd.h>
#endif

#if !defined(_WIN32)
#include <sys/resource.h>
#endif

#include "client/util.h"

#include "client/array.h"
#include "client/string.h"
#include "client/time.h"

#ifndef NO_COMPRESSION
#include "client/lzma.h"
#endif

#ifndef STATIC
#define STATIC static
#endif

typedef struct Path	 Path;
typedef struct Node	 Node;
typedef struct Entry Entry;

typedef struct DFSState {
	int idx;
	u8	depth;
	u8	limit;
} DFSState;

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

STATIC void load_mem(char* path);
STATIC void load_mem2(char* compressed_buf, long compressed_len);
STATIC void load_mem3(char* buf);

STATIC Entry* find_entry(string name);
STATIC Path	  find_path(string start, string target);
STATIC void	  path_free(Path* head);
STATIC bool	  dfs(Entry* entry, string target, DFSState state, Node* path);

STATIC int	  nr_entries = 0;
STATIC Entry* entries;
STATIC u8*	  depths;

#define DUMP_FORMAT_VERSION 1
STATIC void load_mem(char* path) {
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
				strm.avail_in = (size_t)compressed_len - input_pos;

				output_buffer  = (char*)realloc(output_buffer, output_size + (size_t)LZMA_OUT_BUF_SIZE);
				strm.next_out  = (uint8_t*)(output_buffer + output_size);
				strm.avail_out = (size_t)LZMA_OUT_BUF_SIZE;

				ret = lzma_code(&strm, LZMA_RUN);
				if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
					printf("Error: Decoding failed: %d\n", ret);
					exit(1);
				}

				output_size += (size_t)LZMA_OUT_BUF_SIZE - strm.avail_out;
				input_pos += (size_t)(strm.next_in - (uint8_t*)(compressed_buf + input_pos));
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
	int32_t dump_date = (int32_t)(version >> 8);
	printf("[info] database file date: 20%02d.%02d.%02d\n", dump_date / 10000, (dump_date / 100) % 100,
		   dump_date % 100);
	memcpy(&nr_entries, p, sizeof(int32_t));
	entries = malloc(sizeof(Entry) * (size_t)nr_entries);
	p += sizeof(int32_t);

	// uint32_t total_links;
	p += sizeof(uint32_t);
	// uint32_t total_title_bytes;
	p += sizeof(uint32_t);

	for (int i = 0; i < nr_entries; i++) {
		Entry* e = &entries[i];

		u16 nr_links;
		memcpy(&nr_links, p, sizeof(u16));
		e->links = ARR(0, nr_links);
		p += sizeof(u16);
	}

	int padding_needed = nr_entries % 4;
	if (padding_needed) {
		p += sizeof(u16) * (size_t)(4 - padding_needed);
	}

	for (int i = 0; i < nr_entries; i++) {
		Entry* e		= &entries[i];
		u16	   nr_links = ARR_LEN(e->links);
		e->links		= ARR(p, nr_links);
		p += (size_t)nr_links * sizeof(u32);
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
		p += (size_t)l;
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

	Path path = (Path){HEAP((Node){.data = string_clone(start)})};

	for (int depth = 0; depth < 12; depth++) {
		DFSState state = (DFSState){.depth = 0, .limit = (u8)depth, .idx = (int)(start_entry - entries)};
		if (dfs(start_entry, target, state, path.node)) return path;
	}
	path_free(&path);
	return path;
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

STATIC bool dfs(Entry* entry, string target, DFSState state, Node* path) {
	string node = entry->title;
	if (string_eq(node, target)) {
		path->data = node;
		return true;
	}

	if (state.limit > state.depth + 1) {
		int d			  = state.limit - state.depth;
		u8* checked_depth = depths + state.idx;
		if (*checked_depth >= d) {
			return false;
		}
		*checked_depth = (u8)d;

		if (!path->next) path->next = HEAP((Node){});

		u16	 nr_links = ARR_LEN(entry->links);
		int* links	  = ARR_PTR(entry->links);
		for (int i = 0; i < nr_links; i++) {
			int		 newi	   = links[i];
			Entry*	 child	   = entries + newi;
			DFSState new_state = (DFSState){.depth = (u8)(state.depth + 1), .limit = state.limit, .idx = newi};
			if (dfs(child, target, new_state, path->next)) {
				string str		 = string_clone(child->title);
				path->next->data = str;
				return true;
			}
		}
	}
	return false;
}

static uint64_t rng64(uint64_t* s) {
	uint64_t x = *s;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	*s = x;
	return x * 2685821657736338717ULL;
}

typedef struct {
	uint32_t  n;
	uint32_t* gid;
	uint32_t* alias;
	float*	  prob;
	uint64_t  rng;
} PRSampler;

static double rng_double01(uint64_t* s) {
	uint64_t r = rng64(s);
	return (double)((r >> 11) & ((1ULL << 53) - 1)) * (1.0 / 9007199254740992.0);
}

static void prsampler_free(PRSampler* S) {
	if (!S) return;
	free(S->gid);
	free(S->alias);
	free(S->prob);
	memset(S, 0, sizeof(*S));
}

static int prsampler_build(PRSampler* S, const double* pr, const uint8_t* active, uint32_t N, double alpha,
						   uint64_t seed) {
	if (!S || !pr || !active) return 0;
	if (alpha <= 0.0) alpha = 1.0;

	memset(S, 0, sizeof(*S));
	S->rng = seed ? seed : 0x9e3779b97f4a7c15ULL;

	uint32_t n = 0;
	for (uint32_t g = 0; g < N; g++)
		if (active[g]) n++;
	if (n == 0) return 0;

	S->n	 = n;
	S->gid	 = (uint32_t*)malloc((size_t)n * sizeof(uint32_t));
	S->alias = (uint32_t*)malloc((size_t)n * sizeof(uint32_t));
	S->prob	 = (float*)malloc((size_t)n * sizeof(float));
	if (!S->gid || !S->alias || !S->prob) {
		prsampler_free(S);
		return 0;
	}

	double*	  q		= (double*)malloc((size_t)n * sizeof(double));
	uint32_t* small = (uint32_t*)malloc((size_t)n * sizeof(uint32_t));
	uint32_t* large = (uint32_t*)malloc((size_t)n * sizeof(uint32_t));
	if (!q || !small || !large) {
		free(q);
		free(small);
		free(large);
		prsampler_free(S);
		return 0;
	}

	double	 sumw = 0.0;
	uint32_t idx  = 0;
	for (uint32_t g = 0; g < N; g++) {
		if (!active[g]) continue;
		S->gid[idx++] = g;

		double p = pr[g];
		if (p <= 0.0) p = DBL_MIN;
		double w = pow(p, alpha);
		if (w == 0.0) w = DBL_MIN;
		q[idx - 1] = w;
		sumw += w;
	}

	if (!(sumw > 0.0)) {
		free(q);
		free(small);
		free(large);
		prsampler_free(S);
		return 0;
	}

	double	 scale = (double)n / sumw;
	uint32_t ns = 0, nl = 0;
	for (uint32_t i = 0; i < n; i++) {
		q[i] *= scale;
		if (q[i] < 1.0) small[ns++] = i;
		else large[nl++] = i;
	}

	while (ns && nl) {
		uint32_t s = small[--ns];
		uint32_t l = large[--nl];

		double ps = q[s];
		if (ps < 0.0) ps = 0.0;
		if (ps > 1.0) ps = 1.0;
		S->prob[s]	= (float)ps;
		S->alias[s] = l;

		q[l] = (q[l] + q[s]) - 1.0;
		if (q[l] < 1.0) small[ns++] = l;
		else large[nl++] = l;
	}

	while (nl) {
		uint32_t i	= large[--nl];
		S->prob[i]	= 1.0f;
		S->alias[i] = i;
	}
	while (ns) {
		uint32_t i	= small[--ns];
		S->prob[i]	= 1.0f;
		S->alias[i] = i;
	}

	free(q);
	free(small);
	free(large);
	return 1;
}

static uint32_t random_biased(PRSampler* S) {
	uint32_t n = S->n;
	uint32_t i = (uint32_t)(rng64(&S->rng) % (uint64_t)n);
	double	 u = rng_double01(&S->rng);
	uint32_t j = (u < (double)S->prob[i]) ? i : S->alias[i];
	return S->gid[j];
}

static void pagerank_compute(const Entry* E, uint32_t N, int iters, double damp, double eps, double** out_rank) {
	if (damp <= 0.0 || damp >= 1.0) damp = 0.85;
	if (iters < 1) iters = 1;

	double* r	= (double*)malloc((size_t)N * sizeof(double));
	double* nxt = (double*)malloc((size_t)N * sizeof(double));
	if (!r || !nxt) {
		fprintf(stderr, "error: out of memory\n");
		exit(1);
	}

	double init = 1.0 / (double)N;
	for (uint32_t i = 0; i < N; i++) r[i] = init;

	for (int it = 0; it < iters; it++) {
		memset(nxt, 0, (size_t)N * sizeof(double));
		double dangling = 0.0;

		for (uint32_t src = 0; src < N; src++) {
			u16 outdeg = ARR_LEN(E[src].links);
			if (outdeg == 0) {
				dangling += r[src];
				continue;
			}
			double share = r[src] / (double)outdeg;
			u32*   L	 = (u32*)ARR_PTR(E[src].links);
			for (u16 j = 0; j < outdeg; j++) {
				u32 dst = L[j];
				if (dst < N) nxt[dst] += share;
			}
		}

		double base		= (1.0 - damp) / (double)N;
		double add_dang = dangling / (double)N;

		double diff = 0.0;
		for (uint32_t i = 0; i < N; i++) {
			double nr = base + damp * (nxt[i] + add_dang);
			diff += fabs(nr - r[i]);
			r[i] = nr;
		}

		if (eps > 0.0 && diff < eps) break;
	}

	free(nxt);
	*out_rank = r;
}

static uint64_t parse_u64_or_die(const char* s, const char* what) {
	if (!s || !*s) {
		fprintf(stderr, "error: missing %s\n", what);
		exit(2);
	}
	errno				   = 0;
	char*			   end = NULL;
	unsigned long long v   = strtoull(s, &end, 10);
	if (errno != 0 || !end || *end != '\0') {
		fprintf(stderr, "error: invalid %s: %s\n", what, s);
		exit(2);
	}
	return (uint64_t)v;
}

static double parse_f64_or_die(const char* s, const char* what) {
	if (!s || !*s) {
		fprintf(stderr, "error: missing %s\n", what);
		exit(2);
	}
	errno	   = 0;
	char*  end = NULL;
	double v   = strtod(s, &end);
	if (errno != 0 || !end || *end != '\0' || !isfinite(v)) {
		fprintf(stderr, "error: invalid %s: %s\n", what, s);
		exit(2);
	}
	return v;
}

static int cmp_u64(const void* a, const void* b) {
	uint64_t x = *(const uint64_t*)a;
	uint64_t y = *(const uint64_t*)b;
	if (x < y) return -1;
	if (x > y) return 1;
	return 0;
}

static uint64_t percentile_nearest_rank(const uint64_t* sorted, uint32_t n, uint32_t p) {
	if (n == 0) return 0;
	if (p == 0) return sorted[0];
	if (p >= 100) return sorted[n - 1];
	uint64_t rank = ((uint64_t)p * (uint64_t)n + 99ULL) / 100ULL; // ceil(p*n/100)
	if (rank < 1) rank = 1;
	uint64_t idx = rank - 1;
	if (idx >= n) idx = n - 1;
	return sorted[idx];
}

static double ns_to_ms(uint64_t ns) {
	return (double)ns / 1e6;
}

static void format_elapsed_mmss_ms(char out[16], uint64_t elapsed_ns) {
	uint64_t total_ms = elapsed_ns / 1000000ULL;
	uint64_t mm		  = total_ms / 60000ULL;
	uint64_t ss		  = (total_ms / 1000ULL) % 60ULL;
	uint64_t ms		  = total_ms % 1000ULL;
	snprintf(out, 16, "%" PRIu64 ":%02" PRIu64 ".%03" PRIu64, mm, ss, ms);
}

static void print_spinner_line(uint32_t iter0, uint32_t iters, string start, string target, u64 bench_start_ns) {
	static const char* spins[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
	const uint32_t	   nspins  = (uint32_t)(sizeof(spins) / sizeof(spins[0]));
	const char*		   spin	   = spins[nspins ? (iter0 % nspins) : 0];

	u64		 now	 = get_monotonic_time();
	uint64_t elapsed = (uint64_t)(now - bench_start_ns);
	char	 tbuf[16];
	format_elapsed_mmss_ms(tbuf, elapsed);

	fprintf(stderr, "\x1b[0K\x1b[1K\x1b[2K\r %s %u / %u `%.*s` -> `%.*s` %s", spin, iter0 + 1, iters, STR_LEN(start),
			STR_PTR(start), STR_LEN(target), STR_PTR(target), tbuf);
	fflush(stderr);
}

#if !defined(_WIN32)
static void print_rusage(const char* label) {
	struct rusage ru;
	if (getrusage(RUSAGE_SELF, &ru) != 0) return;
	// On macOS, ru_maxrss is in bytes. On Linux, it's kilobytes.
#if defined(__APPLE__)
	ru.ru_maxrss /= 1024;
#endif
	long		maxrss = ru.ru_maxrss;
	const char* unit   = "KB";

	if (maxrss > 1024 * 8) {
		maxrss /= 1024;
		unit = "MB";
	}

	if (maxrss > 1024 * 8) {
		maxrss /= 1024;
		unit = "GB";
	}

	fprintf(stdout, "[mem] %s: ru_maxrss=%ld%s\n", label, maxrss, unit);
}
#endif

int main(int argc, char** argv) {
	TIME_INIT();

	if (argc < 2) {
		fprintf(stderr, "usage: %s <db.bin|db.xz> [--iters N] [--alpha A] [--seed S]\n", argv[0]);
		return 2;
	}

	const char* db_path = argv[1];
	uint32_t	iters	= 1000;
	double		alpha	= 1.6;
	uint64_t	seed	= 1234567ULL;

	for (int i = 2; i < argc; i++) {
		if ((strcmp(argv[i], "--iters") == 0 || strcmp(argv[i], "-n") == 0) && i + 1 < argc) {
			iters = (uint32_t)parse_u64_or_die(argv[++i], "iters");
		} else if (strcmp(argv[i], "--alpha") == 0 && i + 1 < argc) {
			alpha = parse_f64_or_die(argv[++i], "alpha");
			if (!(alpha > 0.0)) {
				fprintf(stderr, "error: alpha must be > 0\n");
				return 2;
			}
		} else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
			seed = parse_u64_or_die(argv[++i], "seed");
		} else {
			fprintf(stderr, "error: unknown arg: %s\n", argv[i]);
			return 2;
		}
	}

	load_mem((char*)db_path);
#if !defined(_WIN32)
	print_rusage("after load");
#endif

	fprintf(stdout, "[bench] entries=%d iters=%u alpha=%.6g seed=%" PRIu64 "\n", nr_entries, iters, alpha, seed);

	uint32_t N		= (uint32_t)nr_entries;
	uint8_t* active = (uint8_t*)malloc((size_t)N);
	if (!active) {
		fprintf(stderr, "error: out of memory\n");
		return 1;
	}
	memset(active, 1, (size_t)N);

	fprintf(stdout, "[bench] computing pagerank...\n");
	double* pr = NULL;
	pagerank_compute(entries, N, 30, 0.85, 0.0, &pr);

	fprintf(stdout, "[bench] building sampler...\n");
	PRSampler samp;
	if (!prsampler_build(&samp, pr, active, N, alpha, seed)) {
		fprintf(stderr, "error: failed building sampler\n");
		return 1;
	}

#if !defined(_WIN32)
	print_rusage("after pagerank+sampler");
#endif

	depths = calloc((size_t)nr_entries, sizeof(u8));
	if (!depths) {
		fprintf(stderr, "error: failed allocating depths\n");
		return 1;
	}

	uint64_t* times = (uint64_t*)malloc((size_t)iters * sizeof(uint64_t));
	if (!times) {
		fprintf(stderr, "error: out of memory\n");
		return 1;
	}

	double	 mean  = 0.0;
	double	 m2	   = 0.0;
	uint64_t min_t = UINT64_MAX;
	uint64_t max_t = 0;
	uint32_t max_s = 0, max_tgt = 0;
	uint32_t not_found = 0;

	u64 bench_start = get_monotonic_time();
	for (uint32_t i = 0; i < iters; i++) {
		uint32_t s = random_biased(&samp);
		uint32_t t = random_biased(&samp);
		while (t == s) t = random_biased(&samp);

		string start  = entries[s].title;
		string target = entries[t].title;
		print_spinner_line(i, iters, start, target, bench_start);

		u64	 t0	  = get_monotonic_time();
		Path path = find_path(start, target);
		u64	 t1	  = get_monotonic_time();

		uint64_t dt = (uint64_t)(t1 - t0);
		times[i]	= dt;
		if (dt < min_t) min_t = dt;
		if (dt > max_t) {
			max_t	= dt;
			max_s	= s;
			max_tgt = t;
		}

		// Welford variance
		double x	 = (double)dt;
		double delta = x - mean;
		mean += delta / (double)(i + 1);
		m2 += delta * (x - mean);

		if (!path.node) not_found++;
		path_free(&path);

		// Exact behavior from interactive client loop: clear depths between queries.
		memset(depths, 0, (size_t)nr_entries);
	}
	fprintf(stderr, "\n");
	u64 bench_end = get_monotonic_time();

	uint64_t wall = (uint64_t)(bench_end - bench_start);

	uint64_t* sorted = (uint64_t*)malloc((size_t)iters * sizeof(uint64_t));
	if (!sorted) {
		fprintf(stderr, "error: out of memory\n");
		return 1;
	}
	memcpy(sorted, times, (size_t)iters * sizeof(uint64_t));
	qsort(sorted, (size_t)iters, sizeof(uint64_t), cmp_u64);

	double stdev = 0.0;
	if (iters > 1) {
		stdev = sqrt(m2 / (double)(iters - 1));
	}

	uint64_t p10 = percentile_nearest_rank(sorted, iters, 10);
	uint64_t p25 = percentile_nearest_rank(sorted, iters, 25);
	uint64_t p50 = percentile_nearest_rank(sorted, iters, 50);
	uint64_t p75 = percentile_nearest_rank(sorted, iters, 75);
	uint64_t p90 = percentile_nearest_rank(sorted, iters, 90);
	uint64_t p99 = percentile_nearest_rank(sorted, iters, 99);

	fprintf(stdout, "\n[timing] wall_ms=%.3f  qps=%.2f\n", ns_to_ms(wall),
			(wall > 0) ? ((double)iters / ((double)wall / 1e9)) : 0.0);
	fprintf(stdout, "[timing] mean_ms=%.3f  stdev_ms=%.3f\n", ns_to_ms((uint64_t)llround(mean)),
			ns_to_ms((uint64_t)llround(stdev)));
	fprintf(stdout, "[timing] min_ms=%.3f  max_ms=%.3f\n", ns_to_ms(min_t), ns_to_ms(max_t));
	fprintf(stdout, "[timing] p10_ms=%.3f p25_ms=%.3f p50_ms=%.3f p75_ms=%.3f p90_ms=%.3f p99_ms=%.3f\n", ns_to_ms(p10),
			ns_to_ms(p25), ns_to_ms(p50), ns_to_ms(p75), ns_to_ms(p90), ns_to_ms(p99));
	fprintf(stdout, "[result] not_found=%u (%.2f%%)\n", not_found,
			iters ? (100.0 * (double)not_found / (double)iters) : 0.0);

	fprintf(stdout, "\n[slowest] dt_ms=%.3f\n", ns_to_ms(max_t));
	fprintf(stdout, "[slowest] start=%.*s\n", STR_LEN(entries[max_s].title), STR_PTR(entries[max_s].title));
	fprintf(stdout, "[slowest] target=%.*s\n", STR_LEN(entries[max_tgt].title), STR_PTR(entries[max_tgt].title));

#if !defined(_WIN32)
	print_rusage("after bench");
#endif

	free(sorted);
	free(times);
	prsampler_free(&samp);
	free(pr);
	free(active);
	free(depths);
	return 0;
}
