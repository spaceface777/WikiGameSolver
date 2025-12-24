// wikidbdiff.c
// Diff + normalize + analyze two xz-compressed Wikipedia link DB snapshots.
// Format inferred from user's loader: magic "WIKI", version(u32), nr_entries(i32),
// total_links(u32), total_title_bytes(u32), then per-entry nr_links(u16) with padding,
// then link arrays (u32 indices), then per-entry title_len(u16), then title bytes blob.
//
// Build: cc -O2 -std=c11 -Wall -Wextra -pedantic wikidbdiff.c -llzma -lm -o wikidbdiff

#include <errno.h>
#include <inttypes.h>
// #include <lzma.h>
#include <ctype.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "client/lzma.h"

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

typedef struct {
	const char* ptr;
	uint16_t	len;
} TitleRef;

typedef struct {
	uint32_t*	links; // points into decompressed buffer
	uint16_t	nr_links;
	uint16_t	title_len;
	const char* title; // points into decompressed buffer
} Entry;

typedef struct {
	uint8_t* buf; // decompressed blob
	size_t	 buf_len;

	uint32_t version_raw;
	uint8_t	 dump_format;
	int32_t	 dump_date_yymmdd; // as stored (version >> 8)
	int32_t	 nr_entries;

	uint32_t total_links;
	uint32_t total_title_bytes;

	Entry* entries;
} WikiDB;

typedef struct {
	uint32_t  n;		 // number of combined titles
	TitleRef* titles;	 // combined titles (sorted)
	uint32_t* mapA;		 // local index -> global index for A
	uint32_t* mapB;		 // local index -> global index for B
	int32_t*  locA_of_g; // global -> local index in A (or -1)
	int32_t*  locB_of_g; // global -> local index in B (or -1)

	uint32_t common_titles;
	uint32_t added_titles;	 // in B not in A
	uint32_t removed_titles; // in A not in B
} CombinedMap;

typedef struct {
	uint32_t* off; // size n+1
	uint32_t* nbr; // size m
	uint64_t  m;
} CSRInv;

typedef struct {
	uint32_t n;
	uint64_t m;

	uint32_t* outdeg; // size n
	uint32_t* indeg;  // size n

	CSRInv inv; // optional; if inv.nbr==NULL then not built
} NormGraph;

static void die(const char* msg) {
	fprintf(stderr, "fatal: %s\n", msg);
	exit(1);
}

static void* xmalloc(size_t n) {
	void* p = malloc(n);
	if (!p) die("out of memory");
	return p;
}

static void* xrealloc(void* p, size_t n) {
	void* q = realloc(p, n);
	if (!q) die("out of memory");
	return q;
}

static uint32_t read_u32(const uint8_t** p) {
	uint32_t v;
	memcpy(&v, *p, sizeof(v));
	*p += sizeof(v);
	return v;
}

static int32_t read_i32(const uint8_t** p) {
	int32_t v;
	memcpy(&v, *p, sizeof(v));
	*p += sizeof(v);
	return v;
}

static uint16_t read_u16(const uint8_t** p) {
	uint16_t v;
	memcpy(&v, *p, sizeof(v));
	*p += sizeof(v);
	return v;
}

static int title_cmp(TitleRef a, TitleRef b) {
	int c = memcmp(a.ptr, b.ptr, MIN(a.len, b.len));
	if (c != 0) return c;
	if (a.len < b.len) return -1;
	if (a.len > b.len) return 1;
	return 0;
}

static void fprint_title(FILE* f, TitleRef t) {
	fwrite(t.ptr, 1, t.len, f);
}

static void print_dump_date(int32_t yymmdd) {
	int yy = yymmdd / 10000;
	int mm = (yymmdd / 100) % 100;
	int dd = yymmdd % 100;
	printf("20%02d.%02d.%02d", yy, mm, dd);
}

/************ Timing ************/

typedef struct {
	struct timespec t0;
} Timer;

static void timer_start(Timer* t) {
	if (clock_gettime(CLOCK_MONOTONIC, &t->t0) != 0) {
		die("clock_gettime(CLOCK_MONOTONIC) failed");
	}
}

static int64_t timer_elapsed_ms(const Timer* t) {
	struct timespec t1;
	if (clock_gettime(CLOCK_MONOTONIC, &t1) != 0) {
		die("clock_gettime(CLOCK_MONOTONIC) failed");
	}
	int64_t sec	 = (int64_t)t1.tv_sec - (int64_t)t->t0.tv_sec;
	int64_t nsec = (int64_t)t1.tv_nsec - (int64_t)t->t0.tv_nsec;
	int64_t ms	 = sec * 1000 + nsec / 1000000;
	return ms;
}

static void fmt_mm_ss_cc(int64_t ms, char* out, size_t out_n) {
	if (ms < 0) ms = 0;
	int64_t cs_total = ms / 10; // centiseconds
	int		cs		 = (int)(cs_total % 100);
	int64_t s_total	 = cs_total / 100;
	int		ss		 = (int)(s_total % 60);
	int64_t mm		 = s_total / 60;
	if (mm > 0) snprintf(out, out_n, "%" PRIi64 ":%02d.%02d", mm, ss, cs);
	else snprintf(out, out_n, "%d.%02d", ss, cs);
}

static void print_step_time(const char* label, const Timer* t) {
	char buf[64];
	fmt_mm_ss_cc(timer_elapsed_ms(t), buf, sizeof(buf));
	printf("[time] %-28s %s\n", label, buf);
}

/************ Title helpers (prefix/suffix heuristics) ************/

static int title_has_prefix(TitleRef t, const char* s) {
	size_t sl = strlen(s);
	if ((size_t)t.len < sl) return 0;
	return memcmp(t.ptr, s, sl) == 0;
}

static int title_has_suffix(TitleRef t, const char* s) {
	size_t sl = strlen(s);
	if ((size_t)t.len < sl) return 0;
	return memcmp(t.ptr + (t.len - (uint16_t)sl), s, sl) == 0;
}

static int title_is_year_page(TitleRef t) {
	if (t.len != 4) return 0;
	for (int i = 0; i < 4; i++) {
		unsigned char c = (unsigned char)t.ptr[i];
		if (!isdigit(c)) return 0;
	}
	return 1;
}

static int title_starts_with_year_in(TitleRef t) {
	// "2015 in aviation", "1979 in music", etc.
	if (t.len < 7) return 0;
	for (int i = 0; i < 4; i++) {
		unsigned char c = (unsigned char)t.ptr[i];
		if (!isdigit(c)) return 0;
	}
	// must have " in " starting at pos 4: "YYYY in ..."
	return (t.ptr[4] == ' ' && t.ptr[5] == 'i' && t.ptr[6] == 'n');
}

static int title_is_cheese_like(TitleRef t) {
	// Very cheap heuristics for "teleport hubs".
	// Tweak freely: these are meant for "no-cheese PageRank" and similar stats.
	if (title_has_prefix(t, "List of ")) return 1;
	if (title_has_prefix(t, "Index of ")) return 1;
	if (title_has_prefix(t, "Timeline of ")) return 1;
	if (title_has_prefix(t, "Deaths in ")) return 1;
	if (title_has_suffix(t, " (disambiguation)")) return 1;
	if (title_is_year_page(t)) return 1;
	if (title_starts_with_year_in(t)) return 1;
	return 0;
}

/************ xz decompression (liblzma) ************/

static uint8_t* read_entire_file(const char* path, size_t* out_len) {
	FILE* fp = fopen(path, "rb");
	if (!fp) {
		fprintf(stderr, "error: open %s: %s\n", path, strerror(errno));
		return NULL;
	}
	if (fseeko(fp, 0, SEEK_END) != 0) {
		fprintf(stderr, "error: seek %s\n", path);
		fclose(fp);
		return NULL;
	}
	off_t sz = ftello(fp);
	if (sz < 0) {
		fprintf(stderr, "error: ftello %s\n", path);
		fclose(fp);
		return NULL;
	}
	if (fseeko(fp, 0, SEEK_SET) != 0) {
		fprintf(stderr, "error: seek start %s\n", path);
		fclose(fp);
		return NULL;
	}
	uint8_t* buf = (uint8_t*)xmalloc((size_t)sz);
	size_t	 rd	 = fread(buf, 1, (size_t)sz, fp);
	fclose(fp);
	if (rd != (size_t)sz) {
		fprintf(stderr, "error: short read %s\n", path);
		free(buf);
		return NULL;
	}
	*out_len = rd;
	return buf;
}

static uint8_t* xz_decompress_mem(const uint8_t* in, size_t in_len, size_t* out_len) {
	lzma_stream strm = LZMA_STREAM_INIT;
	lzma_ret	ret	 = lzma_stream_decoder(&strm, UINT64_MAX, 0);
	if (ret != LZMA_OK) die("lzma_stream_decoder failed");

	size_t	 cap	 = 64u * 1024u * 1024u; // grow as needed
	uint8_t* out	 = (uint8_t*)xmalloc(cap);
	size_t	 out_pos = 0;

	strm.next_in  = in;
	strm.avail_in = in_len;

	while (1) {
		if (out_pos == cap) {
			cap = cap + cap / 2 + 1;
			out = (uint8_t*)xrealloc(out, cap);
		}
		strm.next_out  = out + out_pos;
		strm.avail_out = cap - out_pos;

		ret		= lzma_code(&strm, LZMA_FINISH);
		out_pos = cap - strm.avail_out;

		if (ret == LZMA_STREAM_END) break;
		if (ret != LZMA_OK) {
			fprintf(stderr, "error: lzma_code failed (%d)\n", (int)ret);
			lzma_end(&strm);
			free(out);
			return NULL;
		}
		// If no progress and no output space, loop will realloc above.
	}

	lzma_end(&strm);
	*out_len = out_pos;
	out		 = (uint8_t*)xrealloc(out, out_pos ? out_pos : 1);
	return out;
}

/************ DB parsing ************/

static int db_parse(WikiDB* db) {
	const uint8_t* p   = db->buf;
	const uint8_t* end = db->buf + db->buf_len;

	if ((size_t)(end - p) < 4) return 0;
	if (!(p[0] == 'W' && p[1] == 'I' && p[2] == 'K' && p[3] == 'I')) {
		fprintf(stderr, "error: invalid magic\n");
		return 0;
	}
	p += 4;

	if ((size_t)(end - p) < 4) return 0;
	db->version_raw		 = read_u32(&p);
	db->dump_format		 = (uint8_t)(db->version_raw & 0xffu);
	db->dump_date_yymmdd = (int32_t)(db->version_raw >> 8);

	if ((size_t)(end - p) < 4) return 0;
	db->nr_entries = read_i32(&p);
	if (db->nr_entries <= 0) {
		fprintf(stderr, "error: nr_entries <= 0\n");
		return 0;
	}

	if ((size_t)(end - p) < 8) return 0;
	db->total_links		  = read_u32(&p);
	db->total_title_bytes = read_u32(&p);

	db->entries = (Entry*)xmalloc((size_t)db->nr_entries * sizeof(Entry));
	memset(db->entries, 0, (size_t)db->nr_entries * sizeof(Entry));

	// Read nr_links table
	for (int32_t i = 0; i < db->nr_entries; i++) {
		if ((size_t)(end - p) < 2) return 0;
		uint16_t nl				= read_u16(&p);
		db->entries[i].nr_links = nl;
		db->entries[i].links	= NULL;
	}

	// padding to multiple of 4 entries (u16)
	int padding_needed = db->nr_entries % 4;
	if (padding_needed) {
		size_t skip = (size_t)(4 - padding_needed) * sizeof(uint16_t);
		if ((size_t)(end - p) < skip) return 0;
		p += skip;
	}

	// Link arrays
	for (int32_t i = 0; i < db->nr_entries; i++) {
		uint16_t nl	  = db->entries[i].nr_links;
		size_t	 need = (size_t)nl * sizeof(uint32_t);
		if ((size_t)(end - p) < need) return 0;
		db->entries[i].links = (uint32_t*)p;
		p += need;
	}

	// title lengths
	for (int32_t i = 0; i < db->nr_entries; i++) {
		if ((size_t)(end - p) < 2) return 0;
		uint16_t l				 = read_u16(&p);
		db->entries[i].title_len = l;
		db->entries[i].title	 = NULL;
	}

	// title bytes blob
	for (int32_t i = 0; i < db->nr_entries; i++) {
		uint16_t l = db->entries[i].title_len;
		if ((size_t)(end - p) < l) return 0;
		db->entries[i].title = (const char*)p;
		p += l;
	}

	// ok if extra bytes exist (future fields), but normally p==end
	return 1;
}

static int db_load_xz(WikiDB* db, const char* path) {
	memset(db, 0, sizeof(*db));

	size_t	 in_len = 0;
	uint8_t* in		= read_entire_file(path, &in_len);
	if (!in) return 0;

	size_t	 out_len = 0;
	uint8_t* out	 = xz_decompress_mem(in, in_len, &out_len);
	free(in);
	if (!out) return 0;

	db->buf		= out;
	db->buf_len = out_len;

	if (!db_parse(db)) {
		fprintf(stderr, "error: failed parsing %s\n", path);
		return 0;
	}
	return 1;
}

static void db_free(WikiDB* db) {
	if (db->entries) free(db->entries);
	if (db->buf) free(db->buf);
	memset(db, 0, sizeof(*db));
}

static TitleRef db_title_ref(const WikiDB* db, int32_t idx) {
	TitleRef t;
	t.ptr = db->entries[idx].title;
	t.len = db->entries[idx].title_len;
	return t;
}

/************ Combined title universe + remaps ************/

static CombinedMap build_combined(const WikiDB* A, const WikiDB* B) {
	CombinedMap cm;
	memset(&cm, 0, sizeof(cm));

	int32_t nA = A->nr_entries;
	int32_t nB = B->nr_entries;

	cm.mapA = (uint32_t*)xmalloc((size_t)nA * sizeof(uint32_t));
	cm.mapB = (uint32_t*)xmalloc((size_t)nB * sizeof(uint32_t));

	// Upper bound on combined size: nA + nB
	cm.titles = (TitleRef*)xmalloc((size_t)(nA + nB) * sizeof(TitleRef));

	int32_t	 i = 0, j = 0;
	uint32_t k = 0;

	while (i < nA || j < nB) {
		if (i < nA && j < nB) {
			TitleRef ta = db_title_ref(A, i);
			TitleRef tb = db_title_ref(B, j);
			int		 c	= title_cmp(ta, tb);
			if (c == 0) {
				cm.titles[k] = ta; // keep A's pointer
				cm.mapA[i]	 = k;
				cm.mapB[j]	 = k;
				i++;
				j++;
				k++;
				cm.common_titles++;
			} else if (c < 0) {
				cm.titles[k] = ta;
				cm.mapA[i]	 = k;
				i++;
				k++;
				cm.removed_titles++; // in A not in B
			} else {
				cm.titles[k] = tb;
				cm.mapB[j]	 = k;
				j++;
				k++;
				cm.added_titles++; // in B not in A
			}
		} else if (i < nA) {
			TitleRef ta	 = db_title_ref(A, i);
			cm.titles[k] = ta;
			cm.mapA[i]	 = k;
			i++;
			k++;
			cm.removed_titles++;
		} else {
			TitleRef tb	 = db_title_ref(B, j);
			cm.titles[k] = tb;
			cm.mapB[j]	 = k;
			j++;
			k++;
			cm.added_titles++;
		}
	}

	cm.n	  = k;
	cm.titles = (TitleRef*)xrealloc(cm.titles, (size_t)cm.n * sizeof(TitleRef));

	cm.locA_of_g = (int32_t*)xmalloc((size_t)cm.n * sizeof(int32_t));
	cm.locB_of_g = (int32_t*)xmalloc((size_t)cm.n * sizeof(int32_t));
	for (uint32_t g = 0; g < cm.n; g++) {
		cm.locA_of_g[g] = -1;
		cm.locB_of_g[g] = -1;
	}
	for (int32_t a = 0; a < nA; a++) cm.locA_of_g[cm.mapA[a]] = a;
	for (int32_t b = 0; b < nB; b++) cm.locB_of_g[cm.mapB[b]] = b;

	return cm;
}

static void combined_free(CombinedMap* cm) {
	if (cm->titles) free(cm->titles);
	if (cm->mapA) free(cm->mapA);
	if (cm->mapB) free(cm->mapB);
	if (cm->locA_of_g) free(cm->locA_of_g);
	if (cm->locB_of_g) free(cm->locB_of_g);
	memset(cm, 0, sizeof(*cm));
}

/************ Remap edges in-place ************/

static uint64_t remap_edges_in_place(WikiDB* db, const uint32_t* local_to_global) {
	uint64_t m = 0;
	for (int32_t i = 0; i < db->nr_entries; i++) {
		Entry*	  e	 = &db->entries[i];
		uint16_t  nl = e->nr_links;
		uint32_t* L	 = e->links;
		for (uint16_t t = 0; t < nl; t++) {
			uint32_t old = L[t];
			L[t]		 = local_to_global[old];
		}
		m += nl;
	}
	return m;
}

static int is_sorted_u32(const uint32_t* a, uint32_t n) {
	if (n <= 1) return 1;
	for (uint32_t i = 1; i < n; i++)
		if (a[i - 1] > a[i]) return 0;
	return 1;
}

static int cmp_u32_qsort(const void* pa, const void* pb) {
	uint32_t a = *(const uint32_t*)pa;
	uint32_t b = *(const uint32_t*)pb;
	if (a < b) return -1;
	if (a > b) return 1;
	return 0;
}

static void force_sort_all(WikiDB* db) {
	for (int32_t i = 0; i < db->nr_entries; i++) {
		Entry* e = &db->entries[i];
		if (e->nr_links > 1) qsort(e->links, e->nr_links, sizeof(uint32_t), cmp_u32_qsort);
	}
}

/************ Build indegree/outdegree + optional inverse adjacency ************/

static void csr_free(CSRInv* inv) {
	if (inv->off) free(inv->off);
	if (inv->nbr) free(inv->nbr);
	memset(inv, 0, sizeof(*inv));
}

static NormGraph build_graph(const WikiDB* db, const CombinedMap* cm, const uint32_t* local_to_global,
							 int build_inverse) {
	NormGraph g;
	memset(&g, 0, sizeof(g));
	g.n = cm->n;

	g.outdeg = (uint32_t*)xmalloc((size_t)g.n * sizeof(uint32_t));
	g.indeg	 = (uint32_t*)xmalloc((size_t)g.n * sizeof(uint32_t));
	memset(g.outdeg, 0, (size_t)g.n * sizeof(uint32_t));
	memset(g.indeg, 0, (size_t)g.n * sizeof(uint32_t));

	// outdegree + indegree counts
	uint64_t m = 0;
	for (int32_t i = 0; i < db->nr_entries; i++) {
		uint32_t src	  = local_to_global[i];
		uint16_t nl		  = db->entries[i].nr_links;
		g.outdeg[src]	  = nl;
		const uint32_t* L = db->entries[i].links;
		for (uint16_t t = 0; t < nl; t++) {
			uint32_t dst = L[t];
			g.indeg[dst]++;
		}
		m += nl;
	}
	g.m = m;

	if (!build_inverse) return g;

	// Build CSR inverse adjacency: for each node v, list incoming neighbors (sources).
	g.inv.m	  = m;
	g.inv.off = (uint32_t*)xmalloc((size_t)(g.n + 1) * sizeof(uint32_t));
	memset(g.inv.off, 0, (size_t)(g.n + 1) * sizeof(uint32_t));

	// Prefix sums from indegree
	// off[0]=0; off[v+1]=off[v]+indeg[v]
	uint64_t run = 0;
	g.inv.off[0] = 0;
	for (uint32_t v = 0; v < g.n; v++) {
		run += g.indeg[v];
		if (run > UINT32_MAX) die("inverse offsets exceed 32-bit");
		g.inv.off[v + 1] = (uint32_t)run;
	}
	if (run != m) die("inverse prefix sum mismatch");

	g.inv.nbr	  = (uint32_t*)xmalloc((size_t)m * sizeof(uint32_t));
	uint32_t* cur = (uint32_t*)xmalloc((size_t)g.n * sizeof(uint32_t));
	memcpy(cur, g.inv.off, (size_t)g.n * sizeof(uint32_t));

	for (int32_t i = 0; i < db->nr_entries; i++) {
		uint32_t		src = local_to_global[i];
		uint16_t		nl	= db->entries[i].nr_links;
		const uint32_t* L	= db->entries[i].links;
		for (uint16_t t = 0; t < nl; t++) {
			uint32_t dst   = L[t];
			uint32_t pos   = cur[dst]++;
			g.inv.nbr[pos] = src;
		}
	}

	free(cur);
	return g;
}

static void graph_free(NormGraph* g) {
	if (g->outdeg) free(g->outdeg);
	if (g->indeg) free(g->indeg);
	csr_free(&g->inv);
	memset(g, 0, sizeof(*g));
}

/************ Top-K heaps (min-heap) ************/

typedef struct {
	uint32_t node;
	uint32_t val;
} TopU32;
typedef struct {
	uint32_t node;
	int64_t	 val;
} TopI64;
typedef struct {
	uint32_t node;
	double	 val;
	uint32_t aux;
} TopD; // aux can store abs-changed edges

static void heap_u32_sift_down(TopU32* h, int n, int i) {
	while (1) {
		int l = 2 * i + 1, r = l + 1, s = i;
		if (l < n && h[l].val < h[s].val) s = l;
		if (r < n && h[r].val < h[s].val) s = r;
		if (s == i) break;
		TopU32 tmp = h[i];
		h[i]	   = h[s];
		h[s]	   = tmp;
		i		   = s;
	}
}
static void heap_u32_sift_up(TopU32* h, int i) {
	while (i > 0) {
		int p = (i - 1) / 2;
		if (h[p].val <= h[i].val) break;
		TopU32 tmp = h[i];
		h[i]	   = h[p];
		h[p]	   = tmp;
		i		   = p;
	}
}
static void topk_u32_push(TopU32* h, int* sz, int k, uint32_t node, uint32_t val) {
	if (*sz < k) {
		h[*sz].node = node;
		h[*sz].val	= val;
		heap_u32_sift_up(h, *sz);
		(*sz)++;
	} else if (k > 0 && val > h[0].val) {
		h[0].node = node;
		h[0].val  = val;
		heap_u32_sift_down(h, *sz, 0);
	}
}

static void heap_i64_sift_down(TopI64* h, int n, int i) {
	while (1) {
		int l = 2 * i + 1, r = l + 1, s = i;
		if (l < n && h[l].val < h[s].val) s = l;
		if (r < n && h[r].val < h[s].val) s = r;
		if (s == i) break;
		TopI64 tmp = h[i];
		h[i]	   = h[s];
		h[s]	   = tmp;
		i		   = s;
	}
}
static void heap_i64_sift_up(TopI64* h, int i) {
	while (i > 0) {
		int p = (i - 1) / 2;
		if (h[p].val <= h[i].val) break;
		TopI64 tmp = h[i];
		h[i]	   = h[p];
		h[p]	   = tmp;
		i		   = p;
	}
}
static void topk_i64_push(TopI64* h, int* sz, int k, uint32_t node, int64_t val) {
	if (*sz < k) {
		h[*sz].node = node;
		h[*sz].val	= val;
		heap_i64_sift_up(h, *sz);
		(*sz)++;
	} else if (k > 0 && val > h[0].val) {
		h[0].node = node;
		h[0].val  = val;
		heap_i64_sift_down(h, *sz, 0);
	}
}

static void heap_d_sift_down(TopD* h, int n, int i) {
	while (1) {
		int l = 2 * i + 1, r = l + 1, s = i;
		if (l < n && h[l].val < h[s].val) s = l;
		if (r < n && h[r].val < h[s].val) s = r;
		if (s == i) break;
		TopD tmp = h[i];
		h[i]	 = h[s];
		h[s]	 = tmp;
		i		 = s;
	}
}
static void heap_d_sift_up(TopD* h, int i) {
	while (i > 0) {
		int p = (i - 1) / 2;
		if (h[p].val <= h[i].val) break;
		TopD tmp = h[i];
		h[i]	 = h[p];
		h[p]	 = tmp;
		i		 = p;
	}
}
static void topk_d_push(TopD* h, int* sz, int k, uint32_t node, double val, uint32_t aux) {
	if (*sz < k) {
		h[*sz].node = node;
		h[*sz].val	= val;
		h[*sz].aux	= aux;
		heap_d_sift_up(h, *sz);
		(*sz)++;
	} else if (k > 0 && val > h[0].val) {
		h[0].node = node;
		h[0].val  = val;
		h[0].aux  = aux;
		heap_d_sift_down(h, *sz, 0);
	}
}

static int cmp_topu32_desc(const void* a, const void* b) {
	const TopU32* x = (const TopU32*)a;
	const TopU32* y = (const TopU32*)b;
	if (x->val < y->val) return 1;
	if (x->val > y->val) return -1;
	return 0;
}
static int cmp_topi64_desc(const void* a, const void* b) {
	const TopI64* x = (const TopI64*)a;
	const TopI64* y = (const TopI64*)b;
	if (x->val < y->val) return 1;
	if (x->val > y->val) return -1;
	return 0;
}
static int cmp_topd_desc(const void* a, const void* b) {
	const TopD* x = (const TopD*)a;
	const TopD* y = (const TopD*)b;
	if (x->val < y->val) return 1;
	if (x->val > y->val) return -1;
	if (x->aux < y->aux) return 1;
	if (x->aux > y->aux) return -1;
	return 0;
}

/************ Added / removed relevance ************/

typedef struct {
	uint32_t node; // global id
	uint64_t val;  // score
	uint32_t indeg;
	uint32_t outdeg;
} TopU64;

static void heap_u64_sift_down(TopU64* h, int n, int i) {
	while (1) {
		int l = 2 * i + 1, r = l + 1, s = i;
		if (l < n && h[l].val < h[s].val) s = l;
		if (r < n && h[r].val < h[s].val) s = r;
		if (s == i) break;
		TopU64 tmp = h[i];
		h[i]	   = h[s];
		h[s]	   = tmp;
		i		   = s;
	}
}
static void heap_u64_sift_up(TopU64* h, int i) {
	while (i > 0) {
		int p = (i - 1) / 2;
		if (h[p].val <= h[i].val) break;
		TopU64 tmp = h[i];
		h[i]	   = h[p];
		h[p]	   = tmp;
		i		   = p;
	}
}
static void topk_u64_push(TopU64* h, int* sz, int k, uint32_t node, uint64_t val, uint32_t indeg, uint32_t outdeg) {
	if (*sz < k) {
		h[*sz].node	  = node;
		h[*sz].val	  = val;
		h[*sz].indeg  = indeg;
		h[*sz].outdeg = outdeg;
		heap_u64_sift_up(h, *sz);
		(*sz)++;
	} else if (k > 0 && val > h[0].val) {
		h[0].node	= node;
		h[0].val	= val;
		h[0].indeg	= indeg;
		h[0].outdeg = outdeg;
		heap_u64_sift_down(h, *sz, 0);
	}
}
static int cmp_topu64_desc(const void* a, const void* b) {
	const TopU64* x = (const TopU64*)a;
	const TopU64* y = (const TopU64*)b;
	if (x->val < y->val) return 1;
	if (x->val > y->val) return -1;
	// tie-break: higher indegree first
	if (x->indeg < y->indeg) return 1;
	if (x->indeg > y->indeg) return -1;
	return 0;
}

static void analyze_added_removed_relevance(const CombinedMap* cm, const NormGraph* GA, const NormGraph* GB, int topk) {
	TopU64* top_added	= (TopU64*)xmalloc((size_t)topk * sizeof(TopU64));
	TopU64* top_removed = (TopU64*)xmalloc((size_t)topk * sizeof(TopU64));
	int		sa = 0, sr = 0;

	for (uint32_t g = 0; g < cm->n; g++) {
		int inA = (cm->locA_of_g[g] >= 0);
		int inB = (cm->locB_of_g[g] >= 0);

		if (!inA && inB) {
			uint32_t indeg	= GB->indeg[g];
			uint32_t outdeg = GB->outdeg[g];
			uint64_t score	= (uint64_t)indeg * 5ULL + (uint64_t)outdeg;
			if (score) topk_u64_push(top_added, &sa, topk, g, score, indeg, outdeg);
		} else if (inA && !inB) {
			uint32_t indeg	= GA->indeg[g];
			uint32_t outdeg = GA->outdeg[g];
			uint64_t score	= (uint64_t)indeg * 5ULL + (uint64_t)outdeg;
			if (score) topk_u64_push(top_removed, &sr, topk, g, score, indeg, outdeg);
		}
	}

	qsort(top_added, (size_t)sa, sizeof(TopU64), cmp_topu64_desc);
	qsort(top_removed, (size_t)sr, sizeof(TopU64), cmp_topu64_desc);

	printf("\nTop %d most 'relevant' ADDED pages (B-only) by score=indeg*5+outdeg:\n", sa);
	for (int i = 0; i < sa; i++) {
		uint32_t g = top_added[i].node;
		printf("  %2d) score=%" PRIu64 " indeg=%u outdeg=%u title=", i + 1, top_added[i].val, top_added[i].indeg,
			   top_added[i].outdeg);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	printf("\nTop %d most 'relevant' REMOVED pages (A-only) by score=indeg*5+outdeg:\n", sr);
	for (int i = 0; i < sr; i++) {
		uint32_t g = top_removed[i].node;
		printf("  %2d) score=%" PRIu64 " indeg=%u outdeg=%u title=", i + 1, top_removed[i].val, top_removed[i].indeg,
			   top_removed[i].outdeg);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	free(top_added);
	free(top_removed);
}

/************ Forward decls ************/

static uint64_t rng64(uint64_t* s);

/************ PageRank (snapshot-local, normalized IDs) ************/

typedef struct {
	uint32_t n_active;
	uint32_t n_cheese;
	uint64_t m_active; // edges considered (to active nodes, after no-cheese handling)
} PRMeta;

static uint8_t* build_active_mask_for_snapshotB(const CombinedMap* cm) {
	uint8_t* active = (uint8_t*)xmalloc((size_t)cm->n);
	for (uint32_t g = 0; g < cm->n; g++) active[g] = (cm->locB_of_g[g] >= 0) ? 1 : 0;
	return active;
}

static uint8_t* build_cheese_mask(const CombinedMap* cm) {
	uint8_t* cheese = (uint8_t*)xmalloc((size_t)cm->n);
	for (uint32_t g = 0; g < cm->n; g++) cheese[g] = title_is_cheese_like(cm->titles[g]) ? 1 : 0;
	return cheese;
}

static void pagerank_compute_B(const WikiDB* B, const CombinedMap* cm, const uint8_t* active, const uint8_t* cheese,
							   int no_cheese_edges, // if 1: cheese nodes do NOT distribute along outgoing edges
							   int iters, double damp, double eps,
							   double** out_rank, // malloc'd length cm->n
							   PRMeta*	meta_out) {
	if (damp <= 0.0 || damp >= 1.0) damp = 0.85;
	if (iters < 1) iters = 1;

	PRMeta meta;
	memset(&meta, 0, sizeof(meta));

	// Count active nodes and cheese nodes (among active).
	for (uint32_t g = 0; g < cm->n; g++) {
		if (active[g]) {
			meta.n_active++;
			if (cheese && cheese[g]) meta.n_cheese++;
		}
	}
	if (meta.n_active == 0) die("pagerank: no active nodes in snapshot B");

	// Precompute effective outdegree (counting only edges to active nodes),
	// and optionally zeroing out "cheese" sources.
	uint32_t* out_eff = (uint32_t*)xmalloc((size_t)cm->n * sizeof(uint32_t));
	memset(out_eff, 0, (size_t)cm->n * sizeof(uint32_t));

	for (int32_t li = 0; li < B->nr_entries; li++) {
		uint32_t src = cm->mapB[li];
		if (!active[src]) continue; // shouldn't happen
		if (no_cheese_edges && cheese && cheese[src]) {
			out_eff[src] = 0;
			continue;
		}
		uint32_t		cnt = 0;
		const uint32_t* L	= B->entries[li].links;
		uint16_t		nl	= B->entries[li].nr_links;
		for (uint16_t t = 0; t < nl; t++) {
			uint32_t dst = L[t];
			if (dst < cm->n && active[dst]) cnt++;
		}
		out_eff[src] = cnt;
		meta.m_active += cnt;
	}

	double* r	= (double*)xmalloc((size_t)cm->n * sizeof(double));
	double* nxt = (double*)xmalloc((size_t)cm->n * sizeof(double));

	// Initialize uniformly over active nodes.
	double init = 1.0 / (double)meta.n_active;
	for (uint32_t g = 0; g < cm->n; g++) r[g] = active[g] ? init : 0.0;

	for (int it = 0; it < iters; it++) {
		memset(nxt, 0, (size_t)cm->n * sizeof(double));

		double dangling = 0.0;

		// Stream edges: src via local index in B.
		for (int32_t li = 0; li < B->nr_entries; li++) {
			uint32_t src = cm->mapB[li];
			if (!active[src]) continue;

			uint32_t oe = out_eff[src];
			if (oe == 0) {
				dangling += r[src];
				continue;
			}

			double			share = r[src] / (double)oe;
			const uint32_t* L	  = B->entries[li].links;
			uint16_t		nl	  = B->entries[li].nr_links;
			for (uint16_t t = 0; t < nl; t++) {
				uint32_t dst = L[t];
				if (dst < cm->n && active[dst]) nxt[dst] += share;
			}
		}

		double base		= (1.0 - damp) / (double)meta.n_active;
		double add_dang = dangling / (double)meta.n_active;

		double diff = 0.0;
		for (uint32_t g = 0; g < cm->n; g++) {
			if (!active[g]) {
				r[g] = 0.0;
				continue;
			}
			double ng = base + damp * (nxt[g] + add_dang);
			diff += fabs(ng - r[g]);
			r[g] = ng;
		}

		if (eps > 0.0 && diff < eps) break;
	}

	free(nxt);
	free(out_eff);

	*out_rank = r;
	if (meta_out) *meta_out = meta;
}

static void pagerank_print_top(const char* label, const CombinedMap* cm, const uint8_t* active, const uint8_t* cheese,
							   const double* r, int topk, int exclude_cheese_from_print) {
	TopD* top = (TopD*)xmalloc((size_t)topk * sizeof(TopD));
	int	  sz  = 0;

	double	 sum	  = 0.0;
	uint32_t n_active = 0;
	for (uint32_t g = 0; g < cm->n; g++) {
		if (!active[g]) continue;
		n_active++;
		sum += r[g];
		if (exclude_cheese_from_print && cheese && cheese[g]) continue;
		topk_d_push(top, &sz, topk, g, r[g], 0);
	}

	qsort(top, (size_t)sz, sizeof(TopD), cmp_topd_desc);

	printf("\n[pagerank] %s\n", label);
	printf("  active_nodes=%u  rank_sum=%.6f\n", n_active, sum);
	printf("  Top %d:\n", sz);
	for (int i = 0; i < sz; i++) {
		uint32_t g = top[i].node;
		printf("  %2d) pr=%.10g title=", i + 1, top[i].val);
		fprint_title(stdout, cm->titles[g]);
		if (cheese && cheese[g]) printf("  [cheese]");
		printf("\n");
	}

	free(top);
}

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

/************ Degree quantiles via reservoir sampling ************/

static uint64_t rng64(uint64_t* s) {
	// xorshift64*
	uint64_t x = *s;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	*s = x;
	return x * 2685821657736338717ULL;
}

static void reservoir_sample_u32(const uint32_t* arr, uint32_t n, uint32_t k, uint32_t* out, uint64_t seed) {
	if (k == 0) return;
	if (k >= n) {
		memcpy(out, arr, (size_t)n * sizeof(uint32_t));
		return;
	}
	uint64_t st = seed ? seed : 0x9e3779b97f4a7c15ULL;
	// Fill initial
	for (uint32_t i = 0; i < k; i++) out[i] = arr[i];
	// Reservoir
	for (uint32_t i = k; i < n; i++) {
		uint64_t r = rng64(&st);
		uint32_t j = (uint32_t)(r % (uint64_t)(i + 1));
		if (j < k) out[j] = arr[i];
	}
}

static void print_quantiles(const char* label, const uint32_t* arr, uint32_t n, uint32_t sample_n) {
	if (n == 0) return;
	uint32_t k = sample_n;
	if (k > n) k = n;
	uint32_t* s = (uint32_t*)xmalloc((size_t)k * sizeof(uint32_t));
	reservoir_sample_u32(arr, n, k, s, 0x123456789abcdef0ULL);
	qsort(s, k, sizeof(uint32_t), cmp_u32_qsort);

	uint32_t p50 = s[(uint64_t)k * 50 / 100];
	uint32_t p90 = s[(uint64_t)k * 90 / 100];
	uint32_t p99 = s[(uint64_t)k * 99 / 100];

	printf("  %s (sample=%u): p50=%u p90=%u p99=%u\n", label, k, p50, p90, p99);
	free(s);
}

/************ Biased PageRank sampling ************/
#include <float.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
	uint32_t  n;	 // number of active items
	uint32_t* gid;	 // [n] maps sampler index -> global node id
	uint32_t* alias; // [n]
	float*	  prob;	 // [n] in [0,1]
	uint64_t  rng;	 // RNG state
} PRSampler;

static double rng_double01(uint64_t* s) {
	// 53-bit precision double in [0,1)
	uint64_t r = rng64(s);
	return (double)((r >> 11) & ((1ULL << 53) - 1)) * (1.0 / 9007199254740992.0); // 2^53
}

static void prsampler_free(PRSampler* S) {
	if (!S) return;
	free(S->gid);
	free(S->alias);
	free(S->prob);
	memset(S, 0, sizeof(*S));
}

// active[g] is 1 for nodes you want eligible (e.g. "present in snapshot B").
// pr[g] should sum to 1 over active nodes (your PageRank output does).
// alpha > 1 biases toward high-PR nodes; alpha=1 is unbiased PR; alpha=0 is uniform (not supported here).
// Returns 1 on success, 0 on failure.
static int prsampler_build(PRSampler*	  S,
						   const double*  pr,	  // [N]
						   const uint8_t* active, // [N]
						   uint32_t N, double alpha, uint64_t seed) {
	if (!S || !pr || !active) return 0;
	if (alpha <= 0.0) alpha = 1.0;

	memset(S, 0, sizeof(*S));
	S->rng = seed ? seed : 0x9e3779b97f4a7c15ULL;

	// Count active nodes
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

	// Temp arrays (freed after build)
	double*	  q		= (double*)malloc((size_t)n * sizeof(double)); // scaled weights
	uint32_t* small = (uint32_t*)malloc((size_t)n * sizeof(uint32_t));
	uint32_t* large = (uint32_t*)malloc((size_t)n * sizeof(uint32_t));
	if (!q || !small || !large) {
		free(q);
		free(small);
		free(large);
		prsampler_free(S);
		return 0;
	}

	// Gather active gids and compute transformed weights
	double	 sumw = 0.0;
	uint32_t idx  = 0;
	for (uint32_t g = 0; g < N; g++) {
		if (!active[g]) continue;
		S->gid[idx++] = g;

		// Transform weight: w = pr^alpha
		// pr should be >0 for active nodes, but guard anyway.
		double p = pr[g];
		if (p <= 0.0) p = DBL_MIN;
		double w = pow(p, alpha);

		// If alpha is large and p tiny, pow may underflow to 0. Clamp.
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

	// Scale so that average q[i] is 1: q[i] = w_i * n / sumw
	double	 scale = (double)n / sumw;
	uint32_t ns = 0, nl = 0;
	for (uint32_t i = 0; i < n; i++) {
		q[i] *= scale;
		if (q[i] < 1.0) small[ns++] = i;
		else large[nl++] = i;
	}

	// Build alias table
	while (ns && nl) {
		uint32_t s = small[--ns];
		uint32_t l = large[--nl];

		// Probability of picking s directly
		double ps = q[s];
		if (ps < 0.0) ps = 0.0;
		if (ps > 1.0) ps = 1.0;
		S->prob[s]	= (float)ps;
		S->alias[s] = l;

		// Decrease l by the deficit of s
		q[l] = (q[l] + q[s]) - 1.0;
		if (q[l] < 1.0) small[ns++] = l;
		else large[nl++] = l;
	}

	// Whatever remains gets prob=1
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

// Returns a global node id, biased toward high PageRank.
static uint32_t random_biased(PRSampler* S) {
	// caller guarantees S built
	uint32_t n = S->n;
	uint32_t i = (uint32_t)(rng64(&S->rng) % (uint64_t)n);
	double	 u = rng_double01(&S->rng);
	uint32_t j = (u < (double)S->prob[i]) ? i : S->alias[i];
	return S->gid[j];
}

/************ Edge overlap + churn (assumes outgoing lists sorted by global id) ************/

static uint32_t intersect_sorted_count(const uint32_t* a, uint32_t na, const uint32_t* b, uint32_t nb) {
	uint32_t i = 0, j = 0, c = 0;
	while (i < na && j < nb) {
		uint32_t x = a[i], y = b[j];
		if (x == y) {
			c++;
			i++;
			j++;
		} else if (x < y) i++;
		else j++;
	}
	return c;
}

static uint32_t intersect_by_sorting_copies(const uint32_t* a, uint32_t na, const uint32_t* b, uint32_t nb) {
	if (na == 0 || nb == 0) return 0;
	uint32_t* aa = (uint32_t*)xmalloc((size_t)na * sizeof(uint32_t));
	uint32_t* bb = (uint32_t*)xmalloc((size_t)nb * sizeof(uint32_t));
	memcpy(aa, a, (size_t)na * sizeof(uint32_t));
	memcpy(bb, b, (size_t)nb * sizeof(uint32_t));
	qsort(aa, na, sizeof(uint32_t), cmp_u32_qsort);
	qsort(bb, nb, sizeof(uint32_t), cmp_u32_qsort);
	uint32_t inter = intersect_sorted_count(aa, na, bb, nb);
	free(aa);
	free(bb);
	return inter;
}

static void print_edge_row_details(const WikiDB* A, const WikiDB* B, const CombinedMap* cm, uint32_t g,
								   uint32_t changed, double churn_or_neg1) {
	int32_t la = cm->locA_of_g[g];
	int32_t lb = cm->locB_of_g[g];

	uint32_t		na = 0, nb = 0;
	const uint32_t *a = NULL, *b = NULL;

	if (la >= 0) {
		na = A->entries[la].nr_links;
		a  = A->entries[la].links;
	}
	if (lb >= 0) {
		nb = B->entries[lb].nr_links;
		b  = B->entries[lb].links;
	}

	uint32_t inter = 0;
	if (na && nb) inter = intersect_sorted_count(a, na, b, nb);
	uint32_t uni = na + nb - inter;

	// If it looks pathological (no overlap), verify by sorting copies (top rows only).
	uint32_t inter2	  = 0;
	int		 verified = 0;
	if (inter == 0 && na && nb) {
		inter2	 = intersect_by_sorting_copies(a, na, b, nb);
		verified = 1;
	}

	double churn = churn_or_neg1;
	if (churn < 0.0) churn = (uni > 0) ? ((double)changed / (double)uni) : 0.0;

	// Columns:
	// churn changed outA outB inter union gid [verify_inter] title
	printf("    %7.4f %8u %6u %6u %6u %6u %8" PRIu32, churn, changed, na, nb, inter, uni, g);
	// if (verified) printf(" verify=%u", inter2);
	printf("  ");
	fprint_title(stdout, cm->titles[g]);
	printf("\n");
}

static void print_edge_table_header(void) {
	printf("    churn    changed   outA   outB  inter  union      gid  title\n");
	printf("    ------  --------  -----  -----  -----  -----  --------  -----\n");
}

static int is_type_change(uint32_t outA, uint32_t outB) {
	uint32_t mn = outA < outB ? outA : outB;
	uint32_t mx = outA > outB ? outA : outB;
	// Heuristic: one side looks like a redirect/disamb stub; the other looks like a real article
	return (mn <= 2 && mx >= 30);
}

static int is_content_pair(uint32_t outA, uint32_t outB) {
	// Heuristic: both sides are “article-y”.
	return (outA >= 30 && outB >= 30);
}

static void analyze_edge_diff(const WikiDB* A, const WikiDB* B, const CombinedMap* cm, int topk, int show_progress) {
	uint64_t common = 0;
	uint64_t edgesA = 0;
	uint64_t edgesB = 0;

	uint64_t nodes_both				= 0;
	uint64_t nodes_both_union_ge_50 = 0;
	uint64_t nodes_both_content		= 0;
	uint64_t nodes_both_typechg		= 0;

	TopD*	top_ratio_all	  = (TopD*)xmalloc((size_t)topk * sizeof(TopD));
	TopD*	top_ratio_content = (TopD*)xmalloc((size_t)topk * sizeof(TopD));
	TopD*	top_ratio_typechg = (TopD*)xmalloc((size_t)topk * sizeof(TopD));
	TopU32* top_abs			  = (TopU32*)xmalloc((size_t)topk * sizeof(TopU32));

	int sz_all = 0, sz_c = 0, sz_t = 0, sz_abs = 0;

	for (uint32_t g = 0; g < cm->n; g++) {
		int32_t la = cm->locA_of_g[g];
		int32_t lb = cm->locB_of_g[g];

		uint32_t		na = 0, nb = 0;
		const uint32_t *a = NULL, *b = NULL;

		if (la >= 0) {
			na = A->entries[la].nr_links;
			a  = A->entries[la].links;
			edgesA += na;
		}
		if (lb >= 0) {
			nb = B->entries[lb].nr_links;
			b  = B->entries[lb].links;
			edgesB += nb;
		}

		// Churn leaderboards consider only pages present in BOTH snapshots:
		if (!(la >= 0 && lb >= 0)) {
			if (show_progress && (g % 1000000u) == 0u && g > 0)
				fprintf(stderr, "[progress] edge-diff processed %" PRIu32 " / %" PRIu32 " nodes\n", g, cm->n);
			continue;
		}

		nodes_both++;

		uint32_t inter = 0;
		if (na && nb) inter = intersect_sorted_count(a, na, b, nb);
		common += inter;

		uint32_t uni	 = na + nb - inter;
		uint32_t changed = (na - inter) + (nb - inter);

		// Absolute change leaderboard (no union filter)
		topk_u32_push(top_abs, &sz_abs, topk, g, changed);

		// Ratio leaderboards (avoid tiny unions)
		if (uni >= 50) {
			nodes_both_union_ge_50++;
			double churn = (double)changed / (double)uni;
			topk_d_push(top_ratio_all, &sz_all, topk, g, churn, changed);

			if (is_content_pair(na, nb)) {
				nodes_both_content++;
				topk_d_push(top_ratio_content, &sz_c, topk, g, churn, changed);
			}
			if (is_type_change(na, nb)) {
				nodes_both_typechg++;
				topk_d_push(top_ratio_typechg, &sz_t, topk, g, churn, changed);
			}
		}

		if (show_progress && (g % 1000000u) == 0u && g > 0)
			fprintf(stderr, "[progress] edge-diff processed %" PRIu32 " / %" PRIu32 " nodes\n", g, cm->n);
	}

	uint64_t removed = edgesA - common;
	uint64_t added	 = edgesB - common;

	printf("\nEdge overlap / churn (directed edges):\n");
	printf("  edges(A) = %" PRIu64 "\n", edgesA);
	printf("  edges(B) = %" PRIu64 "\n", edgesB);
	printf("  common   = %" PRIu64 "\n", common);
	printf("  removed  = %" PRIu64 "  (in A not in B)\n", removed);
	printf("  added    = %" PRIu64 "  (in B not in A)\n", added);

	if ((edgesA + edgesB - common) > 0) {
		double global_jacc = (double)common / (double)(edgesA + edgesB - common);
		printf("  global Jaccard(edge set) = %.6f\n", global_jacc);
	}

	printf("  churn leaderboards (common pages only):\n");
	printf("    nodes_both=%" PRIu64 "\n", nodes_both);
	printf("    nodes_both_union>=50=%" PRIu64 "\n", nodes_both_union_ge_50);
	printf("    nodes_both_content(outA>=50 && outB>=50)=%" PRIu64 "\n", nodes_both_content);
	printf("    nodes_both_type_change(min<=2 && max>=50)=%" PRIu64 "\n", nodes_both_typechg);

	qsort(top_ratio_all, (size_t)sz_all, sizeof(TopD), cmp_topd_desc);
	qsort(top_ratio_content, (size_t)sz_c, sizeof(TopD), cmp_topd_desc);
	qsort(top_ratio_typechg, (size_t)sz_t, sizeof(TopD), cmp_topd_desc);
	qsort(top_abs, (size_t)sz_abs, sizeof(TopU32), cmp_topu32_desc);

	printf("\n[churn] Top %d by outgoing-link churn ratio (union>=50, common pages):\n", sz_all);
	print_edge_table_header();
	for (int i = 0; i < sz_all; i++) {
		uint32_t g = top_ratio_all[i].node;
		print_edge_row_details(A, B, cm, g, top_ratio_all[i].aux, top_ratio_all[i].val);
	}

	printf("\n[churn] Top %d by churn ratio (CONTENT-CHANGE only):\n", sz_c);
	print_edge_table_header();
	for (int i = 0; i < sz_c; i++) {
		uint32_t g = top_ratio_content[i].node;
		print_edge_row_details(A, B, cm, g, top_ratio_content[i].aux, top_ratio_content[i].val);
	}

	printf("\n[churn] Top %d by churn ratio (TYPE-CHANGE only):\n", sz_t);
	print_edge_table_header();
	for (int i = 0; i < sz_t; i++) {
		uint32_t g = top_ratio_typechg[i].node;
		print_edge_row_details(A, B, cm, g, top_ratio_typechg[i].aux, top_ratio_typechg[i].val);
	}

	printf("\n[churn] Top %d by ABSOLUTE outgoing-link changes (common pages):\n", sz_abs);
	print_edge_table_header();
	for (int i = 0; i < sz_abs; i++) {
		uint32_t g = top_abs[i].node;
		// churn computed inside printer when churn_or_neg1 < 0
		print_edge_row_details(A, B, cm, g, top_abs[i].val, -1.0);
	}

	free(top_ratio_all);
	free(top_ratio_content);
	free(top_ratio_typechg);
	free(top_abs);
}

/************ Main analysis ************/

static void analyze_degrees(const CombinedMap* cm, const NormGraph* GA, const NormGraph* GB, int topk,
							uint32_t sample_n) {
	printf("\nDegree summaries (normalized title universe n=%" PRIu32 "):\n", cm->n);
	printf("  A: m=%" PRIu64 " mean_out=%.4f mean_in=%.4f\n", GA->m, (double)GA->m / (double)cm->n,
		   (double)GA->m / (double)cm->n);
	printf("  B: m=%" PRIu64 " mean_out=%.4f mean_in=%.4f\n", GB->m, (double)GB->m / (double)cm->n,
		   (double)GB->m / (double)cm->n);

	// Presence + zero-degree counts (both "all nodes" and "present only")
	uint32_t presentA = 0, presentB = 0, presentBoth = 0;
	uint32_t absentA = 0, absentB = 0; // absent from snapshot

	uint32_t z_outA_all = 0, z_inA_all = 0, z_outB_all = 0, z_inB_all = 0;
	uint32_t z_outA_pres = 0, z_inA_pres = 0, z_outB_pres = 0, z_inB_pres = 0;
	for (uint32_t g = 0; g < cm->n; g++) {
		int a = (cm->locA_of_g[g] >= 0);
		int b = (cm->locB_of_g[g] >= 0);
		if (a) presentA++;
		else absentA++;
		if (b) presentB++;
		else absentB++;
		if (a && b) presentBoth++;

		// "all nodes" (includes absences => will count missing as zeros)
		if (GA->outdeg[g] == 0) z_outA_all++;
		if (GA->indeg[g] == 0) z_inA_all++;
		if (GB->outdeg[g] == 0) z_outB_all++;
		if (GB->indeg[g] == 0) z_inB_all++;

		// "present only" (the meaningful zero-degree numbers)
		if (a) {
			if (GA->outdeg[g] == 0) z_outA_pres++;
			if (GA->indeg[g] == 0) z_inA_pres++;
		}
		if (b) {
			if (GB->outdeg[g] == 0) z_outB_pres++;
			if (GB->indeg[g] == 0) z_inB_pres++;
		}
	}
	printf("  Presence: presentA=%u presentB=%u presentBoth=%u\n", presentA, presentB, presentBoth);
	printf("  Absences: absentA=%u absentB=%u (combined n=%" PRIu32 ")\n", absentA, absentB, cm->n);

	printf("  Zero outdegree (ALL nodes): A=%u (%.2f%%)  B=%u (%.2f%%)\n", z_outA_all,
		   100.0 * (double)z_outA_all / (double)cm->n, z_outB_all, 100.0 * (double)z_outB_all / (double)cm->n);
	printf("  Zero indegree  (ALL nodes): A=%u (%.2f%%)  B=%u (%.2f%%)\n", z_inA_all,
		   100.0 * (double)z_inA_all / (double)cm->n, z_inB_all, 100.0 * (double)z_inB_all / (double)cm->n);

	if (presentA) {
		printf("  Zero outdegree (PRESENT only): A=%u (%.2f%% of presentA)\n", z_outA_pres,
			   100.0 * (double)z_outA_pres / (double)presentA);
		printf("  Zero indegree  (PRESENT only): A=%u (%.2f%% of presentA)\n", z_inA_pres,
			   100.0 * (double)z_inA_pres / (double)presentA);
	}
	if (presentB) {
		printf("  Zero outdegree (PRESENT only): B=%u (%.2f%% of presentB)\n", z_outB_pres,
			   100.0 * (double)z_outB_pres / (double)presentB);
		printf("  Zero indegree  (PRESENT only): B=%u (%.2f%% of presentB)\n", z_inB_pres,
			   100.0 * (double)z_inB_pres / (double)presentB);
	}

	print_quantiles("A outdegree", GA->outdeg, cm->n, sample_n);
	print_quantiles("A indegree ", GA->indeg, cm->n, sample_n);
	print_quantiles("B outdegree", GB->outdeg, cm->n, sample_n);
	print_quantiles("B indegree ", GB->indeg, cm->n, sample_n);

	// top hubs and gainers/losers
	TopU32* top_inA	 = (TopU32*)xmalloc((size_t)topk * sizeof(TopU32));
	TopU32* top_inB	 = (TopU32*)xmalloc((size_t)topk * sizeof(TopU32));
	TopU32* top_outA = (TopU32*)xmalloc((size_t)topk * sizeof(TopU32));
	TopU32* top_outB = (TopU32*)xmalloc((size_t)topk * sizeof(TopU32));

	TopI64* gain_in	 = (TopI64*)xmalloc((size_t)topk * sizeof(TopI64));
	TopI64* loss_in	 = (TopI64*)xmalloc((size_t)topk * sizeof(TopI64));
	TopI64* gain_out = (TopI64*)xmalloc((size_t)topk * sizeof(TopI64));
	TopI64* loss_out = (TopI64*)xmalloc((size_t)topk * sizeof(TopI64));

	int s_inA = 0, s_inB = 0, s_outA = 0, s_outB = 0;
	int s_gi = 0, s_li = 0, s_go = 0, s_lo = 0;

	// Correlations (log1p to tame hubs)
	double	 sx = 0, sy = 0, sxx = 0, syy = 0, sxy = 0;
	double	 sx2 = 0, sy2 = 0, sxx2 = 0, syy2 = 0, sxy2 = 0;
	uint64_t cnt = 0;

	for (uint32_t g = 0; g < cm->n; g++) {
		uint32_t ia = GA->indeg[g];
		uint32_t ib = GB->indeg[g];
		uint32_t oa = GA->outdeg[g];
		uint32_t ob = GB->outdeg[g];

		topk_u32_push(top_inA, &s_inA, topk, g, ia);
		topk_u32_push(top_inB, &s_inB, topk, g, ib);
		topk_u32_push(top_outA, &s_outA, topk, g, oa);
		topk_u32_push(top_outB, &s_outB, topk, g, ob);

		int64_t di	= (int64_t)ib - (int64_t)ia;
		int64_t do_ = (int64_t)ob - (int64_t)oa;
		if (di > 0) topk_i64_push(gain_in, &s_gi, topk, g, di);
		if (-di > 0) topk_i64_push(loss_in, &s_li, topk, g, -di); // store abs for losers
		if (do_ > 0) topk_i64_push(gain_out, &s_go, topk, g, do_);
		if (-do_ > 0) topk_i64_push(loss_out, &s_lo, topk, g, -do_);

		// correlations only for pages present in both
		if (cm->locA_of_g[g] >= 0 && cm->locB_of_g[g] >= 0) {
			double x = log1p((double)ia);
			double y = log1p((double)ib);
			sx += x;
			sy += y;
			sxx += x * x;
			syy += y * y;
			sxy += x * y;

			double x2 = log1p((double)oa);
			double y2 = log1p((double)ob);
			sx2 += x2;
			sy2 += y2;
			sxx2 += x2 * x2;
			syy2 += y2 * y2;
			sxy2 += x2 * y2;

			cnt++;
		}
	}

	qsort(top_inA, (size_t)s_inA, sizeof(TopU32), cmp_topu32_desc);
	qsort(top_inB, (size_t)s_inB, sizeof(TopU32), cmp_topu32_desc);
	qsort(top_outA, (size_t)s_outA, sizeof(TopU32), cmp_topu32_desc);
	qsort(top_outB, (size_t)s_outB, sizeof(TopU32), cmp_topu32_desc);

	qsort(gain_in, (size_t)s_gi, sizeof(TopI64), cmp_topi64_desc);
	qsort(loss_in, (size_t)s_li, sizeof(TopI64), cmp_topi64_desc);
	qsort(gain_out, (size_t)s_go, sizeof(TopI64), cmp_topi64_desc);
	qsort(loss_out, (size_t)s_lo, sizeof(TopI64), cmp_topi64_desc);

	printf("\nTop %d indegree hubs (A):\n", s_inA);
	for (int i = 0; i < s_inA; i++) {
		uint32_t g = top_inA[i].node;
		printf("  %2d) indeg=%u title=", i + 1, top_inA[i].val);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	printf("\nTop %d indegree hubs (B):\n", s_inB);
	for (int i = 0; i < s_inB; i++) {
		uint32_t g = top_inB[i].node;
		printf("  %2d) indeg=%u title=", i + 1, top_inB[i].val);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	printf("\nTop %d outdegree hubs (A):\n", s_outA);
	for (int i = 0; i < s_outA; i++) {
		uint32_t g = top_outA[i].node;
		printf("  %2d) outdeg=%u title=", i + 1, top_outA[i].val);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	printf("\nTop %d outdegree hubs (B):\n", s_outB);
	for (int i = 0; i < s_outB; i++) {
		uint32_t g = top_outB[i].node;
		printf("  %2d) outdeg=%u title=", i + 1, top_outB[i].val);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	printf("\nTop %d indegree gainers (B - A):\n", s_gi);
	for (int i = 0; i < s_gi; i++) {
		uint32_t g = gain_in[i].node;
		printf("  %2d) +%" PRIi64 " title=", i + 1, gain_in[i].val);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	printf("\nTop %d indegree losers (A - B):\n", s_li);
	for (int i = 0; i < s_li; i++) {
		uint32_t g = loss_in[i].node;
		printf("  %2d) -%" PRIi64 " title=", i + 1, loss_in[i].val);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	printf("\nTop %d outdegree gainers (B - A):\n", s_go);
	for (int i = 0; i < s_go; i++) {
		uint32_t g = gain_out[i].node;
		printf("  %2d) +%" PRIi64 " title=", i + 1, gain_out[i].val);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	printf("\nTop %d outdegree losers (A - B):\n", s_lo);
	for (int i = 0; i < s_lo; i++) {
		uint32_t g = loss_out[i].node;
		printf("  %2d) -%" PRIi64 " title=", i + 1, loss_out[i].val);
		fprint_title(stdout, cm->titles[g]);
		printf("\n");
	}

	if (cnt > 2) {
		double mx = sx / (double)cnt, my = sy / (double)cnt;
		double vx  = sxx / (double)cnt - mx * mx;
		double vy  = syy / (double)cnt - my * my;
		double cov = sxy / (double)cnt - mx * my;
		double r   = (vx > 0 && vy > 0) ? cov / sqrt(vx * vy) : 0.0;

		double mx2 = sx2 / (double)cnt, my2 = sy2 / (double)cnt;
		double vx2	= sxx2 / (double)cnt - mx2 * mx2;
		double vy2	= syy2 / (double)cnt - my2 * my2;
		double cov2 = sxy2 / (double)cnt - mx2 * my2;
		double r2	= (vx2 > 0 && vy2 > 0) ? cov2 / sqrt(vx2 * vy2) : 0.0;

		printf("\nSimilarity (common pages only, log1p degrees):\n");
		printf("  corr(log1p indegree A, log1p indegree B) = %.6f\n", r);
		printf("  corr(log1p outdegree A, log1p outdegree B) = %.6f\n", r2);
	}

	free(top_inA);
	free(top_inB);
	free(top_outA);
	free(top_outB);
	free(gain_in);
	free(loss_in);
	free(gain_out);
	free(loss_out);
}

/************ CLI ************/

static void usage(const char* argv0) {
	fprintf(stderr,
			"usage: %s old.db.xz new.db.xz [options]\n"
			"options:\n"
			"  --top K               top-k to print (default 30)\n"
			"  --sample N            reservoir sample for degree quantiles (default 1000000)\n"
			"  --no-edge-diff        skip edge overlap/churn pass\n"
			"  --no-inverse          do not build full inverse adjacency (still counts indegree)\n"
			"  --force-sort          qsort every outgoing list after remap (expensive)\n"
			"\n"
			"  --pagerank            compute PageRank on snapshot B (power iteration)\n"
			"  --pagerank-no-cheese  also compute PageRank where cheese pages don't distribute\n"
			"  --pr-iters N          PageRank iterations (default 30)\n"
			"  --pr-damp D           PageRank damping factor (default 0.85)\n"
			"  --pr-eps E            PageRank early-stop L1 threshold (default 0 disables)\n"
			"  --pr-exclude-cheese   exclude cheese pages from printed top list\n"
			"\n"
			"  --diameter            run directed longest-shortest-path heuristic on snapshot B\n"
			"  --diam-sweeps N       number of double-sweeps (default 8)\n"
			"  --diam-min-visited N  ignore BFS results visiting <N nodes (default 250000)\n"
			"  --diam-min-out N      seed nodes must have outdeg>=N (default 30)\n",
			argv0);
	exit(2);
}

int main(int argc, char** argv) {
	if (argc < 3) usage(argv[0]);

	// make stdout line buffered
	setvbuf(stdout, NULL, _IOLBF, 0);

	Timer total, step;
	timer_start(&total);

	const char* pathA = argv[1];
	const char* pathB = argv[2];

	int		 topk		  = 30;
	uint32_t sample_n	  = 1000000;
	int		 do_edge_diff = 1;
	int		 do_inverse	  = 1;
	int		 force_sort	  = 0;

	int	   do_pagerank			   = 0;
	int	   do_pagerank_no_cheese   = 0;
	int	   pr_exclude_cheese_print = 0;
	int	   pr_iters				   = 30;
	double pr_damp				   = 0.85;
	double pr_eps				   = 0.0; // 0 => disabled

	int		 do_diameter	  = 0;
	int		 diam_sweeps	  = 8;
	uint32_t diam_min_visited = 250000;
	uint32_t diam_min_out	  = 30;

	for (int i = 3; i < argc; i++) {
		if (strcmp(argv[i], "--top") == 0) {
			if (i + 1 >= argc) usage(argv[0]);
			topk = atoi(argv[++i]);
			if (topk <= 0) topk = 30;
		} else if (strcmp(argv[i], "--sample") == 0) {
			if (i + 1 >= argc) usage(argv[0]);
			long long v = atoll(argv[++i]);
			if (v < 1000) v = 1000;
			if (v > 5000000) v = 5000000; // keep sane by default
			sample_n = (uint32_t)v;
		} else if (strcmp(argv[i], "--no-edge-diff") == 0) {
			do_edge_diff = 0;
		} else if (strcmp(argv[i], "--no-inverse") == 0) {
			do_inverse = 0;
		} else if (strcmp(argv[i], "--force-sort") == 0) {
			force_sort = 1;
		} else if (strcmp(argv[i], "--pagerank") == 0) {
			do_pagerank = 1;
		} else if (strcmp(argv[i], "--pagerank-no-cheese") == 0) {
			do_pagerank			  = 1;
			do_pagerank_no_cheese = 1;
		} else if (strcmp(argv[i], "--pr-iters") == 0) {
			if (i + 1 >= argc) usage(argv[0]);
			pr_iters = atoi(argv[++i]);
			if (pr_iters < 1) pr_iters = 1;
			if (pr_iters > 200) pr_iters = 200;
		} else if (strcmp(argv[i], "--pr-damp") == 0) {
			if (i + 1 >= argc) usage(argv[0]);
			pr_damp = atof(argv[++i]);
		} else if (strcmp(argv[i], "--pr-eps") == 0) {
			if (i + 1 >= argc) usage(argv[0]);
			pr_eps = atof(argv[++i]);
			if (pr_eps < 0.0) pr_eps = 0.0;
		} else if (strcmp(argv[i], "--pr-exclude-cheese") == 0) {
			pr_exclude_cheese_print = 1;
		} else if (strcmp(argv[i], "--diameter") == 0) {
			do_diameter = 1;
		} else if (strcmp(argv[i], "--diam-sweeps") == 0) {
			if (i + 1 >= argc) usage(argv[0]);
			diam_sweeps = atoi(argv[++i]);
			if (diam_sweeps < 1) diam_sweeps = 1;
			if (diam_sweeps > 100) diam_sweeps = 100;
		} else if (strcmp(argv[i], "--diam-min-visited") == 0) {
			if (i + 1 >= argc) usage(argv[0]);
			long long v = atoll(argv[++i]);
			if (v < 0) v = 0;
			if (v > 7000000LL) v = 7000000LL;
			diam_min_visited = (uint32_t)v;
		} else if (strcmp(argv[i], "--diam-min-out") == 0) {
			if (i + 1 >= argc) usage(argv[0]);
			long long v = atoll(argv[++i]);
			if (v < 0) v = 0;
			if (v > 1000000LL) v = 1000000LL;
			diam_min_out = (uint32_t)v;
		} else {
			usage(argv[0]);
		}
	}

	WikiDB A, B;
	printf("[load] %s\n", pathA);
	timer_start(&step);
	if (!db_load_xz(&A, pathA)) die("failed loading A");
	printf("  date=");
	print_dump_date(A.dump_date_yymmdd);
	printf(" entries=%d links=%u title_bytes=%u\n", A.nr_entries, A.total_links, A.total_title_bytes);
	print_step_time("load A", &step);

	printf("[load] %s\n", pathB);
	timer_start(&step);
	if (!db_load_xz(&B, pathB)) die("failed loading B");
	printf("  date=");
	print_dump_date(B.dump_date_yymmdd);
	printf(" entries=%d links=%u title_bytes=%u\n", B.nr_entries, B.total_links, B.total_title_bytes);
	print_step_time("load B", &step);

	printf("\n[normalize] building combined title universe (merge of sorted title lists)\n");
	timer_start(&step);
	CombinedMap cm = build_combined(&A, &B);

	printf("  combined n=%" PRIu32 "\n", cm.n);
	printf("  common=%" PRIu32 " added(B-only)=%" PRIu32 " removed(A-only)=%" PRIu32 "\n", cm.common_titles,
		   cm.added_titles, cm.removed_titles);
	print_step_time("build combined titles", &step);

	printf("\n[normalize] remapping edges in-place to combined global IDs\n");
	timer_start(&step);
	uint64_t mA = remap_edges_in_place(&A, cm.mapA);
	uint64_t mB = remap_edges_in_place(&B, cm.mapB);
	printf("  remapped edges: A=%" PRIu64 " B=%" PRIu64 "\n", mA, mB);
	print_step_time("remap edges", &step);

	// Optional: force-sort all outgoing lists (heavy), else sanity-check a small sample.
	timer_start(&step);
	if (force_sort) {
		printf("[normalize] --force-sort enabled: sorting all outgoing lists (both DBs)\n");
		force_sort_all(&A);
		force_sort_all(&B);
	} else {
		// quick sanity check first ~50k nodes
		int		badA = 0, badB = 0;
		int32_t limA = A.nr_entries < 50000 ? A.nr_entries : 50000;
		int32_t limB = B.nr_entries < 50000 ? B.nr_entries : 50000;
		for (int32_t i = 0; i < limA; i++)
			if (!is_sorted_u32(A.entries[i].links, A.entries[i].nr_links)) {
				badA = 1;
				break;
			}
		for (int32_t i = 0; i < limB; i++)
			if (!is_sorted_u32(B.entries[i].links, B.entries[i].nr_links)) {
				badB = 1;
				break;
			}
		if (badA || badB) {
			fprintf(stderr,
					"warning: detected unsorted outgoing lists in %s.\n"
					"         edge-diff/churn assumes sorted lists.\n"
					"         rerun with --force-sort (expensive) or ensure DB builder sorts adjacency.\n",
					(badA && badB) ? "A and B" : (badA ? "A" : "B"));
		}
	}
	print_step_time(force_sort ? "force-sort outgoing lists" : "sort/sanity check", &step);

	printf("\n[build] computing degrees%s\n", do_inverse ? " and inverse graphs" : "");
	timer_start(&step);
	NormGraph GA = build_graph(&A, &cm, cm.mapA, do_inverse);
	NormGraph GB = build_graph(&B, &cm, cm.mapB, do_inverse);
	print_step_time(do_inverse ? "build degrees+inverse" : "build degrees", &step);

	timer_start(&step);
	analyze_degrees(&cm, &GA, &GB, topk, sample_n);
	print_step_time("analyze degrees", &step);

	timer_start(&step);
	analyze_added_removed_relevance(&cm, &GA, &GB, topk);
	print_step_time("analyze added/removed", &step);

	// Optional: PageRank + "no-cheese" PageRank (snapshot B).
	if (do_pagerank || do_diameter) {
		// Build masks once if either feature is used.
		timer_start(&step);
		uint8_t* activeB = build_active_mask_for_snapshotB(&cm);
		uint8_t* cheese	 = build_cheese_mask(&cm);
		print_step_time("build masks (active/cheese)", &step);

		if (do_pagerank) {
			timer_start(&step);
			double* pr = NULL;
			PRMeta	meta;
			pagerank_compute_B(&B, &cm, activeB, cheese, 0, pr_iters, pr_damp, pr_eps, &pr, &meta);
			printf("\n[pagerank] raw (snapshot B)\n");
			printf("  iters=%d damp=%.4f eps=%g  active=%u  cheese(active)=%u  edges_considered=%" PRIu64 "\n",
				   pr_iters, pr_damp, pr_eps, meta.n_active, meta.n_cheese, meta.m_active);
			pagerank_print_top("raw PageRank (B)", &cm, activeB, cheese, pr, topk, pr_exclude_cheese_print);
			print_step_time("pagerank raw", &step);

			timer_start(&step);
			printf("\n[pagerank] sampler (snapshot B)\n");
			PRSampler samp;
			if (!prsampler_build(&samp, pr, activeB, cm.n, 3.0, 1234567ULL)) {
				die("failed to build PRSampler");
			}
			for (int k = 0; k < 10; k++) {
				uint32_t g = random_biased(&samp);
				printf("biased pick %d: ", k);
				fprint_title(stdout, cm.titles[g]);
				printf("\n");
			}
			prsampler_free(&samp);
			print_step_time("pagerank sampler", &step);

			free(pr);

			if (do_pagerank_no_cheese) {
				timer_start(&step);
				double* pr2 = NULL;
				PRMeta	meta2;
				pagerank_compute_B(&B, &cm, activeB, cheese, 1, pr_iters, pr_damp, pr_eps, &pr2, &meta2);
				printf("\n[pagerank] no-cheese (snapshot B)\n");
				printf("  iters=%d damp=%.4f eps=%g  active=%u  cheese(active)=%u  edges_considered=%" PRIu64 "\n",
					   pr_iters, pr_damp, pr_eps, meta2.n_active, meta2.n_cheese, meta2.m_active);
				pagerank_print_top("no-cheese PageRank (B) [cheese sources don't distribute]", &cm, activeB, cheese,
								   pr2, topk, pr_exclude_cheese_print);
				free(pr2);
				print_step_time("pagerank no-cheese", &step);
			}
		}

		if (do_diameter) {
			timer_start(&step);
			analyze_directed_longest_shortest_path_B(&B, &cm, activeB, diam_sweeps, diam_min_visited, diam_min_out);
			print_step_time("diameter heuristic", &step);
		}

		free(activeB);
		free(cheese);
	}

	if (do_edge_diff) {
		printf("\n[diff] edge overlap + churn (this pass is bandwidth-heavy on big DBs)\n");
		timer_start(&step);
		analyze_edge_diff(&A, &B, &cm, topk, 1);
		print_step_time("edge diff", &step);
	} else {
		printf("\n[diff] edge overlap/churn skipped (--no-edge-diff)\n");
	}

	// Future extension hooks:
	// - PageRank (power iteration) using outgoing lists + dangling handling.
	// - Approx PageRank / personalization.
	// - Strong components / reachability sampling.
	// - Per-page MinHash sketches for fast churn at scale.

	timer_start(&step);
	graph_free(&GA);
	graph_free(&GB);
	combined_free(&cm);
	db_free(&A);
	db_free(&B);
	print_step_time("cleanup", &step);
	print_step_time("overall", &total);

	return 0;
}
