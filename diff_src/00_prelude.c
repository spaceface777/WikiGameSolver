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

#include "../client/lzma.h"

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
