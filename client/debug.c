#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "array.h"
#include "string.h"
#include "util.h"

/* ========= Data structures ========= */

typedef struct Entry {
	string title;
	array  links; // array<u32> of outgoing link indices
} Entry;

typedef struct DB {
	int	   current_version_hdr;
	int	   nr_entries;
	Entry* entries;
	char*  backing_mem; // keep backing buffer alive (string pointers reference this)
	long   backing_len;
} DB;

typedef struct TitleIdx {
	string title;
	int	   idx;
} TitleIdx;

typedef struct PageUnionItem {
	string title;	 // canonical title (from either db)
	int	   idx1;	 // index in db1, -1 if absent
	int	   idx2;	 // index in db2, -1 if absent
	int	   sort_key; // max(INCOMING count in db1, db2)
} PageUnionItem;

/* ========= Config ========= */

#define DUMP_FORMAT_VERSION 1
static const int report_every = 1000;

/* ========= Utilities ========= */

static void die(const char* msg) {
	fputs(msg, stderr);
	fputc('\n', stderr);
	exit(1);
}

static int string_cmp(const string* a, const string* b) {
	size_t an = STR_LEN(*a), bn = STR_LEN(*b);
	size_t n = an < bn ? an : bn;
	int	   r = memcmp(STR_PTR(*a), STR_PTR(*b), n);
	if (r != 0) return r;
	if (an < bn) return -1;
	if (an > bn) return 1;
	return 0;
}

static int cmp_qsort_strings(const void* a, const void* b) {
	const string* sa = (const string*)a;
	const string* sb = (const string*)b;
	return string_cmp(sa, sb);
}

static int cmp_titleidx_by_title(const void* a, const void* b) {
	const TitleIdx* A = (const TitleIdx*)a;
	const TitleIdx* B = (const TitleIdx*)b;
	return string_cmp(&A->title, &B->title);
}

static int cmp_union_items_desc(const void* a, const void* b) {
	const PageUnionItem* A = (const PageUnionItem*)a;
	const PageUnionItem* B = (const PageUnionItem*)b;
	if (A->sort_key != B->sort_key) return (B->sort_key - A->sort_key);
	return string_cmp(&A->title, &B->title);
}

static void fprint_string(FILE* out, const string s) {
	fprintf(out, "%.*s", STR_LEN(s), STR_PTR(s));
}

/* ========= DB loading ========= */

static void load_db(const char* path, DB* db, const char* label) {
	memset(db, 0, sizeof(*db));

	printf("[step] %s: reading db file into memory...\n", label);
	fflush(stdout);
	FILE* file = fopen(path, "rb");
	if (!file) {
		fprintf(stderr, "error: open '%s': %s\n", path, strerror(errno));
		exit(1);
	}

	fseek(file, 0, SEEK_END);
	long file_len = ftell(file);
	fseek(file, 0, SEEK_SET);

	char* file_buf = (char*)malloc(file_len);
	if (!file_buf) die("error: OOM");
	if ((long)fread(file_buf, 1, file_len, file) != file_len) {
		fprintf(stderr, "error: read '%s': %s\n", path, strerror(errno));
		exit(1);
	}
	fclose(file);

	printf("[step] %s: parsing header...\n", label);
	fflush(stdout);
	char* p = file_buf;

	unsigned int magic = *(unsigned int*)p;
	p += sizeof(magic);
	if (magic != *(unsigned int*)"WIKI") {
		free(file_buf);
		die("error: invalid magic");
	}

	unsigned int version = *(unsigned int*)p;
	p += sizeof(version);
	db->current_version_hdr = (int)version;
	u8 dump_format			= version & 0xff;
	if (dump_format != DUMP_FORMAT_VERSION) {
		free(file_buf);
		if (dump_format > DUMP_FORMAT_VERSION) die("error: db newer than program; update client.");
		else die("error: db older than program; update database.");
	}

	memcpy(&db->nr_entries, p, sizeof(int32_t));
	p += sizeof(int32_t);
	// uint32_t total_links;
	p += sizeof(uint32_t);
	// uint32_t total_title_bytes;
	p += sizeof(uint32_t);

	printf("[step] %s: allocating entries (%d)...\n", label, db->nr_entries);
	fflush(stdout);
	db->entries = (Entry*)malloc(sizeof(Entry) * db->nr_entries);
	if (!db->entries) die("error: OOM");

	for (int i = 0; i < db->nr_entries; i++) {
		u16 nr_links;
		memcpy(&nr_links, p, sizeof(u16));
		db->entries[i].links = ARR(0, nr_links);
		p += sizeof(u16);
	}

	int padding_mod4 = db->nr_entries % 4;
	if (padding_mod4) p += sizeof(u16) * (4 - padding_mod4);

	printf("[step] %s: wiring link arrays...\n", label);
	fflush(stdout);
	for (int i = 0; i < db->nr_entries; i++) {
		Entry* e		= &db->entries[i];
		u16	   nr_links = ARR_LEN(e->links);
		e->links		= ARR(p, nr_links);
		p += nr_links * sizeof(u32);
	}

	printf("[step] %s: reading title lengths...\n", label);
	fflush(stdout);
	for (int i = 0; i < db->nr_entries; i++) {
		u16 l;
		memcpy(&l, p, sizeof(u16));
		p += sizeof(u16);
		db->entries[i].title = STR(0, l);
	}

	printf("[step] %s: wiring title pointers...\n", label);
	fflush(stdout);
	for (int i = 0; i < db->nr_entries; i++) {
		u16 l				 = STR_LEN(db->entries[i].title);
		db->entries[i].title = STR(p, l);
		p += l;
	}

	db->backing_mem = file_buf;
	db->backing_len = file_len;
	printf("[done] %s loaded.\n\n", label);
	fflush(stdout);
}

/* ========= Indexing & helpers ========= */

static void build_title_index(const DB* db, TitleIdx** out_arr, size_t* out_n, const char* label) {
	printf("[step] %s: building title index...\n", label);
	fflush(stdout);
	size_t	  n	  = (size_t)db->nr_entries;
	TitleIdx* arr = (TitleIdx*)malloc(sizeof(TitleIdx) * n);
	if (!arr && n) die("error: OOM");
	for (size_t i = 0; i < n; i++) {
		arr[i].title = db->entries[i].title;
		arr[i].idx	 = (int)i;
	}
	qsort(arr, n, sizeof(TitleIdx), cmp_titleidx_by_title);
	printf("[done] %s: title index built (%zu)\n\n", label, n);
	fflush(stdout);
	*out_arr = arr;
	*out_n	 = n;
}

static int find_idx_by_index(TitleIdx* arr, size_t n, string key) {
	TitleIdx probe;
	probe.title	  = key;
	probe.idx	  = -1;
	TitleIdx* hit = (TitleIdx*)bsearch(&probe, arr, n, sizeof(TitleIdx), cmp_titleidx_by_title);
	return hit ? hit->idx : -1;
}

/* Compute INCOMING degrees for all pages in a DB */
static int* compute_in_degrees(const DB* db) {
	int	 n	   = db->nr_entries;
	int* indeg = (int*)calloc((size_t)n, sizeof(int));
	if (!indeg && n) die("error: OOM");
	for (int i = 0; i < n; i++) {
		const Entry* e		= &db->entries[i];
		u16			 nlinks = ARR_LEN(e->links);
		u32*		 links	= ARR_PTR(e->links);
		for (u16 j = 0; j < nlinks; j++) {
			int tgt = (int)links[j];
			if (tgt >= 0 && tgt < n) indeg[tgt]++; // count incoming edge to tgt
		}
	}
	return indeg;
}

/* Collect titles of outgoing links for page_idx (used for diff body) */
static string* collect_link_titles(const DB* db, int page_idx, size_t* out_count) {
	*out_count = 0;
	if (page_idx < 0 || page_idx >= db->nr_entries) return NULL;
	Entry* e	  = &db->entries[page_idx];
	u16	   nlinks = ARR_LEN(e->links);
	u32*   links  = ARR_PTR(e->links);

	size_t cnt = 0;
	for (u16 i = 0; i < nlinks; i++) {
		int idx = (int)links[i];
		if (idx >= 0 && idx < db->nr_entries) cnt++;
	}
	string* out = (string*)malloc(sizeof(string) * cnt);
	if (!out && cnt) die("error: OOM");
	size_t k = 0;
	for (u16 i = 0; i < nlinks; i++) {
		int idx = (int)links[i];
		if (idx >= 0 && idx < db->nr_entries) out[k++] = db->entries[idx].title;
	}
	*out_count = cnt;
	return out;
}

/* Set equality & diff printing for sorted string lists */
static int link_sets_equal(string* A, size_t nA, string* B, size_t nB) {
	if (nA != nB) return 0;
	qsort(A, nA, sizeof(string), cmp_qsort_strings);
	qsort(B, nB, sizeof(string), cmp_qsort_strings);
	for (size_t i = 0; i < nA; i++)
		if (string_cmp(&A[i], &B[i]) != 0) return 0;
	return 1;
}

static void diff_and_write(FILE* out, string* A, size_t nA, string* B, size_t nB) {
	qsort(A, nA, sizeof(string), cmp_qsort_strings);
	qsort(B, nB, sizeof(string), cmp_qsort_strings);
	size_t i = 0, j = 0;
	while (i < nA || j < nB) {
		if (i == nA) {
			fprintf(out, "    + ");
			fprint_string(out, B[j++]);
			fputc('\n', out);
		} else if (j == nB) {
			fprintf(out, "    - ");
			fprint_string(out, A[i++]);
			fputc('\n', out);
		} else {
			int cmp = string_cmp(&A[i], &B[j]);
			if (cmp == 0) {
				i++;
				j++;
			} else if (cmp < 0) {
				fprintf(out, "    - ");
				fprint_string(out, A[i++]);
				fputc('\n', out);
			} else {
				fprintf(out, "    + ");
				fprint_string(out, B[j++]);
				fputc('\n', out);
			}
		}
	}
}

/* ========= Main ========= */

int main(int argc, char** argv) {
	if (argc != 4) {
		fprintf(stderr, "error: invalid arguments\n");
		fprintf(stderr, "usage: %s [db1] [db2] [out_file.txt]\n", argv[0]);
		exit(1);
	}
	const char* out_path = argv[3];
	FILE*		out		 = fopen(out_path, "w");
	if (!out) {
		fprintf(stderr, "error: open output '%s': %s\n", out_path, strerror(errno));
		exit(1);
	}

	/* 1) Load DBs */
	DB db1, db2;
	load_db(argv[1], &db1, "db1");
	load_db(argv[2], &db2, "db2");

	/* 2) Build fast title indexes */
	TitleIdx *idx1 = NULL, *idx2 = NULL;
	size_t	  nidx1 = 0, nidx2 = 0;
	build_title_index(&db1, &idx1, &nidx1, "db1");
	build_title_index(&db2, &idx2, &nidx2, "db2");

	/* 3) Precompute INCOMING degrees (new behavior) */
	printf("[step] computing incoming degrees...\n");
	fflush(stdout);
	int* indeg1 = compute_in_degrees(&db1);
	int* indeg2 = compute_in_degrees(&db2);
	printf("[done] incoming degrees computed.\n\n");
	fflush(stdout);

	/* 4) Build union of titles */
	printf("[step] building union of titles...\n");
	fflush(stdout);
	size_t	total = (size_t)db1.nr_entries + (size_t)db2.nr_entries;
	string* all	  = (string*)malloc(sizeof(string) * total);
	if (!all && total) die("error: OOM");
	size_t k = 0;
	for (int i = 0; i < db1.nr_entries; i++) all[k++] = db1.entries[i].title;
	for (int i = 0; i < db2.nr_entries; i++) all[k++] = db2.entries[i].title;

	printf("[step] sorting all titles (%zu)...\n", k);
	fflush(stdout);
	qsort(all, k, sizeof(string), cmp_qsort_strings);

	/* 5) Deduplicate titles */
	printf("[step] deduplicating titles...\n");
	fflush(stdout);
	string* uniq = (string*)malloc(sizeof(string) * k);
	if (!uniq && k) die("error: OOM");
	size_t u = 0;
	for (size_t i = 0; i < k;) {
		uniq[u++] = all[i];
		size_t j  = i + 1;
		while (j < k && string_cmp(&all[i], &all[j]) == 0) j++;
		i = j;
	}
	free(all);
	printf("[done] unique titles: %zu\n\n", u);
	fflush(stdout);

	/* 6) Build union items with INCOMING sort keys */
	printf("[step] indexing pages and computing sort keys (incoming degree)...\n");
	fflush(stdout);
	PageUnionItem* items = (PageUnionItem*)malloc(sizeof(PageUnionItem) * u);
	if (!items && u) die("error: OOM");

	for (size_t i = 0; i < u; i++) {
		string title = uniq[i];
		int	   e1	 = find_idx_by_index(idx1, nidx1, title);
		int	   e2	 = find_idx_by_index(idx2, nidx2, title);
		int	   n1	 = (e1 >= 0) ? indeg1[e1] : 0; // incoming
		int	   n2	 = (e2 >= 0) ? indeg2[e2] : 0; // incoming

		items[i].title	  = title;
		items[i].idx1	  = e1;
		items[i].idx2	  = e2;
		items[i].sort_key = (n1 > n2) ? n1 : n2;

		if (((i + 1) % report_every == 0) || (i + 1 == u)) {
			printf("\r       indexed: %zu / %zu (%.2f%%)           ", i + 1, u, ((double)(i + 1) * 100.0 / (double)u));
			fflush(stdout);
		}
	}
	free(uniq);
	printf("\n[done] indexing complete.\n\n");
	fflush(stdout);

	/* 7) Sort by descending INCOMING degree */
	printf("[step] sorting union items by incoming-degree desc...\n");
	fflush(stdout);
	qsort(items, u, sizeof(PageUnionItem), cmp_union_items_desc);
	printf("[done] sorting complete.\n\n");
	fflush(stdout);

	/* 8) Emit diffs with progress */
	printf("[step] writing diffs to '%s'...\n", out_path);
	fflush(stdout);
	for (size_t i = 0; i < u; i++) {
		PageUnionItem* it = &items[i];

		if (it->idx1 >= 0 && it->idx2 < 0) {
			fprintf(out, "\n\n# -");
			fprint_string(out, it->title);
			fputc('\n', out);
			size_t	nA = 0;
			string* A  = collect_link_titles(&db1, it->idx1, &nA);
			qsort(A, nA, sizeof(string), cmp_qsort_strings);
			for (size_t t = 0; t < nA; t++) {
				fprintf(out, "    - ");
				fprint_string(out, A[t]);
				fputc('\n', out);
			}
			free(A);
		} else if (it->idx2 >= 0 && it->idx1 < 0) {
			fprintf(out, "\n\n# +");
			fprint_string(out, it->title);
			fputc('\n', out);
			size_t	nB = 0;
			string* B  = collect_link_titles(&db2, it->idx2, &nB);
			qsort(B, nB, sizeof(string), cmp_qsort_strings);
			for (size_t t = 0; t < nB; t++) {
				fprintf(out, "    + ");
				fprint_string(out, B[t]);
				fputc('\n', out);
			}
			free(B);
		} else {
			size_t	nA = 0, nB = 0;
			string* A = collect_link_titles(&db1, it->idx1, &nA);
			string* B = collect_link_titles(&db2, it->idx2, &nB);

			string* Aeq = nA ? (string*)malloc(sizeof(string) * nA) : NULL;
			string* Beq = nB ? (string*)malloc(sizeof(string) * nB) : NULL;
			if (Aeq) memcpy(Aeq, A, sizeof(string) * nA);
			if (Beq) memcpy(Beq, B, sizeof(string) * nB);

			int equal = link_sets_equal(Aeq ? Aeq : A, nA, Beq ? Beq : B, nB);
			if (Aeq) free(Aeq);
			if (Beq) free(Beq);

			if (!equal) {
				fprintf(out, "\n\n# ");
				fprint_string(out, it->title);
				fputc('\n', out);
				diff_and_write(out, A, nA, B, nB);
			}
			free(A);
			free(B);
		}

		if (((i + 1) % report_every) == 0 || (i + 1) == u) {
			double pct = (u == 0) ? 100.0 : ((double)(i + 1) * 100.0 / (double)u);
			printf("\r       written: %d / %d (%.2f%%)               ", (int)(i + 1), (int)u, pct);
			fflush(stdout);
		}
	}
	printf("\n[done] finished writing diffs.\n\n");
	fflush(stdout);

	/* 9) Cleanup */
	free(items);
	free(indeg1);
	free(indeg2);
	free(idx1);
	free(idx2);
	free(db1.entries);
	free(db2.entries);
	free(db1.backing_mem);
	free(db2.backing_mem);
	fclose(out);

	fprintf(stderr, "Wrote diffs to %s\n", out_path);
	return 0;
}
