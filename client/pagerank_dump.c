// Build a mmap-friendly pagerank alias-table dump file.
//
// File format (all fields little-endian):
//
//   Header (16 bytes):
//     u8[4]  magic        "PRDB"
//     u32    version      1
//     u32    count        N (number of entries)
//     u32    strings_off  byte offset from file start to string pool
//
//   Entry table (N * 12 bytes):
//     u32    str_off      offset into string pool for this entry's title
//     u32    alias_idx    alias table index
//     f32    prob         probability threshold [0,1]
//
//   String pool:
//     packed title bytes (no terminators)
//
//   Title length for entry i is derived as:
//     i < N-1: entry[i+1].str_off - entry[i].str_off
//     i == N-1: (file_size - strings_off) - entry[i].str_off
//
// Sampling is O(1):
//   i = random % N
//   u = random_double [0,1)
//   j = (u < entry[i].prob) ? i : entry[i].alias_idx
//   title = string_pool[entry[j].str_off .. +str_len_of(j)]

#include <float.h>
#include <math.h>

#define PRDUMP_MAGIC_0 'P'
#define PRDUMP_MAGIC_1 'R'
#define PRDUMP_MAGIC_2 'D'
#define PRDUMP_MAGIC_3 'B'
#define PRDUMP_VERSION 1

#pragma pack(push, 1)
typedef struct {
	u8  magic[4];
	u32 version;
	u32 count;
	u32 strings_off;
} PRDumpHeader;

typedef struct {
	u32   str_off;
	u32   alias_idx;
	float prob;
} PRDumpEntry;
#pragma pack(pop)

_Static_assert(sizeof(PRDumpHeader) == 16, "PRDumpHeader must be 16 bytes");
_Static_assert(sizeof(PRDumpEntry) == 12, "PRDumpEntry must be 12 bytes");

STATIC void pagerank_dump(Graph* g, const char* out_path) {
	if (!g || !g->validated) {
		fprintf(stderr, "error: pagerank_dump requires validated graph\n");
		exit(1);
	}

	// Build pagerank if not already computed
	pagerank_build(g, 100, 0.85, 1e-8, 1.2);

	u32            N  = g->N;
	const double*  pr = g->pagerank;

	printf("Building alias table for %u nodes...\n", (unsigned)N);

	// --- Build alias table (same algorithm as bench_mode.c PRSampler) ---
	u32*   alias = (u32*)malloc((size_t)N * sizeof(u32));
	float* prob  = (float*)malloc((size_t)N * sizeof(float));
	if (!alias || !prob) {
		fprintf(stderr, "error: OOM in pagerank_dump alias alloc\n");
		exit(1);
	}

	double* q     = (double*)malloc((size_t)N * sizeof(double));
	u32*    small = (u32*)malloc((size_t)N * sizeof(u32));
	u32*    large = (u32*)malloc((size_t)N * sizeof(u32));
	if (!q || !small || !large) {
		fprintf(stderr, "error: OOM in pagerank_dump work arrays\n");
		exit(1);
	}

	double sum = 0.0;
	for (u32 i = 0; i < N; i++) {
		double w = pr[i];
		if (w <= 0.0) w = DBL_MIN;
		q[i] = w;
		sum += w;
	}

	if (!(sum > 0.0)) {
		fprintf(stderr, "error: pagerank sum is zero\n");
		exit(1);
	}

	double scale = (double)N / sum;
	u32    ns = 0, nl = 0;
	for (u32 i = 0; i < N; i++) {
		q[i] *= scale;
		if (q[i] < 1.0) small[ns++] = i;
		else large[nl++] = i;
	}

	while (ns && nl) {
		u32 s = small[--ns];
		u32 l = large[--nl];

		double ps = q[s];
		if (ps < 0.0) ps = 0.0;
		if (ps > 1.0) ps = 1.0;
		prob[s]  = (float)ps;
		alias[s] = l;

		q[l] = (q[l] + q[s]) - 1.0;
		if (q[l] < 1.0) small[ns++] = l;
		else large[nl++] = l;
	}

	while (nl) {
		u32 i    = large[--nl];
		prob[i]  = 1.0f;
		alias[i] = i;
	}
	while (ns) {
		u32 i    = small[--ns];
		prob[i]  = 1.0f;
		alias[i] = i;
	}

	free(q);
	free(small);
	free(large);

	// --- Compute string pool layout ---
	u32 total_str_bytes = 0;
	for (u32 i = 0; i < N; i++) {
		total_str_bytes += (u32)STR_LEN(g->titles[i]);
	}

	u32 strings_off = (u32)(sizeof(PRDumpHeader) + (size_t)N * sizeof(PRDumpEntry));

	// --- Build entry table ---
	PRDumpEntry* entries = (PRDumpEntry*)malloc((size_t)N * sizeof(PRDumpEntry));
	if (!entries) {
		fprintf(stderr, "error: OOM in pagerank_dump entries\n");
		exit(1);
	}

	u32 str_cursor = 0;
	for (u32 i = 0; i < N; i++) {
		u32 slen             = (u32)STR_LEN(g->titles[i]);
		entries[i].str_off   = str_cursor;
		entries[i].alias_idx = alias[i];
		entries[i].prob      = prob[i];
		str_cursor += slen;
	}

	free(alias);
	free(prob);

	// --- Write file ---
	FILE* f = fopen(out_path, "wb");
	if (!f) {
		fprintf(stderr, "error: cannot open '%s' for writing: %s\n", out_path, strerror(errno));
		exit(1);
	}

	PRDumpHeader hdr;
	hdr.magic[0]    = PRDUMP_MAGIC_0;
	hdr.magic[1]    = PRDUMP_MAGIC_1;
	hdr.magic[2]    = PRDUMP_MAGIC_2;
	hdr.magic[3]    = PRDUMP_MAGIC_3;
	hdr.version     = PRDUMP_VERSION;
	hdr.count       = N;
	hdr.strings_off = strings_off;

	if (fwrite(&hdr, sizeof(hdr), 1, f) != 1) goto write_err;
	if (fwrite(entries, sizeof(PRDumpEntry), N, f) != N) goto write_err;

	// Write string pool
	for (u32 i = 0; i < N; i++) {
		u32         slen = (u32)STR_LEN(g->titles[i]);
		const char* sptr = STR_PTR(g->titles[i]);
		if (slen > 0 && fwrite(sptr, 1, slen, f) != slen) goto write_err;
	}

	fclose(f);
	free(entries);

	u64 file_size = (u64)strings_off + (u64)total_str_bytes;
	printf("Wrote pagerank dump: %s (%llu bytes, %u entries, %u string bytes)\n",
	       out_path, (unsigned long long)file_size, (unsigned)N, (unsigned)total_str_bytes);
	return;

write_err:
	fprintf(stderr, "error: failed to write '%s': %s\n", out_path, strerror(errno));
	fclose(f);
	free(entries);
	exit(1);
}
