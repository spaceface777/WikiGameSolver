// gen_prsampler_index.c
// Load ONE Wikipedia link DB (.xz), compute PageRank, build PRSampler,
// and write 1,000,000 sampled entry titles (newline-separated).
//
// Build (macOS): cc -O2 -std=c11 -Wall -Wextra -pedantic gen_prsampler_index.c -lm -o gen_prsampler_index

#include "diff_src/00_prelude.c"
#include "diff_src/02_title_helpers.c"
#include "diff_src/03_xz.c"
#include "diff_src/04_db_parsing.c"

static uint64_t rng64(uint64_t* s) {
	// xorshift64*
	uint64_t x = *s;
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	*s = x;
	return x * 2685821657736338717ULL;
}

#include "diff_src/08_topk.c"
#include "diff_src/10_pagerank.c"
#include "diff_src/13_prsampler.c"

static CombinedMap build_combined_single(const WikiDB* db) {
	if (!db || db->nr_entries <= 0) die("build_combined_single: empty db");

	CombinedMap cm;
	memset(&cm, 0, sizeof(cm));

	cm.n		 = (uint32_t)db->nr_entries;
	cm.titles	 = (TitleRef*)xmalloc((size_t)cm.n * sizeof(TitleRef));
	cm.mapB		 = (uint32_t*)xmalloc((size_t)cm.n * sizeof(uint32_t));
	cm.locA_of_g = (int32_t*)xmalloc((size_t)cm.n * sizeof(int32_t));
	cm.locB_of_g = (int32_t*)xmalloc((size_t)cm.n * sizeof(int32_t));

	for (uint32_t i = 0; i < cm.n; i++) {
		cm.titles[i]	= db_title_ref(db, (int32_t)i);
		cm.mapB[i]		= i;
		cm.locA_of_g[i] = -1;
		cm.locB_of_g[i] = (int32_t)i;
	}

	cm.common_titles  = cm.n;
	cm.added_titles	  = 0;
	cm.removed_titles = 0;
	return cm;
}

static void combined_single_free(CombinedMap* cm) {
	if (!cm) return;
	if (cm->titles) free(cm->titles);
	if (cm->mapA) free(cm->mapA);
	if (cm->mapB) free(cm->mapB);
	if (cm->locA_of_g) free(cm->locA_of_g);
	if (cm->locB_of_g) free(cm->locB_of_g);
	memset(cm, 0, sizeof(*cm));
}

static uint64_t parse_u64_or_die(const char* s, const char* what) {
	if (!s || !*s) die("missing integer argument");
	errno				   = 0;
	char*			   end = NULL;
	unsigned long long v   = strtoull(s, &end, 10);
	if (errno != 0 || !end || *end != '\0') {
		fprintf(stderr, "error: invalid %s: %s\n", what, s);
		exit(2);
	}
	return (uint64_t)v;
}

int main(int argc, char** argv) {
	if (argc < 3) {
		fprintf(stderr, "usage: %s <wiki_db.xz> <out.txt> [seed] [alpha]\n", argv[0]);
		fprintf(stderr, "  Writes 1,000,000 newline-separated sampled titles.\n");
		fprintf(stderr, "  seed  (default 1234567)\n");
		fprintf(stderr, "  alpha (default 2.0) biases toward high-PR nodes\n");
		return 2;
	}

	const char* db_path	 = argv[1];
	const char* out_path = argv[2];
	uint64_t	seed	 = (argc >= 4) ? parse_u64_or_die(argv[3], "seed") : 1234567ULL;
	double		alpha	 = 2.0;
	if (argc >= 5) {
		char* end = NULL;
		errno	  = 0;
		alpha	  = strtod(argv[4], &end);
		if (errno != 0 || !end || *end != '\0' || !(alpha > 0.0)) {
			fprintf(stderr, "error: invalid alpha: %s\n", argv[4]);
			return 2;
		}
	}

	WikiDB db;
	if (!db_load_xz(&db, db_path)) die("failed loading db");

	CombinedMap cm = build_combined_single(&db);

	uint8_t* active = (uint8_t*)xmalloc((size_t)cm.n);
	memset(active, 1, (size_t)cm.n);
	uint8_t* cheese = build_cheese_mask(&cm);

	double* pr = NULL;
	PRMeta	meta;
	pagerank_compute_B(&db, &cm, active, cheese, 0 /*no_cheese_edges*/, 30 /*iters*/, 0.85 /*damp*/, 0.0 /*eps*/, &pr,
					   &meta);

	PRSampler samp;
	if (!prsampler_build(&samp, pr, active, cm.n, alpha, seed)) die("failed to build PRSampler");

	FILE* out = fopen(out_path, "wb");
	if (!out) {
		fprintf(stderr, "error: open %s: %s\n", out_path, strerror(errno));
		return 1;
	}

	const uint32_t nsamples = 1000000u;
	for (uint32_t i = 0; i < nsamples; i++) {
		uint32_t g = random_biased(&samp);
		fprint_title(out, cm.titles[g]);
		fputc('\n', out);
	}

	if (ferror(out)) {
		fprintf(stderr, "error: write failed: %s\n", strerror(errno));
		fclose(out);
		return 1;
	}
	fclose(out);

	prsampler_free(&samp);
	free(pr);
	free(active);
	free(cheese);
	combined_single_free(&cm);
	db_free(&db);
	return 0;
}
