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
