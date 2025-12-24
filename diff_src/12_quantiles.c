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
