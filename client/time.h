#define nanosecond (1ull)
#define microsecond (1000ull * nanosecond)
#define millisecond (1000ull * microsecond)
#define second (1000ull * millisecond)


#ifdef _WIN32
LARGE_INTEGER __freq;

#define TIME_INIT() do { \
	QueryPerformanceFrequency(&__freq); \
} while(0)
#else
#define TIME_INIT()
#endif

INLINE u64 get_monotonic_time() {
	#ifdef _WIN32
		LARGE_INTEGER t;
		QueryPerformanceCounter(&t);

		return t.QuadPart * second / __freq.QuadPart;
	#else
		struct timespec t;
		clock_gettime(CLOCK_MONOTONIC, &t);
		return (u64)t.tv_sec * second + t.tv_nsec;
	#endif
}

INLINE string format_time(u64 ts) {
	char buf[64] = {0};

	if (ts < millisecond) return SLIT("1ms");
	if (ts < second) snprintf(buf, sizeof(buf), "%llums", ts / millisecond);
	else snprintf(buf, sizeof(buf), "%.1f sec", (f64)ts / second);

	return string_clone(STR(buf, strlen(buf)));
}
