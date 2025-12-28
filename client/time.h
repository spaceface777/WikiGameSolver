// #pragma once
// #include <stdint.h>
// #include <stdio.h>
// #include <time.h>
// #include <string.h>

// typedef uint64_t u64;
// typedef double   f64;

#define nanosecond	(1ull)
#define microsecond (1000ull * nanosecond)
#define millisecond (1000ull * microsecond)
#define second		(1000ull * millisecond)

#ifdef _WIN32
#include <windows.h>
static LARGE_INTEGER __freq;
#define TIME_INIT() QueryPerformanceFrequency(&__freq)
#else
#define TIME_INIT()
#endif

static inline u64 get_monotonic_time(void) {
#ifdef _WIN32
	LARGE_INTEGER t;
	QueryPerformanceCounter(&t);
	return (u64)t.QuadPart * second / __freq.QuadPart;
#else
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (u64)t.tv_sec * second + (u64)t.tv_nsec;
#endif
}

/* --- Simple formatting helpers --- */

static inline const char* fmt_timebuf(u64 dt, char* buf, size_t sz) {
	if (dt <= microsecond) snprintf(buf, sz, "%llu ns", (unsigned long long)dt);
	if (dt <= millisecond) snprintf(buf, sz, "%llu µs", (unsigned long long)(dt / 1000));
	else if (dt < second) snprintf(buf, sz, "%.3f ms", (double)dt / 1e6);
	else snprintf(buf, sz, "%.3f s", (double)dt / 1e9);
	return buf;
}

/* --- Timer struct for scoped timing --- */
typedef struct {
	u64 start;
	const char* label;
} Timer;

static inline Timer timer_begin(const char* label) {
	Timer t = { .start = get_monotonic_time(), .label = label };
	return t;
}

static inline void timer_end(Timer t) {
	u64 end = get_monotonic_time();
	char tmp[64];
	fmt_timebuf(end - t.start, tmp, sizeof(tmp));
	fprintf(stderr, "[%s] took %s\n", t.label ? t.label : "step", tmp);
}

/* --- Utility macro for inline profiling --- */
#define TIME_STEP(label, block)                                      \
	do {                                                             \
		u64 __t0 = get_monotonic_time();                             \
		{ block; }                                                   \
		u64 __t1 = get_monotonic_time();                             \
		char __buf[64];                                              \
		fmt_timebuf(__t1 - __t0, __buf, sizeof(__buf));              \
		fprintf(stderr, "[%s] finished in %s\n", (label), __buf);    \
	} while (0)

/* --- Timestamped log line --- */
static inline void log_ts(const char* msg) {
	static u64 base = 0;
	if (!base) base = get_monotonic_time();
	u64 now = get_monotonic_time();
	char tmp[64];
	fmt_timebuf(now - base, tmp, sizeof(tmp));
	fprintf(stderr, "[%s] %s\n", tmp, msg);
}
