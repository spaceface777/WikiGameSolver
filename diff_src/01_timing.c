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
