// copy something to the heap
// #define HEAP(src) ((typeof(src)*)memcpy(malloc(sizeof(src)), &((typeof(src)[]){src}), sizeof(src)))
#define HEAP(src) (memcpy(malloc(sizeof(src)), &src, sizeof(src)))

#define null NULL

#define INLINE static inline __attribute__((always_inline))

// see https://stackoverflow.com/a/18584390
#define VA_LENGTH(...) VA_LENGTH_(0, ## __VA_ARGS__, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
#define VA_LENGTH_(_0, _1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, N, ...) N

#define QUERY(src) ""src, sizeof(src)

#define PANIC(msg) {\
	fprintf(stderr, "panic: "msg);\
	exit(1);\
}

#define SQL_PANIC(msg) {\
	fprintf(stderr, "panic: "msg": %s\n", sqlite3_errmsg(db));\
	exit(1);\
}

#ifndef NASSERT
	#define ASSERT(cond, msg) {\
		if (!(cond)) { PANIC(msg) }\
	}

	#define SQL_ASSERT(cond, msg) {\
		if (!(cond)) { SQL_PANIC(msg) }\
	}
#else
	#define ASSERT(cond, msg) { (cond) }

	#define SQL_ASSERT(cond, msg) { (cond) }
	}
#endif

#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

INLINE void* memdup(const void* src, size_t len) {
	void* dst = malloc(len);
	memcpy(dst, src, len);
	return dst;
}