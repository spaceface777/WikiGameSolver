#ifdef __linux__
	// // fixes sqlite compilation
	// #define _GNU_SOURCE 1
	// #include <unistd.h>
	// #include <sys/mman.h>
	#define HAVE_MREMAP 0
#endif

// perf. improvements
#define SQLITE_DQS 0
#define SQLITE_DEFAULT_MEMSTATUS 0
#define SQLITE_DEFAULT_WAL_SYNCHRONOUS 1
#define SQLITE_LIKE_DOESNT_MATCH_BLOBS 1
#define SQLITE_MAX_EXPR_DEPTH 0
#define SQLITE_OMIT_DECLTYPE 1
#define SQLITE_OMIT_DEPRECATED 1
#define SQLITE_OMIT_PROGRESS_CALLBACK 1
#define SQLITE_OMIT_SHARED_CACHE 1
#define SQLITE_OMIT_AUTOINIT 1

#ifndef __TINYC__
	#define SQLITE_USE_ALLOCA 1
#endif

#define SQLITE_DEFAULT_LOCKING_MODE 1

#include "thirdparty/sqlite3.c"
#include "thirdparty/sqlite3.h"


#define SQL_PANIC(msg) {\
	fprintf(stderr, "panic: "msg": %s\n", sqlite3_errmsg(db));\
	exit(1);\
}

#ifndef NASSERT
	#define SQL_ASSERT(cond, msg) { if (!(cond)) { SQL_PANIC(msg) } }
#else
	#define SQL_ASSERT(cond, msg) { (cond) }
#endif
