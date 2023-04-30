#ifndef TUKLIB_CPUCORES_H
#define TUKLIB_CPUCORES_H

#ifndef TUKLIB_COMMON_H
#define TUKLIB_COMMON_H

#ifdef HAVE_CONFIG_H

#ifndef LZMA_SYSDEFS_H
#define LZMA_SYSDEFS_H

#ifdef __MINGW32__
#define __USE_MINGW_ANSI_STDIO 1
#endif

#include <stddef.h>

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <limits.h>

#ifndef UINT32_C
#if UINT_MAX != 4294967295U
#error UINT32_C is not defined and unsigned int is not 32-bit.
#endif
#define UINT32_C(n) n ## U
#endif
#ifndef UINT32_MAX
#define UINT32_MAX UINT32_C(4294967295)
#endif
#ifndef PRIu32
#define PRIu32 "u"
#endif
#ifndef PRIx32
#define PRIx32 "x"
#endif
#ifndef PRIX32
#define PRIX32 "X"
#endif

#if ULONG_MAX == 4294967295UL
#ifndef UINT64_C
#define UINT64_C(n) n ## ULL
#endif
#ifndef PRIu64
#define PRIu64 "llu"
#endif
#ifndef PRIx64
#define PRIx64 "llx"
#endif
#ifndef PRIX64
#define PRIX64 "llX"
#endif
#else
#ifndef UINT64_C
#define UINT64_C(n) n ## UL
#endif
#ifndef PRIu64
#define PRIu64 "lu"
#endif
#ifndef PRIx64
#define PRIx64 "lx"
#endif
#ifndef PRIX64
#define PRIX64 "lX"
#endif
#endif
#ifndef UINT64_MAX
#define UINT64_MAX UINT64_C(18446744073709551615)
#endif

#if defined(__INTERIX) || defined(_SCO_DS)
#undef SIZE_MAX
#endif

#ifndef SIZE_MAX
#if SIZEOF_SIZE_T == 4
#define SIZE_MAX UINT32_MAX
#elif SIZEOF_SIZE_T == 8
#define SIZE_MAX UINT64_MAX
#else
#error size_t is not 32-bit or 64-bit
#endif
#endif
#if SIZE_MAX != UINT32_MAX && SIZE_MAX != UINT64_MAX
#error size_t is not 32-bit or 64-bit
#endif

#include <stdlib.h>
#include <assert.h>

#ifdef HAVE_STDBOOL_H
#include <stdbool.h>
#else
#if ! HAVE__BOOL
typedef unsigned char _Bool;
#endif
#define bool _Bool
#define false 0
#define true 1
#define __bool_true_false_are_defined 1
#endif

#include <string.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

#if defined(_WIN32) && defined(_MSC_VER)
#ifndef inline
#define inline __inline
#endif
#ifndef restrict
#define restrict __restrict
#endif
#endif

#undef memzero
#define memzero(s, n) memset(s, 0, n)

#define my_min(x, y) ((x) < (y) ? (x) : (y))
#define my_max(x, y) ((x) > (y) ? (x) : (y))

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#endif

#if defined(__GNUC__) && ((__GNUC__ == 4 && __GNUC_MINOR__ >= 3) || __GNUC__ > 4)
#define lzma_attr_alloc_size(x) __attribute__((__alloc_size__(x)))
#else
#define lzma_attr_alloc_size(x)
#endif

#endif

#else
#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>
#endif

#ifndef TUKLIB_SYMBOL_PREFIX
#define TUKLIB_SYMBOL_PREFIX
#endif

#define TUKLIB_CAT_X(a, b) a ## b
#define TUKLIB_CAT(a, b) TUKLIB_CAT_X(a, b)

#ifndef TUKLIB_SYMBOL
#define TUKLIB_SYMBOL(sym) TUKLIB_CAT(TUKLIB_SYMBOL_PREFIX, sym)
#endif

#ifndef TUKLIB_DECLS_BEGIN
#ifdef __cplusplus
#define TUKLIB_DECLS_BEGIN extern "C" {
#else
#define TUKLIB_DECLS_BEGIN
#endif
#endif

#ifndef TUKLIB_DECLS_END
#ifdef __cplusplus
#define TUKLIB_DECLS_END }
#else
#define TUKLIB_DECLS_END
#endif
#endif

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#define TUKLIB_GNUC_REQ(major, minor) ((__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)) || __GNUC__ > (major))
#else
#define TUKLIB_GNUC_REQ(major, minor) 0
#endif

#if TUKLIB_GNUC_REQ(2, 5)
#define tuklib_attr_noreturn __attribute__((__noreturn__))
#else
#define tuklib_attr_noreturn
#endif

#if (defined(_WIN32) && !defined(__CYGWIN__)) || defined(__OS2__) || defined(__MSDOS__)
#define TUKLIB_DOSLIKE 1
#endif

#endif

TUKLIB_DECLS_BEGIN

#define tuklib_cpucores TUKLIB_SYMBOL(tuklib_cpucores)
extern uint32_t tuklib_cpucores(void);

TUKLIB_DECLS_END
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0500
#endif
#include <windows.h>

#elif defined(TUKLIB_CPUCORES_SCHED_GETAFFINITY)
#include <sched.h>

#elif defined(TUKLIB_CPUCORES_CPUSET)
#include <sys/param.h>
#include <sys/cpuset.h>

#elif defined(TUKLIB_CPUCORES_SYSCTL)
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/sysctl.h>

#elif defined(TUKLIB_CPUCORES_SYSCONF)
#include <unistd.h>

#elif defined(TUKLIB_CPUCORES_PSTAT_GETDYNAMIC)
#include <sys/param.h>
#include <sys/pstat.h>
#endif

extern uint32_t
tuklib_cpucores(void)
{
	uint32_t ret = 0;

#if defined(_WIN32) || defined(__CYGWIN__)
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	ret = sysinfo.dwNumberOfProcessors;

#elif defined(TUKLIB_CPUCORES_SCHED_GETAFFINITY)
	cpu_set_t cpu_mask;
	if (sched_getaffinity(0, sizeof(cpu_mask), &cpu_mask) == 0)
		ret = (uint32_t)CPU_COUNT(&cpu_mask);

#elif defined(TUKLIB_CPUCORES_CPUSET)
	cpuset_t set;
	if (cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
			sizeof(set), &set) == 0) {
#ifdef CPU_COUNT
		ret = (uint32_t)CPU_COUNT(&set);
#else
		for (unsigned i = 0; i < CPU_SETSIZE; ++i)
			if (CPU_ISSET(i, &set))
				++ret;
#endif
	}

#elif defined(TUKLIB_CPUCORES_SYSCTL)

#ifdef HW_NCPUONLINE
	int name[2] = { CTL_HW, HW_NCPUONLINE };
#else
	int name[2] = { CTL_HW, HW_NCPU };
#endif
	int cpus;
	size_t cpus_size = sizeof(cpus);
	if (sysctl(name, 2, &cpus, &cpus_size, NULL, 0) != -1
			&& cpus_size == sizeof(cpus) && cpus > 0)
		ret = (uint32_t)cpus;

#elif defined(TUKLIB_CPUCORES_SYSCONF)
#ifdef _SC_NPROCESSORS_ONLN

	const long cpus = sysconf(_SC_NPROCESSORS_ONLN);
#else

	const long cpus = sysconf(_SC_NPROC_ONLN);
#endif
	if (cpus > 0)
		ret = (uint32_t)cpus;

#elif defined(TUKLIB_CPUCORES_PSTAT_GETDYNAMIC)
	struct pst_dynamic pst;
	if (pstat_getdynamic(&pst, sizeof(pst), 1, 0) != -1)
		ret = (uint32_t)pst.psd_proc_cnt;
#endif

	return ret;
}

#ifndef TUKLIB_PHYSMEM_H
#define TUKLIB_PHYSMEM_H

TUKLIB_DECLS_BEGIN

#define tuklib_physmem TUKLIB_SYMBOL(tuklib_physmem)
extern uint64_t tuklib_physmem(void);

TUKLIB_DECLS_END
#endif

#if defined(_WIN32) || defined(__CYGWIN__)
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0500
#endif
#include <windows.h>

#elif defined(__OS2__)
#define INCL_DOSMISC
#include <os2.h>

#elif defined(__DJGPP__)
#include <dpmi.h>

#elif defined(__VMS)
#include <lib$routines.h>
#include <syidef.h>
#include <ssdef.h>

#elif defined(AMIGA) || defined(__AROS__)
#define __USE_INLINE__
#include <proto/exec.h>

#elif defined(__QNX__)
#include <sys/syspage.h>
#include <string.h>

#elif defined(TUKLIB_PHYSMEM_AIX)
#include <sys/systemcfg.h>

#elif defined(TUKLIB_PHYSMEM_SYSCONF)
#include <unistd.h>

#elif defined(TUKLIB_PHYSMEM_SYSCTL)
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/sysctl.h>

#elif defined(TUKLIB_PHYSMEM_GETSYSINFO)
#include <sys/sysinfo.h>
#include <machine/hal_sysinfo.h>

#elif defined(TUKLIB_PHYSMEM_PSTAT_GETSTATIC)
#include <sys/param.h>
#include <sys/pstat.h>

#elif defined(TUKLIB_PHYSMEM_GETINVENT_R)
#include <invent.h>

#elif defined(TUKLIB_PHYSMEM_SYSINFO)
#include <sys/sysinfo.h>
#endif

extern uint64_t
tuklib_physmem(void)
{
	uint64_t ret = 0;

#if defined(_WIN32) || defined(__CYGWIN__)
	if ((GetVersion() & 0xFF) >= 5) {

		HMODULE kernel32 = GetModuleHandle(TEXT("kernel32.dll"));
		if (kernel32 != NULL) {
			typedef BOOL (WINAPI *gmse_type)(LPMEMORYSTATUSEX);
			gmse_type gmse = (gmse_type)GetProcAddress(
					kernel32, "GlobalMemoryStatusEx");
			if (gmse != NULL) {
				MEMORYSTATUSEX meminfo;
				meminfo.dwLength = sizeof(meminfo);
				if (gmse(&meminfo))
					ret = meminfo.ullTotalPhys;
			}
		}
	}

	if (ret == 0) {

		MEMORYSTATUS meminfo;
		meminfo.dwLength = sizeof(meminfo);
		GlobalMemoryStatus(&meminfo);
		ret = meminfo.dwTotalPhys;
	}

#elif defined(__OS2__)
	unsigned long mem;
	if (DosQuerySysInfo(QSV_TOTPHYSMEM, QSV_TOTPHYSMEM,
			&mem, sizeof(mem)) == 0)
		ret = mem;

#elif defined(__DJGPP__)
	__dpmi_free_mem_info meminfo;
	if (__dpmi_get_free_memory_information(&meminfo) == 0
			&& meminfo.total_number_of_physical_pages
				!= (unsigned long)-1)
		ret = (uint64_t)meminfo.total_number_of_physical_pages * 4096;

#elif defined(__VMS)
	int vms_mem;
	int val = SYI$_MEMSIZE;
	if (LIB$GETSYI(&val, &vms_mem, 0, 0, 0, 0) == SS$_NORMAL)
		ret = (uint64_t)vms_mem * 8192;

#elif defined(AMIGA) || defined(__AROS__)
	ret = AvailMem(MEMF_TOTAL);

#elif defined(__QNX__)
	const struct asinfo_entry *entries = SYSPAGE_ENTRY(asinfo);
	size_t count = SYSPAGE_ENTRY_SIZE(asinfo) / sizeof(struct asinfo_entry);
	const char *strings = SYSPAGE_ENTRY(strings)->data;

	for (size_t i = 0; i < count; ++i)
		if (strcmp(strings + entries[i].name, "ram") == 0)
			ret += entries[i].end - entries[i].start + 1;

#elif defined(TUKLIB_PHYSMEM_AIX)
	ret = _system_configuration.physmem;

#elif defined(TUKLIB_PHYSMEM_SYSCONF)
	const long pagesize = sysconf(_SC_PAGESIZE);
	const long pages = sysconf(_SC_PHYS_PAGES);
	if (pagesize != -1 && pages != -1)

		ret = (uint64_t)pagesize * (uint64_t)pages;

#elif defined(TUKLIB_PHYSMEM_SYSCTL)
	int name[2] = {
		CTL_HW,
#ifdef HW_PHYSMEM64
		HW_PHYSMEM64
#else
		HW_PHYSMEM
#endif
	};
	union {
		uint32_t u32;
		uint64_t u64;
	} mem;
	size_t mem_ptr_size = sizeof(mem.u64);
	if (sysctl(name, 2, &mem.u64, &mem_ptr_size, NULL, 0) != -1) {

		if (mem_ptr_size == sizeof(mem.u64))
			ret = mem.u64;
		else if (mem_ptr_size == sizeof(mem.u32))
			ret = mem.u32;
	}

#elif defined(TUKLIB_PHYSMEM_GETSYSINFO)

	int memkb;
	int start = 0;
	if (getsysinfo(GSI_PHYSMEM, (caddr_t)&memkb, sizeof(memkb), &start)
			!= -1)
		ret = (uint64_t)memkb * 1024;

#elif defined(TUKLIB_PHYSMEM_PSTAT_GETSTATIC)
	struct pst_static pst;
	if (pstat_getstatic(&pst, sizeof(pst), 1, 0) != -1)
		ret = (uint64_t)pst.physical_memory * (uint64_t)pst.page_size;

#elif defined(TUKLIB_PHYSMEM_GETINVENT_R)
	inv_state_t *st = NULL;
	if (setinvent_r(&st) != -1) {
		inventory_t *i;
		while ((i = getinvent_r(st)) != NULL) {
			if (i->inv_class == INV_MEMORY
					&& i->inv_type == INV_MAIN_MB) {
				ret = (uint64_t)i->inv_state << 20;
				break;
			}
		}

		endinvent_r(st);
	}

#elif defined(TUKLIB_PHYSMEM_SYSINFO)
	struct sysinfo si;
	if (sysinfo(&si) == 0)
		ret = (uint64_t)si.totalram * si.mem_unit;
#endif

	return ret;
}

#ifndef LZMA_ALONE_DECODER_H
#define LZMA_ALONE_DECODER_H

#ifndef LZMA_COMMON_H
#define LZMA_COMMON_H

#ifndef MYTHREAD_H
#define MYTHREAD_H

#if defined(MYTHREAD_POSIX) || defined(MYTHREAD_WIN95) || defined(MYTHREAD_VISTA)
#define MYTHREAD_ENABLED 1
#endif

#ifdef MYTHREAD_ENABLED

#define mythread_sync(mutex) mythread_sync_helper1(mutex, __LINE__)
#define mythread_sync_helper1(mutex, line) mythread_sync_helper2(mutex, line)
#define mythread_sync_helper2(mutex, line) for (unsigned int mythread_i_ ## line = 0; mythread_i_ ## line ? (mythread_mutex_unlock(&(mutex)), 0) : (mythread_mutex_lock(&(mutex)), 1); mythread_i_ ## line = 1) for (unsigned int mythread_j_ ## line = 0; !mythread_j_ ## line; mythread_j_ ## line = 1)
#endif

#if !defined(MYTHREAD_ENABLED)

#define mythread_once(func) \
do { static bool once_ = false; if (!once_) { func(); once_ = true; } \
} while (0)

#if !(defined(_WIN32) && !defined(__CYGWIN__))

#include <signal.h>

static inline void
mythread_sigmask(int how, const sigset_t *restrict set,
		sigset_t *restrict oset)
{
	int ret = sigprocmask(how, set, oset);
	assert(ret == 0);
	(void)ret;
}
#endif

#elif defined(MYTHREAD_POSIX)

#include <sys/time.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

#define MYTHREAD_RET_TYPE void *
#define MYTHREAD_RET_VALUE NULL

typedef pthread_t mythread;
typedef pthread_mutex_t mythread_mutex;

typedef struct {
	pthread_cond_t cond;
#ifdef HAVE_CLOCK_GETTIME

	clockid_t clk_id;
#endif
} mythread_cond;

typedef struct timespec mythread_condtime;

#define mythread_once(func) do { static pthread_once_t once_ = PTHREAD_ONCE_INIT; pthread_once(&once_, &func); } while (0)

static inline void
mythread_sigmask(int how, const sigset_t *restrict set,
		sigset_t *restrict oset)
{
#ifdef __VMS
	(void)how;
	(void)set;
	(void)oset;
#else
	int ret = pthread_sigmask(how, set, oset);
	assert(ret == 0);
	(void)ret;
#endif
}

static inline int
mythread_create(mythread *thread, void *(*func)(void *arg), void *arg)
{
	sigset_t old;
	sigset_t all;
	sigfillset(&all);

	mythread_sigmask(SIG_SETMASK, &all, &old);
	const int ret = pthread_create(thread, NULL, func, arg);
	mythread_sigmask(SIG_SETMASK, &old, NULL);

	return ret;
}

static inline int
mythread_join(mythread thread)
{
	return pthread_join(thread, NULL);
}

static inline int
mythread_mutex_init(mythread_mutex *mutex)
{
	return pthread_mutex_init(mutex, NULL);
}

static inline void
mythread_mutex_destroy(mythread_mutex *mutex)
{
	int ret = pthread_mutex_destroy(mutex);
	assert(ret == 0);
	(void)ret;
}

static inline void
mythread_mutex_lock(mythread_mutex *mutex)
{
	int ret = pthread_mutex_lock(mutex);
	assert(ret == 0);
	(void)ret;
}

static inline void
mythread_mutex_unlock(mythread_mutex *mutex)
{
	int ret = pthread_mutex_unlock(mutex);
	assert(ret == 0);
	(void)ret;
}

static inline int
mythread_cond_init(mythread_cond *mycond)
{
#ifdef HAVE_CLOCK_GETTIME

#if defined(HAVE_PTHREAD_CONDATTR_SETCLOCK) && HAVE_DECL_CLOCK_MONOTONIC
	struct timespec ts;
	pthread_condattr_t condattr;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0
			&& pthread_condattr_init(&condattr) == 0) {
		int ret = pthread_condattr_setclock(
				&condattr, CLOCK_MONOTONIC);
		if (ret == 0)
			ret = pthread_cond_init(&mycond->cond, &condattr);

		pthread_condattr_destroy(&condattr);

		if (ret == 0) {
			mycond->clk_id = CLOCK_MONOTONIC;
			return 0;
		}
	}

#endif

	mycond->clk_id = CLOCK_REALTIME;
#endif

	return pthread_cond_init(&mycond->cond, NULL);
}

static inline void
mythread_cond_destroy(mythread_cond *cond)
{
	int ret = pthread_cond_destroy(&cond->cond);
	assert(ret == 0);
	(void)ret;
}

static inline void
mythread_cond_signal(mythread_cond *cond)
{
	int ret = pthread_cond_signal(&cond->cond);
	assert(ret == 0);
	(void)ret;
}

static inline void
mythread_cond_wait(mythread_cond *cond, mythread_mutex *mutex)
{
	int ret = pthread_cond_wait(&cond->cond, mutex);
	assert(ret == 0);
	(void)ret;
}

static inline int
mythread_cond_timedwait(mythread_cond *cond, mythread_mutex *mutex,
		const mythread_condtime *condtime)
{
	int ret = pthread_cond_timedwait(&cond->cond, mutex, condtime);
	assert(ret == 0 || ret == ETIMEDOUT);
	return ret;
}

static inline void
mythread_condtime_set(mythread_condtime *condtime, const mythread_cond *cond,
		uint32_t timeout_ms)
{
	condtime->tv_sec = timeout_ms / 1000;
	condtime->tv_nsec = (timeout_ms % 1000) * 1000000;

#ifdef HAVE_CLOCK_GETTIME
	struct timespec now;
	int ret = clock_gettime(cond->clk_id, &now);
	assert(ret == 0);
	(void)ret;

	condtime->tv_sec += now.tv_sec;
	condtime->tv_nsec += now.tv_nsec;
#else
	(void)cond;

	struct timeval now;
	gettimeofday(&now, NULL);

	condtime->tv_sec += now.tv_sec;
	condtime->tv_nsec += now.tv_usec * 1000L;
#endif

	if (condtime->tv_nsec >= 1000000000L) {
		condtime->tv_nsec -= 1000000000L;
		++condtime->tv_sec;
	}
}

#elif defined(MYTHREAD_WIN95) || defined(MYTHREAD_VISTA)

#define WIN32_LEAN_AND_MEAN
#ifdef MYTHREAD_VISTA
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <windows.h>
#include <process.h>

#define MYTHREAD_RET_TYPE unsigned int __stdcall
#define MYTHREAD_RET_VALUE 0

typedef HANDLE mythread;
typedef CRITICAL_SECTION mythread_mutex;

#ifdef MYTHREAD_WIN95
typedef HANDLE mythread_cond;
#else
typedef CONDITION_VARIABLE mythread_cond;
#endif

typedef struct {

	DWORD start;

	DWORD timeout;
} mythread_condtime;

#ifdef MYTHREAD_VISTA
#define mythread_once(func) do { static INIT_ONCE once_ = INIT_ONCE_STATIC_INIT; BOOL pending_; if (!InitOnceBeginInitialize(&once_, 0, &pending_, NULL)) abort(); if (pending_) { func(); if (!InitOnceComplete(&once, 0, NULL)) abort(); } } while (0)
#endif

static inline int
mythread_create(mythread *thread,
		unsigned int (__stdcall *func)(void *arg), void *arg)
{
	uintptr_t ret = _beginthreadex(NULL, 0, func, arg, 0, NULL);
	if (ret == 0)
		return -1;

	*thread = (HANDLE)ret;
	return 0;
}

static inline int
mythread_join(mythread thread)
{
	int ret = 0;

	if (WaitForSingleObject(thread, INFINITE) != WAIT_OBJECT_0)
		ret = -1;

	if (!CloseHandle(thread))
		ret = -1;

	return ret;
}

static inline int
mythread_mutex_init(mythread_mutex *mutex)
{
	InitializeCriticalSection(mutex);
	return 0;
}

static inline void
mythread_mutex_destroy(mythread_mutex *mutex)
{
	DeleteCriticalSection(mutex);
}

static inline void
mythread_mutex_lock(mythread_mutex *mutex)
{
	EnterCriticalSection(mutex);
}

static inline void
mythread_mutex_unlock(mythread_mutex *mutex)
{
	LeaveCriticalSection(mutex);
}

static inline int
mythread_cond_init(mythread_cond *cond)
{
#ifdef MYTHREAD_WIN95
	*cond = CreateEvent(NULL, FALSE, FALSE, NULL);
	return *cond == NULL ? -1 : 0;
#else
	InitializeConditionVariable(cond);
	return 0;
#endif
}

static inline void
mythread_cond_destroy(mythread_cond *cond)
{
#ifdef MYTHREAD_WIN95
	CloseHandle(*cond);
#else
	(void)cond;
#endif
}

static inline void
mythread_cond_signal(mythread_cond *cond)
{
#ifdef MYTHREAD_WIN95
	SetEvent(*cond);
#else
	WakeConditionVariable(cond);
#endif
}

static inline void
mythread_cond_wait(mythread_cond *cond, mythread_mutex *mutex)
{
#ifdef MYTHREAD_WIN95
	LeaveCriticalSection(mutex);
	WaitForSingleObject(*cond, INFINITE);
	EnterCriticalSection(mutex);
#else
	BOOL ret = SleepConditionVariableCS(cond, mutex, INFINITE);
	assert(ret);
	(void)ret;
#endif
}

static inline int
mythread_cond_timedwait(mythread_cond *cond, mythread_mutex *mutex,
		const mythread_condtime *condtime)
{
#ifdef MYTHREAD_WIN95
	LeaveCriticalSection(mutex);
#endif

	DWORD elapsed = GetTickCount() - condtime->start;
	DWORD timeout = elapsed >= condtime->timeout
			? 0 : condtime->timeout - elapsed;

#ifdef MYTHREAD_WIN95
	DWORD ret = WaitForSingleObject(*cond, timeout);
	assert(ret == WAIT_OBJECT_0 || ret == WAIT_TIMEOUT);

	EnterCriticalSection(mutex);

	return ret == WAIT_TIMEOUT;
#else
	BOOL ret = SleepConditionVariableCS(cond, mutex, timeout);
	assert(ret || GetLastError() == ERROR_TIMEOUT);
	return !ret;
#endif
}

static inline void
mythread_condtime_set(mythread_condtime *condtime, const mythread_cond *cond,
		uint32_t timeout)
{
	(void)cond;
	condtime->start = GetTickCount();
	condtime->timeout = timeout;
}

#endif

#endif

#ifndef TUKLIB_INTEGER_H
#define TUKLIB_INTEGER_H

#include <string.h>

#if defined(__INTEL_COMPILER) && (__INTEL_COMPILER >= 1500)
#include <immintrin.h>
#endif

#if defined(HAVE___BUILTIN_BSWAPXX)

#define bswap16(n) __builtin_bswap16(n)
#define bswap32(n) __builtin_bswap32(n)
#define bswap64(n) __builtin_bswap64(n)

#elif defined(HAVE_BYTESWAP_H)

#include <byteswap.h>
#ifdef HAVE_BSWAP_16
#define bswap16(num) bswap_16(num)
#endif
#ifdef HAVE_BSWAP_32
#define bswap32(num) bswap_32(num)
#endif
#ifdef HAVE_BSWAP_64
#define bswap64(num) bswap_64(num)
#endif

#elif defined(HAVE_SYS_ENDIAN_H)

#include <sys/endian.h>

#elif defined(HAVE_SYS_BYTEORDER_H)

#include <sys/byteorder.h>
#ifdef BSWAP_16
#define bswap16(num) BSWAP_16(num)
#endif
#ifdef BSWAP_32
#define bswap32(num) BSWAP_32(num)
#endif
#ifdef BSWAP_64
#define bswap64(num) BSWAP_64(num)
#endif
#ifdef BE_16
#define conv16be(num) BE_16(num)
#endif
#ifdef BE_32
#define conv32be(num) BE_32(num)
#endif
#ifdef BE_64
#define conv64be(num) BE_64(num)
#endif
#ifdef LE_16
#define conv16le(num) LE_16(num)
#endif
#ifdef LE_32
#define conv32le(num) LE_32(num)
#endif
#ifdef LE_64
#define conv64le(num) LE_64(num)
#endif
#endif

#ifndef bswap16
#define bswap16(n) (uint16_t)( (((n) & 0x00FFU) << 8) | (((n) & 0xFF00U) >> 8) )
#endif

#ifndef bswap32
#define bswap32(n) (uint32_t)( (((n) & UINT32_C(0x000000FF)) << 24) | (((n) & UINT32_C(0x0000FF00)) << 8) | (((n) & UINT32_C(0x00FF0000)) >> 8) | (((n) & UINT32_C(0xFF000000)) >> 24) )
#endif

#ifndef bswap64
#define bswap64(n) (uint64_t)( (((n) & UINT64_C(0x00000000000000FF)) << 56) | (((n) & UINT64_C(0x000000000000FF00)) << 40) | (((n) & UINT64_C(0x0000000000FF0000)) << 24) | (((n) & UINT64_C(0x00000000FF000000)) << 8) | (((n) & UINT64_C(0x000000FF00000000)) >> 8) | (((n) & UINT64_C(0x0000FF0000000000)) >> 24) | (((n) & UINT64_C(0x00FF000000000000)) >> 40) | (((n) & UINT64_C(0xFF00000000000000)) >> 56) )
#endif

#ifdef WORDS_BIGENDIAN
#ifndef conv16be
#define conv16be(num) ((uint16_t)(num))
#endif
#ifndef conv32be
#define conv32be(num) ((uint32_t)(num))
#endif
#ifndef conv64be
#define conv64be(num) ((uint64_t)(num))
#endif
#ifndef conv16le
#define conv16le(num) bswap16(num)
#endif
#ifndef conv32le
#define conv32le(num) bswap32(num)
#endif
#ifndef conv64le
#define conv64le(num) bswap64(num)
#endif
#else
#ifndef conv16be
#define conv16be(num) bswap16(num)
#endif
#ifndef conv32be
#define conv32be(num) bswap32(num)
#endif
#ifndef conv64be
#define conv64be(num) bswap64(num)
#endif
#ifndef conv16le
#define conv16le(num) ((uint16_t)(num))
#endif
#ifndef conv32le
#define conv32le(num) ((uint32_t)(num))
#endif
#ifndef conv64le
#define conv64le(num) ((uint64_t)(num))
#endif
#endif

static inline uint16_t
read16ne(const uint8_t *buf)
{
#if defined(TUKLIB_FAST_UNALIGNED_ACCESS) && defined(TUKLIB_USE_UNSAFE_TYPE_PUNNING)
	return *(const uint16_t *)buf;
#else
	uint16_t num;
	memcpy(&num, buf, sizeof(num));
	return num;
#endif
}

static inline uint32_t
read32ne(const uint8_t *buf)
{
#if defined(TUKLIB_FAST_UNALIGNED_ACCESS) && defined(TUKLIB_USE_UNSAFE_TYPE_PUNNING)
	return *(const uint32_t *)buf;
#else
	uint32_t num;
	memcpy(&num, buf, sizeof(num));
	return num;
#endif
}

static inline uint64_t
read64ne(const uint8_t *buf)
{
#if defined(TUKLIB_FAST_UNALIGNED_ACCESS) && defined(TUKLIB_USE_UNSAFE_TYPE_PUNNING)
	return *(const uint64_t *)buf;
#else
	uint64_t num;
	memcpy(&num, buf, sizeof(num));
	return num;
#endif
}

static inline void
write16ne(uint8_t *buf, uint16_t num)
{
#if defined(TUKLIB_FAST_UNALIGNED_ACCESS) && defined(TUKLIB_USE_UNSAFE_TYPE_PUNNING)
	*(uint16_t *)buf = num;
#else
	memcpy(buf, &num, sizeof(num));
#endif
	return;
}

static inline void
write32ne(uint8_t *buf, uint32_t num)
{
#if defined(TUKLIB_FAST_UNALIGNED_ACCESS) && defined(TUKLIB_USE_UNSAFE_TYPE_PUNNING)
	*(uint32_t *)buf = num;
#else
	memcpy(buf, &num, sizeof(num));
#endif
	return;
}

static inline void
write64ne(uint8_t *buf, uint64_t num)
{
#if defined(TUKLIB_FAST_UNALIGNED_ACCESS) && defined(TUKLIB_USE_UNSAFE_TYPE_PUNNING)
	*(uint64_t *)buf = num;
#else
	memcpy(buf, &num, sizeof(num));
#endif
	return;
}

static inline uint16_t
read16be(const uint8_t *buf)
{
#if defined(WORDS_BIGENDIAN) || defined(TUKLIB_FAST_UNALIGNED_ACCESS)
	uint16_t num = read16ne(buf);
	return conv16be(num);
#else
	uint16_t num = ((uint16_t)buf[0] << 8) | (uint16_t)buf[1];
	return num;
#endif
}

static inline uint16_t
read16le(const uint8_t *buf)
{
#if !defined(WORDS_BIGENDIAN) || defined(TUKLIB_FAST_UNALIGNED_ACCESS)
	uint16_t num = read16ne(buf);
	return conv16le(num);
#else
	uint16_t num = ((uint16_t)buf[0]) | ((uint16_t)buf[1] << 8);
	return num;
#endif
}

static inline uint32_t
read32be(const uint8_t *buf)
{
#if defined(WORDS_BIGENDIAN) || defined(TUKLIB_FAST_UNALIGNED_ACCESS)
	uint32_t num = read32ne(buf);
	return conv32be(num);
#else
	uint32_t num = (uint32_t)buf[0] << 24;
	num |= (uint32_t)buf[1] << 16;
	num |= (uint32_t)buf[2] << 8;
	num |= (uint32_t)buf[3];
	return num;
#endif
}

static inline uint32_t
read32le(const uint8_t *buf)
{
#if !defined(WORDS_BIGENDIAN) || defined(TUKLIB_FAST_UNALIGNED_ACCESS)
	uint32_t num = read32ne(buf);
	return conv32le(num);
#else
	uint32_t num = (uint32_t)buf[0];
	num |= (uint32_t)buf[1] << 8;
	num |= (uint32_t)buf[2] << 16;
	num |= (uint32_t)buf[3] << 24;
	return num;
#endif
}

static inline uint64_t
read64be(const uint8_t *buf)
{
#if defined(WORDS_BIGENDIAN) || defined(TUKLIB_FAST_UNALIGNED_ACCESS)
	uint64_t num = read64ne(buf);
	return conv64be(num);
#else
	uint64_t num = (uint64_t)buf[0] << 56;
	num |= (uint64_t)buf[1] << 48;
	num |= (uint64_t)buf[2] << 40;
	num |= (uint64_t)buf[3] << 32;
	num |= (uint64_t)buf[4] << 24;
	num |= (uint64_t)buf[5] << 16;
	num |= (uint64_t)buf[6] << 8;
	num |= (uint64_t)buf[7];
	return num;
#endif
}

static inline uint64_t
read64le(const uint8_t *buf)
{
#if !defined(WORDS_BIGENDIAN) || defined(TUKLIB_FAST_UNALIGNED_ACCESS)
	uint64_t num = read64ne(buf);
	return conv64le(num);
#else
	uint64_t num = (uint64_t)buf[0];
	num |= (uint64_t)buf[1] << 8;
	num |= (uint64_t)buf[2] << 16;
	num |= (uint64_t)buf[3] << 24;
	num |= (uint64_t)buf[4] << 32;
	num |= (uint64_t)buf[5] << 40;
	num |= (uint64_t)buf[6] << 48;
	num |= (uint64_t)buf[7] << 56;
	return num;
#endif
}

#if defined(WORDS_BIGENDIAN) || defined(TUKLIB_FAST_UNALIGNED_ACCESS)
#define write16be(buf, num) write16ne(buf, conv16be(num))
#define write32be(buf, num) write32ne(buf, conv32be(num))
#define write64be(buf, num) write64ne(buf, conv64be(num))
#endif

#if !defined(WORDS_BIGENDIAN) || defined(TUKLIB_FAST_UNALIGNED_ACCESS)
#define write16le(buf, num) write16ne(buf, conv16le(num))
#define write32le(buf, num) write32ne(buf, conv32le(num))
#define write64le(buf, num) write64ne(buf, conv64le(num))
#endif

#ifndef write16be
static inline void
write16be(uint8_t *buf, uint16_t num)
{
	buf[0] = (uint8_t)(num >> 8);
	buf[1] = (uint8_t)num;
	return;
}
#endif

#ifndef write16le
static inline void
write16le(uint8_t *buf, uint16_t num)
{
	buf[0] = (uint8_t)num;
	buf[1] = (uint8_t)(num >> 8);
	return;
}
#endif

#ifndef write32be
static inline void
write32be(uint8_t *buf, uint32_t num)
{
	buf[0] = (uint8_t)(num >> 24);
	buf[1] = (uint8_t)(num >> 16);
	buf[2] = (uint8_t)(num >> 8);
	buf[3] = (uint8_t)num;
	return;
}
#endif

#ifndef write32le
static inline void
write32le(uint8_t *buf, uint32_t num)
{
	buf[0] = (uint8_t)num;
	buf[1] = (uint8_t)(num >> 8);
	buf[2] = (uint8_t)(num >> 16);
	buf[3] = (uint8_t)(num >> 24);
	return;
}
#endif

#ifdef HAVE___BUILTIN_ASSUME_ALIGNED
#define tuklib_memcpy_aligned(dest, src, size) memcpy(dest, __builtin_assume_aligned(src, size), size)
#else
#define tuklib_memcpy_aligned(dest, src, size) memcpy(dest, src, size)
#ifndef TUKLIB_FAST_UNALIGNED_ACCESS
#define TUKLIB_USE_UNSAFE_ALIGNED_READS 1
#endif
#endif

static inline uint16_t
aligned_read16ne(const uint8_t *buf)
{
#if defined(TUKLIB_USE_UNSAFE_TYPE_PUNNING) || defined(TUKLIB_USE_UNSAFE_ALIGNED_READS)
	return *(const uint16_t *)buf;
#else
	uint16_t num;
	tuklib_memcpy_aligned(&num, buf, sizeof(num));
	return num;
#endif
}

static inline uint32_t
aligned_read32ne(const uint8_t *buf)
{
#if defined(TUKLIB_USE_UNSAFE_TYPE_PUNNING) || defined(TUKLIB_USE_UNSAFE_ALIGNED_READS)
	return *(const uint32_t *)buf;
#else
	uint32_t num;
	tuklib_memcpy_aligned(&num, buf, sizeof(num));
	return num;
#endif
}

static inline uint64_t
aligned_read64ne(const uint8_t *buf)
{
#if defined(TUKLIB_USE_UNSAFE_TYPE_PUNNING) || defined(TUKLIB_USE_UNSAFE_ALIGNED_READS)
	return *(const uint64_t *)buf;
#else
	uint64_t num;
	tuklib_memcpy_aligned(&num, buf, sizeof(num));
	return num;
#endif
}

static inline void
aligned_write16ne(uint8_t *buf, uint16_t num)
{
#ifdef TUKLIB_USE_UNSAFE_TYPE_PUNNING
	*(uint16_t *)buf = num;
#else
	tuklib_memcpy_aligned(buf, &num, sizeof(num));
#endif
	return;
}

static inline void
aligned_write32ne(uint8_t *buf, uint32_t num)
{
#ifdef TUKLIB_USE_UNSAFE_TYPE_PUNNING
	*(uint32_t *)buf = num;
#else
	tuklib_memcpy_aligned(buf, &num, sizeof(num));
#endif
	return;
}

static inline void
aligned_write64ne(uint8_t *buf, uint64_t num)
{
#ifdef TUKLIB_USE_UNSAFE_TYPE_PUNNING
	*(uint64_t *)buf = num;
#else
	tuklib_memcpy_aligned(buf, &num, sizeof(num));
#endif
	return;
}

static inline uint16_t
aligned_read16be(const uint8_t *buf)
{
	uint16_t num = aligned_read16ne(buf);
	return conv16be(num);
}

static inline uint16_t
aligned_read16le(const uint8_t *buf)
{
	uint16_t num = aligned_read16ne(buf);
	return conv16le(num);
}

static inline uint32_t
aligned_read32be(const uint8_t *buf)
{
	uint32_t num = aligned_read32ne(buf);
	return conv32be(num);
}

static inline uint32_t
aligned_read32le(const uint8_t *buf)
{
	uint32_t num = aligned_read32ne(buf);
	return conv32le(num);
}

static inline uint64_t
aligned_read64be(const uint8_t *buf)
{
	uint64_t num = aligned_read64ne(buf);
	return conv64be(num);
}

static inline uint64_t
aligned_read64le(const uint8_t *buf)
{
	uint64_t num = aligned_read64ne(buf);
	return conv64le(num);
}

#define aligned_write16be(buf, num) aligned_write16ne((buf), conv16be(num))
#define aligned_write16le(buf, num) aligned_write16ne((buf), conv16le(num))
#define aligned_write32be(buf, num) aligned_write32ne((buf), conv32be(num))
#define aligned_write32le(buf, num) aligned_write32ne((buf), conv32le(num))
#define aligned_write64be(buf, num) aligned_write64ne((buf), conv64be(num))
#define aligned_write64le(buf, num) aligned_write64ne((buf), conv64le(num))

static inline uint32_t
bsr32(uint32_t n)
{

#if defined(__INTEL_COMPILER)
	return _bit_scan_reverse(n);

#elif TUKLIB_GNUC_REQ(3, 4) && UINT_MAX == UINT32_MAX

	return (uint32_t)__builtin_clz(n) ^ 31U;

#elif defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
	uint32_t i;
	__asm__("bsrl %1, %0" : "=r" (i) : "rm" (n));
	return i;

#elif defined(_MSC_VER)
	unsigned long i;
	_BitScanReverse(&i, n);
	return i;

#else
	uint32_t i = 31;

	if ((n & 0xFFFF0000) == 0) {
		n <<= 16;
		i = 15;
	}

	if ((n & 0xFF000000) == 0) {
		n <<= 8;
		i -= 8;
	}

	if ((n & 0xF0000000) == 0) {
		n <<= 4;
		i -= 4;
	}

	if ((n & 0xC0000000) == 0) {
		n <<= 2;
		i -= 2;
	}

	if ((n & 0x80000000) == 0)
		--i;

	return i;
#endif
}

static inline uint32_t
clz32(uint32_t n)
{
#if defined(__INTEL_COMPILER)
	return _bit_scan_reverse(n) ^ 31U;

#elif TUKLIB_GNUC_REQ(3, 4) && UINT_MAX == UINT32_MAX
	return (uint32_t)__builtin_clz(n);

#elif defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
	uint32_t i;
	__asm__("bsrl %1, %0\n\t"
		"xorl $31, %0"
		: "=r" (i) : "rm" (n));
	return i;

#elif defined(_MSC_VER)
	unsigned long i;
	_BitScanReverse(&i, n);
	return i ^ 31U;

#else
	uint32_t i = 0;

	if ((n & 0xFFFF0000) == 0) {
		n <<= 16;
		i = 16;
	}

	if ((n & 0xFF000000) == 0) {
		n <<= 8;
		i += 8;
	}

	if ((n & 0xF0000000) == 0) {
		n <<= 4;
		i += 4;
	}

	if ((n & 0xC0000000) == 0) {
		n <<= 2;
		i += 2;
	}

	if ((n & 0x80000000) == 0)
		++i;

	return i;
#endif
}

static inline uint32_t
ctz32(uint32_t n)
{
#if defined(__INTEL_COMPILER)
	return _bit_scan_forward(n);

#elif TUKLIB_GNUC_REQ(3, 4) && UINT_MAX >= UINT32_MAX
	return (uint32_t)__builtin_ctz(n);

#elif defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
	uint32_t i;
	__asm__("bsfl %1, %0" : "=r" (i) : "rm" (n));
	return i;

#elif defined(_MSC_VER)
	unsigned long i;
	_BitScanForward(&i, n);
	return i;

#else
	uint32_t i = 0;

	if ((n & 0x0000FFFF) == 0) {
		n >>= 16;
		i = 16;
	}

	if ((n & 0x000000FF) == 0) {
		n >>= 8;
		i += 8;
	}

	if ((n & 0x0000000F) == 0) {
		n >>= 4;
		i += 4;
	}

	if ((n & 0x00000003) == 0) {
		n >>= 2;
		i += 2;
	}

	if ((n & 0x00000001) == 0)
		++i;

	return i;
#endif
}

#define bsf32 ctz32

#endif

#if defined(_WIN32) || defined(__CYGWIN__)
#ifdef DLL_EXPORT
#define LZMA_API_EXPORT __declspec(dllexport)
#else
#define LZMA_API_EXPORT
#endif

#elif HAVE_VISIBILITY
#define LZMA_API_EXPORT __attribute__((__visibility__("default")))
#else
#define LZMA_API_EXPORT
#endif

#define LZMA_API(type) LZMA_API_EXPORT type LZMA_API_CALL

#ifndef LZMA_H
#define LZMA_H

#ifndef LZMA_MANUAL_HEADERS

#include <stddef.h>

#if !defined(UINT32_C) || !defined(UINT64_C) || !defined(UINT32_MAX) || !defined(UINT64_MAX)

#if defined(_WIN32) && defined(_MSC_VER) && _MSC_VER < 1800
			typedef unsigned __int8 uint8_t;
			typedef unsigned __int32 uint32_t;
			typedef unsigned __int64 uint64_t;
#else

#ifdef __cplusplus

#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS 1
#endif
#ifndef __STDC_CONSTANT_MACROS
#define __STDC_CONSTANT_MACROS 1
#endif
#endif

#include <inttypes.h>
#endif

#ifndef UINT32_C
#if defined(_WIN32) && defined(_MSC_VER)
#define UINT32_C(n) n ## UI32
#else
#define UINT32_C(n) n ## U
#endif
#endif

#ifndef UINT64_C
#if defined(_WIN32) && defined(_MSC_VER)
#define UINT64_C(n) n ## UI64
#else

#include <limits.h>
#if ULONG_MAX == 4294967295UL
#define UINT64_C(n) n ## ULL
#else
#define UINT64_C(n) n ## UL
#endif
#endif
#endif

#ifndef UINT32_MAX
#define UINT32_MAX (UINT32_C(4294967295))
#endif

#ifndef UINT64_MAX
#define UINT64_MAX (UINT64_C(18446744073709551615))
#endif
#endif
#endif

#ifndef LZMA_API_IMPORT
#if !defined(LZMA_API_STATIC) && defined(_WIN32) && !defined(__GNUC__)
#define LZMA_API_IMPORT __declspec(dllimport)
#else
#define LZMA_API_IMPORT
#endif
#endif

#ifndef LZMA_API_CALL
#if defined(_WIN32) && !defined(__CYGWIN__)
#define LZMA_API_CALL __cdecl
#else
#define LZMA_API_CALL
#endif
#endif

#ifndef LZMA_API
#define LZMA_API(type) LZMA_API_IMPORT type LZMA_API_CALL
#endif

#ifndef lzma_nothrow
#if defined(__cplusplus)
#if __cplusplus >= 201103L || (defined(_MSVC_LANG) && _MSVC_LANG >= 201103L)
#define lzma_nothrow noexcept
#else
#define lzma_nothrow throw()
#endif
#elif defined(__GNUC__) && (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 3))
#define lzma_nothrow __attribute__((__nothrow__))
#else
#define lzma_nothrow
#endif
#endif

#if defined(__GNUC__) && __GNUC__ >= 3
#ifndef lzma_attribute
#define lzma_attribute(attr) __attribute__(attr)
#endif

#ifndef lzma_attr_warn_unused_result
#if __GNUC__ == 3 && __GNUC_MINOR__ < 4
#define lzma_attr_warn_unused_result
#endif
#endif

#else
#ifndef lzma_attribute
#define lzma_attribute(attr)
#endif
#endif

#ifndef lzma_attr_pure
#define lzma_attr_pure lzma_attribute((__pure__))
#endif

#ifndef lzma_attr_const
#define lzma_attr_const lzma_attribute((__const__))
#endif

#ifndef lzma_attr_warn_unused_result
#define lzma_attr_warn_unused_result lzma_attribute((__warn_unused_result__))
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define LZMA_H_INTERNAL 1

#ifndef LZMA_H_INTERNAL
#error Never include this file directly. Use <lzma.h> instead.
#endif

#define LZMA_VERSION_MAJOR 5
#define LZMA_VERSION_MINOR 3
#define LZMA_VERSION_PATCH 5
#define LZMA_VERSION_STABILITY LZMA_VERSION_STABILITY_BETA

#ifndef LZMA_VERSION_COMMIT
#define LZMA_VERSION_COMMIT ""
#endif

#define LZMA_VERSION_STABILITY_ALPHA 0
#define LZMA_VERSION_STABILITY_BETA 1
#define LZMA_VERSION_STABILITY_STABLE 2

#define LZMA_VERSION (LZMA_VERSION_MAJOR * UINT32_C(10000000) + LZMA_VERSION_MINOR * UINT32_C(10000) + LZMA_VERSION_PATCH * UINT32_C(10) + LZMA_VERSION_STABILITY)

#if LZMA_VERSION_STABILITY == LZMA_VERSION_STABILITY_ALPHA
#define LZMA_VERSION_STABILITY_STRING "alpha"
#elif LZMA_VERSION_STABILITY == LZMA_VERSION_STABILITY_BETA
#define LZMA_VERSION_STABILITY_STRING "beta"
#elif LZMA_VERSION_STABILITY == LZMA_VERSION_STABILITY_STABLE
#define LZMA_VERSION_STABILITY_STRING ""
#else
#error Incorrect LZMA_VERSION_STABILITY
#endif

#define LZMA_VERSION_STRING_C_(major, minor, patch, stability, commit) #major "." #minor "." #patch stability commit

#define LZMA_VERSION_STRING_C(major, minor, patch, stability, commit) LZMA_VERSION_STRING_C_(major, minor, patch, stability, commit)

#define LZMA_VERSION_STRING LZMA_VERSION_STRING_C( LZMA_VERSION_MAJOR, LZMA_VERSION_MINOR, LZMA_VERSION_PATCH, LZMA_VERSION_STABILITY_STRING, LZMA_VERSION_COMMIT)

#ifndef LZMA_H_INTERNAL_RC

extern LZMA_API(uint32_t) lzma_version_number(void)
		lzma_nothrow lzma_attr_const;

extern LZMA_API(const char *) lzma_version_string(void)
		lzma_nothrow lzma_attr_const;

#endif

#ifndef LZMA_H_INTERNAL
#error Never include this file directly. Use <lzma.h> instead.
#endif

typedef unsigned char lzma_bool;

typedef enum {
	LZMA_RESERVED_ENUM      = 0
} lzma_reserved_enum;

typedef enum {
	LZMA_OK                 = 0,

	LZMA_STREAM_END         = 1,

	LZMA_NO_CHECK           = 2,

	LZMA_UNSUPPORTED_CHECK  = 3,

	LZMA_GET_CHECK          = 4,

	LZMA_MEM_ERROR          = 5,

	LZMA_MEMLIMIT_ERROR     = 6,

	LZMA_FORMAT_ERROR       = 7,

	LZMA_OPTIONS_ERROR      = 8,

	LZMA_DATA_ERROR         = 9,

	LZMA_BUF_ERROR          = 10,

	LZMA_PROG_ERROR         = 11,

	LZMA_SEEK_NEEDED        = 12,

	LZMA_RET_INTERNAL1      = 101,
	LZMA_RET_INTERNAL2      = 102,
	LZMA_RET_INTERNAL3      = 103,
	LZMA_RET_INTERNAL4      = 104,
	LZMA_RET_INTERNAL5      = 105,
	LZMA_RET_INTERNAL6      = 106,
	LZMA_RET_INTERNAL7      = 107,
	LZMA_RET_INTERNAL8      = 108
} lzma_ret;

typedef enum {
	LZMA_RUN = 0,

	LZMA_SYNC_FLUSH = 1,

	LZMA_FULL_FLUSH = 2,

	LZMA_FULL_BARRIER = 4,

	LZMA_FINISH = 3

} lzma_action;

typedef struct {

	void *(LZMA_API_CALL *alloc)(void *opaque, size_t nmemb, size_t size);

	void (LZMA_API_CALL *free)(void *opaque, void *ptr);

	void *opaque;

} lzma_allocator;

typedef struct lzma_internal_s lzma_internal;

typedef struct {
	const uint8_t *next_in;
	size_t avail_in;
	uint64_t total_in;

	uint8_t *next_out;
	size_t avail_out;
	uint64_t total_out;

	const lzma_allocator *allocator;

	lzma_internal *internal;

	void *reserved_ptr1;
	void *reserved_ptr2;
	void *reserved_ptr3;
	void *reserved_ptr4;

	uint64_t seek_pos;

	uint64_t reserved_int2;
	size_t reserved_int3;
	size_t reserved_int4;
	lzma_reserved_enum reserved_enum1;
	lzma_reserved_enum reserved_enum2;

} lzma_stream;

#define LZMA_STREAM_INIT { NULL, 0, 0, NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, NULL, 0, 0, 0, 0, LZMA_RESERVED_ENUM, LZMA_RESERVED_ENUM }

extern LZMA_API(lzma_ret) lzma_code(lzma_stream *strm, lzma_action action)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(void) lzma_end(lzma_stream *strm) lzma_nothrow;

extern LZMA_API(void) lzma_get_progress(lzma_stream *strm,
		uint64_t *progress_in, uint64_t *progress_out) lzma_nothrow;

extern LZMA_API(uint64_t) lzma_memusage(const lzma_stream *strm)
		lzma_nothrow lzma_attr_pure;

extern LZMA_API(uint64_t) lzma_memlimit_get(const lzma_stream *strm)
		lzma_nothrow lzma_attr_pure;

extern LZMA_API(lzma_ret) lzma_memlimit_set(
		lzma_stream *strm, uint64_t memlimit) lzma_nothrow;

#ifndef LZMA_H_INTERNAL
#error Never include this file directly. Use <lzma.h> instead.
#endif

#define LZMA_VLI_MAX (UINT64_MAX / 2)

#define LZMA_VLI_UNKNOWN UINT64_MAX

#define LZMA_VLI_BYTES_MAX 9

#define LZMA_VLI_C(n) UINT64_C(n)

typedef uint64_t lzma_vli;

#define lzma_vli_is_valid(vli) ((vli) <= LZMA_VLI_MAX || (vli) == LZMA_VLI_UNKNOWN)

extern LZMA_API(lzma_ret) lzma_vli_encode(lzma_vli vli, size_t *vli_pos,
		uint8_t *out, size_t *out_pos, size_t out_size) lzma_nothrow;

extern LZMA_API(lzma_ret) lzma_vli_decode(lzma_vli *vli, size_t *vli_pos,
		const uint8_t *in, size_t *in_pos, size_t in_size)
		lzma_nothrow;

extern LZMA_API(uint32_t) lzma_vli_size(lzma_vli vli)
		lzma_nothrow lzma_attr_pure;

#ifndef LZMA_H_INTERNAL
#error Never include this file directly. Use <lzma.h> instead.
#endif

typedef enum {
	LZMA_CHECK_NONE     = 0,

	LZMA_CHECK_CRC32    = 1,

	LZMA_CHECK_CRC64    = 4,

	LZMA_CHECK_SHA256   = 10

} lzma_check;

#define LZMA_CHECK_ID_MAX 15

extern LZMA_API(lzma_bool) lzma_check_is_supported(lzma_check check)
		lzma_nothrow lzma_attr_const;

extern LZMA_API(uint32_t) lzma_check_size(lzma_check check)
		lzma_nothrow lzma_attr_const;

#define LZMA_CHECK_SIZE_MAX 64

extern LZMA_API(uint32_t) lzma_crc32(
		const uint8_t *buf, size_t size, uint32_t crc)
		lzma_nothrow lzma_attr_pure;

extern LZMA_API(uint64_t) lzma_crc64(
		const uint8_t *buf, size_t size, uint64_t crc)
		lzma_nothrow lzma_attr_pure;

extern LZMA_API(lzma_check) lzma_get_check(const lzma_stream *strm)
		lzma_nothrow;

#ifndef LZMA_H_INTERNAL
#error Never include this file directly. Use <lzma.h> instead.
#endif

#define LZMA_FILTERS_MAX 4

typedef struct {

	lzma_vli id;

	void *options;

} lzma_filter;

extern LZMA_API(lzma_bool) lzma_filter_encoder_is_supported(lzma_vli id)
		lzma_nothrow lzma_attr_const;

extern LZMA_API(lzma_bool) lzma_filter_decoder_is_supported(lzma_vli id)
		lzma_nothrow lzma_attr_const;

extern LZMA_API(lzma_ret) lzma_filters_copy(
		const lzma_filter *src, lzma_filter *dest,
		const lzma_allocator *allocator)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(void) lzma_filters_free(
		lzma_filter *filters, const lzma_allocator *allocator)
		lzma_nothrow;

extern LZMA_API(uint64_t) lzma_raw_encoder_memusage(const lzma_filter *filters)
		lzma_nothrow lzma_attr_pure;

extern LZMA_API(uint64_t) lzma_raw_decoder_memusage(const lzma_filter *filters)
		lzma_nothrow lzma_attr_pure;

extern LZMA_API(lzma_ret) lzma_raw_encoder(
		lzma_stream *strm, const lzma_filter *filters)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_raw_decoder(
		lzma_stream *strm, const lzma_filter *filters)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_filters_update(
		lzma_stream *strm, const lzma_filter *filters) lzma_nothrow;

extern LZMA_API(lzma_ret) lzma_raw_buffer_encode(
		const lzma_filter *filters, const lzma_allocator *allocator,
		const uint8_t *in, size_t in_size, uint8_t *out,
		size_t *out_pos, size_t out_size) lzma_nothrow;

extern LZMA_API(lzma_ret) lzma_raw_buffer_decode(
		const lzma_filter *filters, const lzma_allocator *allocator,
		const uint8_t *in, size_t *in_pos, size_t in_size,
		uint8_t *out, size_t *out_pos, size_t out_size) lzma_nothrow;

extern LZMA_API(lzma_ret) lzma_properties_size(
		uint32_t *size, const lzma_filter *filter) lzma_nothrow;

extern LZMA_API(lzma_ret) lzma_properties_encode(
		const lzma_filter *filter, uint8_t *props) lzma_nothrow;

extern LZMA_API(lzma_ret) lzma_properties_decode(
		lzma_filter *filter, const lzma_allocator *allocator,
		const uint8_t *props, size_t props_size) lzma_nothrow;

extern LZMA_API(lzma_ret) lzma_filter_flags_size(
		uint32_t *size, const lzma_filter *filter)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_filter_flags_encode(const lzma_filter *filter,
		uint8_t *out, size_t *out_pos, size_t out_size)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_filter_flags_decode(
		lzma_filter *filter, const lzma_allocator *allocator,
		const uint8_t *in, size_t *in_pos, size_t in_size)
		lzma_nothrow lzma_attr_warn_unused_result;

#define LZMA_STR_ALL_FILTERS    UINT32_C(0x01)

#define LZMA_STR_NO_VALIDATION  UINT32_C(0x02)

#define LZMA_STR_ENCODER        UINT32_C(0x10)

#define LZMA_STR_DECODER        UINT32_C(0x20)

#define LZMA_STR_GETOPT_LONG    UINT32_C(0x40)

#define LZMA_STR_NO_SPACES      UINT32_C(0x80)

extern LZMA_API(const char *) lzma_str_to_filters(
		const char *str, int *error_pos, lzma_filter *filters,
		uint32_t flags, const lzma_allocator *allocator)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_str_from_filters(
		char **str, const lzma_filter *filters, uint32_t flags,
		const lzma_allocator *allocator)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_str_list_filters(
		char **str, lzma_vli filter_id, uint32_t flags,
		const lzma_allocator *allocator)
		lzma_nothrow lzma_attr_warn_unused_result;

#ifndef LZMA_H_INTERNAL
#error Never include this file directly. Use <lzma.h> instead.
#endif

#define LZMA_FILTER_X86         LZMA_VLI_C(0x04)

#define LZMA_FILTER_POWERPC     LZMA_VLI_C(0x05)

#define LZMA_FILTER_IA64        LZMA_VLI_C(0x06)

#define LZMA_FILTER_ARM         LZMA_VLI_C(0x07)

#define LZMA_FILTER_ARMTHUMB    LZMA_VLI_C(0x08)

#define LZMA_FILTER_SPARC       LZMA_VLI_C(0x09)

#define LZMA_FILTER_ARM64       LZMA_VLI_C(0x3FDB87B33B27020B)

typedef struct {

	uint32_t start_offset;

} lzma_options_bcj;

#ifndef LZMA_H_INTERNAL
#error Never include this file directly. Use <lzma.h> instead.
#endif

#define LZMA_FILTER_DELTA       LZMA_VLI_C(0x03)

typedef enum {
	LZMA_DELTA_TYPE_BYTE
} lzma_delta_type;

typedef struct {

	lzma_delta_type type;

	uint32_t dist;
#define LZMA_DELTA_DIST_MIN 1
#define LZMA_DELTA_DIST_MAX 256

	uint32_t reserved_int1;
	uint32_t reserved_int2;
	uint32_t reserved_int3;
	uint32_t reserved_int4;
	void *reserved_ptr1;
	void *reserved_ptr2;

} lzma_options_delta;

#ifndef LZMA_H_INTERNAL
#error Never include this file directly. Use <lzma.h> instead.
#endif

#define LZMA_FILTER_LZMA1       LZMA_VLI_C(0x4000000000000001)

#define LZMA_FILTER_LZMA1EXT    LZMA_VLI_C(0x4000000000000002)

#define LZMA_FILTER_LZMA2       LZMA_VLI_C(0x21)

typedef enum {
	LZMA_MF_HC3     = 0x03,

	LZMA_MF_HC4     = 0x04,

	LZMA_MF_BT2     = 0x12,

	LZMA_MF_BT3     = 0x13,

	LZMA_MF_BT4     = 0x14

} lzma_match_finder;

extern LZMA_API(lzma_bool) lzma_mf_is_supported(lzma_match_finder match_finder)
		lzma_nothrow lzma_attr_const;

typedef enum {
	LZMA_MODE_FAST = 1,

	LZMA_MODE_NORMAL = 2

} lzma_mode;

extern LZMA_API(lzma_bool) lzma_mode_is_supported(lzma_mode mode)
		lzma_nothrow lzma_attr_const;

typedef struct {

	uint32_t dict_size;
#define LZMA_DICT_SIZE_MIN       UINT32_C(4096)
#define LZMA_DICT_SIZE_DEFAULT   (UINT32_C(1) << 23)

	const uint8_t *preset_dict;

	uint32_t preset_dict_size;

	uint32_t lc;
#define LZMA_LCLP_MIN    0
#define LZMA_LCLP_MAX    4
#define LZMA_LC_DEFAULT  3

	uint32_t lp;
#define LZMA_LP_DEFAULT  0

	uint32_t pb;
#define LZMA_PB_MIN      0
#define LZMA_PB_MAX      4
#define LZMA_PB_DEFAULT  2

	lzma_mode mode;

	uint32_t nice_len;

	lzma_match_finder mf;

	uint32_t depth;

	uint32_t ext_flags;
#define LZMA_LZMA1EXT_ALLOW_EOPM   UINT32_C(0x01)

	uint32_t ext_size_low;

	uint32_t ext_size_high;

	uint32_t reserved_int4;
	uint32_t reserved_int5;
	uint32_t reserved_int6;
	uint32_t reserved_int7;
	uint32_t reserved_int8;
	lzma_reserved_enum reserved_enum1;
	lzma_reserved_enum reserved_enum2;
	lzma_reserved_enum reserved_enum3;
	lzma_reserved_enum reserved_enum4;
	void *reserved_ptr1;
	void *reserved_ptr2;

} lzma_options_lzma;

#define lzma_set_ext_size(opt_lzma2, u64size) \
do { (opt_lzma2).ext_size_low = (uint32_t)(u64size); (opt_lzma2).ext_size_high = (uint32_t)((uint64_t)(u64size) >> 32); \
} while (0)

extern LZMA_API(lzma_bool) lzma_lzma_preset(
		lzma_options_lzma *options, uint32_t preset) lzma_nothrow;

#ifndef LZMA_H_INTERNAL
#error Never include this file directly. Use <lzma.h> instead.
#endif

#define LZMA_PRESET_DEFAULT     UINT32_C(6)

#define LZMA_PRESET_LEVEL_MASK  UINT32_C(0x1F)

#define LZMA_PRESET_EXTREME       (UINT32_C(1) << 31)

typedef struct {

	uint32_t flags;

	uint32_t threads;

	uint64_t block_size;

	uint32_t timeout;

	uint32_t preset;

	const lzma_filter *filters;

	lzma_check check;

	lzma_reserved_enum reserved_enum1;
	lzma_reserved_enum reserved_enum2;
	lzma_reserved_enum reserved_enum3;
	uint32_t reserved_int1;
	uint32_t reserved_int2;
	uint32_t reserved_int3;
	uint32_t reserved_int4;

	uint64_t memlimit_threading;

	uint64_t memlimit_stop;

	uint64_t reserved_int7;
	uint64_t reserved_int8;
	void *reserved_ptr1;
	void *reserved_ptr2;
	void *reserved_ptr3;
	void *reserved_ptr4;

} lzma_mt;

extern LZMA_API(uint64_t) lzma_easy_encoder_memusage(uint32_t preset)
		lzma_nothrow lzma_attr_pure;

extern LZMA_API(uint64_t) lzma_easy_decoder_memusage(uint32_t preset)
		lzma_nothrow lzma_attr_pure;

extern LZMA_API(lzma_ret) lzma_easy_encoder(
		lzma_stream *strm, uint32_t preset, lzma_check check)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_easy_buffer_encode(
		uint32_t preset, lzma_check check,
		const lzma_allocator *allocator,
		const uint8_t *in, size_t in_size,
		uint8_t *out, size_t *out_pos, size_t out_size) lzma_nothrow;

extern LZMA_API(lzma_ret) lzma_stream_encoder(lzma_stream *strm,
		const lzma_filter *filters, lzma_check check)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(uint64_t) lzma_stream_encoder_mt_memusage(
		const lzma_mt *options) lzma_nothrow lzma_attr_pure;

extern LZMA_API(lzma_ret) lzma_stream_encoder_mt(
		lzma_stream *strm, const lzma_mt *options)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_alone_encoder(
		lzma_stream *strm, const lzma_options_lzma *options)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(size_t) lzma_stream_buffer_bound(size_t uncompressed_size)
		lzma_nothrow;

extern LZMA_API(lzma_ret) lzma_stream_buffer_encode(
		lzma_filter *filters, lzma_check check,
		const lzma_allocator *allocator,
		const uint8_t *in, size_t in_size,
		uint8_t *out, size_t *out_pos, size_t out_size)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_microlzma_encoder(
		lzma_stream *strm, const lzma_options_lzma *options);

#define LZMA_TELL_NO_CHECK              UINT32_C(0x01)

#define LZMA_TELL_UNSUPPORTED_CHECK     UINT32_C(0x02)

#define LZMA_TELL_ANY_CHECK             UINT32_C(0x04)

#define LZMA_IGNORE_CHECK               UINT32_C(0x10)

#define LZMA_CONCATENATED               UINT32_C(0x08)

#define LZMA_FAIL_FAST                  UINT32_C(0x20)

extern LZMA_API(lzma_ret) lzma_stream_decoder(
		lzma_stream *strm, uint64_t memlimit, uint32_t flags)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_stream_decoder_mt(
		lzma_stream *strm, const lzma_mt *options)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_auto_decoder(
		lzma_stream *strm, uint64_t memlimit, uint32_t flags)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_alone_decoder(
		lzma_stream *strm, uint64_t memlimit)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_lzip_decoder(
		lzma_stream *strm, uint64_t memlimit, uint32_t flags)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_stream_buffer_decode(
		uint64_t *memlimit, uint32_t flags,
		const lzma_allocator *allocator,
		const uint8_t *in, size_t *in_pos, size_t in_size,
		uint8_t *out, size_t *out_pos, size_t out_size)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_microlzma_decoder(
		lzma_stream *strm, uint64_t comp_size,
		uint64_t uncomp_size, lzma_bool uncomp_size_is_exact,
		uint32_t dict_size);

#ifndef LZMA_H_INTERNAL
#error Never include this file directly. Use <lzma.h> instead.
#endif

#define LZMA_STREAM_HEADER_SIZE 12

typedef struct {

	uint32_t version;

	lzma_vli backward_size;
#define LZMA_BACKWARD_SIZE_MIN 4
#define LZMA_BACKWARD_SIZE_MAX (LZMA_VLI_C(1) << 34)

	lzma_check check;

	lzma_reserved_enum reserved_enum1;
	lzma_reserved_enum reserved_enum2;
	lzma_reserved_enum reserved_enum3;
	lzma_reserved_enum reserved_enum4;
	lzma_bool reserved_bool1;
	lzma_bool reserved_bool2;
	lzma_bool reserved_bool3;
	lzma_bool reserved_bool4;
	lzma_bool reserved_bool5;
	lzma_bool reserved_bool6;
	lzma_bool reserved_bool7;
	lzma_bool reserved_bool8;
	uint32_t reserved_int1;
	uint32_t reserved_int2;

} lzma_stream_flags;

extern LZMA_API(lzma_ret) lzma_stream_header_encode(
		const lzma_stream_flags *options, uint8_t *out)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_stream_footer_encode(
		const lzma_stream_flags *options, uint8_t *out)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_stream_header_decode(
		lzma_stream_flags *options, const uint8_t *in)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_stream_footer_decode(
		lzma_stream_flags *options, const uint8_t *in)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_stream_flags_compare(
		const lzma_stream_flags *a, const lzma_stream_flags *b)
		lzma_nothrow lzma_attr_pure;

#ifndef LZMA_H_INTERNAL
#error Never include this file directly. Use <lzma.h> instead.
#endif

typedef struct {

	uint32_t version;

	uint32_t header_size;
#define LZMA_BLOCK_HEADER_SIZE_MIN 8
#define LZMA_BLOCK_HEADER_SIZE_MAX 1024

	lzma_check check;

	lzma_vli compressed_size;

	lzma_vli uncompressed_size;

	lzma_filter *filters;

	uint8_t raw_check[LZMA_CHECK_SIZE_MAX];

	void *reserved_ptr1;
	void *reserved_ptr2;
	void *reserved_ptr3;
	uint32_t reserved_int1;
	uint32_t reserved_int2;
	lzma_vli reserved_int3;
	lzma_vli reserved_int4;
	lzma_vli reserved_int5;
	lzma_vli reserved_int6;
	lzma_vli reserved_int7;
	lzma_vli reserved_int8;
	lzma_reserved_enum reserved_enum1;
	lzma_reserved_enum reserved_enum2;
	lzma_reserved_enum reserved_enum3;
	lzma_reserved_enum reserved_enum4;

	lzma_bool ignore_check;

	lzma_bool reserved_bool2;
	lzma_bool reserved_bool3;
	lzma_bool reserved_bool4;
	lzma_bool reserved_bool5;
	lzma_bool reserved_bool6;
	lzma_bool reserved_bool7;
	lzma_bool reserved_bool8;

} lzma_block;

#define lzma_block_header_size_decode(b) (((uint32_t)(b) + 1) * 4)

extern LZMA_API(lzma_ret) lzma_block_header_size(lzma_block *block)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_block_header_encode(
		const lzma_block *block, uint8_t *out)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_block_header_decode(lzma_block *block,
		const lzma_allocator *allocator, const uint8_t *in)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_block_compressed_size(
		lzma_block *block, lzma_vli unpadded_size)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_vli) lzma_block_unpadded_size(const lzma_block *block)
		lzma_nothrow lzma_attr_pure;

extern LZMA_API(lzma_vli) lzma_block_total_size(const lzma_block *block)
		lzma_nothrow lzma_attr_pure;

extern LZMA_API(lzma_ret) lzma_block_encoder(
		lzma_stream *strm, lzma_block *block)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_block_decoder(
		lzma_stream *strm, lzma_block *block)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(size_t) lzma_block_buffer_bound(size_t uncompressed_size)
		lzma_nothrow;

extern LZMA_API(lzma_ret) lzma_block_buffer_encode(
		lzma_block *block, const lzma_allocator *allocator,
		const uint8_t *in, size_t in_size,
		uint8_t *out, size_t *out_pos, size_t out_size)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_block_uncomp_encode(lzma_block *block,
		const uint8_t *in, size_t in_size,
		uint8_t *out, size_t *out_pos, size_t out_size)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_block_buffer_decode(
		lzma_block *block, const lzma_allocator *allocator,
		const uint8_t *in, size_t *in_pos, size_t in_size,
		uint8_t *out, size_t *out_pos, size_t out_size)
		lzma_nothrow;

#ifndef LZMA_H_INTERNAL
#error Never include this file directly. Use <lzma.h> instead.
#endif

typedef struct lzma_index_s lzma_index;

typedef struct {
	struct {

		const lzma_stream_flags *flags;

		const void *reserved_ptr1;
		const void *reserved_ptr2;
		const void *reserved_ptr3;

		lzma_vli number;

		lzma_vli block_count;

		lzma_vli compressed_offset;

		lzma_vli uncompressed_offset;

		lzma_vli compressed_size;

		lzma_vli uncompressed_size;

		lzma_vli padding;

		lzma_vli reserved_vli1;
		lzma_vli reserved_vli2;
		lzma_vli reserved_vli3;
		lzma_vli reserved_vli4;
	} stream;

	struct {

		lzma_vli number_in_file;

		lzma_vli compressed_file_offset;

		lzma_vli uncompressed_file_offset;

		lzma_vli number_in_stream;

		lzma_vli compressed_stream_offset;

		lzma_vli uncompressed_stream_offset;

		lzma_vli uncompressed_size;

		lzma_vli unpadded_size;

		lzma_vli total_size;

		lzma_vli reserved_vli1;
		lzma_vli reserved_vli2;
		lzma_vli reserved_vli3;
		lzma_vli reserved_vli4;

		const void *reserved_ptr1;
		const void *reserved_ptr2;
		const void *reserved_ptr3;
		const void *reserved_ptr4;
	} block;

	union {
		const void *p;
		size_t s;
		lzma_vli v;
	} internal[6];
} lzma_index_iter;

typedef enum {
	LZMA_INDEX_ITER_ANY             = 0,

	LZMA_INDEX_ITER_STREAM          = 1,

	LZMA_INDEX_ITER_BLOCK           = 2,

	LZMA_INDEX_ITER_NONEMPTY_BLOCK  = 3

} lzma_index_iter_mode;

extern LZMA_API(uint64_t) lzma_index_memusage(
		lzma_vli streams, lzma_vli blocks) lzma_nothrow;

extern LZMA_API(uint64_t) lzma_index_memused(const lzma_index *i)
		lzma_nothrow;

extern LZMA_API(lzma_index *) lzma_index_init(const lzma_allocator *allocator)
		lzma_nothrow;

extern LZMA_API(void) lzma_index_end(
		lzma_index *i, const lzma_allocator *allocator) lzma_nothrow;

extern LZMA_API(lzma_ret) lzma_index_append(
		lzma_index *i, const lzma_allocator *allocator,
		lzma_vli unpadded_size, lzma_vli uncompressed_size)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_index_stream_flags(
		lzma_index *i, const lzma_stream_flags *stream_flags)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(uint32_t) lzma_index_checks(const lzma_index *i)
		lzma_nothrow lzma_attr_pure;

extern LZMA_API(lzma_ret) lzma_index_stream_padding(
		lzma_index *i, lzma_vli stream_padding)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_vli) lzma_index_stream_count(const lzma_index *i)
		lzma_nothrow lzma_attr_pure;

extern LZMA_API(lzma_vli) lzma_index_block_count(const lzma_index *i)
		lzma_nothrow lzma_attr_pure;

extern LZMA_API(lzma_vli) lzma_index_size(const lzma_index *i)
		lzma_nothrow lzma_attr_pure;

extern LZMA_API(lzma_vli) lzma_index_stream_size(const lzma_index *i)
		lzma_nothrow lzma_attr_pure;

extern LZMA_API(lzma_vli) lzma_index_total_size(const lzma_index *i)
		lzma_nothrow lzma_attr_pure;

extern LZMA_API(lzma_vli) lzma_index_file_size(const lzma_index *i)
		lzma_nothrow lzma_attr_pure;

extern LZMA_API(lzma_vli) lzma_index_uncompressed_size(const lzma_index *i)
		lzma_nothrow lzma_attr_pure;

extern LZMA_API(void) lzma_index_iter_init(
		lzma_index_iter *iter, const lzma_index *i) lzma_nothrow;

extern LZMA_API(void) lzma_index_iter_rewind(lzma_index_iter *iter)
		lzma_nothrow;

extern LZMA_API(lzma_bool) lzma_index_iter_next(
		lzma_index_iter *iter, lzma_index_iter_mode mode)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_bool) lzma_index_iter_locate(
		lzma_index_iter *iter, lzma_vli target) lzma_nothrow;

extern LZMA_API(lzma_ret) lzma_index_cat(lzma_index *dest, lzma_index *src,
		const lzma_allocator *allocator)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_index *) lzma_index_dup(
		const lzma_index *i, const lzma_allocator *allocator)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_index_encoder(
		lzma_stream *strm, const lzma_index *i)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_index_decoder(
		lzma_stream *strm, lzma_index **i, uint64_t memlimit)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_index_buffer_encode(const lzma_index *i,
		uint8_t *out, size_t *out_pos, size_t out_size) lzma_nothrow;

extern LZMA_API(lzma_ret) lzma_index_buffer_decode(lzma_index **i,
		uint64_t *memlimit, const lzma_allocator *allocator,
		const uint8_t *in, size_t *in_pos, size_t in_size)
		lzma_nothrow;

extern LZMA_API(lzma_ret) lzma_file_info_decoder(
		lzma_stream *strm, lzma_index **dest_index,
		uint64_t memlimit, uint64_t file_size)
		lzma_nothrow;

#ifndef LZMA_H_INTERNAL
#error Never include this file directly. Use <lzma.h> instead.
#endif

typedef struct lzma_index_hash_s lzma_index_hash;

extern LZMA_API(lzma_index_hash *) lzma_index_hash_init(
		lzma_index_hash *index_hash, const lzma_allocator *allocator)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(void) lzma_index_hash_end(
		lzma_index_hash *index_hash, const lzma_allocator *allocator)
		lzma_nothrow;

extern LZMA_API(lzma_ret) lzma_index_hash_append(lzma_index_hash *index_hash,
		lzma_vli unpadded_size, lzma_vli uncompressed_size)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_ret) lzma_index_hash_decode(lzma_index_hash *index_hash,
		const uint8_t *in, size_t *in_pos, size_t in_size)
		lzma_nothrow lzma_attr_warn_unused_result;

extern LZMA_API(lzma_vli) lzma_index_hash_size(
		const lzma_index_hash *index_hash)
		lzma_nothrow lzma_attr_pure;

#ifndef LZMA_H_INTERNAL
#error Never include this file directly. Use <lzma.h> instead.
#endif

extern LZMA_API(uint64_t) lzma_physmem(void) lzma_nothrow;

extern LZMA_API(uint32_t) lzma_cputhreads(void) lzma_nothrow;

#undef LZMA_H_INTERNAL

#ifdef __cplusplus
}
#endif

#endif

#ifdef __has_attribute
#define lzma_has_attribute(attr) __has_attribute(attr)
#else
#define lzma_has_attribute(attr) 0
#endif

#if defined(HAVE_SYMBOL_VERSIONS_LINUX) && (HAVE_SYMBOL_VERSIONS_LINUX == 2 && !defined(PIC))
#undef HAVE_SYMBOL_VERSIONS_LINUX
#endif

#ifdef HAVE_SYMBOL_VERSIONS_LINUX

#if lzma_has_attribute(__symver__)
#define LZMA_SYMVER_API(extnamever, type, intname) extern __attribute__((__symver__(extnamever))) LZMA_API(type) intname
#else
#define LZMA_SYMVER_API(extnamever, type, intname) __asm__(".symver " #intname "," extnamever); extern LZMA_API(type) intname
#endif
#endif

#ifdef __GNUC__
#define likely(expr) __builtin_expect(expr, true)
#define unlikely(expr) __builtin_expect(expr, false)
#else
#define likely(expr) (expr)
#define unlikely(expr) (expr)
#endif

#define LZMA_BUFFER_SIZE 4096

#define LZMA_THREADS_MAX 16384

#define LZMA_MEMUSAGE_BASE (UINT64_C(1) << 15)

#define LZMA_FILTER_RESERVED_START (LZMA_VLI_C(1) << 62)

#define LZMA_SUPPORTED_FLAGS ( LZMA_TELL_NO_CHECK | LZMA_TELL_UNSUPPORTED_CHECK | LZMA_TELL_ANY_CHECK | LZMA_IGNORE_CHECK | LZMA_CONCATENATED | LZMA_FAIL_FAST )

#define LZMA_ACTION_MAX ((unsigned int)(LZMA_FULL_BARRIER))

#define LZMA_TIMED_OUT LZMA_RET_INTERNAL1

#define LZMA_INDEX_DETECTED LZMA_RET_INTERNAL2

typedef struct lzma_next_coder_s lzma_next_coder;

typedef struct lzma_filter_info_s lzma_filter_info;

typedef lzma_ret (*lzma_init_function)(
		lzma_next_coder *next, const lzma_allocator *allocator,
		const lzma_filter_info *filters);

typedef lzma_ret (*lzma_code_function)(
		void *coder, const lzma_allocator *allocator,
		const uint8_t *restrict in, size_t *restrict in_pos,
		size_t in_size, uint8_t *restrict out,
		size_t *restrict out_pos, size_t out_size,
		lzma_action action);

typedef void (*lzma_end_function)(
		void *coder, const lzma_allocator *allocator);

struct lzma_filter_info_s {

	lzma_vli id;

	lzma_init_function init;

	void *options;
};

struct lzma_next_coder_s {

	void *coder;

	lzma_vli id;

	uintptr_t init;

	lzma_code_function code;

	lzma_end_function end;

	void (*get_progress)(void *coder,
			uint64_t *progress_in, uint64_t *progress_out);

	lzma_check (*get_check)(const void *coder);

	lzma_ret (*memconfig)(void *coder, uint64_t *memusage,
			uint64_t *old_memlimit, uint64_t new_memlimit);

	lzma_ret (*update)(void *coder, const lzma_allocator *allocator,
			const lzma_filter *filters,
			const lzma_filter *reversed_filters);

	lzma_ret (*set_out_limit)(void *coder, uint64_t *uncomp_size,
			uint64_t out_limit);
};

#define LZMA_NEXT_CODER_INIT (lzma_next_coder){ .coder = NULL, .init = (uintptr_t)(NULL), .id = LZMA_VLI_UNKNOWN, .code = NULL, .end = NULL, .get_progress = NULL, .get_check = NULL, .memconfig = NULL, .update = NULL, .set_out_limit = NULL, }

struct lzma_internal_s {

	lzma_next_coder next;

	enum {
		ISEQ_RUN,
		ISEQ_SYNC_FLUSH,
		ISEQ_FULL_FLUSH,
		ISEQ_FINISH,
		ISEQ_FULL_BARRIER,
		ISEQ_END,
		ISEQ_ERROR,
	} sequence;

	size_t avail_in;

	bool supported_actions[LZMA_ACTION_MAX + 1];

	bool allow_buf_error;
};

extern void *lzma_alloc(size_t size, const lzma_allocator *allocator)
		lzma_attribute((__malloc__)) lzma_attr_alloc_size(1);

extern void * lzma_attribute((__malloc__)) lzma_attr_alloc_size(1)
		lzma_alloc_zero(size_t size, const lzma_allocator *allocator);

extern void lzma_free(void *ptr, const lzma_allocator *allocator);

extern lzma_ret lzma_strm_init(lzma_stream *strm);

extern lzma_ret lzma_next_filter_init(lzma_next_coder *next,
		const lzma_allocator *allocator,
		const lzma_filter_info *filters);

extern lzma_ret lzma_next_filter_update(
		lzma_next_coder *next, const lzma_allocator *allocator,
		const lzma_filter *reversed_filters);

extern void lzma_next_end(lzma_next_coder *next,
		const lzma_allocator *allocator);

extern size_t lzma_bufcpy(const uint8_t *restrict in, size_t *restrict in_pos,
		size_t in_size, uint8_t *restrict out,
		size_t *restrict out_pos, size_t out_size);

#define return_if_error(expr) \
do { const lzma_ret ret_ = (expr); if (ret_ != LZMA_OK) return ret_; \
} while (0)

#define lzma_next_coder_init(func, next, allocator) \
do { if ((uintptr_t)(func) != (next)->init) lzma_next_end(next, allocator); (next)->init = (uintptr_t)(func); \
} while (0)

#define lzma_next_strm_init(func, strm, ...) \
do { return_if_error(lzma_strm_init(strm)); const lzma_ret ret_ = func(&(strm)->internal->next, (strm)->allocator, __VA_ARGS__); if (ret_ != LZMA_OK) { lzma_end(strm); return ret_; } \
} while (0)

#endif

extern lzma_ret lzma_alone_decoder_init(
		lzma_next_coder *next, const lzma_allocator *allocator,
		uint64_t memlimit, bool picky);

#endif

#ifndef LZMA_LZMA_DECODER_H
#define LZMA_LZMA_DECODER_H

extern lzma_ret lzma_lzma_decoder_init(lzma_next_coder *next,
		const lzma_allocator *allocator,
		const lzma_filter_info *filters);

extern uint64_t lzma_lzma_decoder_memusage(const void *options);

extern lzma_ret lzma_lzma_props_decode(
		void **options, const lzma_allocator *allocator,
		const uint8_t *props, size_t props_size);

extern bool lzma_lzma_lclppb_decode(
		lzma_options_lzma *options, uint8_t byte);

#ifdef LZMA_LZ_DECODER_H

extern lzma_ret lzma_lzma_decoder_create(
		lzma_lz_decoder *lz, const lzma_allocator *allocator,
		const lzma_options_lzma *opt, lzma_lz_options *lz_options);

extern uint64_t lzma_lzma_decoder_memusage_nocheck(const void *options);

#endif

#endif

#ifndef LZMA_LZ_DECODER_H
#define LZMA_LZ_DECODER_H

typedef struct {

	uint8_t *buf;

	size_t pos;

	size_t full;

	size_t limit;

	size_t size;

	bool need_reset;

} lzma_dict;

typedef struct {
	size_t dict_size;
	const uint8_t *preset_dict;
	size_t preset_dict_size;
} lzma_lz_options;

typedef struct {

	void *coder;

	lzma_ret (*code)(void *coder,
			lzma_dict *restrict dict, const uint8_t *restrict in,
			size_t *restrict in_pos, size_t in_size);

	void (*reset)(void *coder, const void *options);

	void (*set_uncompressed)(void *coder, lzma_vli uncompressed_size,
			bool allow_eopm);

	void (*end)(void *coder, const lzma_allocator *allocator);

} lzma_lz_decoder;

#define LZMA_LZ_DECODER_INIT (lzma_lz_decoder){ .coder = NULL, .code = NULL, .reset = NULL, .set_uncompressed = NULL, .end = NULL, }

extern lzma_ret lzma_lz_decoder_init(lzma_next_coder *next,
		const lzma_allocator *allocator,
		const lzma_filter_info *filters,
		lzma_ret (*lz_init)(lzma_lz_decoder *lz,
			const lzma_allocator *allocator,
			lzma_vli id, const void *options,
			lzma_lz_options *lz_options));

extern uint64_t lzma_lz_decoder_memusage(size_t dictionary_size);

static inline uint8_t
dict_get(const lzma_dict *const dict, const uint32_t distance)
{
	return dict->buf[dict->pos - distance - 1
			+ (distance < dict->pos ? 0 : dict->size)];
}

static inline bool
dict_is_empty(const lzma_dict *const dict)
{
	return dict->full == 0;
}

static inline bool
dict_is_distance_valid(const lzma_dict *const dict, const size_t distance)
{
	return dict->full > distance;
}

static inline bool
dict_repeat(lzma_dict *dict, uint32_t distance, uint32_t *len)
{

	const size_t dict_avail = dict->limit - dict->pos;
	uint32_t left = my_min(dict_avail, *len);
	*len -= left;

	if (distance < left) {

		do {
			dict->buf[dict->pos] = dict_get(dict, distance);
			++dict->pos;
		} while (--left > 0);

	} else if (distance < dict->pos) {

		memcpy(dict->buf + dict->pos,
				dict->buf + dict->pos - distance - 1,
				left);
		dict->pos += left;

	} else {

		assert(dict->full == dict->size);
		const uint32_t copy_pos
				= dict->pos - distance - 1 + dict->size;
		uint32_t copy_size = dict->size - copy_pos;

		if (copy_size < left) {
			memmove(dict->buf + dict->pos, dict->buf + copy_pos,
					copy_size);
			dict->pos += copy_size;
			copy_size = left - copy_size;
			memcpy(dict->buf + dict->pos, dict->buf, copy_size);
			dict->pos += copy_size;
		} else {
			memmove(dict->buf + dict->pos, dict->buf + copy_pos,
					left);
			dict->pos += left;
		}
	}

	if (dict->full < dict->pos)
		dict->full = dict->pos;

	return unlikely(*len != 0);
}

static inline bool
dict_put(lzma_dict *dict, uint8_t byte)
{
	if (unlikely(dict->pos == dict->limit))
		return true;

	dict->buf[dict->pos++] = byte;

	if (dict->pos > dict->full)
		dict->full = dict->pos;

	return false;
}

static inline void
dict_write(lzma_dict *restrict dict, const uint8_t *restrict in,
		size_t *restrict in_pos, size_t in_size,
		size_t *restrict left)
{

	if (in_size - *in_pos > *left)
		in_size = *in_pos + *left;

	*left -= lzma_bufcpy(in, in_pos, in_size,
			dict->buf, &dict->pos, dict->limit);

	if (dict->pos > dict->full)
		dict->full = dict->pos;

	return;
}

static inline void
dict_reset(lzma_dict *dict)
{
	dict->need_reset = true;
	return;
}

#endif

typedef struct {
	lzma_next_coder next;

	enum {
		SEQ_ALONE_PROPERTIES,
		SEQ_ALONE_DICTIONARY_SIZE,
		SEQ_ALONE_UNCOMPRESSED_SIZE,
		SEQ_ALONE_CODER_INIT,
		SEQ_ALONE_CODE,
	} sequence;

	bool picky;

	size_t pos;

	lzma_vli uncompressed_size;

	uint64_t memlimit;

	uint64_t memusage;

	lzma_options_lzma options;
} lzma_alone_coder;

static lzma_ret
alone_decode(void *coder_ptr, const lzma_allocator *allocator,
		const uint8_t *restrict in, size_t *restrict in_pos,
		size_t in_size, uint8_t *restrict out,
		size_t *restrict out_pos, size_t out_size,
		lzma_action action)
{
	lzma_alone_coder *coder = coder_ptr;

	while (*out_pos < out_size
			&& (coder->sequence == SEQ_ALONE_CODE || *in_pos < in_size))
	switch (coder->sequence) {
	case SEQ_ALONE_PROPERTIES:
		if (lzma_lzma_lclppb_decode(&coder->options, in[*in_pos]))
			return LZMA_FORMAT_ERROR;

		coder->sequence = SEQ_ALONE_DICTIONARY_SIZE;
		++*in_pos;
		break;

	case SEQ_ALONE_DICTIONARY_SIZE:
		coder->options.dict_size
				|= (size_t)(in[*in_pos]) << (coder->pos * 8);

		if (++coder->pos == 4) {
			if (coder->picky && coder->options.dict_size
					!= UINT32_MAX) {

				uint32_t d = coder->options.dict_size - 1;
				d |= d >> 2;
				d |= d >> 3;
				d |= d >> 4;
				d |= d >> 8;
				d |= d >> 16;
				++d;

				if (d != coder->options.dict_size)
					return LZMA_FORMAT_ERROR;
			}

			coder->pos = 0;
			coder->sequence = SEQ_ALONE_UNCOMPRESSED_SIZE;
		}

		++*in_pos;
		break;

	case SEQ_ALONE_UNCOMPRESSED_SIZE:
		coder->uncompressed_size
				|= (lzma_vli)(in[*in_pos]) << (coder->pos * 8);
		++*in_pos;
		if (++coder->pos < 8)
			break;

		if (coder->picky
				&& coder->uncompressed_size != LZMA_VLI_UNKNOWN
				&& coder->uncompressed_size
					>= (LZMA_VLI_C(1) << 38))
			return LZMA_FORMAT_ERROR;

		coder->options.ext_flags = LZMA_LZMA1EXT_ALLOW_EOPM;
		lzma_set_ext_size(coder->options, coder->uncompressed_size);

		coder->memusage = lzma_lzma_decoder_memusage(&coder->options)
				+ LZMA_MEMUSAGE_BASE;

		coder->pos = 0;
		coder->sequence = SEQ_ALONE_CODER_INIT;

	case SEQ_ALONE_CODER_INIT: {
		if (coder->memusage > coder->memlimit)
			return LZMA_MEMLIMIT_ERROR;

		lzma_filter_info filters[2] = {
			{
				.id = LZMA_FILTER_LZMA1EXT,
				.init = &lzma_lzma_decoder_init,
				.options = &coder->options,
			}, {
				.init = NULL,
			}
		};

		return_if_error(lzma_next_filter_init(&coder->next,
				allocator, filters));

		coder->sequence = SEQ_ALONE_CODE;
		break;
	}

	case SEQ_ALONE_CODE: {
		return coder->next.code(coder->next.coder,
				allocator, in, in_pos, in_size,
				out, out_pos, out_size, action);
	}

	default:
		return LZMA_PROG_ERROR;
	}

	return LZMA_OK;
}

static void
alone_decoder_end(void *coder_ptr, const lzma_allocator *allocator)
{
	lzma_alone_coder *coder = coder_ptr;
	lzma_next_end(&coder->next, allocator);
	lzma_free(coder, allocator);
	return;
}

static lzma_ret
alone_decoder_memconfig(void *coder_ptr, uint64_t *memusage,
		uint64_t *old_memlimit, uint64_t new_memlimit)
{
	lzma_alone_coder *coder = coder_ptr;

	*memusage = coder->memusage;
	*old_memlimit = coder->memlimit;

	if (new_memlimit != 0) {
		if (new_memlimit < coder->memusage)
			return LZMA_MEMLIMIT_ERROR;

		coder->memlimit = new_memlimit;
	}

	return LZMA_OK;
}

extern lzma_ret
lzma_alone_decoder_init(lzma_next_coder *next, const lzma_allocator *allocator,
		uint64_t memlimit, bool picky)
{
	lzma_next_coder_init(&lzma_alone_decoder_init, next, allocator);

	lzma_alone_coder *coder = next->coder;

	if (coder == NULL) {
		coder = lzma_alloc(sizeof(lzma_alone_coder), allocator);
		if (coder == NULL)
			return LZMA_MEM_ERROR;

		next->coder = coder;
		next->code = &alone_decode;
		next->end = &alone_decoder_end;
		next->memconfig = &alone_decoder_memconfig;
		coder->next = LZMA_NEXT_CODER_INIT;
	}

	coder->sequence = SEQ_ALONE_PROPERTIES;
	coder->picky = picky;
	coder->pos = 0;
	coder->options.dict_size = 0;
	coder->options.preset_dict = NULL;
	coder->options.preset_dict_size = 0;
	coder->uncompressed_size = 0;
	coder->memlimit = my_max(1, memlimit);
	coder->memusage = LZMA_MEMUSAGE_BASE;

	return LZMA_OK;
}

extern LZMA_API(lzma_ret)
lzma_alone_decoder(lzma_stream *strm, uint64_t memlimit)
{
	lzma_next_strm_init(lzma_alone_decoder_init, strm, memlimit, false);

	strm->internal->supported_actions[LZMA_RUN] = true;
	strm->internal->supported_actions[LZMA_FINISH] = true;

	return LZMA_OK;
}

#ifndef LZMA_STREAM_DECODER_H
#define LZMA_STREAM_DECODER_H

extern lzma_ret lzma_stream_decoder_init(
		lzma_next_coder *next, const lzma_allocator *allocator,
		uint64_t memlimit, uint32_t flags);

#endif

#ifdef HAVE_LZIP_DECODER

#ifndef LZMA_LZIP_DECODER_H
#define LZMA_LZIP_DECODER_H

extern lzma_ret lzma_lzip_decoder_init(
		lzma_next_coder *next, const lzma_allocator *allocator,
		uint64_t memlimit, uint32_t flags);

lzma_ret lzma_lzip_decoder_init(
		lzma_next_coder *next, const lzma_allocator *allocator,
		uint64_t memlimit, uint32_t flags) {
			(void)next;
			(void)allocator;
			(void)memlimit;
			(void)flags;
			return LZMA_PROG_ERROR;
		}

#endif

#endif

typedef struct {

	lzma_next_coder next;

	uint64_t memlimit;
	uint32_t flags;

	enum {
		SEQ_AUTO_INIT,
		SEQ_AUTO_CODE,
		SEQ_AUTO_FINISH,
	} sequence;
} lzma_auto_coder;

static lzma_ret
auto_decode(void *coder_ptr, const lzma_allocator *allocator,
		const uint8_t *restrict in, size_t *restrict in_pos,
		size_t in_size, uint8_t *restrict out,
		size_t *restrict out_pos, size_t out_size, lzma_action action)
{
	lzma_auto_coder *coder = coder_ptr;

	switch (coder->sequence) {
	case SEQ_AUTO_INIT:
		if (*in_pos >= in_size)
			return LZMA_OK;

		coder->sequence = SEQ_AUTO_CODE;

		if (in[*in_pos] == 0xFD) {
			return_if_error(lzma_stream_decoder_init(
					&coder->next, allocator,
					coder->memlimit, coder->flags));
#ifdef HAVE_LZIP_DECODER
		} else if (in[*in_pos] == 0x4C) {
			return_if_error(lzma_lzip_decoder_init(
					&coder->next, allocator,
					coder->memlimit, coder->flags));
#endif
		} else {
			return_if_error(lzma_alone_decoder_init(&coder->next,
					allocator, coder->memlimit, true));

			if (coder->flags & LZMA_TELL_NO_CHECK)
				return LZMA_NO_CHECK;

			if (coder->flags & LZMA_TELL_ANY_CHECK)
				return LZMA_GET_CHECK;
		}

	case SEQ_AUTO_CODE: {
		const lzma_ret ret = coder->next.code(
				coder->next.coder, allocator,
				in, in_pos, in_size,
				out, out_pos, out_size, action);
		if (ret != LZMA_STREAM_END
				|| (coder->flags & LZMA_CONCATENATED) == 0)
			return ret;

		coder->sequence = SEQ_AUTO_FINISH;
	}

	case SEQ_AUTO_FINISH:

		if (*in_pos < in_size)
			return LZMA_DATA_ERROR;

		return action == LZMA_FINISH ? LZMA_STREAM_END : LZMA_OK;

	default:
		assert(0);
		return LZMA_PROG_ERROR;
	}
}

static void
auto_decoder_end(void *coder_ptr, const lzma_allocator *allocator)
{
	lzma_auto_coder *coder = coder_ptr;
	lzma_next_end(&coder->next, allocator);
	lzma_free(coder, allocator);
	return;
}

static lzma_check
auto_decoder_get_check(const void *coder_ptr)
{
	const lzma_auto_coder *coder = coder_ptr;

	return coder->next.get_check == NULL ? LZMA_CHECK_NONE
			: coder->next.get_check(coder->next.coder);
}

static lzma_ret
auto_decoder_memconfig(void *coder_ptr, uint64_t *memusage,
		uint64_t *old_memlimit, uint64_t new_memlimit)
{
	lzma_auto_coder *coder = coder_ptr;

	lzma_ret ret;

	if (coder->next.memconfig != NULL) {
		ret = coder->next.memconfig(coder->next.coder,
				memusage, old_memlimit, new_memlimit);
		assert(*old_memlimit == coder->memlimit);
	} else {

		*memusage = LZMA_MEMUSAGE_BASE;
		*old_memlimit = coder->memlimit;

		ret = LZMA_OK;
		if (new_memlimit != 0 && new_memlimit < *memusage)
			ret = LZMA_MEMLIMIT_ERROR;
	}

	if (ret == LZMA_OK && new_memlimit != 0)
		coder->memlimit = new_memlimit;

	return ret;
}

static lzma_ret
auto_decoder_init(lzma_next_coder *next, const lzma_allocator *allocator,
		uint64_t memlimit, uint32_t flags)
{
	lzma_next_coder_init(&auto_decoder_init, next, allocator);

	if (flags & ~LZMA_SUPPORTED_FLAGS)
		return LZMA_OPTIONS_ERROR;

	lzma_auto_coder *coder = next->coder;
	if (coder == NULL) {
		coder = lzma_alloc(sizeof(lzma_auto_coder), allocator);
		if (coder == NULL)
			return LZMA_MEM_ERROR;

		next->coder = coder;
		next->code = &auto_decode;
		next->end = &auto_decoder_end;
		next->get_check = &auto_decoder_get_check;
		next->memconfig = &auto_decoder_memconfig;
		coder->next = LZMA_NEXT_CODER_INIT;
	}

	coder->memlimit = my_max(1, memlimit);
	coder->flags = flags;
	coder->sequence = SEQ_AUTO_INIT;

	return LZMA_OK;
}

extern LZMA_API(lzma_ret)
lzma_auto_decoder(lzma_stream *strm, uint64_t memlimit, uint32_t flags)
{
	lzma_next_strm_init(auto_decoder_init, strm, memlimit, flags);

	strm->internal->supported_actions[LZMA_RUN] = true;
	strm->internal->supported_actions[LZMA_FINISH] = true;

	return LZMA_OK;
}

#ifndef LZMA_BLOCK_DECODER_H
#define LZMA_BLOCK_DECODER_H

extern lzma_ret lzma_block_decoder_init(lzma_next_coder *next,
		const lzma_allocator *allocator, lzma_block *block);

#endif

extern LZMA_API(lzma_ret)
lzma_block_buffer_decode(lzma_block *block, const lzma_allocator *allocator,
		const uint8_t *in, size_t *in_pos, size_t in_size,
		uint8_t *out, size_t *out_pos, size_t out_size)
{
	if (in_pos == NULL || (in == NULL && *in_pos != in_size)
			|| *in_pos > in_size || out_pos == NULL
			|| (out == NULL && *out_pos != out_size)
			|| *out_pos > out_size)
		return LZMA_PROG_ERROR;

	lzma_next_coder block_decoder = LZMA_NEXT_CODER_INIT;
	lzma_ret ret = lzma_block_decoder_init(
			&block_decoder, allocator, block);

	if (ret == LZMA_OK) {

		const size_t in_start = *in_pos;
		const size_t out_start = *out_pos;

		ret = block_decoder.code(block_decoder.coder, allocator,
				in, in_pos, in_size, out, out_pos, out_size,
				LZMA_FINISH);

		if (ret == LZMA_STREAM_END) {
			ret = LZMA_OK;
		} else {
			if (ret == LZMA_OK) {

				assert(*in_pos == in_size
						|| *out_pos == out_size);

				if (*in_pos == in_size)
					ret = LZMA_DATA_ERROR;
				else
					ret = LZMA_BUF_ERROR;
			}

			*in_pos = in_start;
			*out_pos = out_start;
		}
	}

	lzma_next_end(&block_decoder, allocator);

	return ret;
}

#ifndef LZMA_FILTER_DECODER_H
#define LZMA_FILTER_DECODER_H

extern lzma_ret lzma_raw_decoder_init(
		lzma_next_coder *next, const lzma_allocator *allocator,
		const lzma_filter *options);

#endif

#ifndef LZMA_CHECK_H
#define LZMA_CHECK_H

#if !(defined(HAVE_CC_SHA256_INIT) || defined(HAVE_SHA256_INIT) || defined(HAVE_SHA256INIT))
#define HAVE_INTERNAL_SHA256 1
#endif

#if defined(HAVE_INTERNAL_SHA256)

#elif defined(HAVE_COMMONCRYPTO_COMMONDIGEST_H)
#include <CommonCrypto/CommonDigest.h>
#elif defined(HAVE_SHA256_H)
#include <sys/types.h>
#include <sha256.h>
#elif defined(HAVE_SHA2_H)
#include <sys/types.h>
#include <sha2.h>
#endif

#if defined(HAVE_INTERNAL_SHA256)

typedef struct {

	uint32_t state[8];

	uint64_t size;
} lzma_sha256_state;
#elif defined(HAVE_CC_SHA256_CTX)
typedef CC_SHA256_CTX lzma_sha256_state;
#elif defined(HAVE_SHA256_CTX)
typedef SHA256_CTX lzma_sha256_state;
#elif defined(HAVE_SHA2_CTX)
typedef SHA2_CTX lzma_sha256_state;
#endif

#if defined(HAVE_INTERNAL_SHA256)

#elif defined(HAVE_CC_SHA256_INIT)
#define LZMA_SHA256FUNC(x) CC_SHA256_ ## x
#elif defined(HAVE_SHA256_INIT)
#define LZMA_SHA256FUNC(x) SHA256_ ## x
#elif defined(HAVE_SHA256INIT)
#define LZMA_SHA256FUNC(x) SHA256 ## x
#endif

#if defined(HAVE_CHECK_SHA256)
#define LZMA_CHECK_BEST LZMA_CHECK_SHA256
#elif defined(HAVE_CHECK_CRC64)
#define LZMA_CHECK_BEST LZMA_CHECK_CRC64
#else
#define LZMA_CHECK_BEST LZMA_CHECK_CRC32
#endif

typedef struct {

	union {
		uint8_t u8[64];
		uint32_t u32[16];
		uint64_t u64[8];
	} buffer;

	union {
		uint32_t crc32;
		uint64_t crc64;
		lzma_sha256_state sha256;
	} state;

} lzma_check_state;

#ifdef HAVE_SMALL
extern uint32_t lzma_crc32_table[1][256];
extern void lzma_crc32_init(void);
#else
extern const uint32_t lzma_crc32_table[8][256];
extern const uint64_t lzma_crc64_table[4][256];
#endif

extern void lzma_check_init(lzma_check_state *check, lzma_check type);

extern void lzma_check_update(lzma_check_state *check, lzma_check type,
		const uint8_t *buf, size_t size);

extern void lzma_check_finish(lzma_check_state *check, lzma_check type);

#ifndef LZMA_SHA256FUNC

extern void lzma_sha256_init(lzma_check_state *check);

extern void lzma_sha256_update(
		const uint8_t *buf, size_t size, lzma_check_state *check);

extern void lzma_sha256_finish(lzma_check_state *check);

#else

static inline void
lzma_sha256_init(lzma_check_state *check)
{
	LZMA_SHA256FUNC(Init)(&check->state.sha256);
}

static inline void
lzma_sha256_update(const uint8_t *buf, size_t size, lzma_check_state *check)
{
#if defined(HAVE_CC_SHA256_INIT) && SIZE_MAX > UINT32_MAX

	while (size > UINT32_MAX) {
		LZMA_SHA256FUNC(Update)(&check->state.sha256, buf, UINT32_MAX);
		buf += UINT32_MAX;
		size -= UINT32_MAX;
	}
#endif

	LZMA_SHA256FUNC(Update)(&check->state.sha256, buf, size);
}

static inline void
lzma_sha256_finish(lzma_check_state *check)
{
	LZMA_SHA256FUNC(Final)(check->buffer.u8, &check->state.sha256);
}

#endif

#endif

typedef struct {
	enum {
		SEQ_BLOCK_DEC_CODE,
		SEQ_BLOCK_DEC_PADDING,
		SEQ_BLOCK_DEC_CHECK,
	} sequence;

	lzma_next_coder next;

	lzma_block *block;

	lzma_vli compressed_size;

	lzma_vli uncompressed_size;

	lzma_vli compressed_limit;

	lzma_vli uncompressed_limit;

	size_t check_pos;

	lzma_check_state check;

	bool ignore_check;
} lzma_block_coder;

static inline bool
is_size_valid(lzma_vli size, lzma_vli reference)
{
	return reference == LZMA_VLI_UNKNOWN || reference == size;
}

static lzma_ret
block_decode(void *coder_ptr, const lzma_allocator *allocator,
		const uint8_t *restrict in, size_t *restrict in_pos,
		size_t in_size, uint8_t *restrict out,
		size_t *restrict out_pos, size_t out_size, lzma_action action)
{
	lzma_block_coder *coder = coder_ptr;

	switch (coder->sequence) {
	case SEQ_BLOCK_DEC_CODE: {
		const size_t in_start = *in_pos;
		const size_t out_start = *out_pos;

		const size_t in_stop = *in_pos + (size_t)my_min(
			in_size - *in_pos,
			coder->compressed_limit - coder->compressed_size);
		const size_t out_stop = *out_pos + (size_t)my_min(
			out_size - *out_pos,
			coder->uncompressed_limit - coder->uncompressed_size);

		const lzma_ret ret = coder->next.code(coder->next.coder,
				allocator, in, in_pos, in_stop,
				out, out_pos, out_stop, action);

		const size_t in_used = *in_pos - in_start;
		const size_t out_used = *out_pos - out_start;

		coder->compressed_size += in_used;
		coder->uncompressed_size += out_used;

		if (ret == LZMA_OK) {
			const bool comp_done = coder->compressed_size
					== coder->block->compressed_size;
			const bool uncomp_done = coder->uncompressed_size
					== coder->block->uncompressed_size;

			if (comp_done && uncomp_done)
				return LZMA_DATA_ERROR;

			if (comp_done && *out_pos < out_size)
				return LZMA_DATA_ERROR;

			if (uncomp_done && *in_pos < in_size)
				return LZMA_DATA_ERROR;
		}

		if (!coder->ignore_check)
			lzma_check_update(&coder->check, coder->block->check,
					out + out_start, out_used);

		if (ret != LZMA_STREAM_END)
			return ret;

		if (!is_size_valid(coder->compressed_size,
					coder->block->compressed_size)
				|| !is_size_valid(coder->uncompressed_size,
					coder->block->uncompressed_size))
			return LZMA_DATA_ERROR;

		coder->block->compressed_size = coder->compressed_size;
		coder->block->uncompressed_size = coder->uncompressed_size;

		coder->sequence = SEQ_BLOCK_DEC_PADDING;
	}

	case SEQ_BLOCK_DEC_PADDING:

		while (coder->compressed_size & 3) {
			if (*in_pos >= in_size)
				return LZMA_OK;

			++coder->compressed_size;

			if (in[(*in_pos)++] != 0x00)
				return LZMA_DATA_ERROR;
		}

		if (coder->block->check == LZMA_CHECK_NONE)
			return LZMA_STREAM_END;

		if (!coder->ignore_check)
			lzma_check_finish(&coder->check, coder->block->check);

		coder->sequence = SEQ_BLOCK_DEC_CHECK;

	case SEQ_BLOCK_DEC_CHECK: {
		const size_t check_size = lzma_check_size(coder->block->check);
		lzma_bufcpy(in, in_pos, in_size, coder->block->raw_check,
				&coder->check_pos, check_size);
		if (coder->check_pos < check_size)
			return LZMA_OK;

		if (!coder->ignore_check
				&& lzma_check_is_supported(coder->block->check)
				&& memcmp(coder->block->raw_check,
					coder->check.buffer.u8,
					check_size) != 0)
			return LZMA_DATA_ERROR;

		return LZMA_STREAM_END;
	}
	}

	return LZMA_PROG_ERROR;
}

static void
block_decoder_end(void *coder_ptr, const lzma_allocator *allocator)
{
	lzma_block_coder *coder = coder_ptr;
	lzma_next_end(&coder->next, allocator);
	lzma_free(coder, allocator);
	return;
}

extern lzma_ret
lzma_block_decoder_init(lzma_next_coder *next, const lzma_allocator *allocator,
		lzma_block *block)
{
	lzma_next_coder_init(&lzma_block_decoder_init, next, allocator);

	if (lzma_block_unpadded_size(block) == 0
			|| !lzma_vli_is_valid(block->uncompressed_size))
		return LZMA_PROG_ERROR;

	lzma_block_coder *coder = next->coder;
	if (coder == NULL) {
		coder = lzma_alloc(sizeof(lzma_block_coder), allocator);
		if (coder == NULL)
			return LZMA_MEM_ERROR;

		next->coder = coder;
		next->code = &block_decode;
		next->end = &block_decoder_end;
		coder->next = LZMA_NEXT_CODER_INIT;
	}

	coder->sequence = SEQ_BLOCK_DEC_CODE;
	coder->block = block;
	coder->compressed_size = 0;
	coder->uncompressed_size = 0;

	coder->compressed_limit
			= block->compressed_size == LZMA_VLI_UNKNOWN
				? (LZMA_VLI_MAX & ~LZMA_VLI_C(3))
					- block->header_size
					- lzma_check_size(block->check)
				: block->compressed_size;

	coder->uncompressed_limit
			= block->uncompressed_size == LZMA_VLI_UNKNOWN
				? LZMA_VLI_MAX
				: block->uncompressed_size;

	coder->check_pos = 0;
	lzma_check_init(&coder->check, block->check);

	coder->ignore_check = block->version >= 1
			? block->ignore_check : false;

	return lzma_raw_decoder_init(&coder->next, allocator,
			block->filters);
}

extern LZMA_API(lzma_ret)
lzma_block_decoder(lzma_stream *strm, lzma_block *block)
{
	lzma_next_strm_init(lzma_block_decoder_init, strm, block);

	strm->internal->supported_actions[LZMA_RUN] = true;
	strm->internal->supported_actions[LZMA_FINISH] = true;

	return LZMA_OK;
}

extern LZMA_API(lzma_ret)
lzma_block_header_decode(lzma_block *block,
		const lzma_allocator *allocator, const uint8_t *in)
{

	for (size_t i = 0; i <= LZMA_FILTERS_MAX; ++i) {
		block->filters[i].id = LZMA_VLI_UNKNOWN;
		block->filters[i].options = NULL;
	}

	if (block->version > 1)
		block->version = 1;

	block->ignore_check = false;

	if (lzma_block_header_size_decode(in[0]) != block->header_size
			|| (unsigned int)(block->check) > LZMA_CHECK_ID_MAX)
		return LZMA_PROG_ERROR;

	const size_t in_size = block->header_size - 4;

	if (lzma_crc32(in, in_size, 0) != read32le(in + in_size)) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
		return LZMA_DATA_ERROR;
#endif
	}

	if (in[1] & 0x3C)
		return LZMA_OPTIONS_ERROR;

	size_t in_pos = 2;

	if (in[1] & 0x40) {
		return_if_error(lzma_vli_decode(&block->compressed_size,
				NULL, in, &in_pos, in_size));

		if (lzma_block_unpadded_size(block) == 0)
			return LZMA_DATA_ERROR;
	} else {
		block->compressed_size = LZMA_VLI_UNKNOWN;
	}

	if (in[1] & 0x80)
		return_if_error(lzma_vli_decode(&block->uncompressed_size,
				NULL, in, &in_pos, in_size));
	else
		block->uncompressed_size = LZMA_VLI_UNKNOWN;

	const size_t filter_count = (in[1] & 3U) + 1;
	for (size_t i = 0; i < filter_count; ++i) {
		const lzma_ret ret = lzma_filter_flags_decode(
				&block->filters[i], allocator,
				in, &in_pos, in_size);
		if (ret != LZMA_OK) {
			lzma_filters_free(block->filters, allocator);
			return ret;
		}
	}

	while (in_pos < in_size) {
		if (in[in_pos++] != 0x00) {
			lzma_filters_free(block->filters, allocator);

			return LZMA_OPTIONS_ERROR;
		}
	}

	return LZMA_OK;
}

#ifndef LZMA_INDEX_H
#define LZMA_INDEX_H

#define UNPADDED_SIZE_MIN LZMA_VLI_C(5)

#define UNPADDED_SIZE_MAX (LZMA_VLI_MAX & ~LZMA_VLI_C(3))

extern uint32_t lzma_index_padding_size(const lzma_index *i);

extern void lzma_index_prealloc(lzma_index *i, lzma_vli records);

static inline lzma_vli
vli_ceil4(lzma_vli vli)
{
	assert(vli <= LZMA_VLI_MAX);
	return (vli + 3) & ~LZMA_VLI_C(3);
}

static inline lzma_vli
index_size_unpadded(lzma_vli count, lzma_vli index_list_size)
{

	return 1 + lzma_vli_size(count) + index_list_size + 4;
}

static inline lzma_vli
index_size(lzma_vli count, lzma_vli index_list_size)
{
	return vli_ceil4(index_size_unpadded(count, index_list_size));
}

static inline lzma_vli
index_stream_size(lzma_vli blocks_size,
		lzma_vli count, lzma_vli index_list_size)
{
	return LZMA_STREAM_HEADER_SIZE + blocks_size
			+ index_size(count, index_list_size)
			+ LZMA_STREAM_HEADER_SIZE;
}

#endif

extern LZMA_API(lzma_ret)
lzma_block_compressed_size(lzma_block *block, lzma_vli unpadded_size)
{

	if (lzma_block_unpadded_size(block) == 0)
		return LZMA_PROG_ERROR;

	const uint32_t container_size = block->header_size
			+ lzma_check_size(block->check);

	if (unpadded_size <= container_size)
		return LZMA_DATA_ERROR;

	const lzma_vli compressed_size = unpadded_size - container_size;
	if (block->compressed_size != LZMA_VLI_UNKNOWN
			&& block->compressed_size != compressed_size)
		return LZMA_DATA_ERROR;

	block->compressed_size = compressed_size;

	return LZMA_OK;
}

extern LZMA_API(lzma_vli)
lzma_block_unpadded_size(const lzma_block *block)
{

	if (block == NULL || block->version > 1
			|| block->header_size < LZMA_BLOCK_HEADER_SIZE_MIN
			|| block->header_size > LZMA_BLOCK_HEADER_SIZE_MAX
			|| (block->header_size & 3)
			|| !lzma_vli_is_valid(block->compressed_size)
			|| block->compressed_size == 0
			|| (unsigned int)(block->check) > LZMA_CHECK_ID_MAX)
		return 0;

	if (block->compressed_size == LZMA_VLI_UNKNOWN)
		return LZMA_VLI_UNKNOWN;

	const lzma_vli unpadded_size = block->compressed_size
				+ block->header_size
				+ lzma_check_size(block->check);

	assert(unpadded_size >= UNPADDED_SIZE_MIN);
	if (unpadded_size > UNPADDED_SIZE_MAX)
		return 0;

	return unpadded_size;
}

extern LZMA_API(lzma_vli)
lzma_block_total_size(const lzma_block *block)
{
	lzma_vli unpadded_size = lzma_block_unpadded_size(block);

	if (unpadded_size != LZMA_VLI_UNKNOWN)
		unpadded_size = vli_ceil4(unpadded_size);

	return unpadded_size;
}

extern LZMA_API(uint32_t)
lzma_version_number(void)
{
	return LZMA_VERSION;
}

extern LZMA_API(const char *)
lzma_version_string(void)
{
	return LZMA_VERSION_STRING;
}

extern void * lzma_attribute((__malloc__)) lzma_attr_alloc_size(1)
lzma_alloc(size_t size, const lzma_allocator *allocator)
{

	if (size == 0)
		size = 1;

	void *ptr;

	if (allocator != NULL && allocator->alloc != NULL)
		ptr = allocator->alloc(allocator->opaque, 1, size);
	else
		ptr = malloc(size);

	return ptr;
}

extern void * lzma_attribute((__malloc__)) lzma_attr_alloc_size(1)
lzma_alloc_zero(size_t size, const lzma_allocator *allocator)
{

	if (size == 0)
		size = 1;

	void *ptr;

	if (allocator != NULL && allocator->alloc != NULL) {
		ptr = allocator->alloc(allocator->opaque, 1, size);
		if (ptr != NULL)
			memzero(ptr, size);
	} else {
		ptr = calloc(1, size);
	}

	return ptr;
}

extern void
lzma_free(void *ptr, const lzma_allocator *allocator)
{
	if (allocator != NULL && allocator->free != NULL)
		allocator->free(allocator->opaque, ptr);
	else
		free(ptr);

	return;
}

extern size_t
lzma_bufcpy(const uint8_t *restrict in, size_t *restrict in_pos,
		size_t in_size, uint8_t *restrict out,
		size_t *restrict out_pos, size_t out_size)
{
	const size_t in_avail = in_size - *in_pos;
	const size_t out_avail = out_size - *out_pos;
	const size_t copy_size = my_min(in_avail, out_avail);

	if (copy_size > 0)
		memcpy(out + *out_pos, in + *in_pos, copy_size);

	*in_pos += copy_size;
	*out_pos += copy_size;

	return copy_size;
}

extern lzma_ret
lzma_next_filter_init(lzma_next_coder *next, const lzma_allocator *allocator,
		const lzma_filter_info *filters)
{
	lzma_next_coder_init(filters[0].init, next, allocator);
	next->id = filters[0].id;
	return filters[0].init == NULL
			? LZMA_OK : filters[0].init(next, allocator, filters);
}

extern lzma_ret
lzma_next_filter_update(lzma_next_coder *next, const lzma_allocator *allocator,
		const lzma_filter *reversed_filters)
{

	if (reversed_filters[0].id != next->id)
		return LZMA_PROG_ERROR;

	if (reversed_filters[0].id == LZMA_VLI_UNKNOWN)
		return LZMA_OK;

	assert(next->update != NULL);
	return next->update(next->coder, allocator, NULL, reversed_filters);
}

extern void
lzma_next_end(lzma_next_coder *next, const lzma_allocator *allocator)
{
	if (next->init != (uintptr_t)(NULL)) {

		if (next->end != NULL)
			next->end(next->coder, allocator);
		else
			lzma_free(next->coder, allocator);

		*next = LZMA_NEXT_CODER_INIT;
	}

	return;
}

extern lzma_ret
lzma_strm_init(lzma_stream *strm)
{
	if (strm == NULL)
		return LZMA_PROG_ERROR;

	if (strm->internal == NULL) {
		strm->internal = lzma_alloc(sizeof(lzma_internal),
				strm->allocator);
		if (strm->internal == NULL)
			return LZMA_MEM_ERROR;

		strm->internal->next = LZMA_NEXT_CODER_INIT;
	}

	memzero(strm->internal->supported_actions,
			sizeof(strm->internal->supported_actions));
	strm->internal->sequence = ISEQ_RUN;
	strm->internal->allow_buf_error = false;

	strm->total_in = 0;
	strm->total_out = 0;

	return LZMA_OK;
}

extern LZMA_API(lzma_ret)
lzma_code(lzma_stream *strm, lzma_action action)
{

	if ((strm->next_in == NULL && strm->avail_in != 0)
			|| (strm->next_out == NULL && strm->avail_out != 0)
			|| strm->internal == NULL
			|| strm->internal->next.code == NULL
			|| (unsigned int)(action) > LZMA_ACTION_MAX
			|| !strm->internal->supported_actions[action])
		return LZMA_PROG_ERROR;

	if (strm->reserved_ptr1 != NULL
			|| strm->reserved_ptr2 != NULL
			|| strm->reserved_ptr3 != NULL
			|| strm->reserved_ptr4 != NULL
			|| strm->reserved_int2 != 0
			|| strm->reserved_int3 != 0
			|| strm->reserved_int4 != 0
			|| strm->reserved_enum1 != LZMA_RESERVED_ENUM
			|| strm->reserved_enum2 != LZMA_RESERVED_ENUM)
		return LZMA_OPTIONS_ERROR;

	switch (strm->internal->sequence) {
	case ISEQ_RUN:
		switch (action) {
		case LZMA_RUN:
			break;

		case LZMA_SYNC_FLUSH:
			strm->internal->sequence = ISEQ_SYNC_FLUSH;
			break;

		case LZMA_FULL_FLUSH:
			strm->internal->sequence = ISEQ_FULL_FLUSH;
			break;

		case LZMA_FINISH:
			strm->internal->sequence = ISEQ_FINISH;
			break;

		case LZMA_FULL_BARRIER:
			strm->internal->sequence = ISEQ_FULL_BARRIER;
			break;
		}

		break;

	case ISEQ_SYNC_FLUSH:

		if (action != LZMA_SYNC_FLUSH
				|| strm->internal->avail_in != strm->avail_in)
			return LZMA_PROG_ERROR;

		break;

	case ISEQ_FULL_FLUSH:
		if (action != LZMA_FULL_FLUSH
				|| strm->internal->avail_in != strm->avail_in)
			return LZMA_PROG_ERROR;

		break;

	case ISEQ_FINISH:
		if (action != LZMA_FINISH
				|| strm->internal->avail_in != strm->avail_in)
			return LZMA_PROG_ERROR;

		break;

	case ISEQ_FULL_BARRIER:
		if (action != LZMA_FULL_BARRIER
				|| strm->internal->avail_in != strm->avail_in)
			return LZMA_PROG_ERROR;

		break;

	case ISEQ_END:
		return LZMA_STREAM_END;

	case ISEQ_ERROR:
	default:
		return LZMA_PROG_ERROR;
	}

	size_t in_pos = 0;
	size_t out_pos = 0;
	lzma_ret ret = strm->internal->next.code(
			strm->internal->next.coder, strm->allocator,
			strm->next_in, &in_pos, strm->avail_in,
			strm->next_out, &out_pos, strm->avail_out, action);

	strm->next_in += in_pos;
	strm->avail_in -= in_pos;
	strm->total_in += in_pos;

	strm->next_out += out_pos;
	strm->avail_out -= out_pos;
	strm->total_out += out_pos;

	strm->internal->avail_in = strm->avail_in;

	switch (ret) {
	case LZMA_OK:

		if (out_pos == 0 && in_pos == 0) {
			if (strm->internal->allow_buf_error)
				ret = LZMA_BUF_ERROR;
			else
				strm->internal->allow_buf_error = true;
		} else {
			strm->internal->allow_buf_error = false;
		}
		break;

	case LZMA_TIMED_OUT:
		strm->internal->allow_buf_error = false;
		ret = LZMA_OK;
		break;

	case LZMA_SEEK_NEEDED:
		strm->internal->allow_buf_error = false;

		if (strm->internal->sequence == ISEQ_FINISH)
			strm->internal->sequence = ISEQ_RUN;

		break;

	case LZMA_STREAM_END:
		if (strm->internal->sequence == ISEQ_SYNC_FLUSH
				|| strm->internal->sequence == ISEQ_FULL_FLUSH
				|| strm->internal->sequence
					== ISEQ_FULL_BARRIER)
			strm->internal->sequence = ISEQ_RUN;
		else
			strm->internal->sequence = ISEQ_END;

	case LZMA_NO_CHECK:
	case LZMA_UNSUPPORTED_CHECK:
	case LZMA_GET_CHECK:
	case LZMA_MEMLIMIT_ERROR:

		strm->internal->allow_buf_error = false;
		break;

	default:

		assert(ret != LZMA_BUF_ERROR);
		strm->internal->sequence = ISEQ_ERROR;
		break;
	}

	return ret;
}

extern LZMA_API(void)
lzma_end(lzma_stream *strm)
{
	if (strm != NULL && strm->internal != NULL) {
		lzma_next_end(&strm->internal->next, strm->allocator);
		lzma_free(strm->internal, strm->allocator);
		strm->internal = NULL;
	}

	return;
}

#ifdef HAVE_SYMBOL_VERSIONS_LINUX

LZMA_SYMVER_API("lzma_get_progress@XZ_5.2.2",
	void, lzma_get_progress_522)(lzma_stream *strm,
		uint64_t *progress_in, uint64_t *progress_out) lzma_nothrow
		__attribute__((__alias__("lzma_get_progress_52")));

LZMA_SYMVER_API("lzma_get_progress@@XZ_5.2",
	void, lzma_get_progress_52)(lzma_stream *strm,
		uint64_t *progress_in, uint64_t *progress_out) lzma_nothrow;

#define lzma_get_progress lzma_get_progress_52
#endif
extern LZMA_API(void)
lzma_get_progress(lzma_stream *strm,
		uint64_t *progress_in, uint64_t *progress_out)
{
	if (strm->internal->next.get_progress != NULL) {
		strm->internal->next.get_progress(strm->internal->next.coder,
				progress_in, progress_out);
	} else {
		*progress_in = strm->total_in;
		*progress_out = strm->total_out;
	}

	return;
}

extern LZMA_API(lzma_check)
lzma_get_check(const lzma_stream *strm)
{

	if (strm->internal->next.get_check == NULL)
		return LZMA_CHECK_NONE;

	return strm->internal->next.get_check(strm->internal->next.coder);
}

extern LZMA_API(uint64_t)
lzma_memusage(const lzma_stream *strm)
{
	uint64_t memusage;
	uint64_t old_memlimit;

	if (strm == NULL || strm->internal == NULL
			|| strm->internal->next.memconfig == NULL
			|| strm->internal->next.memconfig(
				strm->internal->next.coder,
				&memusage, &old_memlimit, 0) != LZMA_OK)
		return 0;

	return memusage;
}

extern LZMA_API(uint64_t)
lzma_memlimit_get(const lzma_stream *strm)
{
	uint64_t old_memlimit;
	uint64_t memusage;

	if (strm == NULL || strm->internal == NULL
			|| strm->internal->next.memconfig == NULL
			|| strm->internal->next.memconfig(
				strm->internal->next.coder,
				&memusage, &old_memlimit, 0) != LZMA_OK)
		return 0;

	return old_memlimit;
}

extern LZMA_API(lzma_ret)
lzma_memlimit_set(lzma_stream *strm, uint64_t new_memlimit)
{

	uint64_t old_memlimit;
	uint64_t memusage;

	if (strm == NULL || strm->internal == NULL
			|| strm->internal->next.memconfig == NULL)
		return LZMA_PROG_ERROR;

	if (new_memlimit == 0)
		new_memlimit = 1;

	return strm->internal->next.memconfig(strm->internal->next.coder,
			&memusage, &old_memlimit, new_memlimit);
}

typedef struct {

	lzma_filter filters[LZMA_FILTERS_MAX + 1];

	lzma_options_lzma opt_lzma;

} lzma_options_easy;

extern bool lzma_easy_preset(lzma_options_easy *easy, uint32_t preset);

extern LZMA_API(uint64_t)
lzma_easy_decoder_memusage(uint32_t preset)
{
	lzma_options_easy opt_easy;
	if (lzma_easy_preset(&opt_easy, preset))
		return UINT32_MAX;

	return lzma_raw_decoder_memusage(opt_easy.filters);
}

extern bool
lzma_easy_preset(lzma_options_easy *opt_easy, uint32_t preset)
{
	if (lzma_lzma_preset(&opt_easy->opt_lzma, preset))
		return true;

	opt_easy->filters[0].id = LZMA_FILTER_LZMA2;
	opt_easy->filters[0].options = &opt_easy->opt_lzma;
	opt_easy->filters[1].id = LZMA_VLI_UNKNOWN;

	return false;
}

extern LZMA_API(lzma_ret)
lzma_raw_buffer_decode(
		const lzma_filter *filters, const lzma_allocator *allocator,
		const uint8_t *in, size_t *in_pos, size_t in_size,
		uint8_t *out, size_t *out_pos, size_t out_size)
{

	if (in == NULL || in_pos == NULL || *in_pos > in_size || out == NULL
			|| out_pos == NULL || *out_pos > out_size)
		return LZMA_PROG_ERROR;

	lzma_next_coder next = LZMA_NEXT_CODER_INIT;
	return_if_error(lzma_raw_decoder_init(&next, allocator, filters));

	const size_t in_start = *in_pos;
	const size_t out_start = *out_pos;

	lzma_ret ret = next.code(next.coder, allocator, in, in_pos, in_size,
			out, out_pos, out_size, LZMA_FINISH);

	if (ret == LZMA_STREAM_END) {
		ret = LZMA_OK;
	} else {
		if (ret == LZMA_OK) {

			assert(*in_pos == in_size || *out_pos == out_size);

			if (*in_pos != in_size) {

				ret = LZMA_BUF_ERROR;

			} else if (*out_pos != out_size) {

				ret = LZMA_DATA_ERROR;

			} else {

				uint8_t tmp[1];
				size_t tmp_pos = 0;
				(void)next.code(next.coder, allocator,
						in, in_pos, in_size,
						tmp, &tmp_pos, 1, LZMA_FINISH);

				if (tmp_pos == 1)
					ret = LZMA_BUF_ERROR;
				else
					ret = LZMA_DATA_ERROR;
			}
		}

		*in_pos = in_start;
		*out_pos = out_start;
	}

	lzma_next_end(&next, allocator);

	return ret;
}

#ifndef LZMA_FILTER_COMMON_H
#define LZMA_FILTER_COMMON_H

typedef struct {

	lzma_vli id;

	lzma_init_function init;

	uint64_t (*memusage)(const void *options);

} lzma_filter_coder;

typedef const lzma_filter_coder *(*lzma_filter_find)(lzma_vli id);

extern lzma_ret lzma_validate_chain(const lzma_filter *filters, size_t *count);

extern lzma_ret lzma_raw_coder_init(
		lzma_next_coder *next, const lzma_allocator *allocator,
		const lzma_filter *filters,
		lzma_filter_find coder_find, bool is_encoder);

extern uint64_t lzma_raw_coder_memusage(lzma_filter_find coder_find,
		const lzma_filter *filters);

#endif

static const struct {

	lzma_vli id;

	size_t options_size;

	bool non_last_ok;

	bool last_ok;

	bool changes_size;

} features[] = {
#if defined (HAVE_ENCODER_LZMA1) || defined(HAVE_DECODER_LZMA1)
	{
		.id = LZMA_FILTER_LZMA1,
		.options_size = sizeof(lzma_options_lzma),
		.non_last_ok = false,
		.last_ok = true,
		.changes_size = true,
	},
	{
		.id = LZMA_FILTER_LZMA1EXT,
		.options_size = sizeof(lzma_options_lzma),
		.non_last_ok = false,
		.last_ok = true,
		.changes_size = true,
	},
#endif
#if defined(HAVE_ENCODER_LZMA2) || defined(HAVE_DECODER_LZMA2)
	{
		.id = LZMA_FILTER_LZMA2,
		.options_size = sizeof(lzma_options_lzma),
		.non_last_ok = false,
		.last_ok = true,
		.changes_size = true,
	},
#endif
#if defined(HAVE_ENCODER_X86) || defined(HAVE_DECODER_X86)
	{
		.id = LZMA_FILTER_X86,
		.options_size = sizeof(lzma_options_bcj),
		.non_last_ok = true,
		.last_ok = false,
		.changes_size = false,
	},
#endif
#if defined(HAVE_ENCODER_POWERPC) || defined(HAVE_DECODER_POWERPC)
	{
		.id = LZMA_FILTER_POWERPC,
		.options_size = sizeof(lzma_options_bcj),
		.non_last_ok = true,
		.last_ok = false,
		.changes_size = false,
	},
#endif
#if defined(HAVE_ENCODER_IA64) || defined(HAVE_DECODER_IA64)
	{
		.id = LZMA_FILTER_IA64,
		.options_size = sizeof(lzma_options_bcj),
		.non_last_ok = true,
		.last_ok = false,
		.changes_size = false,
	},
#endif
#if defined(HAVE_ENCODER_ARM) || defined(HAVE_DECODER_ARM)
	{
		.id = LZMA_FILTER_ARM,
		.options_size = sizeof(lzma_options_bcj),
		.non_last_ok = true,
		.last_ok = false,
		.changes_size = false,
	},
#endif
#if defined(HAVE_ENCODER_ARMTHUMB) || defined(HAVE_DECODER_ARMTHUMB)
	{
		.id = LZMA_FILTER_ARMTHUMB,
		.options_size = sizeof(lzma_options_bcj),
		.non_last_ok = true,
		.last_ok = false,
		.changes_size = false,
	},
#endif
#if defined(HAVE_ENCODER_ARM64) || defined(HAVE_DECODER_ARM64)
	{
		.id = LZMA_FILTER_ARM64,
		.options_size = sizeof(lzma_options_bcj),
		.non_last_ok = true,
		.last_ok = false,
		.changes_size = false,
	},
#endif
#if defined(HAVE_ENCODER_SPARC) || defined(HAVE_DECODER_SPARC)
	{
		.id = LZMA_FILTER_SPARC,
		.options_size = sizeof(lzma_options_bcj),
		.non_last_ok = true,
		.last_ok = false,
		.changes_size = false,
	},
#endif
#if defined(HAVE_ENCODER_DELTA) || defined(HAVE_DECODER_DELTA)
	{
		.id = LZMA_FILTER_DELTA,
		.options_size = sizeof(lzma_options_delta),
		.non_last_ok = true,
		.last_ok = false,
		.changes_size = false,
	},
#endif
	{
		.id = LZMA_VLI_UNKNOWN
	}
};

extern LZMA_API(lzma_ret)
lzma_filters_copy(const lzma_filter *src, lzma_filter *real_dest,
		const lzma_allocator *allocator)
{
	if (src == NULL || real_dest == NULL)
		return LZMA_PROG_ERROR;

	lzma_filter dest[LZMA_FILTERS_MAX + 1];

	lzma_ret ret;
	size_t i;
	for (i = 0; src[i].id != LZMA_VLI_UNKNOWN; ++i) {

		if (i == LZMA_FILTERS_MAX) {
			ret = LZMA_OPTIONS_ERROR;
			goto error;
		}

		dest[i].id = src[i].id;

		if (src[i].options == NULL) {
			dest[i].options = NULL;
		} else {

			size_t j;
			for (j = 0; src[i].id != features[j].id; ++j) {
				if (features[j].id == LZMA_VLI_UNKNOWN) {
					ret = LZMA_OPTIONS_ERROR;
					goto error;
				}
			}

			dest[i].options = lzma_alloc(features[j].options_size,
					allocator);
			if (dest[i].options == NULL) {
				ret = LZMA_MEM_ERROR;
				goto error;
			}

			memcpy(dest[i].options, src[i].options,
					features[j].options_size);
		}
	}

	assert(i < LZMA_FILTERS_MAX + 1);
	dest[i].id = LZMA_VLI_UNKNOWN;
	dest[i].options = NULL;

	memcpy(real_dest, dest, (i + 1) * sizeof(lzma_filter));

	return LZMA_OK;

error:

	while (i-- > 0)
		lzma_free(dest[i].options, allocator);

	return ret;
}

extern LZMA_API(void)
lzma_filters_free(lzma_filter *filters, const lzma_allocator *allocator)
{
	if (filters == NULL)
		return;

	for (size_t i = 0; filters[i].id != LZMA_VLI_UNKNOWN; ++i) {
		if (i == LZMA_FILTERS_MAX) {

			assert(0);
			break;
		}

		lzma_free(filters[i].options, allocator);
		filters[i].options = NULL;
		filters[i].id = LZMA_VLI_UNKNOWN;
	}

	return;
}

extern lzma_ret
lzma_validate_chain(const lzma_filter *filters, size_t *count)
{

	if (filters == NULL || filters[0].id == LZMA_VLI_UNKNOWN)
		return LZMA_PROG_ERROR;

	size_t changes_size_count = 0;

	bool non_last_ok = true;

	bool last_ok = false;

	size_t i = 0;
	do {
		size_t j;
		for (j = 0; filters[i].id != features[j].id; ++j)
			if (features[j].id == LZMA_VLI_UNKNOWN)
				return LZMA_OPTIONS_ERROR;

		if (!non_last_ok)
			return LZMA_OPTIONS_ERROR;

		non_last_ok = features[j].non_last_ok;
		last_ok = features[j].last_ok;
		changes_size_count += features[j].changes_size;

	} while (filters[++i].id != LZMA_VLI_UNKNOWN);

	if (i > LZMA_FILTERS_MAX || !last_ok || changes_size_count > 3)
		return LZMA_OPTIONS_ERROR;

	*count = i;
	return LZMA_OK;
}

extern lzma_ret
lzma_raw_coder_init(lzma_next_coder *next, const lzma_allocator *allocator,
		const lzma_filter *options,
		lzma_filter_find coder_find, bool is_encoder)
{

	size_t count;
	return_if_error(lzma_validate_chain(options, &count));

	lzma_filter_info filters[LZMA_FILTERS_MAX + 1];
	if (is_encoder) {
		for (size_t i = 0; i < count; ++i) {

			const size_t j = count - i - 1;

			const lzma_filter_coder *const fc
					= coder_find(options[i].id);
			if (fc == NULL || fc->init == NULL)
				return LZMA_OPTIONS_ERROR;

			filters[j].id = options[i].id;
			filters[j].init = fc->init;
			filters[j].options = options[i].options;
		}
	} else {
		for (size_t i = 0; i < count; ++i) {
			const lzma_filter_coder *const fc
					= coder_find(options[i].id);
			if (fc == NULL || fc->init == NULL)
				return LZMA_OPTIONS_ERROR;

			filters[i].id = options[i].id;
			filters[i].init = fc->init;
			filters[i].options = options[i].options;
		}
	}

	filters[count].id = LZMA_VLI_UNKNOWN;
	filters[count].init = NULL;

	const lzma_ret ret = lzma_next_filter_init(next, allocator, filters);
	if (ret != LZMA_OK)
		lzma_next_end(next, allocator);

	return ret;
}

extern uint64_t
lzma_raw_coder_memusage(lzma_filter_find coder_find,
		const lzma_filter *filters)
{

	{
		size_t tmp;
		if (lzma_validate_chain(filters, &tmp) != LZMA_OK)
			return UINT64_MAX;
	}

	uint64_t total = 0;
	size_t i = 0;

	do {
		const lzma_filter_coder *const fc
				 = coder_find(filters[i].id);
		if (fc == NULL)
			return UINT64_MAX;

		if (fc->memusage == NULL) {

			total += 1024;
		} else {

			const uint64_t usage
					= fc->memusage(filters[i].options);
			if (usage == UINT64_MAX)
				return UINT64_MAX;

			total += usage;
		}
	} while (filters[++i].id != LZMA_VLI_UNKNOWN);

	return total + LZMA_MEMUSAGE_BASE;
}

#ifndef LZMA_LZMA2_DECODER_H
#define LZMA_LZMA2_DECODER_H

extern lzma_ret lzma_lzma2_decoder_init(lzma_next_coder *next,
		const lzma_allocator *allocator,
		const lzma_filter_info *filters);

extern uint64_t lzma_lzma2_decoder_memusage(const void *options);

extern lzma_ret lzma_lzma2_props_decode(
		void **options, const lzma_allocator *allocator,
		const uint8_t *props, size_t props_size);

#endif

#ifndef LZMA_SIMPLE_DECODER_H
#define LZMA_SIMPLE_DECODER_H

#ifndef LZMA_SIMPLE_CODER_H
#define LZMA_SIMPLE_CODER_H

extern lzma_ret lzma_simple_x86_encoder_init(lzma_next_coder *next,
		const lzma_allocator *allocator,
		const lzma_filter_info *filters);

extern lzma_ret lzma_simple_x86_decoder_init(lzma_next_coder *next,
		const lzma_allocator *allocator,
		const lzma_filter_info *filters);

extern lzma_ret lzma_simple_powerpc_encoder_init(lzma_next_coder *next,
		const lzma_allocator *allocator,
		const lzma_filter_info *filters);

extern lzma_ret lzma_simple_powerpc_decoder_init(lzma_next_coder *next,
		const lzma_allocator *allocator,
		const lzma_filter_info *filters);

extern lzma_ret lzma_simple_ia64_encoder_init(lzma_next_coder *next,
		const lzma_allocator *allocator,
		const lzma_filter_info *filters);

extern lzma_ret lzma_simple_ia64_decoder_init(lzma_next_coder *next,
		const lzma_allocator *allocator,
		const lzma_filter_info *filters);

extern lzma_ret lzma_simple_arm_encoder_init(lzma_next_coder *next,
		const lzma_allocator *allocator,
		const lzma_filter_info *filters);

extern lzma_ret lzma_simple_arm_decoder_init(lzma_next_coder *next,
		const lzma_allocator *allocator,
		const lzma_filter_info *filters);

extern lzma_ret lzma_simple_armthumb_encoder_init(lzma_next_coder *next,
		const lzma_allocator *allocator,
		const lzma_filter_info *filters);

extern lzma_ret lzma_simple_armthumb_decoder_init(lzma_next_coder *next,
		const lzma_allocator *allocator,
		const lzma_filter_info *filters);

extern lzma_ret lzma_simple_arm64_encoder_init(lzma_next_coder *next,
               const lzma_allocator *allocator,
               const lzma_filter_info *filters);

extern lzma_ret lzma_simple_arm64_decoder_init(lzma_next_coder *next,
               const lzma_allocator *allocator,
               const lzma_filter_info *filters);

extern lzma_ret lzma_simple_sparc_encoder_init(lzma_next_coder *next,
		const lzma_allocator *allocator,
		const lzma_filter_info *filters);

extern lzma_ret lzma_simple_sparc_decoder_init(lzma_next_coder *next,
		const lzma_allocator *allocator,
		const lzma_filter_info *filters);

#endif

extern lzma_ret lzma_simple_props_decode(
		void **options, const lzma_allocator *allocator,
		const uint8_t *props, size_t props_size);

#endif

#ifndef LZMA_DELTA_DECODER_H
#define LZMA_DELTA_DECODER_H

#ifndef LZMA_DELTA_COMMON_H
#define LZMA_DELTA_COMMON_H

extern uint64_t lzma_delta_coder_memusage(const void *options);

#endif

extern lzma_ret lzma_delta_decoder_init(lzma_next_coder *next,
		const lzma_allocator *allocator,
		const lzma_filter_info *filters);

extern lzma_ret lzma_delta_props_decode(
		void **options, const lzma_allocator *allocator,
		const uint8_t *props, size_t props_size);

#endif

typedef struct {

	lzma_vli id;

	lzma_init_function init;

	uint64_t (*memusage)(const void *options);

	lzma_ret (*props_decode)(
			void **options, const lzma_allocator *allocator,
			const uint8_t *props, size_t props_size);

} lzma_filter_decoder;

static const lzma_filter_decoder decoders[] = {
#ifdef HAVE_DECODER_LZMA1
	{
		.id = LZMA_FILTER_LZMA1,
		.init = &lzma_lzma_decoder_init,
		.memusage = &lzma_lzma_decoder_memusage,
		.props_decode = &lzma_lzma_props_decode,
	},
	{
		.id = LZMA_FILTER_LZMA1EXT,
		.init = &lzma_lzma_decoder_init,
		.memusage = &lzma_lzma_decoder_memusage,
		.props_decode = &lzma_lzma_props_decode,
	},
#endif
#ifdef HAVE_DECODER_LZMA2
	{
		.id = LZMA_FILTER_LZMA2,
		.init = &lzma_lzma2_decoder_init,
		.memusage = &lzma_lzma2_decoder_memusage,
		.props_decode = &lzma_lzma2_props_decode,
	},
#endif
#ifdef HAVE_DECODER_X86
	{
		.id = LZMA_FILTER_X86,
		.init = &lzma_simple_x86_decoder_init,
		.memusage = NULL,
		.props_decode = &lzma_simple_props_decode,
	},
#endif
#ifdef HAVE_DECODER_POWERPC
	{
		.id = LZMA_FILTER_POWERPC,
		.init = &lzma_simple_powerpc_decoder_init,
		.memusage = NULL,
		.props_decode = &lzma_simple_props_decode,
	},
#endif
#ifdef HAVE_DECODER_IA64
	{
		.id = LZMA_FILTER_IA64,
		.init = &lzma_simple_ia64_decoder_init,
		.memusage = NULL,
		.props_decode = &lzma_simple_props_decode,
	},
#endif
#ifdef HAVE_DECODER_ARM
	{
		.id = LZMA_FILTER_ARM,
		.init = &lzma_simple_arm_decoder_init,
		.memusage = NULL,
		.props_decode = &lzma_simple_props_decode,
	},
#endif
#ifdef HAVE_DECODER_ARMTHUMB
	{
		.id = LZMA_FILTER_ARMTHUMB,
		.init = &lzma_simple_armthumb_decoder_init,
		.memusage = NULL,
		.props_decode = &lzma_simple_props_decode,
	},
#endif
#ifdef HAVE_DECODER_ARM64
	{
		.id = LZMA_FILTER_ARM64,
		.init = &lzma_simple_arm64_decoder_init,
		.memusage = NULL,
		.props_decode = &lzma_simple_props_decode,
	},
#endif
#ifdef HAVE_DECODER_SPARC
	{
		.id = LZMA_FILTER_SPARC,
		.init = &lzma_simple_sparc_decoder_init,
		.memusage = NULL,
		.props_decode = &lzma_simple_props_decode,
	},
#endif
#ifdef HAVE_DECODER_DELTA
	{
		.id = LZMA_FILTER_DELTA,
		.init = &lzma_delta_decoder_init,
		.memusage = &lzma_delta_coder_memusage,
		.props_decode = &lzma_delta_props_decode,
	},
#endif
};

static const lzma_filter_decoder *
decoder_find(lzma_vli id)
{
	for (size_t i = 0; i < ARRAY_SIZE(decoders); ++i)
		if (decoders[i].id == id)
			return decoders + i;

	return NULL;
}

extern LZMA_API(lzma_bool)
lzma_filter_decoder_is_supported(lzma_vli id)
{
	return decoder_find(id) != NULL;
}

extern lzma_ret
lzma_raw_decoder_init(lzma_next_coder *next, const lzma_allocator *allocator,
		const lzma_filter *options)
{
	return lzma_raw_coder_init(next, allocator,
			options, (lzma_filter_find)(&decoder_find), false);
}

extern LZMA_API(lzma_ret)
lzma_raw_decoder(lzma_stream *strm, const lzma_filter *options)
{
	lzma_next_strm_init(lzma_raw_decoder_init, strm, options);

	strm->internal->supported_actions[LZMA_RUN] = true;
	strm->internal->supported_actions[LZMA_FINISH] = true;

	return LZMA_OK;
}

extern LZMA_API(uint64_t)
lzma_raw_decoder_memusage(const lzma_filter *filters)
{
	return lzma_raw_coder_memusage(
			(lzma_filter_find)(&decoder_find), filters);
}

extern LZMA_API(lzma_ret)
lzma_properties_decode(lzma_filter *filter, const lzma_allocator *allocator,
		const uint8_t *props, size_t props_size)
{

	filter->options = NULL;

	const lzma_filter_decoder *const fd = decoder_find(filter->id);
	if (fd == NULL)
		return LZMA_OPTIONS_ERROR;

	if (fd->props_decode == NULL)
		return props_size == 0 ? LZMA_OK : LZMA_OPTIONS_ERROR;

	return fd->props_decode(
			&filter->options, allocator, props, props_size);
}

extern LZMA_API(lzma_ret)
lzma_filter_flags_decode(
		lzma_filter *filter, const lzma_allocator *allocator,
		const uint8_t *in, size_t *in_pos, size_t in_size)
{

	filter->options = NULL;

	return_if_error(lzma_vli_decode(&filter->id, NULL,
			in, in_pos, in_size));

	if (filter->id >= LZMA_FILTER_RESERVED_START)
		return LZMA_DATA_ERROR;

	lzma_vli props_size;
	return_if_error(lzma_vli_decode(&props_size, NULL,
			in, in_pos, in_size));

	if (in_size - *in_pos < props_size)
		return LZMA_DATA_ERROR;

	const lzma_ret ret = lzma_properties_decode(
			filter, allocator, in + *in_pos, props_size);

	*in_pos += props_size;

	return ret;
}

#ifdef HAVE_SYMBOL_VERSIONS_LINUX

LZMA_SYMVER_API("lzma_cputhreads@XZ_5.2.2",
	uint32_t, lzma_cputhreads_522)(void) lzma_nothrow
		__attribute__((__alias__("lzma_cputhreads_52")));

LZMA_SYMVER_API("lzma_cputhreads@@XZ_5.2",
	uint32_t, lzma_cputhreads_52)(void) lzma_nothrow;

#define lzma_cputhreads lzma_cputhreads_52
#endif
extern LZMA_API(uint32_t)
lzma_cputhreads(void)
{
	return tuklib_cpucores();
}

extern LZMA_API(uint64_t)
lzma_physmem(void)
{

	return tuklib_physmem();
}

#ifndef LZMA_STREAM_FLAGS_COMMON_H
#define LZMA_STREAM_FLAGS_COMMON_H

#define LZMA_STREAM_FLAGS_SIZE 2

extern const uint8_t lzma_header_magic[6];
extern const uint8_t lzma_footer_magic[2];

static inline bool
is_backward_size_valid(const lzma_stream_flags *options)
{
	return options->backward_size >= LZMA_BACKWARD_SIZE_MIN
			&& options->backward_size <= LZMA_BACKWARD_SIZE_MAX
			&& (options->backward_size & 3) == 0;
}

#endif

#define INDEX_GROUP_SIZE 512

#define PREALLOC_MAX ((SIZE_MAX - sizeof(index_group)) / sizeof(index_record))

typedef struct index_tree_node_s index_tree_node;
struct index_tree_node_s {

	lzma_vli uncompressed_base;

	lzma_vli compressed_base;

	index_tree_node *parent;
	index_tree_node *left;
	index_tree_node *right;
};

typedef struct {

	index_tree_node *root;

	index_tree_node *leftmost;

	index_tree_node *rightmost;

	uint32_t count;

} index_tree;

typedef struct {
	lzma_vli uncompressed_sum;
	lzma_vli unpadded_sum;
} index_record;

typedef struct {

	index_tree_node node;

	lzma_vli number_base;

	size_t allocated;

	size_t last;

	index_record records[];

} index_group;

typedef struct {

	index_tree_node node;

	uint32_t number;

	lzma_vli block_number_base;

	index_tree groups;

	lzma_vli record_count;

	lzma_vli index_list_size;

	lzma_stream_flags stream_flags;

	lzma_vli stream_padding;

} index_stream;

struct lzma_index_s {

	index_tree streams;

	lzma_vli uncompressed_size;

	lzma_vli total_size;

	lzma_vli record_count;

	lzma_vli index_list_size;

	size_t prealloc;

	uint32_t checks;
};

static void
index_tree_init(index_tree *tree)
{
	tree->root = NULL;
	tree->leftmost = NULL;
	tree->rightmost = NULL;
	tree->count = 0;
	return;
}

static void
index_tree_node_end(index_tree_node *node, const lzma_allocator *allocator,
		void (*free_func)(void *node, const lzma_allocator *allocator))
{

	if (node->left != NULL)
		index_tree_node_end(node->left, allocator, free_func);

	if (node->right != NULL)
		index_tree_node_end(node->right, allocator, free_func);

	free_func(node, allocator);
	return;
}

static void
index_tree_end(index_tree *tree, const lzma_allocator *allocator,
		void (*free_func)(void *node, const lzma_allocator *allocator))
{
	assert(free_func != NULL);

	if (tree->root != NULL)
		index_tree_node_end(tree->root, allocator, free_func);

	return;
}

static void
index_tree_append(index_tree *tree, index_tree_node *node)
{
	node->parent = tree->rightmost;
	node->left = NULL;
	node->right = NULL;

	++tree->count;

	if (tree->root == NULL) {
		tree->root = node;
		tree->leftmost = node;
		tree->rightmost = node;
		return;
	}

	assert(tree->rightmost->uncompressed_base <= node->uncompressed_base);
	assert(tree->rightmost->compressed_base < node->compressed_base);

	tree->rightmost->right = node;
	tree->rightmost = node;

	uint32_t up = tree->count ^ (UINT32_C(1) << bsr32(tree->count));
	if (up != 0) {

		up = ctz32(tree->count) + 2;
		do {
			node = node->parent;
		} while (--up > 0);

		index_tree_node *pivot = node->right;

		if (node->parent == NULL) {
			tree->root = pivot;
		} else {
			assert(node->parent->right == node);
			node->parent->right = pivot;
		}

		pivot->parent = node->parent;

		node->right = pivot->left;
		if (node->right != NULL)
			node->right->parent = node;

		pivot->left = node;
		node->parent = pivot;
	}

	return;
}

static void *
index_tree_next(const index_tree_node *node)
{
	if (node->right != NULL) {
		node = node->right;
		while (node->left != NULL)
			node = node->left;

		return (void *)(node);
	}

	while (node->parent != NULL && node->parent->right == node)
		node = node->parent;

	return (void *)(node->parent);
}

static void *
index_tree_locate(const index_tree *tree, lzma_vli target)
{
	const index_tree_node *result = NULL;
	const index_tree_node *node = tree->root;

	assert(tree->leftmost == NULL
			|| tree->leftmost->uncompressed_base == 0);

	while (node != NULL) {
		if (node->uncompressed_base > target) {
			node = node->left;
		} else {
			result = node;
			node = node->right;
		}
	}

	return (void *)(result);
}

static index_stream *
index_stream_init(lzma_vli compressed_base, lzma_vli uncompressed_base,
		uint32_t stream_number, lzma_vli block_number_base,
		const lzma_allocator *allocator)
{
	index_stream *s = lzma_alloc(sizeof(index_stream), allocator);
	if (s == NULL)
		return NULL;

	s->node.uncompressed_base = uncompressed_base;
	s->node.compressed_base = compressed_base;
	s->node.parent = NULL;
	s->node.left = NULL;
	s->node.right = NULL;

	s->number = stream_number;
	s->block_number_base = block_number_base;

	index_tree_init(&s->groups);

	s->record_count = 0;
	s->index_list_size = 0;
	s->stream_flags.version = UINT32_MAX;
	s->stream_padding = 0;

	return s;
}

static void
index_stream_end(void *node, const lzma_allocator *allocator)
{
	index_stream *s = node;
	index_tree_end(&s->groups, allocator, &lzma_free);
	lzma_free(s, allocator);
	return;
}

static lzma_index *
index_init_plain(const lzma_allocator *allocator)
{
	lzma_index *i = lzma_alloc(sizeof(lzma_index), allocator);
	if (i != NULL) {
		index_tree_init(&i->streams);
		i->uncompressed_size = 0;
		i->total_size = 0;
		i->record_count = 0;
		i->index_list_size = 0;
		i->prealloc = INDEX_GROUP_SIZE;
		i->checks = 0;
	}

	return i;
}

extern LZMA_API(lzma_index *)
lzma_index_init(const lzma_allocator *allocator)
{
	lzma_index *i = index_init_plain(allocator);
	if (i == NULL)
		return NULL;

	index_stream *s = index_stream_init(0, 0, 1, 0, allocator);
	if (s == NULL) {
		lzma_free(i, allocator);
		return NULL;
	}

	index_tree_append(&i->streams, &s->node);

	return i;
}

extern LZMA_API(void)
lzma_index_end(lzma_index *i, const lzma_allocator *allocator)
{

	if (i != NULL) {
		index_tree_end(&i->streams, allocator, &index_stream_end);
		lzma_free(i, allocator);
	}

	return;
}

extern void
lzma_index_prealloc(lzma_index *i, lzma_vli records)
{
	if (records > PREALLOC_MAX)
		records = PREALLOC_MAX;

	i->prealloc = (size_t)(records);
	return;
}

extern LZMA_API(uint64_t)
lzma_index_memusage(lzma_vli streams, lzma_vli blocks)
{

	const size_t alloc_overhead = 4 * sizeof(void *);

	const size_t stream_base = sizeof(index_stream)
			+ sizeof(index_group) + 2 * alloc_overhead;

	const size_t group_base = sizeof(index_group)
			+ INDEX_GROUP_SIZE * sizeof(index_record)
			+ alloc_overhead;

	const lzma_vli groups
			= (blocks + INDEX_GROUP_SIZE - 1) / INDEX_GROUP_SIZE;

	const uint64_t streams_mem = streams * stream_base;
	const uint64_t groups_mem = groups * group_base;

	const uint64_t index_base = sizeof(lzma_index) + alloc_overhead;

	const uint64_t limit = UINT64_MAX - index_base;
	if (streams == 0 || streams > UINT32_MAX || blocks > LZMA_VLI_MAX
			|| streams > limit / stream_base
			|| groups > limit / group_base
			|| limit - streams_mem < groups_mem)
		return UINT64_MAX;

	return index_base + streams_mem + groups_mem;
}

extern LZMA_API(uint64_t)
lzma_index_memused(const lzma_index *i)
{
	return lzma_index_memusage(i->streams.count, i->record_count);
}

extern LZMA_API(lzma_vli)
lzma_index_block_count(const lzma_index *i)
{
	return i->record_count;
}

extern LZMA_API(lzma_vli)
lzma_index_stream_count(const lzma_index *i)
{
	return i->streams.count;
}

extern LZMA_API(lzma_vli)
lzma_index_size(const lzma_index *i)
{
	return index_size(i->record_count, i->index_list_size);
}

extern LZMA_API(lzma_vli)
lzma_index_total_size(const lzma_index *i)
{
	return i->total_size;
}

extern LZMA_API(lzma_vli)
lzma_index_stream_size(const lzma_index *i)
{

	return LZMA_STREAM_HEADER_SIZE + i->total_size
			+ index_size(i->record_count, i->index_list_size)
			+ LZMA_STREAM_HEADER_SIZE;
}

static lzma_vli
index_file_size(lzma_vli compressed_base, lzma_vli unpadded_sum,
		lzma_vli record_count, lzma_vli index_list_size,
		lzma_vli stream_padding)
{

	lzma_vli file_size = compressed_base + 2 * LZMA_STREAM_HEADER_SIZE
			+ stream_padding + vli_ceil4(unpadded_sum);
	if (file_size > LZMA_VLI_MAX)
		return LZMA_VLI_UNKNOWN;

	file_size += index_size(record_count, index_list_size);
	if (file_size > LZMA_VLI_MAX)
		return LZMA_VLI_UNKNOWN;

	return file_size;
}

extern LZMA_API(lzma_vli)
lzma_index_file_size(const lzma_index *i)
{
	const index_stream *s = (const index_stream *)(i->streams.rightmost);
	const index_group *g = (const index_group *)(s->groups.rightmost);
	return index_file_size(s->node.compressed_base,
			g == NULL ? 0 : g->records[g->last].unpadded_sum,
			s->record_count, s->index_list_size,
			s->stream_padding);
}

extern LZMA_API(lzma_vli)
lzma_index_uncompressed_size(const lzma_index *i)
{
	return i->uncompressed_size;
}

extern LZMA_API(uint32_t)
lzma_index_checks(const lzma_index *i)
{
	uint32_t checks = i->checks;

	const index_stream *s = (const index_stream *)(i->streams.rightmost);
	if (s->stream_flags.version != UINT32_MAX)
		checks |= UINT32_C(1) << s->stream_flags.check;

	return checks;
}

extern uint32_t
lzma_index_padding_size(const lzma_index *i)
{
	return (LZMA_VLI_C(4) - index_size_unpadded(
			i->record_count, i->index_list_size)) & 3;
}

extern LZMA_API(lzma_ret)
lzma_index_stream_flags(lzma_index *i, const lzma_stream_flags *stream_flags)
{
	if (i == NULL || stream_flags == NULL)
		return LZMA_PROG_ERROR;

	return_if_error(lzma_stream_flags_compare(
			stream_flags, stream_flags));

	index_stream *s = (index_stream *)(i->streams.rightmost);
	s->stream_flags = *stream_flags;

	return LZMA_OK;
}

extern LZMA_API(lzma_ret)
lzma_index_stream_padding(lzma_index *i, lzma_vli stream_padding)
{
	if (i == NULL || stream_padding > LZMA_VLI_MAX
			|| (stream_padding & 3) != 0)
		return LZMA_PROG_ERROR;

	index_stream *s = (index_stream *)(i->streams.rightmost);

	const lzma_vli old_stream_padding = s->stream_padding;
	s->stream_padding = 0;
	if (lzma_index_file_size(i) + stream_padding > LZMA_VLI_MAX) {
		s->stream_padding = old_stream_padding;
		return LZMA_DATA_ERROR;
	}

	s->stream_padding = stream_padding;
	return LZMA_OK;
}

extern LZMA_API(lzma_ret)
lzma_index_append(lzma_index *i, const lzma_allocator *allocator,
		lzma_vli unpadded_size, lzma_vli uncompressed_size)
{

	if (i == NULL || unpadded_size < UNPADDED_SIZE_MIN
			|| unpadded_size > UNPADDED_SIZE_MAX
			|| uncompressed_size > LZMA_VLI_MAX)
		return LZMA_PROG_ERROR;

	index_stream *s = (index_stream *)(i->streams.rightmost);
	index_group *g = (index_group *)(s->groups.rightmost);

	const lzma_vli compressed_base = g == NULL ? 0
			: vli_ceil4(g->records[g->last].unpadded_sum);
	const lzma_vli uncompressed_base = g == NULL ? 0
			: g->records[g->last].uncompressed_sum;
	const uint32_t index_list_size_add = lzma_vli_size(unpadded_size)
			+ lzma_vli_size(uncompressed_size);

	if (uncompressed_base + uncompressed_size > LZMA_VLI_MAX)
		return LZMA_DATA_ERROR;

	if (index_file_size(s->node.compressed_base,
			compressed_base + unpadded_size, s->record_count + 1,
			s->index_list_size + index_list_size_add,
			s->stream_padding) == LZMA_VLI_UNKNOWN)
		return LZMA_DATA_ERROR;

	if (index_size(i->record_count + 1,
			i->index_list_size + index_list_size_add)
			> LZMA_BACKWARD_SIZE_MAX)
		return LZMA_DATA_ERROR;

	if (g != NULL && g->last + 1 < g->allocated) {

		++g->last;
	} else {

		g = lzma_alloc(sizeof(index_group)
				+ i->prealloc * sizeof(index_record),
				allocator);
		if (g == NULL)
			return LZMA_MEM_ERROR;

		g->last = 0;
		g->allocated = i->prealloc;

		i->prealloc = INDEX_GROUP_SIZE;

		g->node.uncompressed_base = uncompressed_base;
		g->node.compressed_base = compressed_base;
		g->number_base = s->record_count + 1;

		index_tree_append(&s->groups, &g->node);
	}

	g->records[g->last].uncompressed_sum
			= uncompressed_base + uncompressed_size;
	g->records[g->last].unpadded_sum
			= compressed_base + unpadded_size;

	++s->record_count;
	s->index_list_size += index_list_size_add;

	i->total_size += vli_ceil4(unpadded_size);
	i->uncompressed_size += uncompressed_size;
	++i->record_count;
	i->index_list_size += index_list_size_add;

	return LZMA_OK;
}

typedef struct {

	lzma_vli uncompressed_size;

	lzma_vli file_size;

	lzma_vli block_number_add;

	uint32_t stream_number_add;

	index_tree *streams;

} index_cat_info;

static void
index_cat_helper(const index_cat_info *info, index_stream *this)
{
	index_stream *left = (index_stream *)(this->node.left);
	index_stream *right = (index_stream *)(this->node.right);

	if (left != NULL)
		index_cat_helper(info, left);

	this->node.uncompressed_base += info->uncompressed_size;
	this->node.compressed_base += info->file_size;
	this->number += info->stream_number_add;
	this->block_number_base += info->block_number_add;
	index_tree_append(info->streams, &this->node);

	if (right != NULL)
		index_cat_helper(info, right);

	return;
}

extern LZMA_API(lzma_ret)
lzma_index_cat(lzma_index *restrict dest, lzma_index *restrict src,
		const lzma_allocator *allocator)
{
	if (dest == NULL || src == NULL)
		return LZMA_PROG_ERROR;

	const lzma_vli dest_file_size = lzma_index_file_size(dest);

	if (dest_file_size + lzma_index_file_size(src) > LZMA_VLI_MAX
			|| dest->uncompressed_size + src->uncompressed_size
				> LZMA_VLI_MAX)
		return LZMA_DATA_ERROR;

	{
		const lzma_vli dest_size = index_size_unpadded(
				dest->record_count, dest->index_list_size);
		const lzma_vli src_size = index_size_unpadded(
				src->record_count, src->index_list_size);
		if (vli_ceil4(dest_size + src_size) > LZMA_BACKWARD_SIZE_MAX)
			return LZMA_DATA_ERROR;
	}

	{
		index_stream *s = (index_stream *)(dest->streams.rightmost);
		index_group *g = (index_group *)(s->groups.rightmost);
		if (g != NULL && g->last + 1 < g->allocated) {
			assert(g->node.left == NULL);
			assert(g->node.right == NULL);

			index_group *newg = lzma_alloc(sizeof(index_group)
					+ (g->last + 1)
					* sizeof(index_record),
					allocator);
			if (newg == NULL)
				return LZMA_MEM_ERROR;

			newg->node = g->node;
			newg->allocated = g->last + 1;
			newg->last = g->last;
			newg->number_base = g->number_base;

			memcpy(newg->records, g->records, newg->allocated
					* sizeof(index_record));

			if (g->node.parent != NULL) {
				assert(g->node.parent->right == &g->node);
				g->node.parent->right = &newg->node;
			}

			if (s->groups.leftmost == &g->node) {
				assert(s->groups.root == &g->node);
				s->groups.leftmost = &newg->node;
				s->groups.root = &newg->node;
			}

			assert(s->groups.rightmost == &g->node);
			s->groups.rightmost = &newg->node;

			lzma_free(g, allocator);

		}
	}

	dest->checks = lzma_index_checks(dest);

	const index_cat_info info = {
		.uncompressed_size = dest->uncompressed_size,
		.file_size = dest_file_size,
		.stream_number_add = dest->streams.count,
		.block_number_add = dest->record_count,
		.streams = &dest->streams,
	};
	index_cat_helper(&info, (index_stream *)(src->streams.root));

	dest->uncompressed_size += src->uncompressed_size;
	dest->total_size += src->total_size;
	dest->record_count += src->record_count;
	dest->index_list_size += src->index_list_size;
	dest->checks |= src->checks;

	lzma_free(src, allocator);

	return LZMA_OK;
}

static index_stream *
index_dup_stream(const index_stream *src, const lzma_allocator *allocator)
{

	if (src->record_count > PREALLOC_MAX)
		return NULL;

	index_stream *dest = index_stream_init(src->node.compressed_base,
			src->node.uncompressed_base, src->number,
			src->block_number_base, allocator);
	if (dest == NULL)
		return NULL;

	dest->record_count = src->record_count;
	dest->index_list_size = src->index_list_size;
	dest->stream_flags = src->stream_flags;
	dest->stream_padding = src->stream_padding;

	if (src->groups.leftmost == NULL)
		return dest;

	index_group *destg = lzma_alloc(sizeof(index_group)
			+ src->record_count * sizeof(index_record),
			allocator);
	if (destg == NULL) {
		index_stream_end(dest, allocator);
		return NULL;
	}

	destg->node.uncompressed_base = 0;
	destg->node.compressed_base = 0;
	destg->number_base = 1;
	destg->allocated = src->record_count;
	destg->last = src->record_count - 1;

	const index_group *srcg = (const index_group *)(src->groups.leftmost);
	size_t i = 0;
	do {
		memcpy(destg->records + i, srcg->records,
				(srcg->last + 1) * sizeof(index_record));
		i += srcg->last + 1;
		srcg = index_tree_next(&srcg->node);
	} while (srcg != NULL);

	assert(i == destg->allocated);

	index_tree_append(&dest->groups, &destg->node);

	return dest;
}

extern LZMA_API(lzma_index *)
lzma_index_dup(const lzma_index *src, const lzma_allocator *allocator)
{

	lzma_index *dest = index_init_plain(allocator);
	if (dest == NULL)
		return NULL;

	dest->uncompressed_size = src->uncompressed_size;
	dest->total_size = src->total_size;
	dest->record_count = src->record_count;
	dest->index_list_size = src->index_list_size;

	const index_stream *srcstream
			= (const index_stream *)(src->streams.leftmost);
	do {
		index_stream *deststream = index_dup_stream(
				srcstream, allocator);
		if (deststream == NULL) {
			lzma_index_end(dest, allocator);
			return NULL;
		}

		index_tree_append(&dest->streams, &deststream->node);

		srcstream = index_tree_next(&srcstream->node);
	} while (srcstream != NULL);

	return dest;
}

enum {
	ITER_INDEX,
	ITER_STREAM,
	ITER_GROUP,
	ITER_RECORD,
	ITER_METHOD,
};

enum {
	ITER_METHOD_NORMAL,
	ITER_METHOD_NEXT,
	ITER_METHOD_LEFTMOST,
};

static void
iter_set_info(lzma_index_iter *iter)
{
	const lzma_index *i = iter->internal[ITER_INDEX].p;
	const index_stream *stream = iter->internal[ITER_STREAM].p;
	const index_group *group = iter->internal[ITER_GROUP].p;
	const size_t record = iter->internal[ITER_RECORD].s;

	if (group == NULL) {

		assert(stream->groups.root == NULL);
		iter->internal[ITER_METHOD].s = ITER_METHOD_LEFTMOST;

	} else if (i->streams.rightmost != &stream->node
			|| stream->groups.rightmost != &group->node) {

		iter->internal[ITER_METHOD].s = ITER_METHOD_NORMAL;

	} else if (stream->groups.leftmost != &group->node) {

		assert(stream->groups.root != &group->node);
		assert(group->node.parent->right == &group->node);
		iter->internal[ITER_METHOD].s = ITER_METHOD_NEXT;
		iter->internal[ITER_GROUP].p = group->node.parent;

	} else {

		assert(stream->groups.root == &group->node);
		assert(group->node.parent == NULL);
		iter->internal[ITER_METHOD].s = ITER_METHOD_LEFTMOST;
		iter->internal[ITER_GROUP].p = NULL;
	}

	iter->stream.number = stream->number;
	iter->stream.block_count = stream->record_count;
	iter->stream.compressed_offset = stream->node.compressed_base;
	iter->stream.uncompressed_offset = stream->node.uncompressed_base;

	iter->stream.flags = stream->stream_flags.version == UINT32_MAX
			? NULL : &stream->stream_flags;
	iter->stream.padding = stream->stream_padding;

	if (stream->groups.rightmost == NULL) {

		iter->stream.compressed_size = index_size(0, 0)
				+ 2 * LZMA_STREAM_HEADER_SIZE;
		iter->stream.uncompressed_size = 0;
	} else {
		const index_group *g = (const index_group *)(
				stream->groups.rightmost);

		iter->stream.compressed_size = 2 * LZMA_STREAM_HEADER_SIZE
				+ index_size(stream->record_count,
					stream->index_list_size)
				+ vli_ceil4(g->records[g->last].unpadded_sum);
		iter->stream.uncompressed_size
				= g->records[g->last].uncompressed_sum;
	}

	if (group != NULL) {
		iter->block.number_in_stream = group->number_base + record;
		iter->block.number_in_file = iter->block.number_in_stream
				+ stream->block_number_base;

		iter->block.compressed_stream_offset
				= record == 0 ? group->node.compressed_base
				: vli_ceil4(group->records[
					record - 1].unpadded_sum);
		iter->block.uncompressed_stream_offset
				= record == 0 ? group->node.uncompressed_base
				: group->records[record - 1].uncompressed_sum;

		iter->block.uncompressed_size
				= group->records[record].uncompressed_sum
				- iter->block.uncompressed_stream_offset;
		iter->block.unpadded_size
				= group->records[record].unpadded_sum
				- iter->block.compressed_stream_offset;
		iter->block.total_size = vli_ceil4(iter->block.unpadded_size);

		iter->block.compressed_stream_offset
				+= LZMA_STREAM_HEADER_SIZE;

		iter->block.compressed_file_offset
				= iter->block.compressed_stream_offset
				+ iter->stream.compressed_offset;
		iter->block.uncompressed_file_offset
				= iter->block.uncompressed_stream_offset
				+ iter->stream.uncompressed_offset;
	}

	return;
}

extern LZMA_API(void)
lzma_index_iter_init(lzma_index_iter *iter, const lzma_index *i)
{
	iter->internal[ITER_INDEX].p = i;
	lzma_index_iter_rewind(iter);
	return;
}

extern LZMA_API(void)
lzma_index_iter_rewind(lzma_index_iter *iter)
{
	iter->internal[ITER_STREAM].p = NULL;
	iter->internal[ITER_GROUP].p = NULL;
	iter->internal[ITER_RECORD].s = 0;
	iter->internal[ITER_METHOD].s = ITER_METHOD_NORMAL;
	return;
}

extern LZMA_API(lzma_bool)
lzma_index_iter_next(lzma_index_iter *iter, lzma_index_iter_mode mode)
{

	if ((unsigned int)(mode) > LZMA_INDEX_ITER_NONEMPTY_BLOCK)
		return true;

	const lzma_index *i = iter->internal[ITER_INDEX].p;
	const index_stream *stream = iter->internal[ITER_STREAM].p;
	const index_group *group = NULL;
	size_t record = iter->internal[ITER_RECORD].s;

	if (mode != LZMA_INDEX_ITER_STREAM) {

		switch (iter->internal[ITER_METHOD].s) {
		case ITER_METHOD_NORMAL:
			group = iter->internal[ITER_GROUP].p;
			break;

		case ITER_METHOD_NEXT:
			group = index_tree_next(iter->internal[ITER_GROUP].p);
			break;

		case ITER_METHOD_LEFTMOST:
			group = (const index_group *)(
					stream->groups.leftmost);
			break;
		}
	}

again:
	if (stream == NULL) {

		stream = (const index_stream *)(i->streams.leftmost);
		if (mode >= LZMA_INDEX_ITER_BLOCK) {

			while (stream->groups.leftmost == NULL) {
				stream = index_tree_next(&stream->node);
				if (stream == NULL)
					return true;
			}
		}

		group = (const index_group *)(stream->groups.leftmost);
		record = 0;

	} else if (group != NULL && record < group->last) {

		++record;

	} else {

		record = 0;

		if (group != NULL)
			group = index_tree_next(&group->node);

		if (group == NULL) {

			do {
				stream = index_tree_next(&stream->node);
				if (stream == NULL)
					return true;
			} while (mode >= LZMA_INDEX_ITER_BLOCK
					&& stream->groups.leftmost == NULL);

			group = (const index_group *)(
					stream->groups.leftmost);
		}
	}

	if (mode == LZMA_INDEX_ITER_NONEMPTY_BLOCK) {

		if (record == 0) {
			if (group->node.uncompressed_base
					== group->records[0].uncompressed_sum)
				goto again;
		} else if (group->records[record - 1].uncompressed_sum
				== group->records[record].uncompressed_sum) {
			goto again;
		}
	}

	iter->internal[ITER_STREAM].p = stream;
	iter->internal[ITER_GROUP].p = group;
	iter->internal[ITER_RECORD].s = record;

	iter_set_info(iter);

	return false;
}

extern LZMA_API(lzma_bool)
lzma_index_iter_locate(lzma_index_iter *iter, lzma_vli target)
{
	const lzma_index *i = iter->internal[ITER_INDEX].p;

	if (i->uncompressed_size <= target)
		return true;

	const index_stream *stream = index_tree_locate(&i->streams, target);
	assert(stream != NULL);
	target -= stream->node.uncompressed_base;

	const index_group *group = index_tree_locate(&stream->groups, target);
	assert(group != NULL);

	size_t left = 0;
	size_t right = group->last;

	while (left < right) {
		const size_t pos = left + (right - left) / 2;
		if (group->records[pos].uncompressed_sum <= target)
			left = pos + 1;
		else
			right = pos;
	}

	iter->internal[ITER_STREAM].p = stream;
	iter->internal[ITER_GROUP].p = group;
	iter->internal[ITER_RECORD].s = left;

	iter_set_info(iter);

	return false;
}

#ifndef LZMA_INDEX_DECODER_H
#define LZMA_INDEX_DECODER_H

extern lzma_ret lzma_index_decoder_init(lzma_next_coder *next,
		const lzma_allocator *allocator,
		lzma_index **i, uint64_t memlimit);

#endif

typedef struct {
	enum {
		SEQ_INDEX_INDICATOR,
		SEQ_INDEX_COUNT,
		SEQ_INDEX_MEMUSAGE,
		SEQ_INDEX_UNPADDED,
		SEQ_INDEX_UNCOMPRESSED,
		SEQ_INDEX_PADDING_INIT,
		SEQ_INDEX_PADDING,
		SEQ_INDEX_CRC32,
	} sequence;

	uint64_t memlimit;

	lzma_index *index;

	lzma_index **index_ptr;

	lzma_vli count;

	lzma_vli unpadded_size;

	lzma_vli uncompressed_size;

	size_t pos;

	uint32_t crc32;
} lzma_index_coder;

static lzma_ret
index_decode(void *coder_ptr, const lzma_allocator *allocator,
		const uint8_t *restrict in, size_t *restrict in_pos,
		size_t in_size,
		uint8_t *restrict out lzma_attribute((__unused__)),
		size_t *restrict out_pos lzma_attribute((__unused__)),
		size_t out_size lzma_attribute((__unused__)),
		lzma_action action lzma_attribute((__unused__)))
{
	lzma_index_coder *coder = coder_ptr;

	const size_t in_start = *in_pos;
	lzma_ret ret = LZMA_OK;

	while (*in_pos < in_size)
	switch (coder->sequence) {
	case SEQ_INDEX_INDICATOR:

		if (in[(*in_pos)++] != 0x00)
			return LZMA_DATA_ERROR;

		coder->sequence = SEQ_INDEX_COUNT;
		break;

	case SEQ_INDEX_COUNT:
		ret = lzma_vli_decode(&coder->count, &coder->pos,
				in, in_pos, in_size);
		if (ret != LZMA_STREAM_END)
			goto out;

		coder->pos = 0;
		coder->sequence = SEQ_INDEX_MEMUSAGE;

	case SEQ_INDEX_MEMUSAGE:
		if (lzma_index_memusage(1, coder->count) > coder->memlimit) {
			ret = LZMA_MEMLIMIT_ERROR;
			goto out;
		}

		lzma_index_prealloc(coder->index, coder->count);

		ret = LZMA_OK;
		coder->sequence = coder->count == 0
				? SEQ_INDEX_PADDING_INIT : SEQ_INDEX_UNPADDED;
		break;

	case SEQ_INDEX_UNPADDED:
	case SEQ_INDEX_UNCOMPRESSED: {
		lzma_vli *size = coder->sequence == SEQ_INDEX_UNPADDED
				? &coder->unpadded_size
				: &coder->uncompressed_size;

		ret = lzma_vli_decode(size, &coder->pos,
				in, in_pos, in_size);
		if (ret != LZMA_STREAM_END)
			goto out;

		ret = LZMA_OK;
		coder->pos = 0;

		if (coder->sequence == SEQ_INDEX_UNPADDED) {

			if (coder->unpadded_size < UNPADDED_SIZE_MIN
					|| coder->unpadded_size
						> UNPADDED_SIZE_MAX)
				return LZMA_DATA_ERROR;

			coder->sequence = SEQ_INDEX_UNCOMPRESSED;
		} else {

			return_if_error(lzma_index_append(
					coder->index, allocator,
					coder->unpadded_size,
					coder->uncompressed_size));

			coder->sequence = --coder->count == 0
					? SEQ_INDEX_PADDING_INIT
					: SEQ_INDEX_UNPADDED;
		}

		break;
	}

	case SEQ_INDEX_PADDING_INIT:
		coder->pos = lzma_index_padding_size(coder->index);
		coder->sequence = SEQ_INDEX_PADDING;

	case SEQ_INDEX_PADDING:
		if (coder->pos > 0) {
			--coder->pos;
			if (in[(*in_pos)++] != 0x00)
				return LZMA_DATA_ERROR;

			break;
		}

		coder->crc32 = lzma_crc32(in + in_start,
				*in_pos - in_start, coder->crc32);

		coder->sequence = SEQ_INDEX_CRC32;

	case SEQ_INDEX_CRC32:
		do {
			if (*in_pos == in_size)
				return LZMA_OK;

			if (((coder->crc32 >> (coder->pos * 8)) & 0xFF)
					!= in[(*in_pos)++]) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
				return LZMA_DATA_ERROR;
#endif
			}

		} while (++coder->pos < 4);

		*coder->index_ptr = coder->index;

		coder->index = NULL;

		return LZMA_STREAM_END;

	default:
		assert(0);
		return LZMA_PROG_ERROR;
	}

out:

	coder->crc32 = lzma_crc32(in + in_start,
			*in_pos - in_start, coder->crc32);

	return ret;
}

static void
index_decoder_end(void *coder_ptr, const lzma_allocator *allocator)
{
	lzma_index_coder *coder = coder_ptr;
	lzma_index_end(coder->index, allocator);
	lzma_free(coder, allocator);
	return;
}

static lzma_ret
index_decoder_memconfig(void *coder_ptr, uint64_t *memusage,
		uint64_t *old_memlimit, uint64_t new_memlimit)
{
	lzma_index_coder *coder = coder_ptr;

	*memusage = lzma_index_memusage(1, coder->count);
	*old_memlimit = coder->memlimit;

	if (new_memlimit != 0) {
		if (new_memlimit < *memusage)
			return LZMA_MEMLIMIT_ERROR;

		coder->memlimit = new_memlimit;
	}

	return LZMA_OK;
}

static lzma_ret
index_decoder_reset(lzma_index_coder *coder, const lzma_allocator *allocator,
		lzma_index **i, uint64_t memlimit)
{

	coder->index_ptr = i;
	*i = NULL;

	coder->index = lzma_index_init(allocator);
	if (coder->index == NULL)
		return LZMA_MEM_ERROR;

	coder->sequence = SEQ_INDEX_INDICATOR;
	coder->memlimit = my_max(1, memlimit);
	coder->count = 0;
	coder->pos = 0;
	coder->crc32 = 0;

	return LZMA_OK;
}

extern lzma_ret
lzma_index_decoder_init(lzma_next_coder *next, const lzma_allocator *allocator,
		lzma_index **i, uint64_t memlimit)
{
	lzma_next_coder_init(&lzma_index_decoder_init, next, allocator);

	if (i == NULL)
		return LZMA_PROG_ERROR;

	lzma_index_coder *coder = next->coder;
	if (coder == NULL) {
		coder = lzma_alloc(sizeof(lzma_index_coder), allocator);
		if (coder == NULL)
			return LZMA_MEM_ERROR;

		next->coder = coder;
		next->code = &index_decode;
		next->end = &index_decoder_end;
		next->memconfig = &index_decoder_memconfig;
		coder->index = NULL;
	} else {
		lzma_index_end(coder->index, allocator);
	}

	return index_decoder_reset(coder, allocator, i, memlimit);
}

extern LZMA_API(lzma_ret)
lzma_index_decoder(lzma_stream *strm, lzma_index **i, uint64_t memlimit)
{
	lzma_next_strm_init(lzma_index_decoder_init, strm, i, memlimit);

	strm->internal->supported_actions[LZMA_RUN] = true;
	strm->internal->supported_actions[LZMA_FINISH] = true;

	return LZMA_OK;
}

extern LZMA_API(lzma_ret)
lzma_index_buffer_decode(lzma_index **i, uint64_t *memlimit,
		const lzma_allocator *allocator,
		const uint8_t *in, size_t *in_pos, size_t in_size)
{

	if (i == NULL || memlimit == NULL
			|| in == NULL || in_pos == NULL || *in_pos > in_size)
		return LZMA_PROG_ERROR;

	lzma_index_coder coder;
	return_if_error(index_decoder_reset(&coder, allocator, i, *memlimit));

	const size_t in_start = *in_pos;

	lzma_ret ret = index_decode(&coder, allocator, in, in_pos, in_size,
			NULL, NULL, 0, LZMA_RUN);

	if (ret == LZMA_STREAM_END) {
		ret = LZMA_OK;
	} else {

		lzma_index_end(coder.index, allocator);
		*in_pos = in_start;

		if (ret == LZMA_OK) {

			ret = LZMA_DATA_ERROR;

		} else if (ret == LZMA_MEMLIMIT_ERROR) {

			*memlimit = lzma_index_memusage(1, coder.count);
		}
	}

	return ret;
}

typedef struct {

	lzma_vli blocks_size;

	lzma_vli uncompressed_size;

	lzma_vli count;

	lzma_vli index_list_size;

	lzma_check_state check;

} lzma_index_hash_info;

struct lzma_index_hash_s {
	enum {
		SEQ_INDEX_HASH_BLOCK,
		SEQ_INDEX_HASH_COUNT,
		SEQ_INDEX_HASH_UNPADDED,
		SEQ_INDEX_HASH_UNCOMPRESSED,
		SEQ_INDEX_HASH_PADDING_INIT,
		SEQ_INDEX_HASH_PADDING,
		SEQ_INDEX_HASH_CRC32,
	} sequence;

	lzma_index_hash_info blocks;

	lzma_index_hash_info records;

	lzma_vli remaining;

	lzma_vli unpadded_size;

	lzma_vli uncompressed_size;

	size_t pos;

	uint32_t crc32;
};

extern LZMA_API(lzma_index_hash *)
lzma_index_hash_init(lzma_index_hash *index_hash,
		const lzma_allocator *allocator)
{
	if (index_hash == NULL) {
		index_hash = lzma_alloc(sizeof(lzma_index_hash), allocator);
		if (index_hash == NULL)
			return NULL;
	}

	index_hash->sequence = SEQ_INDEX_HASH_BLOCK;
	index_hash->blocks.blocks_size = 0;
	index_hash->blocks.uncompressed_size = 0;
	index_hash->blocks.count = 0;
	index_hash->blocks.index_list_size = 0;
	index_hash->records.blocks_size = 0;
	index_hash->records.uncompressed_size = 0;
	index_hash->records.count = 0;
	index_hash->records.index_list_size = 0;
	index_hash->unpadded_size = 0;
	index_hash->uncompressed_size = 0;
	index_hash->pos = 0;
	index_hash->crc32 = 0;

	(void)lzma_check_init(&index_hash->blocks.check, LZMA_CHECK_BEST);
	(void)lzma_check_init(&index_hash->records.check, LZMA_CHECK_BEST);

	return index_hash;
}

extern LZMA_API(void)
lzma_index_hash_end(lzma_index_hash *index_hash,
		const lzma_allocator *allocator)
{
	lzma_free(index_hash, allocator);
	return;
}

extern LZMA_API(lzma_vli)
lzma_index_hash_size(const lzma_index_hash *index_hash)
{

	return index_size(index_hash->blocks.count,
			index_hash->blocks.index_list_size);
}

static void
hash_append(lzma_index_hash_info *info, lzma_vli unpadded_size,
		lzma_vli uncompressed_size)
{
	info->blocks_size += vli_ceil4(unpadded_size);
	info->uncompressed_size += uncompressed_size;
	info->index_list_size += lzma_vli_size(unpadded_size)
			+ lzma_vli_size(uncompressed_size);
	++info->count;

	const lzma_vli sizes[2] = { unpadded_size, uncompressed_size };
	lzma_check_update(&info->check, LZMA_CHECK_BEST,
			(const uint8_t *)(sizes), sizeof(sizes));

	return;
}

extern LZMA_API(lzma_ret)
lzma_index_hash_append(lzma_index_hash *index_hash, lzma_vli unpadded_size,
		lzma_vli uncompressed_size)
{

	if (index_hash->sequence != SEQ_INDEX_HASH_BLOCK
			|| unpadded_size < UNPADDED_SIZE_MIN
			|| unpadded_size > UNPADDED_SIZE_MAX
			|| uncompressed_size > LZMA_VLI_MAX)
		return LZMA_PROG_ERROR;

	hash_append(&index_hash->blocks, unpadded_size, uncompressed_size);

	if (index_hash->blocks.blocks_size > LZMA_VLI_MAX
			|| index_hash->blocks.uncompressed_size > LZMA_VLI_MAX
			|| index_size(index_hash->blocks.count,
					index_hash->blocks.index_list_size)
				> LZMA_BACKWARD_SIZE_MAX
			|| index_stream_size(index_hash->blocks.blocks_size,
					index_hash->blocks.count,
					index_hash->blocks.index_list_size)
				> LZMA_VLI_MAX)
		return LZMA_DATA_ERROR;

	return LZMA_OK;
}

extern LZMA_API(lzma_ret)
lzma_index_hash_decode(lzma_index_hash *index_hash, const uint8_t *in,
		size_t *in_pos, size_t in_size)
{

	if (*in_pos >= in_size)
		return LZMA_BUF_ERROR;

	const size_t in_start = *in_pos;
	lzma_ret ret = LZMA_OK;

	while (*in_pos < in_size)
	switch (index_hash->sequence) {
	case SEQ_INDEX_HASH_BLOCK:

		if (in[(*in_pos)++] != 0x00)
			return LZMA_DATA_ERROR;

		index_hash->sequence = SEQ_INDEX_HASH_COUNT;
		break;

	case SEQ_INDEX_HASH_COUNT: {
		ret = lzma_vli_decode(&index_hash->remaining,
				&index_hash->pos, in, in_pos, in_size);
		if (ret != LZMA_STREAM_END)
			goto out;

		if (index_hash->remaining != index_hash->blocks.count)
			return LZMA_DATA_ERROR;

		ret = LZMA_OK;
		index_hash->pos = 0;

		index_hash->sequence = index_hash->remaining == 0
				? SEQ_INDEX_HASH_PADDING_INIT : SEQ_INDEX_HASH_UNPADDED;
		break;
	}

	case SEQ_INDEX_HASH_UNPADDED:
	case SEQ_INDEX_HASH_UNCOMPRESSED: {
		lzma_vli *size = index_hash->sequence == SEQ_INDEX_HASH_UNPADDED
				? &index_hash->unpadded_size
				: &index_hash->uncompressed_size;

		ret = lzma_vli_decode(size, &index_hash->pos,
				in, in_pos, in_size);
		if (ret != LZMA_STREAM_END)
			goto out;

		ret = LZMA_OK;
		index_hash->pos = 0;

		if (index_hash->sequence == SEQ_INDEX_HASH_UNPADDED) {
			if (index_hash->unpadded_size < UNPADDED_SIZE_MIN
					|| index_hash->unpadded_size
						> UNPADDED_SIZE_MAX)
				return LZMA_DATA_ERROR;

			index_hash->sequence = SEQ_INDEX_HASH_UNCOMPRESSED;
		} else {

			hash_append(&index_hash->records,
					index_hash->unpadded_size,
					index_hash->uncompressed_size);

			if (index_hash->blocks.blocks_size
					< index_hash->records.blocks_size
					|| index_hash->blocks.uncompressed_size
					< index_hash->records.uncompressed_size
					|| index_hash->blocks.index_list_size
					< index_hash->records.index_list_size)
				return LZMA_DATA_ERROR;

			index_hash->sequence = --index_hash->remaining == 0
					? SEQ_INDEX_HASH_PADDING_INIT : SEQ_INDEX_HASH_UNPADDED;
		}

		break;
	}

	case SEQ_INDEX_HASH_PADDING_INIT:
		index_hash->pos = (LZMA_VLI_C(4) - index_size_unpadded(
				index_hash->records.count,
				index_hash->records.index_list_size)) & 3;
		index_hash->sequence = SEQ_INDEX_HASH_PADDING;

	case SEQ_INDEX_HASH_PADDING:
		if (index_hash->pos > 0) {
			--index_hash->pos;
			if (in[(*in_pos)++] != 0x00)
				return LZMA_DATA_ERROR;

			break;
		}

		if (index_hash->blocks.blocks_size
				!= index_hash->records.blocks_size
				|| index_hash->blocks.uncompressed_size
				!= index_hash->records.uncompressed_size
				|| index_hash->blocks.index_list_size
				!= index_hash->records.index_list_size)
			return LZMA_DATA_ERROR;

		lzma_check_finish(&index_hash->blocks.check, LZMA_CHECK_BEST);
		lzma_check_finish(&index_hash->records.check, LZMA_CHECK_BEST);
		if (memcmp(index_hash->blocks.check.buffer.u8,
				index_hash->records.check.buffer.u8,
				lzma_check_size(LZMA_CHECK_BEST)) != 0)
			return LZMA_DATA_ERROR;

		index_hash->crc32 = lzma_crc32(in + in_start,
				*in_pos - in_start, index_hash->crc32);

		index_hash->sequence = SEQ_INDEX_HASH_CRC32;

	case SEQ_INDEX_HASH_CRC32:
		do {
			if (*in_pos == in_size)
				return LZMA_OK;

			if (((index_hash->crc32 >> (index_hash->pos * 8))
					& 0xFF) != in[(*in_pos)++]) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
				return LZMA_DATA_ERROR;
#endif
			}

		} while (++index_hash->pos < 4);

		return LZMA_STREAM_END;

	default:
		assert(0);
		return LZMA_PROG_ERROR;
	}

out:

	index_hash->crc32 = lzma_crc32(in + in_start,
			*in_pos - in_start, index_hash->crc32);

	return ret;
}

typedef struct lzma_outbuf_s lzma_outbuf;
struct lzma_outbuf_s {

	lzma_outbuf *next;

	void *worker;

	size_t allocated;

	size_t pos;

	size_t decoder_in_pos;

	bool finished;

	lzma_ret finish_ret;

	lzma_vli unpadded_size;
	lzma_vli uncompressed_size;

	uint8_t buf[];
};

typedef struct {

	lzma_outbuf *head;
	lzma_outbuf *tail;

	size_t read_pos;

	lzma_outbuf *cache;

	uint64_t mem_allocated;

	uint64_t mem_in_use;

	uint32_t bufs_in_use;

	uint32_t bufs_allocated;

	uint32_t bufs_limit;
} lzma_outq;

extern uint64_t lzma_outq_memusage(uint64_t buf_size_max, uint32_t threads);

extern lzma_ret lzma_outq_init(lzma_outq *outq,
		const lzma_allocator *allocator, uint32_t threads);

extern void lzma_outq_end(lzma_outq *outq, const lzma_allocator *allocator);

extern void lzma_outq_clear_cache(
		lzma_outq *outq, const lzma_allocator *allocator);

extern void lzma_outq_clear_cache2(
		lzma_outq *outq, const lzma_allocator *allocator,
		size_t keep_size);

extern lzma_ret lzma_outq_prealloc_buf(
		lzma_outq *outq, const lzma_allocator *allocator, size_t size);

extern lzma_outbuf *lzma_outq_get_buf(lzma_outq *outq, void *worker);

extern bool lzma_outq_is_readable(const lzma_outq *outq);

extern lzma_ret lzma_outq_read(lzma_outq *restrict outq,
		const lzma_allocator *restrict allocator,
		uint8_t *restrict out, size_t *restrict out_pos,
		size_t out_size, lzma_vli *restrict unpadded_size,
		lzma_vli *restrict uncompressed_size);

extern void lzma_outq_enable_partial_output(lzma_outq *outq,
		void (*enable_partial_output)(void *worker));

static inline bool
lzma_outq_has_buf(const lzma_outq *outq)
{
	return outq->bufs_in_use < outq->bufs_limit;
}

static inline bool
lzma_outq_is_empty(const lzma_outq *outq)
{
	return outq->bufs_in_use == 0;
}

static inline uint64_t
lzma_outq_outbuf_memusage(size_t buf_size)
{
	assert(buf_size <= SIZE_MAX - sizeof(lzma_outbuf));
	return sizeof(lzma_outbuf) + buf_size;
}

#define GET_BUFS_LIMIT(threads) (2 * (threads))

extern uint64_t
lzma_outq_memusage(uint64_t buf_size_max, uint32_t threads)
{

	const uint64_t limit
			= UINT64_MAX / GET_BUFS_LIMIT(LZMA_THREADS_MAX) / 2;

	if (threads > LZMA_THREADS_MAX || buf_size_max > limit)
		return UINT64_MAX;

	return GET_BUFS_LIMIT(threads)
			* lzma_outq_outbuf_memusage(buf_size_max);
}

static void
move_head_to_cache(lzma_outq *outq, const lzma_allocator *allocator)
{
	assert(outq->head != NULL);
	assert(outq->tail != NULL);
	assert(outq->bufs_in_use > 0);

	lzma_outbuf *buf = outq->head;
	outq->head = buf->next;
	if (outq->head == NULL)
		outq->tail = NULL;

	if (outq->cache != NULL && outq->cache->allocated != buf->allocated)
		lzma_outq_clear_cache(outq, allocator);

	buf->next = outq->cache;
	outq->cache = buf;

	--outq->bufs_in_use;
	outq->mem_in_use -= lzma_outq_outbuf_memusage(buf->allocated);

	return;
}

static void
free_one_cached_buffer(lzma_outq *outq, const lzma_allocator *allocator)
{
	assert(outq->cache != NULL);

	lzma_outbuf *buf = outq->cache;
	outq->cache = buf->next;

	--outq->bufs_allocated;
	outq->mem_allocated -= lzma_outq_outbuf_memusage(buf->allocated);

	lzma_free(buf, allocator);
	return;
}

extern void
lzma_outq_clear_cache(lzma_outq *outq, const lzma_allocator *allocator)
{
	while (outq->cache != NULL)
		free_one_cached_buffer(outq, allocator);

	return;
}

extern void
lzma_outq_clear_cache2(lzma_outq *outq, const lzma_allocator *allocator,
		size_t keep_size)
{
	if (outq->cache == NULL)
		return;

	while (outq->cache->next != NULL)
		free_one_cached_buffer(outq, allocator);

	if (outq->cache->allocated != keep_size)
		free_one_cached_buffer(outq, allocator);

	return;
}

extern lzma_ret
lzma_outq_init(lzma_outq *outq, const lzma_allocator *allocator,
		uint32_t threads)
{
	if (threads > LZMA_THREADS_MAX)
		return LZMA_OPTIONS_ERROR;

	const uint32_t bufs_limit = GET_BUFS_LIMIT(threads);

	while (outq->head != NULL)
		move_head_to_cache(outq, allocator);

	while (bufs_limit < outq->bufs_allocated)
		free_one_cached_buffer(outq, allocator);

	outq->bufs_limit = bufs_limit;
	outq->read_pos = 0;

	return LZMA_OK;
}

extern void
lzma_outq_end(lzma_outq *outq, const lzma_allocator *allocator)
{
	while (outq->head != NULL)
		move_head_to_cache(outq, allocator);

	lzma_outq_clear_cache(outq, allocator);
	return;
}

extern lzma_ret
lzma_outq_prealloc_buf(lzma_outq *outq, const lzma_allocator *allocator,
		size_t size)
{

	assert(outq->bufs_in_use < outq->bufs_limit);

	if (outq->cache != NULL && outq->cache->allocated == size)
		return LZMA_OK;

	if (size > SIZE_MAX - sizeof(lzma_outbuf))
		return LZMA_MEM_ERROR;

	const size_t alloc_size = lzma_outq_outbuf_memusage(size);

	lzma_outq_clear_cache(outq, allocator);

	outq->cache = lzma_alloc(alloc_size, allocator);
	if (outq->cache == NULL)
		return LZMA_MEM_ERROR;

	outq->cache->next = NULL;
	outq->cache->allocated = size;

	++outq->bufs_allocated;
	outq->mem_allocated += alloc_size;

	return LZMA_OK;
}

extern lzma_outbuf *
lzma_outq_get_buf(lzma_outq *outq, void *worker)
{

	assert(outq->bufs_in_use < outq->bufs_limit);
	assert(outq->bufs_in_use < outq->bufs_allocated);
	assert(outq->cache != NULL);

	lzma_outbuf *buf = outq->cache;
	outq->cache = buf->next;
	buf->next = NULL;

	if (outq->tail != NULL) {
		assert(outq->head != NULL);
		outq->tail->next = buf;
	} else {
		assert(outq->head == NULL);
		outq->head = buf;
	}

	outq->tail = buf;

	buf->worker = worker;
	buf->finished = false;
	buf->finish_ret = LZMA_STREAM_END;
	buf->pos = 0;
	buf->decoder_in_pos = 0;

	buf->unpadded_size = 0;
	buf->uncompressed_size = 0;

	++outq->bufs_in_use;
	outq->mem_in_use += lzma_outq_outbuf_memusage(buf->allocated);

	return buf;
}

extern bool
lzma_outq_is_readable(const lzma_outq *outq)
{
	if (outq->head == NULL)
		return false;

	return outq->read_pos < outq->head->pos || outq->head->finished;
}

extern lzma_ret
lzma_outq_read(lzma_outq *restrict outq,
		const lzma_allocator *restrict allocator,
		uint8_t *restrict out, size_t *restrict out_pos,
		size_t out_size,
		lzma_vli *restrict unpadded_size,
		lzma_vli *restrict uncompressed_size)
{

	if (outq->bufs_in_use == 0)
		return LZMA_OK;

	lzma_outbuf *buf = outq->head;

	lzma_bufcpy(buf->buf, &outq->read_pos, buf->pos,
			out, out_pos, out_size);

	if (!buf->finished || outq->read_pos < buf->pos)
		return LZMA_OK;

	if (unpadded_size != NULL)
		*unpadded_size = buf->unpadded_size;

	if (uncompressed_size != NULL)
		*uncompressed_size = buf->uncompressed_size;

	const lzma_ret finish_ret = buf->finish_ret;

	move_head_to_cache(outq, allocator);
	outq->read_pos = 0;

	return finish_ret;
}

extern void
lzma_outq_enable_partial_output(lzma_outq *outq,
		void (*enable_partial_output)(void *worker))
{
	if (outq->head != NULL && !outq->head->finished
			&& outq->head->worker != NULL) {
		enable_partial_output(outq->head->worker);

		outq->head->worker = NULL;
	}

	return;
}

extern LZMA_API(lzma_ret)
lzma_stream_buffer_decode(uint64_t *memlimit, uint32_t flags,
		const lzma_allocator *allocator,
		const uint8_t *in, size_t *in_pos, size_t in_size,
		uint8_t *out, size_t *out_pos, size_t out_size)
{

	if (in_pos == NULL || (in == NULL && *in_pos != in_size)
			|| *in_pos > in_size || out_pos == NULL
			|| (out == NULL && *out_pos != out_size)
			|| *out_pos > out_size)
		return LZMA_PROG_ERROR;

	if (flags & LZMA_TELL_ANY_CHECK)
		return LZMA_PROG_ERROR;

	lzma_next_coder stream_decoder = LZMA_NEXT_CODER_INIT;
	lzma_ret ret = lzma_stream_decoder_init(
			&stream_decoder, allocator, *memlimit, flags);

	if (ret == LZMA_OK) {

		const size_t in_start = *in_pos;
		const size_t out_start = *out_pos;

		ret = stream_decoder.code(stream_decoder.coder, allocator,
				in, in_pos, in_size, out, out_pos, out_size,
				LZMA_FINISH);

		if (ret == LZMA_STREAM_END) {
			ret = LZMA_OK;
		} else {

			*in_pos = in_start;
			*out_pos = out_start;

			if (ret == LZMA_OK) {

				assert(*in_pos == in_size
						|| *out_pos == out_size);

				if (*in_pos == in_size)
					ret = LZMA_DATA_ERROR;
				else
					ret = LZMA_BUF_ERROR;

			} else if (ret == LZMA_MEMLIMIT_ERROR) {

				uint64_t memusage;
				(void)stream_decoder.memconfig(
						stream_decoder.coder,
						memlimit, &memusage, 0);
			}
		}
	}

	lzma_next_end(&stream_decoder, allocator);

	return ret;
}

typedef struct {
	enum {
		SEQ_DEC_STREAM_HEADER,
		SEQ_DEC_BLOCK_HEADER,
		SEQ_DEC_BLOCK_INIT,
		SEQ_DEC_BLOCK_RUN,
		SEQ_DEC_INDEX,
		SEQ_DEC_STREAM_FOOTER,
		SEQ_DEC_STREAM_PADDING,
	} sequence;

	lzma_next_coder block_decoder;

	lzma_block block_options;

	lzma_stream_flags stream_flags;

	lzma_index_hash *index_hash;

	uint64_t memlimit;

	uint64_t memusage;

	bool tell_no_check;

	bool tell_unsupported_check;

	bool tell_any_check;

	bool ignore_check;

	bool concatenated;

	bool first_stream;

	size_t pos;

	uint8_t buffer[LZMA_BLOCK_HEADER_SIZE_MAX];
} lzma_stream_coder;

static lzma_ret
stream_decoder_reset_no_mt(lzma_stream_coder *coder, const lzma_allocator *allocator)
{

	coder->index_hash = lzma_index_hash_init(coder->index_hash, allocator);
	if (coder->index_hash == NULL)
		return LZMA_MEM_ERROR;

	coder->sequence = SEQ_DEC_STREAM_HEADER;
	coder->pos = 0;

	return LZMA_OK;
}

static lzma_ret
stream_decode(void *coder_ptr, const lzma_allocator *allocator,
		const uint8_t *restrict in, size_t *restrict in_pos,
		size_t in_size, uint8_t *restrict out,
		size_t *restrict out_pos, size_t out_size, lzma_action action)
{
	lzma_stream_coder *coder = coder_ptr;

	while (true)
	switch (coder->sequence) {
	case SEQ_DEC_STREAM_HEADER: {

		lzma_bufcpy(in, in_pos, in_size, coder->buffer, &coder->pos,
				LZMA_STREAM_HEADER_SIZE);

		if (coder->pos < LZMA_STREAM_HEADER_SIZE)
			return LZMA_OK;

		coder->pos = 0;

		const lzma_ret ret = lzma_stream_header_decode(
				&coder->stream_flags, coder->buffer);
		if (ret != LZMA_OK)
			return ret == LZMA_FORMAT_ERROR && !coder->first_stream
					? LZMA_DATA_ERROR : ret;

		coder->first_stream = false;

		coder->block_options.check = coder->stream_flags.check;

		coder->sequence = SEQ_DEC_BLOCK_HEADER;

		if (coder->tell_no_check && coder->stream_flags.check
				== LZMA_CHECK_NONE)
			return LZMA_NO_CHECK;

		if (coder->tell_unsupported_check
				&& !lzma_check_is_supported(
					coder->stream_flags.check))
			return LZMA_UNSUPPORTED_CHECK;

		if (coder->tell_any_check)
			return LZMA_GET_CHECK;
	}

	case SEQ_DEC_BLOCK_HEADER: {
		if (*in_pos >= in_size)
			return LZMA_OK;

		if (coder->pos == 0) {

			if (in[*in_pos] == 0x00) {
				coder->sequence = SEQ_DEC_INDEX;
				break;
			}

			coder->block_options.header_size
					= lzma_block_header_size_decode(
						in[*in_pos]);
		}

		lzma_bufcpy(in, in_pos, in_size, coder->buffer, &coder->pos,
				coder->block_options.header_size);

		if (coder->pos < coder->block_options.header_size)
			return LZMA_OK;

		coder->pos = 0;
		coder->sequence = SEQ_DEC_BLOCK_INIT;
	}

	case SEQ_DEC_BLOCK_INIT: {

		coder->block_options.version = 1;

		lzma_filter filters[LZMA_FILTERS_MAX + 1];
		coder->block_options.filters = filters;

		return_if_error(lzma_block_header_decode(&coder->block_options,
				allocator, coder->buffer));

		coder->block_options.ignore_check = coder->ignore_check;

		const uint64_t memusage = lzma_raw_decoder_memusage(filters);
		lzma_ret ret;

		if (memusage == UINT64_MAX) {

			ret = LZMA_OPTIONS_ERROR;
		} else {

			coder->memusage = memusage;

			if (memusage > coder->memlimit) {

				ret = LZMA_MEMLIMIT_ERROR;
			} else {

				ret = lzma_block_decoder_init(
						&coder->block_decoder,
						allocator,
						&coder->block_options);
			}
		}

		lzma_filters_free(filters, allocator);
		coder->block_options.filters = NULL;

		if (ret != LZMA_OK)
			return ret;

		coder->sequence = SEQ_DEC_BLOCK_RUN;
	}

	case SEQ_DEC_BLOCK_RUN: {
		const lzma_ret ret = coder->block_decoder.code(
				coder->block_decoder.coder, allocator,
				in, in_pos, in_size, out, out_pos, out_size,
				action);

		if (ret != LZMA_STREAM_END)
			return ret;

		return_if_error(lzma_index_hash_append(coder->index_hash,
				lzma_block_unpadded_size(
					&coder->block_options),
				coder->block_options.uncompressed_size));

		coder->sequence = SEQ_DEC_BLOCK_HEADER;
		break;
	}

	case SEQ_DEC_INDEX: {

		if (*in_pos >= in_size)
			return LZMA_OK;

		const lzma_ret ret = lzma_index_hash_decode(coder->index_hash,
				in, in_pos, in_size);
		if (ret != LZMA_STREAM_END)
			return ret;

		coder->sequence = SEQ_DEC_STREAM_FOOTER;
	}

	case SEQ_DEC_STREAM_FOOTER: {

		lzma_bufcpy(in, in_pos, in_size, coder->buffer, &coder->pos,
				LZMA_STREAM_HEADER_SIZE);

		if (coder->pos < LZMA_STREAM_HEADER_SIZE)
			return LZMA_OK;

		coder->pos = 0;

		lzma_stream_flags footer_flags;
		const lzma_ret ret = lzma_stream_footer_decode(
				&footer_flags, coder->buffer);
		if (ret != LZMA_OK)
			return ret == LZMA_FORMAT_ERROR
					? LZMA_DATA_ERROR : ret;

		if (lzma_index_hash_size(coder->index_hash)
				!= footer_flags.backward_size)
			return LZMA_DATA_ERROR;

		return_if_error(lzma_stream_flags_compare(
				&coder->stream_flags, &footer_flags));

		if (!coder->concatenated)
			return LZMA_STREAM_END;

		coder->sequence = SEQ_DEC_STREAM_PADDING;
	}

	case SEQ_DEC_STREAM_PADDING:
		assert(coder->concatenated);

		while (true) {
			if (*in_pos >= in_size) {

				if (action != LZMA_FINISH)
					return LZMA_OK;

				return coder->pos == 0
						? LZMA_STREAM_END
						: LZMA_DATA_ERROR;
			}

			if (in[*in_pos] != 0x00)
				break;

			++*in_pos;
			coder->pos = (coder->pos + 1) & 3;
		}

		if (coder->pos != 0) {
			++*in_pos;
			return LZMA_DATA_ERROR;
		}

		return_if_error(stream_decoder_reset_no_mt(coder, allocator));
		break;

	default:
		assert(0);
		return LZMA_PROG_ERROR;
	}

}

static void
stream_decoder_end(void *coder_ptr, const lzma_allocator *allocator)
{
	lzma_stream_coder *coder = coder_ptr;
	lzma_next_end(&coder->block_decoder, allocator);
	lzma_index_hash_end(coder->index_hash, allocator);
	lzma_free(coder, allocator);
	return;
}

static lzma_check
stream_decoder_get_check(const void *coder_ptr)
{
	const lzma_stream_coder *coder = coder_ptr;
	return coder->stream_flags.check;
}

static lzma_ret
stream_decoder_memconfig(void *coder_ptr, uint64_t *memusage,
		uint64_t *old_memlimit, uint64_t new_memlimit)
{
	lzma_stream_coder *coder = coder_ptr;

	*memusage = coder->memusage;
	*old_memlimit = coder->memlimit;

	if (new_memlimit != 0) {
		if (new_memlimit < coder->memusage)
			return LZMA_MEMLIMIT_ERROR;

		coder->memlimit = new_memlimit;
	}

	return LZMA_OK;
}

extern lzma_ret
lzma_stream_decoder_init(
		lzma_next_coder *next, const lzma_allocator *allocator,
		uint64_t memlimit, uint32_t flags)
{
	lzma_next_coder_init(&lzma_stream_decoder_init, next, allocator);

	if (flags & ~LZMA_SUPPORTED_FLAGS)
		return LZMA_OPTIONS_ERROR;

	lzma_stream_coder *coder = next->coder;
	if (coder == NULL) {
		coder = lzma_alloc(sizeof(lzma_stream_coder), allocator);
		if (coder == NULL)
			return LZMA_MEM_ERROR;

		next->coder = coder;
		next->code = &stream_decode;
		next->end = &stream_decoder_end;
		next->get_check = &stream_decoder_get_check;
		next->memconfig = &stream_decoder_memconfig;

		coder->block_decoder = LZMA_NEXT_CODER_INIT;
		coder->index_hash = NULL;
	}

	coder->memlimit = my_max(1, memlimit);
	coder->memusage = LZMA_MEMUSAGE_BASE;
	coder->tell_no_check = (flags & LZMA_TELL_NO_CHECK) != 0;
	coder->tell_unsupported_check
			= (flags & LZMA_TELL_UNSUPPORTED_CHECK) != 0;
	coder->tell_any_check = (flags & LZMA_TELL_ANY_CHECK) != 0;
	coder->ignore_check = (flags & LZMA_IGNORE_CHECK) != 0;
	coder->concatenated = (flags & LZMA_CONCATENATED) != 0;
	coder->first_stream = true;

	return stream_decoder_reset_no_mt(coder, allocator);
}

extern LZMA_API(lzma_ret)
lzma_stream_decoder(lzma_stream *strm, uint64_t memlimit, uint32_t flags)
{
	lzma_next_strm_init(lzma_stream_decoder_init, strm, memlimit, flags);

	strm->internal->supported_actions[LZMA_RUN] = true;
	strm->internal->supported_actions[LZMA_FINISH] = true;

	return LZMA_OK;
}

typedef enum {

	THR_IDLE,

	THR_RUN,

	THR_STOP,

	THR_EXIT,

} worker_state;

typedef enum {

	PARTIAL_DISABLED,

	PARTIAL_START,

	PARTIAL_ENABLED,

} partial_update_mode;

struct worker_thread {

	worker_state state;

	uint8_t *in;

	size_t in_size;

	size_t in_filled;

	size_t in_pos;

	size_t out_pos;

	struct lzma_stream_coder *coder;

	const lzma_allocator *allocator;

	lzma_outbuf *outbuf;

	size_t progress_in;

	size_t progress_out;

	partial_update_mode partial_update;

	lzma_next_coder block_decoder;

	lzma_block block_options;

	uint64_t mem_filters;

	struct worker_thread *next;

	mythread_mutex mutex;
	mythread_cond cond;

	mythread thread_id;
};

struct lzma_stream_coder {
	enum {
		SEQ_DEC_MT_STREAM_HEADER,
		SEQ_DEC_MT_BLOCK_HEADER,
		SEQ_DEC_MT_BLOCK_INIT,
		SEQ_DEC_MT_BLOCK_THR_INIT,
		SEQ_DEC_MT_BLOCK_THR_RUN,
		SEQ_DEC_MT_BLOCK_DIRECT_INIT,
		SEQ_DEC_MT_BLOCK_DIRECT_RUN,
		SEQ_DEC_MT_INDEX_WAIT_OUTPUT,
		SEQ_DEC_MT_INDEX_DECODE,
		SEQ_DEC_MT_STREAM_FOOTER,
		SEQ_DEC_MT_STREAM_PADDING,
		SEQ_DEC_MT_ERROR,
	} sequence;

	lzma_next_coder block_decoder;

	lzma_block block_options;

	lzma_filter filters[LZMA_FILTERS_MAX + 1];

	lzma_stream_flags stream_flags;

	lzma_index_hash *index_hash;

	uint32_t timeout;

	lzma_ret thread_error;

	lzma_ret pending_error;

	uint32_t threads_max;

	uint32_t threads_initialized;

	struct worker_thread *threads;

	struct worker_thread *threads_free;

	struct worker_thread *thr;

	lzma_outq outq;

	mythread_mutex mutex;
	mythread_cond cond;

	uint64_t memlimit_threading;

	uint64_t memlimit_stop;

	uint64_t mem_direct_mode;

	uint64_t mem_in_use;

	uint64_t mem_cached;

	uint64_t mem_next_filters;

	uint64_t mem_next_in;

	uint64_t mem_next_block;

	uint64_t progress_in;

	uint64_t progress_out;

	bool tell_no_check;

	bool tell_unsupported_check;

	bool tell_any_check;

	bool ignore_check;

	bool concatenated;

	bool fail_fast;

	bool first_stream;

	bool out_was_filled;

	size_t pos;

	uint8_t buffer[LZMA_BLOCK_HEADER_SIZE_MAX];
};

static void
worker_enable_partial_update(void *thr_ptr)
{
	struct worker_thread *thr = thr_ptr;

	mythread_sync(thr->mutex) {
		thr->partial_update = PARTIAL_START;
		mythread_cond_signal(&thr->cond);
	}
}

static void
worker_stop(struct worker_thread *thr)
{

	thr->coder->mem_in_use -= thr->in_size;
	thr->in_size = 0;

	thr->coder->mem_in_use -= thr->mem_filters;
	thr->coder->mem_cached += thr->mem_filters;

	thr->next = thr->coder->threads_free;
	thr->coder->threads_free = thr;

	mythread_cond_signal(&thr->coder->cond);
	return;
}

static MYTHREAD_RET_TYPE
worker_decoder(void *thr_ptr)
{
	struct worker_thread *thr = thr_ptr;
	size_t in_filled;
	partial_update_mode partial_update;
	lzma_ret ret;

next_loop_lock:

	mythread_mutex_lock(&thr->mutex);
next_loop_unlocked:

	if (thr->state == THR_IDLE) {
		mythread_cond_wait(&thr->cond, &thr->mutex);
		goto next_loop_unlocked;
	}

	if (thr->state == THR_EXIT) {
		mythread_mutex_unlock(&thr->mutex);

		lzma_free(thr->in, thr->allocator);
		lzma_next_end(&thr->block_decoder, thr->allocator);

		mythread_mutex_destroy(&thr->mutex);
		mythread_cond_destroy(&thr->cond);

		return MYTHREAD_RET_VALUE;
	}

	if (thr->state == THR_STOP) {
		thr->state = THR_IDLE;
		mythread_mutex_unlock(&thr->mutex);

		mythread_sync(thr->coder->mutex) {
			worker_stop(thr);
		}

		goto next_loop_lock;
	}

	assert(thr->state == THR_RUN);

	thr->progress_in = thr->in_pos;
	thr->progress_out = thr->out_pos;

	in_filled = thr->in_filled;
	partial_update = thr->partial_update;

	if (in_filled == thr->in_pos && partial_update != PARTIAL_START) {
		mythread_cond_wait(&thr->cond, &thr->mutex);
		goto next_loop_unlocked;
	}

	mythread_mutex_unlock(&thr->mutex);

	const size_t chunk_size = 16384;
	if ((in_filled - thr->in_pos) > chunk_size)
		in_filled = thr->in_pos + chunk_size;

	ret = thr->block_decoder.code(
			thr->block_decoder.coder, thr->allocator,
			thr->in, &thr->in_pos, in_filled,
			thr->outbuf->buf, &thr->out_pos,
			thr->outbuf->allocated, LZMA_RUN);

	if (ret == LZMA_OK) {
		if (partial_update != PARTIAL_DISABLED) {

			thr->partial_update = PARTIAL_ENABLED;

			mythread_sync(thr->coder->mutex) {
				thr->outbuf->pos = thr->out_pos;
				thr->outbuf->decoder_in_pos = thr->in_pos;
				mythread_cond_signal(&thr->coder->cond);
			}
		}

		goto next_loop_lock;
	}

	assert(ret != LZMA_STREAM_END || thr->in_pos == thr->in_size);
	assert(ret != LZMA_STREAM_END
		|| thr->out_pos == thr->block_options.uncompressed_size);

	lzma_free(thr->in, thr->allocator);
	thr->in = NULL;

	mythread_sync(thr->mutex) {
		if (thr->state != THR_EXIT)
			thr->state = THR_IDLE;
	}

	mythread_sync(thr->coder->mutex) {

		thr->coder->progress_in += thr->in_pos;
		thr->coder->progress_out += thr->out_pos;
		thr->progress_in = 0;
		thr->progress_out = 0;

		thr->outbuf->pos = thr->out_pos;
		thr->outbuf->decoder_in_pos = thr->in_pos;
		thr->outbuf->finished = true;
		thr->outbuf->finish_ret = ret;
		thr->outbuf = NULL;

		if (ret != LZMA_STREAM_END
				&& thr->coder->thread_error == LZMA_OK)
			thr->coder->thread_error = ret;

		worker_stop(thr);
	}

	goto next_loop_lock;
}

static void
threads_end(struct lzma_stream_coder *coder, const lzma_allocator *allocator)
{
	for (uint32_t i = 0; i < coder->threads_initialized; ++i) {
		mythread_sync(coder->threads[i].mutex) {
			coder->threads[i].state = THR_EXIT;
			mythread_cond_signal(&coder->threads[i].cond);
		}
	}

	for (uint32_t i = 0; i < coder->threads_initialized; ++i)
		mythread_join(coder->threads[i].thread_id);

	lzma_free(coder->threads, allocator);
	coder->threads_initialized = 0;
	coder->threads = NULL;
	coder->threads_free = NULL;

	coder->mem_in_use = 0;
	coder->mem_cached = 0;

	return;
}

static void
threads_stop(struct lzma_stream_coder *coder)
{
	for (uint32_t i = 0; i < coder->threads_initialized; ++i) {
		mythread_sync(coder->threads[i].mutex) {

			if (coder->threads[i].state != THR_IDLE) {
				coder->threads[i].state = THR_STOP;
				mythread_cond_signal(&coder->threads[i].cond);
			}
		}
	}

	return;
}

static lzma_ret
initialize_new_thread(struct lzma_stream_coder *coder,
		const lzma_allocator *allocator)
{

	if (coder->threads == NULL) {
		coder->threads = lzma_alloc(
			coder->threads_max * sizeof(struct worker_thread),
			allocator);

		if (coder->threads == NULL)
			return LZMA_MEM_ERROR;
	}

	assert(coder->threads_initialized < coder->threads_max);
	struct worker_thread *thr
			= &coder->threads[coder->threads_initialized];

	if (mythread_mutex_init(&thr->mutex))
		goto error_mutex;

	if (mythread_cond_init(&thr->cond))
		goto error_cond;

	thr->state = THR_IDLE;
	thr->in = NULL;
	thr->in_size = 0;
	thr->allocator = allocator;
	thr->coder = coder;
	thr->outbuf = NULL;
	thr->block_decoder = LZMA_NEXT_CODER_INIT;
	thr->mem_filters = 0;

	if (mythread_create(&thr->thread_id, worker_decoder, thr))
		goto error_thread;

	++coder->threads_initialized;
	coder->thr = thr;

	return LZMA_OK;

error_thread:
	mythread_cond_destroy(&thr->cond);

error_cond:
	mythread_mutex_destroy(&thr->mutex);

error_mutex:
	return LZMA_MEM_ERROR;
}

static lzma_ret
get_thread(struct lzma_stream_coder *coder, const lzma_allocator *allocator)
{

	mythread_sync(coder->mutex) {
		if (coder->threads_free != NULL) {
			coder->thr = coder->threads_free;
			coder->threads_free = coder->threads_free->next;

			coder->mem_cached -= coder->thr->mem_filters;
		}
	}

	if (coder->thr == NULL) {
		assert(coder->threads_initialized < coder->threads_max);

		return_if_error(initialize_new_thread(coder, allocator));
	}

	coder->thr->in_filled = 0;
	coder->thr->in_pos = 0;
	coder->thr->out_pos = 0;

	coder->thr->progress_in = 0;
	coder->thr->progress_out = 0;

	coder->thr->partial_update = PARTIAL_DISABLED;

	return LZMA_OK;
}

static lzma_ret
read_output_and_wait(struct lzma_stream_coder *coder,
		const lzma_allocator *allocator,
		uint8_t *restrict out, size_t *restrict out_pos,
		size_t out_size,
		bool *input_is_possible,
		bool waiting_allowed,
		mythread_condtime *wait_abs, bool *has_blocked)
{
	lzma_ret ret = LZMA_OK;

	mythread_sync(coder->mutex) {
		do {

			const size_t out_start = *out_pos;
			do {
				ret = lzma_outq_read(&coder->outq, allocator,
						out, out_pos, out_size,
						NULL, NULL);

				if (ret == LZMA_STREAM_END)
					lzma_outq_enable_partial_output(
						&coder->outq,
						&worker_enable_partial_update);

			} while (ret == LZMA_STREAM_END);

			if (ret != LZMA_OK)
				break;

			if (*out_pos == out_size && *out_pos != out_start)
				coder->out_was_filled = true;

			if (coder->thread_error != LZMA_OK) {

				if (coder->fail_fast) {
					ret = coder->thread_error;
					break;
				}

				coder->pending_error = LZMA_PROG_ERROR;
			}

			if (input_is_possible != NULL
					&& coder->memlimit_threading
						- coder->mem_in_use
						- coder->outq.mem_in_use
						>= coder->mem_next_block
					&& lzma_outq_has_buf(&coder->outq)
					&& (coder->threads_initialized
							< coder->threads_max
						|| coder->threads_free
							!= NULL)) {
				*input_is_possible = true;
				break;
			}

			if (!waiting_allowed)
				break;

			if (lzma_outq_is_empty(&coder->outq)) {
				assert(input_is_possible == NULL);
				break;
			}

			if (lzma_outq_is_readable(&coder->outq)) {
				assert(*out_pos == out_size);
				break;
			}

			if (coder->thr != NULL && coder->thr->partial_update
					!= PARTIAL_DISABLED) {

				assert(coder->thr->outbuf == coder->outq.head);
				assert(coder->thr->outbuf == coder->outq.tail);

				if (coder->thr->outbuf->decoder_in_pos
						== coder->thr->in_filled)
					break;
			}

			if (coder->timeout != 0) {

				if (!*has_blocked) {
					*has_blocked = true;
					mythread_condtime_set(wait_abs,
							&coder->cond,
							coder->timeout);
				}

				if (mythread_cond_timedwait(&coder->cond,
						&coder->mutex,
						wait_abs) != 0) {
					ret = LZMA_TIMED_OUT;
					break;
				}
			} else {
				mythread_cond_wait(&coder->cond,
						&coder->mutex);
			}
		} while (ret == LZMA_OK);
	}

	if (ret != LZMA_OK && ret != LZMA_TIMED_OUT)
		threads_stop(coder);

	return ret;
}

static lzma_ret
decode_block_header(struct lzma_stream_coder *coder,
		const lzma_allocator *allocator, const uint8_t *restrict in,
		size_t *restrict in_pos, size_t in_size)
{
	if (*in_pos >= in_size)
		return LZMA_OK;

	if (coder->pos == 0) {

		if (in[*in_pos] == 0x00)
			return LZMA_INDEX_DETECTED;

		coder->block_options.header_size
				= lzma_block_header_size_decode(
					in[*in_pos]);
	}

	lzma_bufcpy(in, in_pos, in_size, coder->buffer, &coder->pos,
			coder->block_options.header_size);

	if (coder->pos < coder->block_options.header_size)
		return LZMA_OK;

	coder->pos = 0;

	coder->block_options.version = 1;

	coder->block_options.filters = coder->filters;

	return_if_error(lzma_block_header_decode(&coder->block_options,
			allocator, coder->buffer));

	coder->block_options.ignore_check = coder->ignore_check;

	return LZMA_STREAM_END;
}

static size_t
comp_blk_size(const struct lzma_stream_coder *coder)
{
	return vli_ceil4(coder->block_options.compressed_size)
			+ lzma_check_size(coder->stream_flags.check);
}

static bool
is_direct_mode_needed(lzma_vli size)
{
	return size == LZMA_VLI_UNKNOWN || size > SIZE_MAX / 3;
}

static lzma_ret
stream_decoder_reset_mt(struct lzma_stream_coder *coder,
		const lzma_allocator *allocator)
{

	coder->index_hash = lzma_index_hash_init(coder->index_hash, allocator);
	if (coder->index_hash == NULL)
		return LZMA_MEM_ERROR;

	coder->sequence = SEQ_DEC_MT_STREAM_HEADER;
	coder->pos = 0;

	return LZMA_OK;
}

static lzma_ret
stream_decode_mt(void *coder_ptr, const lzma_allocator *allocator,
		 const uint8_t *restrict in, size_t *restrict in_pos,
		 size_t in_size,
		 uint8_t *restrict out, size_t *restrict out_pos,
		 size_t out_size, lzma_action action)
{
	struct lzma_stream_coder *coder = coder_ptr;

	mythread_condtime wait_abs;
	bool has_blocked = false;

	const bool waiting_allowed = action == LZMA_FINISH
			|| (*in_pos == in_size && !coder->out_was_filled);
	coder->out_was_filled = false;

	while (true)
	switch (coder->sequence) {
	case SEQ_DEC_MT_STREAM_HEADER: {

		const size_t in_old = *in_pos;
		lzma_bufcpy(in, in_pos, in_size, coder->buffer, &coder->pos,
				LZMA_STREAM_HEADER_SIZE);
		coder->progress_in += *in_pos - in_old;

		if (coder->pos < LZMA_STREAM_HEADER_SIZE)
			return LZMA_OK;

		coder->pos = 0;

		const lzma_ret ret = lzma_stream_header_decode(
				&coder->stream_flags, coder->buffer);
		if (ret != LZMA_OK)
			return ret == LZMA_FORMAT_ERROR && !coder->first_stream
					? LZMA_DATA_ERROR : ret;

		coder->first_stream = false;

		coder->block_options.check = coder->stream_flags.check;

		coder->sequence = SEQ_DEC_MT_BLOCK_HEADER;

		if (coder->tell_no_check && coder->stream_flags.check
				== LZMA_CHECK_NONE)
			return LZMA_NO_CHECK;

		if (coder->tell_unsupported_check
				&& !lzma_check_is_supported(
					coder->stream_flags.check))
			return LZMA_UNSUPPORTED_CHECK;

		if (coder->tell_any_check)
			return LZMA_GET_CHECK;
	}

	case SEQ_DEC_MT_BLOCK_HEADER: {
		const size_t in_old = *in_pos;
		const lzma_ret ret = decode_block_header(coder, allocator,
				in, in_pos, in_size);
		coder->progress_in += *in_pos - in_old;

		if (ret == LZMA_OK) {

			assert(*in_pos == in_size);

			if (action == LZMA_FINISH && coder->fail_fast) {

				threads_stop(coder);
				return LZMA_DATA_ERROR;
			}

			return_if_error(read_output_and_wait(coder, allocator,
				out, out_pos, out_size,
				NULL, waiting_allowed,
				&wait_abs, &has_blocked));

			if (coder->pending_error != LZMA_OK) {
				coder->sequence = SEQ_DEC_MT_ERROR;
				break;
			}

			return LZMA_OK;
		}

		if (ret == LZMA_INDEX_DETECTED) {
			coder->sequence = SEQ_DEC_MT_INDEX_WAIT_OUTPUT;
			break;
		}

		if (ret != LZMA_STREAM_END) {

			coder->pending_error = ret;
			coder->sequence = SEQ_DEC_MT_ERROR;
			break;
		}

		coder->mem_next_filters = lzma_raw_decoder_memusage(
				coder->filters);

		if (coder->mem_next_filters == UINT64_MAX) {

			coder->pending_error = LZMA_OPTIONS_ERROR;
			coder->sequence = SEQ_DEC_MT_ERROR;
			break;
		}

		coder->sequence = SEQ_DEC_MT_BLOCK_INIT;
	}

	case SEQ_DEC_MT_BLOCK_INIT: {

		if (coder->mem_next_filters > coder->memlimit_stop) {

			return_if_error(read_output_and_wait(coder, allocator,
					out, out_pos, out_size,
					NULL, true, &wait_abs, &has_blocked));

			if (!lzma_outq_is_empty(&coder->outq))
				return LZMA_OK;

			return LZMA_MEMLIMIT_ERROR;
		}

		if (is_direct_mode_needed(coder->block_options.compressed_size)
				|| is_direct_mode_needed(
				coder->block_options.uncompressed_size)) {
			coder->sequence = SEQ_DEC_MT_BLOCK_DIRECT_INIT;
			break;
		}

		coder->mem_next_in = comp_blk_size(coder);
		const uint64_t mem_buffers = coder->mem_next_in
				+ lzma_outq_outbuf_memusage(
				coder->block_options.uncompressed_size);

		if (UINT64_MAX - mem_buffers < coder->mem_next_filters) {

			coder->sequence = SEQ_DEC_MT_BLOCK_DIRECT_INIT;
			break;
		}

		coder->mem_next_block = coder->mem_next_filters + mem_buffers;

		if (coder->mem_next_block > coder->memlimit_threading) {
			coder->sequence = SEQ_DEC_MT_BLOCK_DIRECT_INIT;
			break;
		}

		lzma_next_end(&coder->block_decoder, allocator);
		coder->mem_direct_mode = 0;

		const lzma_ret ret = lzma_index_hash_append(coder->index_hash,
				lzma_block_unpadded_size(
					&coder->block_options),
				coder->block_options.uncompressed_size);
		if (ret != LZMA_OK) {
			coder->pending_error = ret;
			coder->sequence = SEQ_DEC_MT_ERROR;
			break;
		}

		coder->sequence = SEQ_DEC_MT_BLOCK_THR_INIT;
	}

	case SEQ_DEC_MT_BLOCK_THR_INIT: {

		bool block_can_start = false;

		return_if_error(read_output_and_wait(coder, allocator,
				out, out_pos, out_size,
				&block_can_start, true,
				&wait_abs, &has_blocked));

		if (coder->pending_error != LZMA_OK) {
			coder->sequence = SEQ_DEC_MT_ERROR;
			break;
		}

		if (!block_can_start) {

			assert(*out_pos == out_size);
			assert(!lzma_outq_is_empty(&coder->outq));
			return LZMA_OK;
		}

		uint64_t mem_in_use;
		uint64_t mem_cached;
		struct worker_thread *thr = NULL;

		mythread_sync(coder->mutex) {
			mem_in_use = coder->mem_in_use;
			mem_cached = coder->mem_cached;
			thr = coder->threads_free;
		}

		const uint64_t mem_max = coder->memlimit_threading
				- coder->mem_next_block;

		if (mem_in_use + mem_cached + coder->outq.mem_allocated
				> mem_max) {

			lzma_outq_clear_cache2(&coder->outq, allocator,
				coder->block_options.uncompressed_size);
		}

		uint64_t mem_freed = 0;
		if (thr != NULL && mem_in_use + mem_cached
				+ coder->outq.mem_in_use > mem_max) {

			if (thr->mem_filters <= coder->mem_next_filters)
				thr = thr->next;

			while (thr != NULL) {
				lzma_next_end(&thr->block_decoder, allocator);
				mem_freed += thr->mem_filters;
				thr->mem_filters = 0;
				thr = thr->next;
			}
		}

		mythread_sync(coder->mutex) {
			coder->mem_cached -= mem_freed;

			coder->mem_in_use += coder->mem_next_in
					+ coder->mem_next_filters;
		}

		lzma_ret ret = lzma_outq_prealloc_buf(
				&coder->outq, allocator,
				coder->block_options.uncompressed_size);
		if (ret != LZMA_OK) {
			threads_stop(coder);
			return ret;
		}

		ret = get_thread(coder, allocator);
		if (ret != LZMA_OK) {
			threads_stop(coder);
			return ret;
		}

		coder->thr->mem_filters = coder->mem_next_filters;

		coder->thr->block_options = coder->block_options;
		ret = lzma_block_decoder_init(
					&coder->thr->block_decoder, allocator,
					&coder->thr->block_options);

		lzma_filters_free(coder->filters, allocator);
		coder->thr->block_options.filters = NULL;

		if (ret != LZMA_OK) {
			coder->pending_error = ret;
			coder->sequence = SEQ_DEC_MT_ERROR;
			break;
		}

		coder->thr->in_size = coder->mem_next_in;
		coder->thr->in = lzma_alloc(coder->thr->in_size, allocator);
		if (coder->thr->in == NULL) {
			threads_stop(coder);
			return LZMA_MEM_ERROR;
		}

		coder->thr->outbuf = lzma_outq_get_buf(
				&coder->outq, coder->thr);

		mythread_sync(coder->thr->mutex) {
			assert(coder->thr->state == THR_IDLE);
			coder->thr->state = THR_RUN;
			mythread_cond_signal(&coder->thr->cond);
		}

		mythread_sync(coder->mutex) {
			lzma_outq_enable_partial_output(&coder->outq,
					&worker_enable_partial_update);
		}

		coder->sequence = SEQ_DEC_MT_BLOCK_THR_RUN;
	}

	case SEQ_DEC_MT_BLOCK_THR_RUN: {
		if (action == LZMA_FINISH && coder->fail_fast) {

			const size_t in_avail = in_size - *in_pos;
			const size_t in_needed = coder->thr->in_size
					- coder->thr->in_filled;
			if (in_avail < in_needed) {
				threads_stop(coder);
				return LZMA_DATA_ERROR;
			}
		}

		size_t cur_in_filled = coder->thr->in_filled;
		lzma_bufcpy(in, in_pos, in_size, coder->thr->in,
				&cur_in_filled, coder->thr->in_size);

		mythread_sync(coder->thr->mutex) {
			coder->thr->in_filled = cur_in_filled;

			mythread_cond_signal(&coder->thr->cond);
		}

		return_if_error(read_output_and_wait(coder, allocator,
				out, out_pos, out_size,
				NULL, waiting_allowed,
				&wait_abs, &has_blocked));

		if (coder->pending_error != LZMA_OK) {
			coder->sequence = SEQ_DEC_MT_ERROR;
			break;
		}

		if (coder->thr->in_filled < coder->thr->in_size) {
			assert(*in_pos == in_size);
			return LZMA_OK;
		}

		coder->thr = NULL;
		coder->sequence = SEQ_DEC_MT_BLOCK_HEADER;
		break;
	}

	case SEQ_DEC_MT_BLOCK_DIRECT_INIT: {

		return_if_error(read_output_and_wait(coder, allocator,
				out, out_pos, out_size,
				NULL, true, &wait_abs, &has_blocked));
		if (!lzma_outq_is_empty(&coder->outq))
			return LZMA_OK;

		lzma_outq_clear_cache(&coder->outq, allocator);

		threads_end(coder, allocator);

		const lzma_ret ret = lzma_block_decoder_init(
				&coder->block_decoder, allocator,
				&coder->block_options);

		lzma_filters_free(coder->filters, allocator);
		coder->block_options.filters = NULL;

		if (ret != LZMA_OK)
			return ret;

		coder->mem_direct_mode = coder->mem_next_filters;

		coder->sequence = SEQ_DEC_MT_BLOCK_DIRECT_RUN;
	}

	case SEQ_DEC_MT_BLOCK_DIRECT_RUN: {
		const size_t in_old = *in_pos;
		const size_t out_old = *out_pos;
		const lzma_ret ret = coder->block_decoder.code(
				coder->block_decoder.coder, allocator,
				in, in_pos, in_size, out, out_pos, out_size,
				action);
		coder->progress_in += *in_pos - in_old;
		coder->progress_out += *out_pos - out_old;

		if (ret != LZMA_STREAM_END)
			return ret;

		return_if_error(lzma_index_hash_append(coder->index_hash,
				lzma_block_unpadded_size(
					&coder->block_options),
				coder->block_options.uncompressed_size));

		coder->sequence = SEQ_DEC_MT_BLOCK_HEADER;
		break;
	}

	case SEQ_DEC_MT_INDEX_WAIT_OUTPUT:

		return_if_error(read_output_and_wait(coder, allocator,
				out, out_pos, out_size,
				NULL, true, &wait_abs, &has_blocked));

		if (!lzma_outq_is_empty(&coder->outq))
			return LZMA_OK;

		coder->sequence = SEQ_DEC_MT_INDEX_DECODE;

	case SEQ_DEC_MT_INDEX_DECODE: {

		if (*in_pos >= in_size)
			return LZMA_OK;

		const size_t in_old = *in_pos;
		const lzma_ret ret = lzma_index_hash_decode(coder->index_hash,
				in, in_pos, in_size);
		coder->progress_in += *in_pos - in_old;
		if (ret != LZMA_STREAM_END)
			return ret;

		coder->sequence = SEQ_DEC_MT_STREAM_FOOTER;
	}

	case SEQ_DEC_MT_STREAM_FOOTER: {

		const size_t in_old = *in_pos;
		lzma_bufcpy(in, in_pos, in_size, coder->buffer, &coder->pos,
				LZMA_STREAM_HEADER_SIZE);
		coder->progress_in += *in_pos - in_old;

		if (coder->pos < LZMA_STREAM_HEADER_SIZE)
			return LZMA_OK;

		coder->pos = 0;

		lzma_stream_flags footer_flags;
		const lzma_ret ret = lzma_stream_footer_decode(
				&footer_flags, coder->buffer);
		if (ret != LZMA_OK)
			return ret == LZMA_FORMAT_ERROR
					? LZMA_DATA_ERROR : ret;

		if (lzma_index_hash_size(coder->index_hash)
				!= footer_flags.backward_size)
			return LZMA_DATA_ERROR;

		return_if_error(lzma_stream_flags_compare(
				&coder->stream_flags, &footer_flags));

		if (!coder->concatenated)
			return LZMA_STREAM_END;

		coder->sequence = SEQ_DEC_MT_STREAM_PADDING;
	}

	case SEQ_DEC_MT_STREAM_PADDING:
		assert(coder->concatenated);

		while (true) {
			if (*in_pos >= in_size) {

				if (action != LZMA_FINISH)
					return LZMA_OK;

				return coder->pos == 0
						? LZMA_STREAM_END
						: LZMA_DATA_ERROR;
			}

			if (in[*in_pos] != 0x00)
				break;

			++*in_pos;
			++coder->progress_in;
			coder->pos = (coder->pos + 1) & 3;
		}

		if (coder->pos != 0) {
			++*in_pos;
			++coder->progress_in;
			return LZMA_DATA_ERROR;
		}

		return_if_error(stream_decoder_reset_mt(coder, allocator));
		break;

	case SEQ_DEC_MT_ERROR:
		if (!coder->fail_fast) {

			return_if_error(read_output_and_wait(coder, allocator,
					out, out_pos, out_size,
					NULL, true, &wait_abs, &has_blocked));

			if (!lzma_outq_is_empty(&coder->outq))
				return LZMA_OK;
		}

		return coder->pending_error;

	default:
		assert(0);
		return LZMA_PROG_ERROR;
	}

}

static void
stream_decoder_mt_end(void *coder_ptr, const lzma_allocator *allocator)
{
	struct lzma_stream_coder *coder = coder_ptr;

	threads_end(coder, allocator);
	lzma_outq_end(&coder->outq, allocator);

	lzma_next_end(&coder->block_decoder, allocator);
	lzma_filters_free(coder->filters, allocator);
	lzma_index_hash_end(coder->index_hash, allocator);

	lzma_free(coder, allocator);
	return;
}

static lzma_check
stream_decoder_mt_get_check(const void *coder_ptr)
{
	const struct lzma_stream_coder *coder = coder_ptr;
	return coder->stream_flags.check;
}

static lzma_ret
stream_decoder_mt_memconfig(void *coder_ptr, uint64_t *memusage,
		uint64_t *old_memlimit, uint64_t new_memlimit)
{

	struct lzma_stream_coder *coder = coder_ptr;

	mythread_sync(coder->mutex) {
		*memusage = coder->mem_direct_mode
				+ coder->mem_in_use
				+ coder->mem_cached
				+ coder->outq.mem_allocated;
	}

	if (*memusage < LZMA_MEMUSAGE_BASE)
		*memusage = LZMA_MEMUSAGE_BASE;

	*old_memlimit = coder->memlimit_stop;

	if (new_memlimit != 0) {
		if (new_memlimit < *memusage)
			return LZMA_MEMLIMIT_ERROR;

		coder->memlimit_stop = new_memlimit;
	}

	return LZMA_OK;
}

static void
stream_decoder_mt_get_progress(void *coder_ptr,
		uint64_t *progress_in, uint64_t *progress_out)
{
	struct lzma_stream_coder *coder = coder_ptr;

	mythread_sync(coder->mutex) {
		*progress_in = coder->progress_in;
		*progress_out = coder->progress_out;

		for (size_t i = 0; i < coder->threads_initialized; ++i) {
			mythread_sync(coder->threads[i].mutex) {
				*progress_in += coder->threads[i].progress_in;
				*progress_out += coder->threads[i]
						.progress_out;
			}
		}
	}

	return;
}

static lzma_ret
stream_decoder_mt_init(lzma_next_coder *next, const lzma_allocator *allocator,
		       const lzma_mt *options)
{
	struct lzma_stream_coder *coder;

	if (options->threads == 0 || options->threads > LZMA_THREADS_MAX)
		return LZMA_OPTIONS_ERROR;

	if (options->flags & ~LZMA_SUPPORTED_FLAGS)
		return LZMA_OPTIONS_ERROR;

	lzma_next_coder_init(&stream_decoder_mt_init, next, allocator);

	coder = next->coder;
	if (!coder) {
		coder = lzma_alloc(sizeof(struct lzma_stream_coder), allocator);
		if (coder == NULL)
			return LZMA_MEM_ERROR;

		next->coder = coder;

		if (mythread_mutex_init(&coder->mutex)) {
			lzma_free(coder, allocator);
			return LZMA_MEM_ERROR;
		}

		if (mythread_cond_init(&coder->cond)) {
			mythread_mutex_destroy(&coder->mutex);
			lzma_free(coder, allocator);
			return LZMA_MEM_ERROR;
		}

		next->code = &stream_decode_mt;
		next->end = &stream_decoder_mt_end;
		next->get_check = &stream_decoder_mt_get_check;
		next->memconfig = &stream_decoder_mt_memconfig;
		next->get_progress = &stream_decoder_mt_get_progress;

		coder->filters[0].id = LZMA_VLI_UNKNOWN;
		memzero(&coder->outq, sizeof(coder->outq));

		coder->block_decoder = LZMA_NEXT_CODER_INIT;
		coder->mem_direct_mode = 0;

		coder->index_hash = NULL;
		coder->threads = NULL;
		coder->threads_free = NULL;
		coder->threads_initialized = 0;
	}

	lzma_filters_free(coder->filters, allocator);

	threads_end(coder, allocator);

	coder->mem_in_use = 0;
	coder->mem_cached = 0;
	coder->mem_next_block = 0;

	coder->progress_in = 0;
	coder->progress_out = 0;

	coder->sequence = SEQ_DEC_MT_STREAM_HEADER;
	coder->thread_error = LZMA_OK;
	coder->pending_error = LZMA_OK;
	coder->thr = NULL;

	coder->timeout = options->timeout;

	coder->memlimit_threading = my_max(1, options->memlimit_threading);
	coder->memlimit_stop = my_max(1, options->memlimit_stop);
	if (coder->memlimit_threading > coder->memlimit_stop)
		coder->memlimit_threading = coder->memlimit_stop;

	coder->tell_no_check = (options->flags & LZMA_TELL_NO_CHECK) != 0;
	coder->tell_unsupported_check
			= (options->flags & LZMA_TELL_UNSUPPORTED_CHECK) != 0;
	coder->tell_any_check = (options->flags & LZMA_TELL_ANY_CHECK) != 0;
	coder->ignore_check = (options->flags & LZMA_IGNORE_CHECK) != 0;
	coder->concatenated = (options->flags & LZMA_CONCATENATED) != 0;
	coder->fail_fast = (options->flags & LZMA_FAIL_FAST) != 0;

	coder->first_stream = true;
	coder->out_was_filled = false;
	coder->pos = 0;

	coder->threads_max = options->threads;

	return_if_error(lzma_outq_init(&coder->outq, allocator,
				       coder->threads_max));

	return stream_decoder_reset_mt(coder, allocator);
}

extern LZMA_API(lzma_ret)
lzma_stream_decoder_mt(lzma_stream *strm, const lzma_mt *options)
{
	lzma_next_strm_init(stream_decoder_mt_init, strm, options);

	strm->internal->supported_actions[LZMA_RUN] = true;
	strm->internal->supported_actions[LZMA_FINISH] = true;

	return LZMA_OK;
}

const uint8_t lzma_header_magic[6] = { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 };
const uint8_t lzma_footer_magic[2] = { 0x59, 0x5A };

extern LZMA_API(lzma_ret)
lzma_stream_flags_compare(
		const lzma_stream_flags *a, const lzma_stream_flags *b)
{

	if (a->version != 0 || b->version != 0)
		return LZMA_OPTIONS_ERROR;

	if ((unsigned int)(a->check) > LZMA_CHECK_ID_MAX
			|| (unsigned int)(b->check) > LZMA_CHECK_ID_MAX)
		return LZMA_PROG_ERROR;

	if (a->check != b->check)
		return LZMA_DATA_ERROR;

	if (a->backward_size != LZMA_VLI_UNKNOWN
			&& b->backward_size != LZMA_VLI_UNKNOWN) {
		if (!is_backward_size_valid(a) || !is_backward_size_valid(b))
			return LZMA_PROG_ERROR;

		if (a->backward_size != b->backward_size)
			return LZMA_DATA_ERROR;
	}

	return LZMA_OK;
}

static bool
stream_flags_decode(lzma_stream_flags *options, const uint8_t *in)
{

	if (in[0] != 0x00 || (in[1] & 0xF0))
		return true;

	options->version = 0;
	options->check = in[1] & 0x0F;

	return false;
}

extern LZMA_API(lzma_ret)
lzma_stream_header_decode(lzma_stream_flags *options, const uint8_t *in)
{

	if (memcmp(in, lzma_header_magic, sizeof(lzma_header_magic)) != 0)
		return LZMA_FORMAT_ERROR;

	const uint32_t crc = lzma_crc32(in + sizeof(lzma_header_magic),
			LZMA_STREAM_FLAGS_SIZE, 0);
	if (crc != read32le(in + sizeof(lzma_header_magic)
			+ LZMA_STREAM_FLAGS_SIZE)) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
		return LZMA_DATA_ERROR;
#endif
	}

	if (stream_flags_decode(options, in + sizeof(lzma_header_magic)))
		return LZMA_OPTIONS_ERROR;

	options->backward_size = LZMA_VLI_UNKNOWN;

	return LZMA_OK;
}

extern LZMA_API(lzma_ret)
lzma_stream_footer_decode(lzma_stream_flags *options, const uint8_t *in)
{

	if (memcmp(in + sizeof(uint32_t) * 2 + LZMA_STREAM_FLAGS_SIZE,
			lzma_footer_magic, sizeof(lzma_footer_magic)) != 0)
		return LZMA_FORMAT_ERROR;

	const uint32_t crc = lzma_crc32(in + sizeof(uint32_t),
			sizeof(uint32_t) + LZMA_STREAM_FLAGS_SIZE, 0);
	if (crc != read32le(in)) {
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
		return LZMA_DATA_ERROR;
#endif
	}

	if (stream_flags_decode(options, in + sizeof(uint32_t) * 2))
		return LZMA_OPTIONS_ERROR;

	options->backward_size = read32le(in + sizeof(uint32_t));
	options->backward_size = (options->backward_size + 1) * 4;

	return LZMA_OK;
}

extern LZMA_API(lzma_ret)
lzma_vli_decode(lzma_vli *restrict vli, size_t *vli_pos,
		const uint8_t *restrict in, size_t *restrict in_pos,
		size_t in_size)
{

	size_t vli_pos_internal = 0;
	if (vli_pos == NULL) {
		vli_pos = &vli_pos_internal;
		*vli = 0;

		if (*in_pos >= in_size)
			return LZMA_DATA_ERROR;

	} else {

		if (*vli_pos == 0)
			*vli = 0;

		if (*vli_pos >= LZMA_VLI_BYTES_MAX
				|| (*vli >> (*vli_pos * 7)) != 0)
			return LZMA_PROG_ERROR;;

		if (*in_pos >= in_size)
			return LZMA_BUF_ERROR;
	}

	do {

		const uint8_t byte = in[*in_pos];
		++*in_pos;

		*vli += (lzma_vli)(byte & 0x7F) << (*vli_pos * 7);
		++*vli_pos;

		if ((byte & 0x80) == 0) {

			if (byte == 0x00 && *vli_pos > 1)
				return LZMA_DATA_ERROR;

			return vli_pos == &vli_pos_internal
					? LZMA_OK : LZMA_STREAM_END;
		}

		if (*vli_pos == LZMA_VLI_BYTES_MAX)
			return LZMA_DATA_ERROR;

	} while (*in_pos < in_size);

	return vli_pos == &vli_pos_internal ? LZMA_DATA_ERROR : LZMA_OK;
}

extern LZMA_API(uint32_t)
lzma_vli_size(lzma_vli vli)
{
	if (vli > LZMA_VLI_MAX)
		return 0;

	uint32_t i = 0;
	do {
		vli >>= 7;
		++i;
	} while (vli != 0);

	assert(i <= LZMA_VLI_BYTES_MAX);
	return i;
}

extern LZMA_API(lzma_bool)
lzma_check_is_supported(lzma_check type)
{
	if ((unsigned int)(type) > LZMA_CHECK_ID_MAX)
		return false;

	static const lzma_bool available_checks[LZMA_CHECK_ID_MAX + 1] = {
		true,

#ifdef HAVE_CHECK_CRC32
		true,
#else
		false,
#endif

		false,
		false,

#ifdef HAVE_CHECK_CRC64
		true,
#else
		false,
#endif

		false,
		false,
		false,
		false,
		false,

#ifdef HAVE_CHECK_SHA256
		true,
#else
		false,
#endif

		false,
		false,
		false,
		false,
		false,
	};

	return available_checks[(unsigned int)(type)];
}

extern LZMA_API(uint32_t)
lzma_check_size(lzma_check type)
{
	if ((unsigned int)(type) > LZMA_CHECK_ID_MAX)
		return UINT32_MAX;

	static const uint8_t check_sizes[LZMA_CHECK_ID_MAX + 1] = {
		0,
		4, 4, 4,
		8, 8, 8,
		16, 16, 16,
		32, 32, 32,
		64, 64, 64
	};

	return check_sizes[(unsigned int)(type)];
}

extern void
lzma_check_init(lzma_check_state *check, lzma_check type)
{
	switch (type) {
	case LZMA_CHECK_NONE:
		break;

#ifdef HAVE_CHECK_CRC32
	case LZMA_CHECK_CRC32:
		check->state.crc32 = 0;
		break;
#endif

#ifdef HAVE_CHECK_CRC64
	case LZMA_CHECK_CRC64:
		check->state.crc64 = 0;
		break;
#endif

#ifdef HAVE_CHECK_SHA256
	case LZMA_CHECK_SHA256:
		lzma_sha256_init(check);
		break;
#endif

	default:
		break;
	}

	return;
}

extern void
lzma_check_update(lzma_check_state *check, lzma_check type,
		const uint8_t *buf, size_t size)
{
	switch (type) {
#ifdef HAVE_CHECK_CRC32
	case LZMA_CHECK_CRC32:
		check->state.crc32 = lzma_crc32(buf, size, check->state.crc32);
		break;
#endif

#ifdef HAVE_CHECK_CRC64
	case LZMA_CHECK_CRC64:
		check->state.crc64 = lzma_crc64(buf, size, check->state.crc64);
		break;
#endif

#ifdef HAVE_CHECK_SHA256
	case LZMA_CHECK_SHA256:
		lzma_sha256_update(buf, size, check);
		break;
#endif

	default:
		break;
	}

	return;
}

extern void
lzma_check_finish(lzma_check_state *check, lzma_check type)
{
	switch (type) {
#ifdef HAVE_CHECK_CRC32
	case LZMA_CHECK_CRC32:
		check->buffer.u32[0] = conv32le(check->state.crc32);
		break;
#endif

#ifdef HAVE_CHECK_CRC64
	case LZMA_CHECK_CRC64:
		check->buffer.u64[0] = conv64le(check->state.crc64);
		break;
#endif

#ifdef HAVE_CHECK_SHA256
	case LZMA_CHECK_SHA256:
		lzma_sha256_finish(check);
		break;
#endif

	default:
		break;
	}

	return;
}

#ifdef WORDS_BIGENDIAN
#define A(x) ((x) >> 24)
#define B(x) (((x) >> 16) & 0xFF)
#define C(x) (((x) >> 8) & 0xFF)
#define D(x) ((x) & 0xFF)

#define S8(x) ((x) << 8)
#define S32(x) ((x) << 32)

#else
#define A(x) ((x) & 0xFF)
#define B(x) (((x) >> 8) & 0xFF)
#define C(x) (((x) >> 16) & 0xFF)
#define D(x) ((x) >> 24)

#define S8(x) ((x) >> 8)
#define S32(x) ((x) >> 32)
#endif

extern LZMA_API(uint32_t)
lzma_crc32(const uint8_t *buf, size_t size, uint32_t crc)
{
	crc = ~crc;

#ifdef WORDS_BIGENDIAN
	crc = bswap32(crc);
#endif

	if (size > 8) {

		while ((uintptr_t)(buf) & 7) {
			crc = lzma_crc32_table[0][*buf++ ^ A(crc)] ^ S8(crc);
			--size;
		}

		const uint8_t *const limit = buf + (size & ~(size_t)(7));

		size &= (size_t)(7);

		while (buf < limit) {
			crc ^= aligned_read32ne(buf);
			buf += 4;

			crc = lzma_crc32_table[7][A(crc)]
			    ^ lzma_crc32_table[6][B(crc)]
			    ^ lzma_crc32_table[5][C(crc)]
			    ^ lzma_crc32_table[4][D(crc)];

			const uint32_t tmp = aligned_read32ne(buf);
			buf += 4;

			crc = lzma_crc32_table[3][A(tmp)]
			    ^ lzma_crc32_table[2][B(tmp)]
			    ^ crc
			    ^ lzma_crc32_table[1][C(tmp)]
			    ^ lzma_crc32_table[0][D(tmp)];
		}
	}

	while (size-- != 0)
		crc = lzma_crc32_table[0][*buf++ ^ A(crc)] ^ S8(crc);

#ifdef WORDS_BIGENDIAN
	crc = bswap32(crc);
#endif

	return ~crc;
}

extern const uint32_t lzma_crc32_table[8][256];

#ifdef WORDS_BIGENDIAN

const uint32_t lzma_crc32_table[8][256] = {
	{
		0x00000000, 0x96300777, 0x2C610EEE, 0xBA510999,
		0x19C46D07, 0x8FF46A70, 0x35A563E9, 0xA395649E,
		0x3288DB0E, 0xA4B8DC79, 0x1EE9D5E0, 0x88D9D297,
		0x2B4CB609, 0xBD7CB17E, 0x072DB8E7, 0x911DBF90,
		0x6410B71D, 0xF220B06A, 0x4871B9F3, 0xDE41BE84,
		0x7DD4DA1A, 0xEBE4DD6D, 0x51B5D4F4, 0xC785D383,
		0x56986C13, 0xC0A86B64, 0x7AF962FD, 0xECC9658A,
		0x4F5C0114, 0xD96C0663, 0x633D0FFA, 0xF50D088D,
		0xC8206E3B, 0x5E10694C, 0xE44160D5, 0x727167A2,
		0xD1E4033C, 0x47D4044B, 0xFD850DD2, 0x6BB50AA5,
		0xFAA8B535, 0x6C98B242, 0xD6C9BBDB, 0x40F9BCAC,
		0xE36CD832, 0x755CDF45, 0xCF0DD6DC, 0x593DD1AB,
		0xAC30D926, 0x3A00DE51, 0x8051D7C8, 0x1661D0BF,
		0xB5F4B421, 0x23C4B356, 0x9995BACF, 0x0FA5BDB8,
		0x9EB80228, 0x0888055F, 0xB2D90CC6, 0x24E90BB1,
		0x877C6F2F, 0x114C6858, 0xAB1D61C1, 0x3D2D66B6,
		0x9041DC76, 0x0671DB01, 0xBC20D298, 0x2A10D5EF,
		0x8985B171, 0x1FB5B606, 0xA5E4BF9F, 0x33D4B8E8,
		0xA2C90778, 0x34F9000F, 0x8EA80996, 0x18980EE1,
		0xBB0D6A7F, 0x2D3D6D08, 0x976C6491, 0x015C63E6,
		0xF4516B6B, 0x62616C1C, 0xD8306585, 0x4E0062F2,
		0xED95066C, 0x7BA5011B, 0xC1F40882, 0x57C40FF5,
		0xC6D9B065, 0x50E9B712, 0xEAB8BE8B, 0x7C88B9FC,
		0xDF1DDD62, 0x492DDA15, 0xF37CD38C, 0x654CD4FB,
		0x5861B24D, 0xCE51B53A, 0x7400BCA3, 0xE230BBD4,
		0x41A5DF4A, 0xD795D83D, 0x6DC4D1A4, 0xFBF4D6D3,
		0x6AE96943, 0xFCD96E34, 0x468867AD, 0xD0B860DA,
		0x732D0444, 0xE51D0333, 0x5F4C0AAA, 0xC97C0DDD,
		0x3C710550, 0xAA410227, 0x10100BBE, 0x86200CC9,
		0x25B56857, 0xB3856F20, 0x09D466B9, 0x9FE461CE,
		0x0EF9DE5E, 0x98C9D929, 0x2298D0B0, 0xB4A8D7C7,
		0x173DB359, 0x810DB42E, 0x3B5CBDB7, 0xAD6CBAC0,
		0x2083B8ED, 0xB6B3BF9A, 0x0CE2B603, 0x9AD2B174,
		0x3947D5EA, 0xAF77D29D, 0x1526DB04, 0x8316DC73,
		0x120B63E3, 0x843B6494, 0x3E6A6D0D, 0xA85A6A7A,
		0x0BCF0EE4, 0x9DFF0993, 0x27AE000A, 0xB19E077D,
		0x44930FF0, 0xD2A30887, 0x68F2011E, 0xFEC20669,
		0x5D5762F7, 0xCB676580, 0x71366C19, 0xE7066B6E,
		0x761BD4FE, 0xE02BD389, 0x5A7ADA10, 0xCC4ADD67,
		0x6FDFB9F9, 0xF9EFBE8E, 0x43BEB717, 0xD58EB060,
		0xE8A3D6D6, 0x7E93D1A1, 0xC4C2D838, 0x52F2DF4F,
		0xF167BBD1, 0x6757BCA6, 0xDD06B53F, 0x4B36B248,
		0xDA2B0DD8, 0x4C1B0AAF, 0xF64A0336, 0x607A0441,
		0xC3EF60DF, 0x55DF67A8, 0xEF8E6E31, 0x79BE6946,
		0x8CB361CB, 0x1A8366BC, 0xA0D26F25, 0x36E26852,
		0x95770CCC, 0x03470BBB, 0xB9160222, 0x2F260555,
		0xBE3BBAC5, 0x280BBDB2, 0x925AB42B, 0x046AB35C,
		0xA7FFD7C2, 0x31CFD0B5, 0x8B9ED92C, 0x1DAEDE5B,
		0xB0C2649B, 0x26F263EC, 0x9CA36A75, 0x0A936D02,
		0xA906099C, 0x3F360EEB, 0x85670772, 0x13570005,
		0x824ABF95, 0x147AB8E2, 0xAE2BB17B, 0x381BB60C,
		0x9B8ED292, 0x0DBED5E5, 0xB7EFDC7C, 0x21DFDB0B,
		0xD4D2D386, 0x42E2D4F1, 0xF8B3DD68, 0x6E83DA1F,
		0xCD16BE81, 0x5B26B9F6, 0xE177B06F, 0x7747B718,
		0xE65A0888, 0x706A0FFF, 0xCA3B0666, 0x5C0B0111,
		0xFF9E658F, 0x69AE62F8, 0xD3FF6B61, 0x45CF6C16,
		0x78E20AA0, 0xEED20DD7, 0x5483044E, 0xC2B30339,
		0x612667A7, 0xF71660D0, 0x4D476949, 0xDB776E3E,
		0x4A6AD1AE, 0xDC5AD6D9, 0x660BDF40, 0xF03BD837,
		0x53AEBCA9, 0xC59EBBDE, 0x7FCFB247, 0xE9FFB530,
		0x1CF2BDBD, 0x8AC2BACA, 0x3093B353, 0xA6A3B424,
		0x0536D0BA, 0x9306D7CD, 0x2957DE54, 0xBF67D923,
		0x2E7A66B3, 0xB84A61C4, 0x021B685D, 0x942B6F2A,
		0x37BE0BB4, 0xA18E0CC3, 0x1BDF055A, 0x8DEF022D
	}, {
		0x00000000, 0x41311B19, 0x82623632, 0xC3532D2B,
		0x04C56C64, 0x45F4777D, 0x86A75A56, 0xC796414F,
		0x088AD9C8, 0x49BBC2D1, 0x8AE8EFFA, 0xCBD9F4E3,
		0x0C4FB5AC, 0x4D7EAEB5, 0x8E2D839E, 0xCF1C9887,
		0x5112C24A, 0x1023D953, 0xD370F478, 0x9241EF61,
		0x55D7AE2E, 0x14E6B537, 0xD7B5981C, 0x96848305,
		0x59981B82, 0x18A9009B, 0xDBFA2DB0, 0x9ACB36A9,
		0x5D5D77E6, 0x1C6C6CFF, 0xDF3F41D4, 0x9E0E5ACD,
		0xA2248495, 0xE3159F8C, 0x2046B2A7, 0x6177A9BE,
		0xA6E1E8F1, 0xE7D0F3E8, 0x2483DEC3, 0x65B2C5DA,
		0xAAAE5D5D, 0xEB9F4644, 0x28CC6B6F, 0x69FD7076,
		0xAE6B3139, 0xEF5A2A20, 0x2C09070B, 0x6D381C12,
		0xF33646DF, 0xB2075DC6, 0x715470ED, 0x30656BF4,
		0xF7F32ABB, 0xB6C231A2, 0x75911C89, 0x34A00790,
		0xFBBC9F17, 0xBA8D840E, 0x79DEA925, 0x38EFB23C,
		0xFF79F373, 0xBE48E86A, 0x7D1BC541, 0x3C2ADE58,
		0x054F79F0, 0x447E62E9, 0x872D4FC2, 0xC61C54DB,
		0x018A1594, 0x40BB0E8D, 0x83E823A6, 0xC2D938BF,
		0x0DC5A038, 0x4CF4BB21, 0x8FA7960A, 0xCE968D13,
		0x0900CC5C, 0x4831D745, 0x8B62FA6E, 0xCA53E177,
		0x545DBBBA, 0x156CA0A3, 0xD63F8D88, 0x970E9691,
		0x5098D7DE, 0x11A9CCC7, 0xD2FAE1EC, 0x93CBFAF5,
		0x5CD76272, 0x1DE6796B, 0xDEB55440, 0x9F844F59,
		0x58120E16, 0x1923150F, 0xDA703824, 0x9B41233D,
		0xA76BFD65, 0xE65AE67C, 0x2509CB57, 0x6438D04E,
		0xA3AE9101, 0xE29F8A18, 0x21CCA733, 0x60FDBC2A,
		0xAFE124AD, 0xEED03FB4, 0x2D83129F, 0x6CB20986,
		0xAB2448C9, 0xEA1553D0, 0x29467EFB, 0x687765E2,
		0xF6793F2F, 0xB7482436, 0x741B091D, 0x352A1204,
		0xF2BC534B, 0xB38D4852, 0x70DE6579, 0x31EF7E60,
		0xFEF3E6E7, 0xBFC2FDFE, 0x7C91D0D5, 0x3DA0CBCC,
		0xFA368A83, 0xBB07919A, 0x7854BCB1, 0x3965A7A8,
		0x4B98833B, 0x0AA99822, 0xC9FAB509, 0x88CBAE10,
		0x4F5DEF5F, 0x0E6CF446, 0xCD3FD96D, 0x8C0EC274,
		0x43125AF3, 0x022341EA, 0xC1706CC1, 0x804177D8,
		0x47D73697, 0x06E62D8E, 0xC5B500A5, 0x84841BBC,
		0x1A8A4171, 0x5BBB5A68, 0x98E87743, 0xD9D96C5A,
		0x1E4F2D15, 0x5F7E360C, 0x9C2D1B27, 0xDD1C003E,
		0x120098B9, 0x533183A0, 0x9062AE8B, 0xD153B592,
		0x16C5F4DD, 0x57F4EFC4, 0x94A7C2EF, 0xD596D9F6,
		0xE9BC07AE, 0xA88D1CB7, 0x6BDE319C, 0x2AEF2A85,
		0xED796BCA, 0xAC4870D3, 0x6F1B5DF8, 0x2E2A46E1,
		0xE136DE66, 0xA007C57F, 0x6354E854, 0x2265F34D,
		0xE5F3B202, 0xA4C2A91B, 0x67918430, 0x26A09F29,
		0xB8AEC5E4, 0xF99FDEFD, 0x3ACCF3D6, 0x7BFDE8CF,
		0xBC6BA980, 0xFD5AB299, 0x3E099FB2, 0x7F3884AB,
		0xB0241C2C, 0xF1150735, 0x32462A1E, 0x73773107,
		0xB4E17048, 0xF5D06B51, 0x3683467A, 0x77B25D63,
		0x4ED7FACB, 0x0FE6E1D2, 0xCCB5CCF9, 0x8D84D7E0,
		0x4A1296AF, 0x0B238DB6, 0xC870A09D, 0x8941BB84,
		0x465D2303, 0x076C381A, 0xC43F1531, 0x850E0E28,
		0x42984F67, 0x03A9547E, 0xC0FA7955, 0x81CB624C,
		0x1FC53881, 0x5EF42398, 0x9DA70EB3, 0xDC9615AA,
		0x1B0054E5, 0x5A314FFC, 0x996262D7, 0xD85379CE,
		0x174FE149, 0x567EFA50, 0x952DD77B, 0xD41CCC62,
		0x138A8D2D, 0x52BB9634, 0x91E8BB1F, 0xD0D9A006,
		0xECF37E5E, 0xADC26547, 0x6E91486C, 0x2FA05375,
		0xE836123A, 0xA9070923, 0x6A542408, 0x2B653F11,
		0xE479A796, 0xA548BC8F, 0x661B91A4, 0x272A8ABD,
		0xE0BCCBF2, 0xA18DD0EB, 0x62DEFDC0, 0x23EFE6D9,
		0xBDE1BC14, 0xFCD0A70D, 0x3F838A26, 0x7EB2913F,
		0xB924D070, 0xF815CB69, 0x3B46E642, 0x7A77FD5B,
		0xB56B65DC, 0xF45A7EC5, 0x370953EE, 0x763848F7,
		0xB1AE09B8, 0xF09F12A1, 0x33CC3F8A, 0x72FD2493
	}, {
		0x00000000, 0x376AC201, 0x6ED48403, 0x59BE4602,
		0xDCA80907, 0xEBC2CB06, 0xB27C8D04, 0x85164F05,
		0xB851130E, 0x8F3BD10F, 0xD685970D, 0xE1EF550C,
		0x64F91A09, 0x5393D808, 0x0A2D9E0A, 0x3D475C0B,
		0x70A3261C, 0x47C9E41D, 0x1E77A21F, 0x291D601E,
		0xAC0B2F1B, 0x9B61ED1A, 0xC2DFAB18, 0xF5B56919,
		0xC8F23512, 0xFF98F713, 0xA626B111, 0x914C7310,
		0x145A3C15, 0x2330FE14, 0x7A8EB816, 0x4DE47A17,
		0xE0464D38, 0xD72C8F39, 0x8E92C93B, 0xB9F80B3A,
		0x3CEE443F, 0x0B84863E, 0x523AC03C, 0x6550023D,
		0x58175E36, 0x6F7D9C37, 0x36C3DA35, 0x01A91834,
		0x84BF5731, 0xB3D59530, 0xEA6BD332, 0xDD011133,
		0x90E56B24, 0xA78FA925, 0xFE31EF27, 0xC95B2D26,
		0x4C4D6223, 0x7B27A022, 0x2299E620, 0x15F32421,
		0x28B4782A, 0x1FDEBA2B, 0x4660FC29, 0x710A3E28,
		0xF41C712D, 0xC376B32C, 0x9AC8F52E, 0xADA2372F,
		0xC08D9A70, 0xF7E75871, 0xAE591E73, 0x9933DC72,
		0x1C259377, 0x2B4F5176, 0x72F11774, 0x459BD575,
		0x78DC897E, 0x4FB64B7F, 0x16080D7D, 0x2162CF7C,
		0xA4748079, 0x931E4278, 0xCAA0047A, 0xFDCAC67B,
		0xB02EBC6C, 0x87447E6D, 0xDEFA386F, 0xE990FA6E,
		0x6C86B56B, 0x5BEC776A, 0x02523168, 0x3538F369,
		0x087FAF62, 0x3F156D63, 0x66AB2B61, 0x51C1E960,
		0xD4D7A665, 0xE3BD6464, 0xBA032266, 0x8D69E067,
		0x20CBD748, 0x17A11549, 0x4E1F534B, 0x7975914A,
		0xFC63DE4F, 0xCB091C4E, 0x92B75A4C, 0xA5DD984D,
		0x989AC446, 0xAFF00647, 0xF64E4045, 0xC1248244,
		0x4432CD41, 0x73580F40, 0x2AE64942, 0x1D8C8B43,
		0x5068F154, 0x67023355, 0x3EBC7557, 0x09D6B756,
		0x8CC0F853, 0xBBAA3A52, 0xE2147C50, 0xD57EBE51,
		0xE839E25A, 0xDF53205B, 0x86ED6659, 0xB187A458,
		0x3491EB5D, 0x03FB295C, 0x5A456F5E, 0x6D2FAD5F,
		0x801B35E1, 0xB771F7E0, 0xEECFB1E2, 0xD9A573E3,
		0x5CB33CE6, 0x6BD9FEE7, 0x3267B8E5, 0x050D7AE4,
		0x384A26EF, 0x0F20E4EE, 0x569EA2EC, 0x61F460ED,
		0xE4E22FE8, 0xD388EDE9, 0x8A36ABEB, 0xBD5C69EA,
		0xF0B813FD, 0xC7D2D1FC, 0x9E6C97FE, 0xA90655FF,
		0x2C101AFA, 0x1B7AD8FB, 0x42C49EF9, 0x75AE5CF8,
		0x48E900F3, 0x7F83C2F2, 0x263D84F0, 0x115746F1,
		0x944109F4, 0xA32BCBF5, 0xFA958DF7, 0xCDFF4FF6,
		0x605D78D9, 0x5737BAD8, 0x0E89FCDA, 0x39E33EDB,
		0xBCF571DE, 0x8B9FB3DF, 0xD221F5DD, 0xE54B37DC,
		0xD80C6BD7, 0xEF66A9D6, 0xB6D8EFD4, 0x81B22DD5,
		0x04A462D0, 0x33CEA0D1, 0x6A70E6D3, 0x5D1A24D2,
		0x10FE5EC5, 0x27949CC4, 0x7E2ADAC6, 0x494018C7,
		0xCC5657C2, 0xFB3C95C3, 0xA282D3C1, 0x95E811C0,
		0xA8AF4DCB, 0x9FC58FCA, 0xC67BC9C8, 0xF1110BC9,
		0x740744CC, 0x436D86CD, 0x1AD3C0CF, 0x2DB902CE,
		0x4096AF91, 0x77FC6D90, 0x2E422B92, 0x1928E993,
		0x9C3EA696, 0xAB546497, 0xF2EA2295, 0xC580E094,
		0xF8C7BC9F, 0xCFAD7E9E, 0x9613389C, 0xA179FA9D,
		0x246FB598, 0x13057799, 0x4ABB319B, 0x7DD1F39A,
		0x3035898D, 0x075F4B8C, 0x5EE10D8E, 0x698BCF8F,
		0xEC9D808A, 0xDBF7428B, 0x82490489, 0xB523C688,
		0x88649A83, 0xBF0E5882, 0xE6B01E80, 0xD1DADC81,
		0x54CC9384, 0x63A65185, 0x3A181787, 0x0D72D586,
		0xA0D0E2A9, 0x97BA20A8, 0xCE0466AA, 0xF96EA4AB,
		0x7C78EBAE, 0x4B1229AF, 0x12AC6FAD, 0x25C6ADAC,
		0x1881F1A7, 0x2FEB33A6, 0x765575A4, 0x413FB7A5,
		0xC429F8A0, 0xF3433AA1, 0xAAFD7CA3, 0x9D97BEA2,
		0xD073C4B5, 0xE71906B4, 0xBEA740B6, 0x89CD82B7,
		0x0CDBCDB2, 0x3BB10FB3, 0x620F49B1, 0x55658BB0,
		0x6822D7BB, 0x5F4815BA, 0x06F653B8, 0x319C91B9,
		0xB48ADEBC, 0x83E01CBD, 0xDA5E5ABF, 0xED3498BE
	}, {
		0x00000000, 0x6567BCB8, 0x8BC809AA, 0xEEAFB512,
		0x5797628F, 0x32F0DE37, 0xDC5F6B25, 0xB938D79D,
		0xEF28B4C5, 0x8A4F087D, 0x64E0BD6F, 0x018701D7,
		0xB8BFD64A, 0xDDD86AF2, 0x3377DFE0, 0x56106358,
		0x9F571950, 0xFA30A5E8, 0x149F10FA, 0x71F8AC42,
		0xC8C07BDF, 0xADA7C767, 0x43087275, 0x266FCECD,
		0x707FAD95, 0x1518112D, 0xFBB7A43F, 0x9ED01887,
		0x27E8CF1A, 0x428F73A2, 0xAC20C6B0, 0xC9477A08,
		0x3EAF32A0, 0x5BC88E18, 0xB5673B0A, 0xD00087B2,
		0x6938502F, 0x0C5FEC97, 0xE2F05985, 0x8797E53D,
		0xD1878665, 0xB4E03ADD, 0x5A4F8FCF, 0x3F283377,
		0x8610E4EA, 0xE3775852, 0x0DD8ED40, 0x68BF51F8,
		0xA1F82BF0, 0xC49F9748, 0x2A30225A, 0x4F579EE2,
		0xF66F497F, 0x9308F5C7, 0x7DA740D5, 0x18C0FC6D,
		0x4ED09F35, 0x2BB7238D, 0xC518969F, 0xA07F2A27,
		0x1947FDBA, 0x7C204102, 0x928FF410, 0xF7E848A8,
		0x3D58149B, 0x583FA823, 0xB6901D31, 0xD3F7A189,
		0x6ACF7614, 0x0FA8CAAC, 0xE1077FBE, 0x8460C306,
		0xD270A05E, 0xB7171CE6, 0x59B8A9F4, 0x3CDF154C,
		0x85E7C2D1, 0xE0807E69, 0x0E2FCB7B, 0x6B4877C3,
		0xA20F0DCB, 0xC768B173, 0x29C70461, 0x4CA0B8D9,
		0xF5986F44, 0x90FFD3FC, 0x7E5066EE, 0x1B37DA56,
		0x4D27B90E, 0x284005B6, 0xC6EFB0A4, 0xA3880C1C,
		0x1AB0DB81, 0x7FD76739, 0x9178D22B, 0xF41F6E93,
		0x03F7263B, 0x66909A83, 0x883F2F91, 0xED589329,
		0x546044B4, 0x3107F80C, 0xDFA84D1E, 0xBACFF1A6,
		0xECDF92FE, 0x89B82E46, 0x67179B54, 0x027027EC,
		0xBB48F071, 0xDE2F4CC9, 0x3080F9DB, 0x55E74563,
		0x9CA03F6B, 0xF9C783D3, 0x176836C1, 0x720F8A79,
		0xCB375DE4, 0xAE50E15C, 0x40FF544E, 0x2598E8F6,
		0x73888BAE, 0x16EF3716, 0xF8408204, 0x9D273EBC,
		0x241FE921, 0x41785599, 0xAFD7E08B, 0xCAB05C33,
		0x3BB659ED, 0x5ED1E555, 0xB07E5047, 0xD519ECFF,
		0x6C213B62, 0x094687DA, 0xE7E932C8, 0x828E8E70,
		0xD49EED28, 0xB1F95190, 0x5F56E482, 0x3A31583A,
		0x83098FA7, 0xE66E331F, 0x08C1860D, 0x6DA63AB5,
		0xA4E140BD, 0xC186FC05, 0x2F294917, 0x4A4EF5AF,
		0xF3762232, 0x96119E8A, 0x78BE2B98, 0x1DD99720,
		0x4BC9F478, 0x2EAE48C0, 0xC001FDD2, 0xA566416A,
		0x1C5E96F7, 0x79392A4F, 0x97969F5D, 0xF2F123E5,
		0x05196B4D, 0x607ED7F5, 0x8ED162E7, 0xEBB6DE5F,
		0x528E09C2, 0x37E9B57A, 0xD9460068, 0xBC21BCD0,
		0xEA31DF88, 0x8F566330, 0x61F9D622, 0x049E6A9A,
		0xBDA6BD07, 0xD8C101BF, 0x366EB4AD, 0x53090815,
		0x9A4E721D, 0xFF29CEA5, 0x11867BB7, 0x74E1C70F,
		0xCDD91092, 0xA8BEAC2A, 0x46111938, 0x2376A580,
		0x7566C6D8, 0x10017A60, 0xFEAECF72, 0x9BC973CA,
		0x22F1A457, 0x479618EF, 0xA939ADFD, 0xCC5E1145,
		0x06EE4D76, 0x6389F1CE, 0x8D2644DC, 0xE841F864,
		0x51792FF9, 0x341E9341, 0xDAB12653, 0xBFD69AEB,
		0xE9C6F9B3, 0x8CA1450B, 0x620EF019, 0x07694CA1,
		0xBE519B3C, 0xDB362784, 0x35999296, 0x50FE2E2E,
		0x99B95426, 0xFCDEE89E, 0x12715D8C, 0x7716E134,
		0xCE2E36A9, 0xAB498A11, 0x45E63F03, 0x208183BB,
		0x7691E0E3, 0x13F65C5B, 0xFD59E949, 0x983E55F1,
		0x2106826C, 0x44613ED4, 0xAACE8BC6, 0xCFA9377E,
		0x38417FD6, 0x5D26C36E, 0xB389767C, 0xD6EECAC4,
		0x6FD61D59, 0x0AB1A1E1, 0xE41E14F3, 0x8179A84B,
		0xD769CB13, 0xB20E77AB, 0x5CA1C2B9, 0x39C67E01,
		0x80FEA99C, 0xE5991524, 0x0B36A036, 0x6E511C8E,
		0xA7166686, 0xC271DA3E, 0x2CDE6F2C, 0x49B9D394,
		0xF0810409, 0x95E6B8B1, 0x7B490DA3, 0x1E2EB11B,
		0x483ED243, 0x2D596EFB, 0xC3F6DBE9, 0xA6916751,
		0x1FA9B0CC, 0x7ACE0C74, 0x9461B966, 0xF10605DE
	}, {
		0x00000000, 0xB029603D, 0x6053C07A, 0xD07AA047,
		0xC0A680F5, 0x708FE0C8, 0xA0F5408F, 0x10DC20B2,
		0xC14B7030, 0x7162100D, 0xA118B04A, 0x1131D077,
		0x01EDF0C5, 0xB1C490F8, 0x61BE30BF, 0xD1975082,
		0x8297E060, 0x32BE805D, 0xE2C4201A, 0x52ED4027,
		0x42316095, 0xF21800A8, 0x2262A0EF, 0x924BC0D2,
		0x43DC9050, 0xF3F5F06D, 0x238F502A, 0x93A63017,
		0x837A10A5, 0x33537098, 0xE329D0DF, 0x5300B0E2,
		0x042FC1C1, 0xB406A1FC, 0x647C01BB, 0xD4556186,
		0xC4894134, 0x74A02109, 0xA4DA814E, 0x14F3E173,
		0xC564B1F1, 0x754DD1CC, 0xA537718B, 0x151E11B6,
		0x05C23104, 0xB5EB5139, 0x6591F17E, 0xD5B89143,
		0x86B821A1, 0x3691419C, 0xE6EBE1DB, 0x56C281E6,
		0x461EA154, 0xF637C169, 0x264D612E, 0x96640113,
		0x47F35191, 0xF7DA31AC, 0x27A091EB, 0x9789F1D6,
		0x8755D164, 0x377CB159, 0xE706111E, 0x572F7123,
		0x4958F358, 0xF9719365, 0x290B3322, 0x9922531F,
		0x89FE73AD, 0x39D71390, 0xE9ADB3D7, 0x5984D3EA,
		0x88138368, 0x383AE355, 0xE8404312, 0x5869232F,
		0x48B5039D, 0xF89C63A0, 0x28E6C3E7, 0x98CFA3DA,
		0xCBCF1338, 0x7BE67305, 0xAB9CD342, 0x1BB5B37F,
		0x0B6993CD, 0xBB40F3F0, 0x6B3A53B7, 0xDB13338A,
		0x0A846308, 0xBAAD0335, 0x6AD7A372, 0xDAFEC34F,
		0xCA22E3FD, 0x7A0B83C0, 0xAA712387, 0x1A5843BA,
		0x4D773299, 0xFD5E52A4, 0x2D24F2E3, 0x9D0D92DE,
		0x8DD1B26C, 0x3DF8D251, 0xED827216, 0x5DAB122B,
		0x8C3C42A9, 0x3C152294, 0xEC6F82D3, 0x5C46E2EE,
		0x4C9AC25C, 0xFCB3A261, 0x2CC90226, 0x9CE0621B,
		0xCFE0D2F9, 0x7FC9B2C4, 0xAFB31283, 0x1F9A72BE,
		0x0F46520C, 0xBF6F3231, 0x6F159276, 0xDF3CF24B,
		0x0EABA2C9, 0xBE82C2F4, 0x6EF862B3, 0xDED1028E,
		0xCE0D223C, 0x7E244201, 0xAE5EE246, 0x1E77827B,
		0x92B0E6B1, 0x2299868C, 0xF2E326CB, 0x42CA46F6,
		0x52166644, 0xE23F0679, 0x3245A63E, 0x826CC603,
		0x53FB9681, 0xE3D2F6BC, 0x33A856FB, 0x838136C6,
		0x935D1674, 0x23747649, 0xF30ED60E, 0x4327B633,
		0x102706D1, 0xA00E66EC, 0x7074C6AB, 0xC05DA696,
		0xD0818624, 0x60A8E619, 0xB0D2465E, 0x00FB2663,
		0xD16C76E1, 0x614516DC, 0xB13FB69B, 0x0116D6A6,
		0x11CAF614, 0xA1E39629, 0x7199366E, 0xC1B05653,
		0x969F2770, 0x26B6474D, 0xF6CCE70A, 0x46E58737,
		0x5639A785, 0xE610C7B8, 0x366A67FF, 0x864307C2,
		0x57D45740, 0xE7FD377D, 0x3787973A, 0x87AEF707,
		0x9772D7B5, 0x275BB788, 0xF72117CF, 0x470877F2,
		0x1408C710, 0xA421A72D, 0x745B076A, 0xC4726757,
		0xD4AE47E5, 0x648727D8, 0xB4FD879F, 0x04D4E7A2,
		0xD543B720, 0x656AD71D, 0xB510775A, 0x05391767,
		0x15E537D5, 0xA5CC57E8, 0x75B6F7AF, 0xC59F9792,
		0xDBE815E9, 0x6BC175D4, 0xBBBBD593, 0x0B92B5AE,
		0x1B4E951C, 0xAB67F521, 0x7B1D5566, 0xCB34355B,
		0x1AA365D9, 0xAA8A05E4, 0x7AF0A5A3, 0xCAD9C59E,
		0xDA05E52C, 0x6A2C8511, 0xBA562556, 0x0A7F456B,
		0x597FF589, 0xE95695B4, 0x392C35F3, 0x890555CE,
		0x99D9757C, 0x29F01541, 0xF98AB506, 0x49A3D53B,
		0x983485B9, 0x281DE584, 0xF86745C3, 0x484E25FE,
		0x5892054C, 0xE8BB6571, 0x38C1C536, 0x88E8A50B,
		0xDFC7D428, 0x6FEEB415, 0xBF941452, 0x0FBD746F,
		0x1F6154DD, 0xAF4834E0, 0x7F3294A7, 0xCF1BF49A,
		0x1E8CA418, 0xAEA5C425, 0x7EDF6462, 0xCEF6045F,
		0xDE2A24ED, 0x6E0344D0, 0xBE79E497, 0x0E5084AA,
		0x5D503448, 0xED795475, 0x3D03F432, 0x8D2A940F,
		0x9DF6B4BD, 0x2DDFD480, 0xFDA574C7, 0x4D8C14FA,
		0x9C1B4478, 0x2C322445, 0xFC488402, 0x4C61E43F,
		0x5CBDC48D, 0xEC94A4B0, 0x3CEE04F7, 0x8CC764CA
	}, {
		0x00000000, 0xA5D35CCB, 0x0BA1C84D, 0xAE729486,
		0x1642919B, 0xB391CD50, 0x1DE359D6, 0xB830051D,
		0x6D8253EC, 0xC8510F27, 0x66239BA1, 0xC3F0C76A,
		0x7BC0C277, 0xDE139EBC, 0x70610A3A, 0xD5B256F1,
		0x9B02D603, 0x3ED18AC8, 0x90A31E4E, 0x35704285,
		0x8D404798, 0x28931B53, 0x86E18FD5, 0x2332D31E,
		0xF68085EF, 0x5353D924, 0xFD214DA2, 0x58F21169,
		0xE0C21474, 0x451148BF, 0xEB63DC39, 0x4EB080F2,
		0x3605AC07, 0x93D6F0CC, 0x3DA4644A, 0x98773881,
		0x20473D9C, 0x85946157, 0x2BE6F5D1, 0x8E35A91A,
		0x5B87FFEB, 0xFE54A320, 0x502637A6, 0xF5F56B6D,
		0x4DC56E70, 0xE81632BB, 0x4664A63D, 0xE3B7FAF6,
		0xAD077A04, 0x08D426CF, 0xA6A6B249, 0x0375EE82,
		0xBB45EB9F, 0x1E96B754, 0xB0E423D2, 0x15377F19,
		0xC08529E8, 0x65567523, 0xCB24E1A5, 0x6EF7BD6E,
		0xD6C7B873, 0x7314E4B8, 0xDD66703E, 0x78B52CF5,
		0x6C0A580F, 0xC9D904C4, 0x67AB9042, 0xC278CC89,
		0x7A48C994, 0xDF9B955F, 0x71E901D9, 0xD43A5D12,
		0x01880BE3, 0xA45B5728, 0x0A29C3AE, 0xAFFA9F65,
		0x17CA9A78, 0xB219C6B3, 0x1C6B5235, 0xB9B80EFE,
		0xF7088E0C, 0x52DBD2C7, 0xFCA94641, 0x597A1A8A,
		0xE14A1F97, 0x4499435C, 0xEAEBD7DA, 0x4F388B11,
		0x9A8ADDE0, 0x3F59812B, 0x912B15AD, 0x34F84966,
		0x8CC84C7B, 0x291B10B0, 0x87698436, 0x22BAD8FD,
		0x5A0FF408, 0xFFDCA8C3, 0x51AE3C45, 0xF47D608E,
		0x4C4D6593, 0xE99E3958, 0x47ECADDE, 0xE23FF115,
		0x378DA7E4, 0x925EFB2F, 0x3C2C6FA9, 0x99FF3362,
		0x21CF367F, 0x841C6AB4, 0x2A6EFE32, 0x8FBDA2F9,
		0xC10D220B, 0x64DE7EC0, 0xCAACEA46, 0x6F7FB68D,
		0xD74FB390, 0x729CEF5B, 0xDCEE7BDD, 0x793D2716,
		0xAC8F71E7, 0x095C2D2C, 0xA72EB9AA, 0x02FDE561,
		0xBACDE07C, 0x1F1EBCB7, 0xB16C2831, 0x14BF74FA,
		0xD814B01E, 0x7DC7ECD5, 0xD3B57853, 0x76662498,
		0xCE562185, 0x6B857D4E, 0xC5F7E9C8, 0x6024B503,
		0xB596E3F2, 0x1045BF39, 0xBE372BBF, 0x1BE47774,
		0xA3D47269, 0x06072EA2, 0xA875BA24, 0x0DA6E6EF,
		0x4316661D, 0xE6C53AD6, 0x48B7AE50, 0xED64F29B,
		0x5554F786, 0xF087AB4D, 0x5EF53FCB, 0xFB266300,
		0x2E9435F1, 0x8B47693A, 0x2535FDBC, 0x80E6A177,
		0x38D6A46A, 0x9D05F8A1, 0x33776C27, 0x96A430EC,
		0xEE111C19, 0x4BC240D2, 0xE5B0D454, 0x4063889F,
		0xF8538D82, 0x5D80D149, 0xF3F245CF, 0x56211904,
		0x83934FF5, 0x2640133E, 0x883287B8, 0x2DE1DB73,
		0x95D1DE6E, 0x300282A5, 0x9E701623, 0x3BA34AE8,
		0x7513CA1A, 0xD0C096D1, 0x7EB20257, 0xDB615E9C,
		0x63515B81, 0xC682074A, 0x68F093CC, 0xCD23CF07,
		0x189199F6, 0xBD42C53D, 0x133051BB, 0xB6E30D70,
		0x0ED3086D, 0xAB0054A6, 0x0572C020, 0xA0A19CEB,
		0xB41EE811, 0x11CDB4DA, 0xBFBF205C, 0x1A6C7C97,
		0xA25C798A, 0x078F2541, 0xA9FDB1C7, 0x0C2EED0C,
		0xD99CBBFD, 0x7C4FE736, 0xD23D73B0, 0x77EE2F7B,
		0xCFDE2A66, 0x6A0D76AD, 0xC47FE22B, 0x61ACBEE0,
		0x2F1C3E12, 0x8ACF62D9, 0x24BDF65F, 0x816EAA94,
		0x395EAF89, 0x9C8DF342, 0x32FF67C4, 0x972C3B0F,
		0x429E6DFE, 0xE74D3135, 0x493FA5B3, 0xECECF978,
		0x54DCFC65, 0xF10FA0AE, 0x5F7D3428, 0xFAAE68E3,
		0x821B4416, 0x27C818DD, 0x89BA8C5B, 0x2C69D090,
		0x9459D58D, 0x318A8946, 0x9FF81DC0, 0x3A2B410B,
		0xEF9917FA, 0x4A4A4B31, 0xE438DFB7, 0x41EB837C,
		0xF9DB8661, 0x5C08DAAA, 0xF27A4E2C, 0x57A912E7,
		0x19199215, 0xBCCACEDE, 0x12B85A58, 0xB76B0693,
		0x0F5B038E, 0xAA885F45, 0x04FACBC3, 0xA1299708,
		0x749BC1F9, 0xD1489D32, 0x7F3A09B4, 0xDAE9557F,
		0x62D95062, 0xC70A0CA9, 0x6978982F, 0xCCABC4E4
	}, {
		0x00000000, 0xB40B77A6, 0x29119F97, 0x9D1AE831,
		0x13244FF4, 0xA72F3852, 0x3A35D063, 0x8E3EA7C5,
		0x674EEF33, 0xD3459895, 0x4E5F70A4, 0xFA540702,
		0x746AA0C7, 0xC061D761, 0x5D7B3F50, 0xE97048F6,
		0xCE9CDE67, 0x7A97A9C1, 0xE78D41F0, 0x53863656,
		0xDDB89193, 0x69B3E635, 0xF4A90E04, 0x40A279A2,
		0xA9D23154, 0x1DD946F2, 0x80C3AEC3, 0x34C8D965,
		0xBAF67EA0, 0x0EFD0906, 0x93E7E137, 0x27EC9691,
		0x9C39BDCF, 0x2832CA69, 0xB5282258, 0x012355FE,
		0x8F1DF23B, 0x3B16859D, 0xA60C6DAC, 0x12071A0A,
		0xFB7752FC, 0x4F7C255A, 0xD266CD6B, 0x666DBACD,
		0xE8531D08, 0x5C586AAE, 0xC142829F, 0x7549F539,
		0x52A563A8, 0xE6AE140E, 0x7BB4FC3F, 0xCFBF8B99,
		0x41812C5C, 0xF58A5BFA, 0x6890B3CB, 0xDC9BC46D,
		0x35EB8C9B, 0x81E0FB3D, 0x1CFA130C, 0xA8F164AA,
		0x26CFC36F, 0x92C4B4C9, 0x0FDE5CF8, 0xBBD52B5E,
		0x79750B44, 0xCD7E7CE2, 0x506494D3, 0xE46FE375,
		0x6A5144B0, 0xDE5A3316, 0x4340DB27, 0xF74BAC81,
		0x1E3BE477, 0xAA3093D1, 0x372A7BE0, 0x83210C46,
		0x0D1FAB83, 0xB914DC25, 0x240E3414, 0x900543B2,
		0xB7E9D523, 0x03E2A285, 0x9EF84AB4, 0x2AF33D12,
		0xA4CD9AD7, 0x10C6ED71, 0x8DDC0540, 0x39D772E6,
		0xD0A73A10, 0x64AC4DB6, 0xF9B6A587, 0x4DBDD221,
		0xC38375E4, 0x77880242, 0xEA92EA73, 0x5E999DD5,
		0xE54CB68B, 0x5147C12D, 0xCC5D291C, 0x78565EBA,
		0xF668F97F, 0x42638ED9, 0xDF7966E8, 0x6B72114E,
		0x820259B8, 0x36092E1E, 0xAB13C62F, 0x1F18B189,
		0x9126164C, 0x252D61EA, 0xB83789DB, 0x0C3CFE7D,
		0x2BD068EC, 0x9FDB1F4A, 0x02C1F77B, 0xB6CA80DD,
		0x38F42718, 0x8CFF50BE, 0x11E5B88F, 0xA5EECF29,
		0x4C9E87DF, 0xF895F079, 0x658F1848, 0xD1846FEE,
		0x5FBAC82B, 0xEBB1BF8D, 0x76AB57BC, 0xC2A0201A,
		0xF2EA1688, 0x46E1612E, 0xDBFB891F, 0x6FF0FEB9,
		0xE1CE597C, 0x55C52EDA, 0xC8DFC6EB, 0x7CD4B14D,
		0x95A4F9BB, 0x21AF8E1D, 0xBCB5662C, 0x08BE118A,
		0x8680B64F, 0x328BC1E9, 0xAF9129D8, 0x1B9A5E7E,
		0x3C76C8EF, 0x887DBF49, 0x15675778, 0xA16C20DE,
		0x2F52871B, 0x9B59F0BD, 0x0643188C, 0xB2486F2A,
		0x5B3827DC, 0xEF33507A, 0x7229B84B, 0xC622CFED,
		0x481C6828, 0xFC171F8E, 0x610DF7BF, 0xD5068019,
		0x6ED3AB47, 0xDAD8DCE1, 0x47C234D0, 0xF3C94376,
		0x7DF7E4B3, 0xC9FC9315, 0x54E67B24, 0xE0ED0C82,
		0x099D4474, 0xBD9633D2, 0x208CDBE3, 0x9487AC45,
		0x1AB90B80, 0xAEB27C26, 0x33A89417, 0x87A3E3B1,
		0xA04F7520, 0x14440286, 0x895EEAB7, 0x3D559D11,
		0xB36B3AD4, 0x07604D72, 0x9A7AA543, 0x2E71D2E5,
		0xC7019A13, 0x730AEDB5, 0xEE100584, 0x5A1B7222,
		0xD425D5E7, 0x602EA241, 0xFD344A70, 0x493F3DD6,
		0x8B9F1DCC, 0x3F946A6A, 0xA28E825B, 0x1685F5FD,
		0x98BB5238, 0x2CB0259E, 0xB1AACDAF, 0x05A1BA09,
		0xECD1F2FF, 0x58DA8559, 0xC5C06D68, 0x71CB1ACE,
		0xFFF5BD0B, 0x4BFECAAD, 0xD6E4229C, 0x62EF553A,
		0x4503C3AB, 0xF108B40D, 0x6C125C3C, 0xD8192B9A,
		0x56278C5F, 0xE22CFBF9, 0x7F3613C8, 0xCB3D646E,
		0x224D2C98, 0x96465B3E, 0x0B5CB30F, 0xBF57C4A9,
		0x3169636C, 0x856214CA, 0x1878FCFB, 0xAC738B5D,
		0x17A6A003, 0xA3ADD7A5, 0x3EB73F94, 0x8ABC4832,
		0x0482EFF7, 0xB0899851, 0x2D937060, 0x999807C6,
		0x70E84F30, 0xC4E33896, 0x59F9D0A7, 0xEDF2A701,
		0x63CC00C4, 0xD7C77762, 0x4ADD9F53, 0xFED6E8F5,
		0xD93A7E64, 0x6D3109C2, 0xF02BE1F3, 0x44209655,
		0xCA1E3190, 0x7E154636, 0xE30FAE07, 0x5704D9A1,
		0xBE749157, 0x0A7FE6F1, 0x97650EC0, 0x236E7966,
		0xAD50DEA3, 0x195BA905, 0x84414134, 0x304A3692
	}, {
		0x00000000, 0x9E00AACC, 0x7D072542, 0xE3078F8E,
		0xFA0E4A84, 0x640EE048, 0x87096FC6, 0x1909C50A,
		0xB51BE5D3, 0x2B1B4F1F, 0xC81CC091, 0x561C6A5D,
		0x4F15AF57, 0xD115059B, 0x32128A15, 0xAC1220D9,
		0x2B31BB7C, 0xB53111B0, 0x56369E3E, 0xC83634F2,
		0xD13FF1F8, 0x4F3F5B34, 0xAC38D4BA, 0x32387E76,
		0x9E2A5EAF, 0x002AF463, 0xE32D7BED, 0x7D2DD121,
		0x6424142B, 0xFA24BEE7, 0x19233169, 0x87239BA5,
		0x566276F9, 0xC862DC35, 0x2B6553BB, 0xB565F977,
		0xAC6C3C7D, 0x326C96B1, 0xD16B193F, 0x4F6BB3F3,
		0xE379932A, 0x7D7939E6, 0x9E7EB668, 0x007E1CA4,
		0x1977D9AE, 0x87777362, 0x6470FCEC, 0xFA705620,
		0x7D53CD85, 0xE3536749, 0x0054E8C7, 0x9E54420B,
		0x875D8701, 0x195D2DCD, 0xFA5AA243, 0x645A088F,
		0xC8482856, 0x5648829A, 0xB54F0D14, 0x2B4FA7D8,
		0x324662D2, 0xAC46C81E, 0x4F414790, 0xD141ED5C,
		0xEDC29D29, 0x73C237E5, 0x90C5B86B, 0x0EC512A7,
		0x17CCD7AD, 0x89CC7D61, 0x6ACBF2EF, 0xF4CB5823,
		0x58D978FA, 0xC6D9D236, 0x25DE5DB8, 0xBBDEF774,
		0xA2D7327E, 0x3CD798B2, 0xDFD0173C, 0x41D0BDF0,
		0xC6F32655, 0x58F38C99, 0xBBF40317, 0x25F4A9DB,
		0x3CFD6CD1, 0xA2FDC61D, 0x41FA4993, 0xDFFAE35F,
		0x73E8C386, 0xEDE8694A, 0x0EEFE6C4, 0x90EF4C08,
		0x89E68902, 0x17E623CE, 0xF4E1AC40, 0x6AE1068C,
		0xBBA0EBD0, 0x25A0411C, 0xC6A7CE92, 0x58A7645E,
		0x41AEA154, 0xDFAE0B98, 0x3CA98416, 0xA2A92EDA,
		0x0EBB0E03, 0x90BBA4CF, 0x73BC2B41, 0xEDBC818D,
		0xF4B54487, 0x6AB5EE4B, 0x89B261C5, 0x17B2CB09,
		0x909150AC, 0x0E91FA60, 0xED9675EE, 0x7396DF22,
		0x6A9F1A28, 0xF49FB0E4, 0x17983F6A, 0x899895A6,
		0x258AB57F, 0xBB8A1FB3, 0x588D903D, 0xC68D3AF1,
		0xDF84FFFB, 0x41845537, 0xA283DAB9, 0x3C837075,
		0xDA853B53, 0x4485919F, 0xA7821E11, 0x3982B4DD,
		0x208B71D7, 0xBE8BDB1B, 0x5D8C5495, 0xC38CFE59,
		0x6F9EDE80, 0xF19E744C, 0x1299FBC2, 0x8C99510E,
		0x95909404, 0x0B903EC8, 0xE897B146, 0x76971B8A,
		0xF1B4802F, 0x6FB42AE3, 0x8CB3A56D, 0x12B30FA1,
		0x0BBACAAB, 0x95BA6067, 0x76BDEFE9, 0xE8BD4525,
		0x44AF65FC, 0xDAAFCF30, 0x39A840BE, 0xA7A8EA72,
		0xBEA12F78, 0x20A185B4, 0xC3A60A3A, 0x5DA6A0F6,
		0x8CE74DAA, 0x12E7E766, 0xF1E068E8, 0x6FE0C224,
		0x76E9072E, 0xE8E9ADE2, 0x0BEE226C, 0x95EE88A0,
		0x39FCA879, 0xA7FC02B5, 0x44FB8D3B, 0xDAFB27F7,
		0xC3F2E2FD, 0x5DF24831, 0xBEF5C7BF, 0x20F56D73,
		0xA7D6F6D6, 0x39D65C1A, 0xDAD1D394, 0x44D17958,
		0x5DD8BC52, 0xC3D8169E, 0x20DF9910, 0xBEDF33DC,
		0x12CD1305, 0x8CCDB9C9, 0x6FCA3647, 0xF1CA9C8B,
		0xE8C35981, 0x76C3F34D, 0x95C47CC3, 0x0BC4D60F,
		0x3747A67A, 0xA9470CB6, 0x4A408338, 0xD44029F4,
		0xCD49ECFE, 0x53494632, 0xB04EC9BC, 0x2E4E6370,
		0x825C43A9, 0x1C5CE965, 0xFF5B66EB, 0x615BCC27,
		0x7852092D, 0xE652A3E1, 0x05552C6F, 0x9B5586A3,
		0x1C761D06, 0x8276B7CA, 0x61713844, 0xFF719288,
		0xE6785782, 0x7878FD4E, 0x9B7F72C0, 0x057FD80C,
		0xA96DF8D5, 0x376D5219, 0xD46ADD97, 0x4A6A775B,
		0x5363B251, 0xCD63189D, 0x2E649713, 0xB0643DDF,
		0x6125D083, 0xFF257A4F, 0x1C22F5C1, 0x82225F0D,
		0x9B2B9A07, 0x052B30CB, 0xE62CBF45, 0x782C1589,
		0xD43E3550, 0x4A3E9F9C, 0xA9391012, 0x3739BADE,
		0x2E307FD4, 0xB030D518, 0x53375A96, 0xCD37F05A,
		0x4A146BFF, 0xD414C133, 0x37134EBD, 0xA913E471,
		0xB01A217B, 0x2E1A8BB7, 0xCD1D0439, 0x531DAEF5,
		0xFF0F8E2C, 0x610F24E0, 0x8208AB6E, 0x1C0801A2,
		0x0501C4A8, 0x9B016E64, 0x7806E1EA, 0xE6064B26
	}
};

#else

const uint32_t lzma_crc32_table[8][256] = {
	{
		0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
		0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
		0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
		0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
		0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
		0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
		0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
		0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
		0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
		0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
		0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
		0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
		0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
		0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
		0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
		0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
		0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
		0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
		0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
		0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
		0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
		0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
		0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
		0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
		0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
		0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
		0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
		0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
		0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
		0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
		0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
		0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
		0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
		0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
		0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
		0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
		0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
		0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
		0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
		0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
		0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
		0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
		0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
		0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
		0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
		0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
		0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
		0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
		0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
		0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
		0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
		0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
		0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
		0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
		0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
		0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
		0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
		0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
		0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
		0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
		0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
		0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
		0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
		0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
	}, {
		0x00000000, 0x191B3141, 0x32366282, 0x2B2D53C3,
		0x646CC504, 0x7D77F445, 0x565AA786, 0x4F4196C7,
		0xC8D98A08, 0xD1C2BB49, 0xFAEFE88A, 0xE3F4D9CB,
		0xACB54F0C, 0xB5AE7E4D, 0x9E832D8E, 0x87981CCF,
		0x4AC21251, 0x53D92310, 0x78F470D3, 0x61EF4192,
		0x2EAED755, 0x37B5E614, 0x1C98B5D7, 0x05838496,
		0x821B9859, 0x9B00A918, 0xB02DFADB, 0xA936CB9A,
		0xE6775D5D, 0xFF6C6C1C, 0xD4413FDF, 0xCD5A0E9E,
		0x958424A2, 0x8C9F15E3, 0xA7B24620, 0xBEA97761,
		0xF1E8E1A6, 0xE8F3D0E7, 0xC3DE8324, 0xDAC5B265,
		0x5D5DAEAA, 0x44469FEB, 0x6F6BCC28, 0x7670FD69,
		0x39316BAE, 0x202A5AEF, 0x0B07092C, 0x121C386D,
		0xDF4636F3, 0xC65D07B2, 0xED705471, 0xF46B6530,
		0xBB2AF3F7, 0xA231C2B6, 0x891C9175, 0x9007A034,
		0x179FBCFB, 0x0E848DBA, 0x25A9DE79, 0x3CB2EF38,
		0x73F379FF, 0x6AE848BE, 0x41C51B7D, 0x58DE2A3C,
		0xF0794F05, 0xE9627E44, 0xC24F2D87, 0xDB541CC6,
		0x94158A01, 0x8D0EBB40, 0xA623E883, 0xBF38D9C2,
		0x38A0C50D, 0x21BBF44C, 0x0A96A78F, 0x138D96CE,
		0x5CCC0009, 0x45D73148, 0x6EFA628B, 0x77E153CA,
		0xBABB5D54, 0xA3A06C15, 0x888D3FD6, 0x91960E97,
		0xDED79850, 0xC7CCA911, 0xECE1FAD2, 0xF5FACB93,
		0x7262D75C, 0x6B79E61D, 0x4054B5DE, 0x594F849F,
		0x160E1258, 0x0F152319, 0x243870DA, 0x3D23419B,
		0x65FD6BA7, 0x7CE65AE6, 0x57CB0925, 0x4ED03864,
		0x0191AEA3, 0x188A9FE2, 0x33A7CC21, 0x2ABCFD60,
		0xAD24E1AF, 0xB43FD0EE, 0x9F12832D, 0x8609B26C,
		0xC94824AB, 0xD05315EA, 0xFB7E4629, 0xE2657768,
		0x2F3F79F6, 0x362448B7, 0x1D091B74, 0x04122A35,
		0x4B53BCF2, 0x52488DB3, 0x7965DE70, 0x607EEF31,
		0xE7E6F3FE, 0xFEFDC2BF, 0xD5D0917C, 0xCCCBA03D,
		0x838A36FA, 0x9A9107BB, 0xB1BC5478, 0xA8A76539,
		0x3B83984B, 0x2298A90A, 0x09B5FAC9, 0x10AECB88,
		0x5FEF5D4F, 0x46F46C0E, 0x6DD93FCD, 0x74C20E8C,
		0xF35A1243, 0xEA412302, 0xC16C70C1, 0xD8774180,
		0x9736D747, 0x8E2DE606, 0xA500B5C5, 0xBC1B8484,
		0x71418A1A, 0x685ABB5B, 0x4377E898, 0x5A6CD9D9,
		0x152D4F1E, 0x0C367E5F, 0x271B2D9C, 0x3E001CDD,
		0xB9980012, 0xA0833153, 0x8BAE6290, 0x92B553D1,
		0xDDF4C516, 0xC4EFF457, 0xEFC2A794, 0xF6D996D5,
		0xAE07BCE9, 0xB71C8DA8, 0x9C31DE6B, 0x852AEF2A,
		0xCA6B79ED, 0xD37048AC, 0xF85D1B6F, 0xE1462A2E,
		0x66DE36E1, 0x7FC507A0, 0x54E85463, 0x4DF36522,
		0x02B2F3E5, 0x1BA9C2A4, 0x30849167, 0x299FA026,
		0xE4C5AEB8, 0xFDDE9FF9, 0xD6F3CC3A, 0xCFE8FD7B,
		0x80A96BBC, 0x99B25AFD, 0xB29F093E, 0xAB84387F,
		0x2C1C24B0, 0x350715F1, 0x1E2A4632, 0x07317773,
		0x4870E1B4, 0x516BD0F5, 0x7A468336, 0x635DB277,
		0xCBFAD74E, 0xD2E1E60F, 0xF9CCB5CC, 0xE0D7848D,
		0xAF96124A, 0xB68D230B, 0x9DA070C8, 0x84BB4189,
		0x03235D46, 0x1A386C07, 0x31153FC4, 0x280E0E85,
		0x674F9842, 0x7E54A903, 0x5579FAC0, 0x4C62CB81,
		0x8138C51F, 0x9823F45E, 0xB30EA79D, 0xAA1596DC,
		0xE554001B, 0xFC4F315A, 0xD7626299, 0xCE7953D8,
		0x49E14F17, 0x50FA7E56, 0x7BD72D95, 0x62CC1CD4,
		0x2D8D8A13, 0x3496BB52, 0x1FBBE891, 0x06A0D9D0,
		0x5E7EF3EC, 0x4765C2AD, 0x6C48916E, 0x7553A02F,
		0x3A1236E8, 0x230907A9, 0x0824546A, 0x113F652B,
		0x96A779E4, 0x8FBC48A5, 0xA4911B66, 0xBD8A2A27,
		0xF2CBBCE0, 0xEBD08DA1, 0xC0FDDE62, 0xD9E6EF23,
		0x14BCE1BD, 0x0DA7D0FC, 0x268A833F, 0x3F91B27E,
		0x70D024B9, 0x69CB15F8, 0x42E6463B, 0x5BFD777A,
		0xDC656BB5, 0xC57E5AF4, 0xEE530937, 0xF7483876,
		0xB809AEB1, 0xA1129FF0, 0x8A3FCC33, 0x9324FD72
	}, {
		0x00000000, 0x01C26A37, 0x0384D46E, 0x0246BE59,
		0x0709A8DC, 0x06CBC2EB, 0x048D7CB2, 0x054F1685,
		0x0E1351B8, 0x0FD13B8F, 0x0D9785D6, 0x0C55EFE1,
		0x091AF964, 0x08D89353, 0x0A9E2D0A, 0x0B5C473D,
		0x1C26A370, 0x1DE4C947, 0x1FA2771E, 0x1E601D29,
		0x1B2F0BAC, 0x1AED619B, 0x18ABDFC2, 0x1969B5F5,
		0x1235F2C8, 0x13F798FF, 0x11B126A6, 0x10734C91,
		0x153C5A14, 0x14FE3023, 0x16B88E7A, 0x177AE44D,
		0x384D46E0, 0x398F2CD7, 0x3BC9928E, 0x3A0BF8B9,
		0x3F44EE3C, 0x3E86840B, 0x3CC03A52, 0x3D025065,
		0x365E1758, 0x379C7D6F, 0x35DAC336, 0x3418A901,
		0x3157BF84, 0x3095D5B3, 0x32D36BEA, 0x331101DD,
		0x246BE590, 0x25A98FA7, 0x27EF31FE, 0x262D5BC9,
		0x23624D4C, 0x22A0277B, 0x20E69922, 0x2124F315,
		0x2A78B428, 0x2BBADE1F, 0x29FC6046, 0x283E0A71,
		0x2D711CF4, 0x2CB376C3, 0x2EF5C89A, 0x2F37A2AD,
		0x709A8DC0, 0x7158E7F7, 0x731E59AE, 0x72DC3399,
		0x7793251C, 0x76514F2B, 0x7417F172, 0x75D59B45,
		0x7E89DC78, 0x7F4BB64F, 0x7D0D0816, 0x7CCF6221,
		0x798074A4, 0x78421E93, 0x7A04A0CA, 0x7BC6CAFD,
		0x6CBC2EB0, 0x6D7E4487, 0x6F38FADE, 0x6EFA90E9,
		0x6BB5866C, 0x6A77EC5B, 0x68315202, 0x69F33835,
		0x62AF7F08, 0x636D153F, 0x612BAB66, 0x60E9C151,
		0x65A6D7D4, 0x6464BDE3, 0x662203BA, 0x67E0698D,
		0x48D7CB20, 0x4915A117, 0x4B531F4E, 0x4A917579,
		0x4FDE63FC, 0x4E1C09CB, 0x4C5AB792, 0x4D98DDA5,
		0x46C49A98, 0x4706F0AF, 0x45404EF6, 0x448224C1,
		0x41CD3244, 0x400F5873, 0x4249E62A, 0x438B8C1D,
		0x54F16850, 0x55330267, 0x5775BC3E, 0x56B7D609,
		0x53F8C08C, 0x523AAABB, 0x507C14E2, 0x51BE7ED5,
		0x5AE239E8, 0x5B2053DF, 0x5966ED86, 0x58A487B1,
		0x5DEB9134, 0x5C29FB03, 0x5E6F455A, 0x5FAD2F6D,
		0xE1351B80, 0xE0F771B7, 0xE2B1CFEE, 0xE373A5D9,
		0xE63CB35C, 0xE7FED96B, 0xE5B86732, 0xE47A0D05,
		0xEF264A38, 0xEEE4200F, 0xECA29E56, 0xED60F461,
		0xE82FE2E4, 0xE9ED88D3, 0xEBAB368A, 0xEA695CBD,
		0xFD13B8F0, 0xFCD1D2C7, 0xFE976C9E, 0xFF5506A9,
		0xFA1A102C, 0xFBD87A1B, 0xF99EC442, 0xF85CAE75,
		0xF300E948, 0xF2C2837F, 0xF0843D26, 0xF1465711,
		0xF4094194, 0xF5CB2BA3, 0xF78D95FA, 0xF64FFFCD,
		0xD9785D60, 0xD8BA3757, 0xDAFC890E, 0xDB3EE339,
		0xDE71F5BC, 0xDFB39F8B, 0xDDF521D2, 0xDC374BE5,
		0xD76B0CD8, 0xD6A966EF, 0xD4EFD8B6, 0xD52DB281,
		0xD062A404, 0xD1A0CE33, 0xD3E6706A, 0xD2241A5D,
		0xC55EFE10, 0xC49C9427, 0xC6DA2A7E, 0xC7184049,
		0xC25756CC, 0xC3953CFB, 0xC1D382A2, 0xC011E895,
		0xCB4DAFA8, 0xCA8FC59F, 0xC8C97BC6, 0xC90B11F1,
		0xCC440774, 0xCD866D43, 0xCFC0D31A, 0xCE02B92D,
		0x91AF9640, 0x906DFC77, 0x922B422E, 0x93E92819,
		0x96A63E9C, 0x976454AB, 0x9522EAF2, 0x94E080C5,
		0x9FBCC7F8, 0x9E7EADCF, 0x9C381396, 0x9DFA79A1,
		0x98B56F24, 0x99770513, 0x9B31BB4A, 0x9AF3D17D,
		0x8D893530, 0x8C4B5F07, 0x8E0DE15E, 0x8FCF8B69,
		0x8A809DEC, 0x8B42F7DB, 0x89044982, 0x88C623B5,
		0x839A6488, 0x82580EBF, 0x801EB0E6, 0x81DCDAD1,
		0x8493CC54, 0x8551A663, 0x8717183A, 0x86D5720D,
		0xA9E2D0A0, 0xA820BA97, 0xAA6604CE, 0xABA46EF9,
		0xAEEB787C, 0xAF29124B, 0xAD6FAC12, 0xACADC625,
		0xA7F18118, 0xA633EB2F, 0xA4755576, 0xA5B73F41,
		0xA0F829C4, 0xA13A43F3, 0xA37CFDAA, 0xA2BE979D,
		0xB5C473D0, 0xB40619E7, 0xB640A7BE, 0xB782CD89,
		0xB2CDDB0C, 0xB30FB13B, 0xB1490F62, 0xB08B6555,
		0xBBD72268, 0xBA15485F, 0xB853F606, 0xB9919C31,
		0xBCDE8AB4, 0xBD1CE083, 0xBF5A5EDA, 0xBE9834ED
	}, {
		0x00000000, 0xB8BC6765, 0xAA09C88B, 0x12B5AFEE,
		0x8F629757, 0x37DEF032, 0x256B5FDC, 0x9DD738B9,
		0xC5B428EF, 0x7D084F8A, 0x6FBDE064, 0xD7018701,
		0x4AD6BFB8, 0xF26AD8DD, 0xE0DF7733, 0x58631056,
		0x5019579F, 0xE8A530FA, 0xFA109F14, 0x42ACF871,
		0xDF7BC0C8, 0x67C7A7AD, 0x75720843, 0xCDCE6F26,
		0x95AD7F70, 0x2D111815, 0x3FA4B7FB, 0x8718D09E,
		0x1ACFE827, 0xA2738F42, 0xB0C620AC, 0x087A47C9,
		0xA032AF3E, 0x188EC85B, 0x0A3B67B5, 0xB28700D0,
		0x2F503869, 0x97EC5F0C, 0x8559F0E2, 0x3DE59787,
		0x658687D1, 0xDD3AE0B4, 0xCF8F4F5A, 0x7733283F,
		0xEAE41086, 0x525877E3, 0x40EDD80D, 0xF851BF68,
		0xF02BF8A1, 0x48979FC4, 0x5A22302A, 0xE29E574F,
		0x7F496FF6, 0xC7F50893, 0xD540A77D, 0x6DFCC018,
		0x359FD04E, 0x8D23B72B, 0x9F9618C5, 0x272A7FA0,
		0xBAFD4719, 0x0241207C, 0x10F48F92, 0xA848E8F7,
		0x9B14583D, 0x23A83F58, 0x311D90B6, 0x89A1F7D3,
		0x1476CF6A, 0xACCAA80F, 0xBE7F07E1, 0x06C36084,
		0x5EA070D2, 0xE61C17B7, 0xF4A9B859, 0x4C15DF3C,
		0xD1C2E785, 0x697E80E0, 0x7BCB2F0E, 0xC377486B,
		0xCB0D0FA2, 0x73B168C7, 0x6104C729, 0xD9B8A04C,
		0x446F98F5, 0xFCD3FF90, 0xEE66507E, 0x56DA371B,
		0x0EB9274D, 0xB6054028, 0xA4B0EFC6, 0x1C0C88A3,
		0x81DBB01A, 0x3967D77F, 0x2BD27891, 0x936E1FF4,
		0x3B26F703, 0x839A9066, 0x912F3F88, 0x299358ED,
		0xB4446054, 0x0CF80731, 0x1E4DA8DF, 0xA6F1CFBA,
		0xFE92DFEC, 0x462EB889, 0x549B1767, 0xEC277002,
		0x71F048BB, 0xC94C2FDE, 0xDBF98030, 0x6345E755,
		0x6B3FA09C, 0xD383C7F9, 0xC1366817, 0x798A0F72,
		0xE45D37CB, 0x5CE150AE, 0x4E54FF40, 0xF6E89825,
		0xAE8B8873, 0x1637EF16, 0x048240F8, 0xBC3E279D,
		0x21E91F24, 0x99557841, 0x8BE0D7AF, 0x335CB0CA,
		0xED59B63B, 0x55E5D15E, 0x47507EB0, 0xFFEC19D5,
		0x623B216C, 0xDA874609, 0xC832E9E7, 0x708E8E82,
		0x28ED9ED4, 0x9051F9B1, 0x82E4565F, 0x3A58313A,
		0xA78F0983, 0x1F336EE6, 0x0D86C108, 0xB53AA66D,
		0xBD40E1A4, 0x05FC86C1, 0x1749292F, 0xAFF54E4A,
		0x322276F3, 0x8A9E1196, 0x982BBE78, 0x2097D91D,
		0x78F4C94B, 0xC048AE2E, 0xD2FD01C0, 0x6A4166A5,
		0xF7965E1C, 0x4F2A3979, 0x5D9F9697, 0xE523F1F2,
		0x4D6B1905, 0xF5D77E60, 0xE762D18E, 0x5FDEB6EB,
		0xC2098E52, 0x7AB5E937, 0x680046D9, 0xD0BC21BC,
		0x88DF31EA, 0x3063568F, 0x22D6F961, 0x9A6A9E04,
		0x07BDA6BD, 0xBF01C1D8, 0xADB46E36, 0x15080953,
		0x1D724E9A, 0xA5CE29FF, 0xB77B8611, 0x0FC7E174,
		0x9210D9CD, 0x2AACBEA8, 0x38191146, 0x80A57623,
		0xD8C66675, 0x607A0110, 0x72CFAEFE, 0xCA73C99B,
		0x57A4F122, 0xEF189647, 0xFDAD39A9, 0x45115ECC,
		0x764DEE06, 0xCEF18963, 0xDC44268D, 0x64F841E8,
		0xF92F7951, 0x41931E34, 0x5326B1DA, 0xEB9AD6BF,
		0xB3F9C6E9, 0x0B45A18C, 0x19F00E62, 0xA14C6907,
		0x3C9B51BE, 0x842736DB, 0x96929935, 0x2E2EFE50,
		0x2654B999, 0x9EE8DEFC, 0x8C5D7112, 0x34E11677,
		0xA9362ECE, 0x118A49AB, 0x033FE645, 0xBB838120,
		0xE3E09176, 0x5B5CF613, 0x49E959FD, 0xF1553E98,
		0x6C820621, 0xD43E6144, 0xC68BCEAA, 0x7E37A9CF,
		0xD67F4138, 0x6EC3265D, 0x7C7689B3, 0xC4CAEED6,
		0x591DD66F, 0xE1A1B10A, 0xF3141EE4, 0x4BA87981,
		0x13CB69D7, 0xAB770EB2, 0xB9C2A15C, 0x017EC639,
		0x9CA9FE80, 0x241599E5, 0x36A0360B, 0x8E1C516E,
		0x866616A7, 0x3EDA71C2, 0x2C6FDE2C, 0x94D3B949,
		0x090481F0, 0xB1B8E695, 0xA30D497B, 0x1BB12E1E,
		0x43D23E48, 0xFB6E592D, 0xE9DBF6C3, 0x516791A6,
		0xCCB0A91F, 0x740CCE7A, 0x66B96194, 0xDE0506F1
	}, {
		0x00000000, 0x3D6029B0, 0x7AC05360, 0x47A07AD0,
		0xF580A6C0, 0xC8E08F70, 0x8F40F5A0, 0xB220DC10,
		0x30704BC1, 0x0D106271, 0x4AB018A1, 0x77D03111,
		0xC5F0ED01, 0xF890C4B1, 0xBF30BE61, 0x825097D1,
		0x60E09782, 0x5D80BE32, 0x1A20C4E2, 0x2740ED52,
		0x95603142, 0xA80018F2, 0xEFA06222, 0xD2C04B92,
		0x5090DC43, 0x6DF0F5F3, 0x2A508F23, 0x1730A693,
		0xA5107A83, 0x98705333, 0xDFD029E3, 0xE2B00053,
		0xC1C12F04, 0xFCA106B4, 0xBB017C64, 0x866155D4,
		0x344189C4, 0x0921A074, 0x4E81DAA4, 0x73E1F314,
		0xF1B164C5, 0xCCD14D75, 0x8B7137A5, 0xB6111E15,
		0x0431C205, 0x3951EBB5, 0x7EF19165, 0x4391B8D5,
		0xA121B886, 0x9C419136, 0xDBE1EBE6, 0xE681C256,
		0x54A11E46, 0x69C137F6, 0x2E614D26, 0x13016496,
		0x9151F347, 0xAC31DAF7, 0xEB91A027, 0xD6F18997,
		0x64D15587, 0x59B17C37, 0x1E1106E7, 0x23712F57,
		0x58F35849, 0x659371F9, 0x22330B29, 0x1F532299,
		0xAD73FE89, 0x9013D739, 0xD7B3ADE9, 0xEAD38459,
		0x68831388, 0x55E33A38, 0x124340E8, 0x2F236958,
		0x9D03B548, 0xA0639CF8, 0xE7C3E628, 0xDAA3CF98,
		0x3813CFCB, 0x0573E67B, 0x42D39CAB, 0x7FB3B51B,
		0xCD93690B, 0xF0F340BB, 0xB7533A6B, 0x8A3313DB,
		0x0863840A, 0x3503ADBA, 0x72A3D76A, 0x4FC3FEDA,
		0xFDE322CA, 0xC0830B7A, 0x872371AA, 0xBA43581A,
		0x9932774D, 0xA4525EFD, 0xE3F2242D, 0xDE920D9D,
		0x6CB2D18D, 0x51D2F83D, 0x167282ED, 0x2B12AB5D,
		0xA9423C8C, 0x9422153C, 0xD3826FEC, 0xEEE2465C,
		0x5CC29A4C, 0x61A2B3FC, 0x2602C92C, 0x1B62E09C,
		0xF9D2E0CF, 0xC4B2C97F, 0x8312B3AF, 0xBE729A1F,
		0x0C52460F, 0x31326FBF, 0x7692156F, 0x4BF23CDF,
		0xC9A2AB0E, 0xF4C282BE, 0xB362F86E, 0x8E02D1DE,
		0x3C220DCE, 0x0142247E, 0x46E25EAE, 0x7B82771E,
		0xB1E6B092, 0x8C869922, 0xCB26E3F2, 0xF646CA42,
		0x44661652, 0x79063FE2, 0x3EA64532, 0x03C66C82,
		0x8196FB53, 0xBCF6D2E3, 0xFB56A833, 0xC6368183,
		0x74165D93, 0x49767423, 0x0ED60EF3, 0x33B62743,
		0xD1062710, 0xEC660EA0, 0xABC67470, 0x96A65DC0,
		0x248681D0, 0x19E6A860, 0x5E46D2B0, 0x6326FB00,
		0xE1766CD1, 0xDC164561, 0x9BB63FB1, 0xA6D61601,
		0x14F6CA11, 0x2996E3A1, 0x6E369971, 0x5356B0C1,
		0x70279F96, 0x4D47B626, 0x0AE7CCF6, 0x3787E546,
		0x85A73956, 0xB8C710E6, 0xFF676A36, 0xC2074386,
		0x4057D457, 0x7D37FDE7, 0x3A978737, 0x07F7AE87,
		0xB5D77297, 0x88B75B27, 0xCF1721F7, 0xF2770847,
		0x10C70814, 0x2DA721A4, 0x6A075B74, 0x576772C4,
		0xE547AED4, 0xD8278764, 0x9F87FDB4, 0xA2E7D404,
		0x20B743D5, 0x1DD76A65, 0x5A7710B5, 0x67173905,
		0xD537E515, 0xE857CCA5, 0xAFF7B675, 0x92979FC5,
		0xE915E8DB, 0xD475C16B, 0x93D5BBBB, 0xAEB5920B,
		0x1C954E1B, 0x21F567AB, 0x66551D7B, 0x5B3534CB,
		0xD965A31A, 0xE4058AAA, 0xA3A5F07A, 0x9EC5D9CA,
		0x2CE505DA, 0x11852C6A, 0x562556BA, 0x6B457F0A,
		0x89F57F59, 0xB49556E9, 0xF3352C39, 0xCE550589,
		0x7C75D999, 0x4115F029, 0x06B58AF9, 0x3BD5A349,
		0xB9853498, 0x84E51D28, 0xC34567F8, 0xFE254E48,
		0x4C059258, 0x7165BBE8, 0x36C5C138, 0x0BA5E888,
		0x28D4C7DF, 0x15B4EE6F, 0x521494BF, 0x6F74BD0F,
		0xDD54611F, 0xE03448AF, 0xA794327F, 0x9AF41BCF,
		0x18A48C1E, 0x25C4A5AE, 0x6264DF7E, 0x5F04F6CE,
		0xED242ADE, 0xD044036E, 0x97E479BE, 0xAA84500E,
		0x4834505D, 0x755479ED, 0x32F4033D, 0x0F942A8D,
		0xBDB4F69D, 0x80D4DF2D, 0xC774A5FD, 0xFA148C4D,
		0x78441B9C, 0x4524322C, 0x028448FC, 0x3FE4614C,
		0x8DC4BD5C, 0xB0A494EC, 0xF704EE3C, 0xCA64C78C
	}, {
		0x00000000, 0xCB5CD3A5, 0x4DC8A10B, 0x869472AE,
		0x9B914216, 0x50CD91B3, 0xD659E31D, 0x1D0530B8,
		0xEC53826D, 0x270F51C8, 0xA19B2366, 0x6AC7F0C3,
		0x77C2C07B, 0xBC9E13DE, 0x3A0A6170, 0xF156B2D5,
		0x03D6029B, 0xC88AD13E, 0x4E1EA390, 0x85427035,
		0x9847408D, 0x531B9328, 0xD58FE186, 0x1ED33223,
		0xEF8580F6, 0x24D95353, 0xA24D21FD, 0x6911F258,
		0x7414C2E0, 0xBF481145, 0x39DC63EB, 0xF280B04E,
		0x07AC0536, 0xCCF0D693, 0x4A64A43D, 0x81387798,
		0x9C3D4720, 0x57619485, 0xD1F5E62B, 0x1AA9358E,
		0xEBFF875B, 0x20A354FE, 0xA6372650, 0x6D6BF5F5,
		0x706EC54D, 0xBB3216E8, 0x3DA66446, 0xF6FAB7E3,
		0x047A07AD, 0xCF26D408, 0x49B2A6A6, 0x82EE7503,
		0x9FEB45BB, 0x54B7961E, 0xD223E4B0, 0x197F3715,
		0xE82985C0, 0x23755665, 0xA5E124CB, 0x6EBDF76E,
		0x73B8C7D6, 0xB8E41473, 0x3E7066DD, 0xF52CB578,
		0x0F580A6C, 0xC404D9C9, 0x4290AB67, 0x89CC78C2,
		0x94C9487A, 0x5F959BDF, 0xD901E971, 0x125D3AD4,
		0xE30B8801, 0x28575BA4, 0xAEC3290A, 0x659FFAAF,
		0x789ACA17, 0xB3C619B2, 0x35526B1C, 0xFE0EB8B9,
		0x0C8E08F7, 0xC7D2DB52, 0x4146A9FC, 0x8A1A7A59,
		0x971F4AE1, 0x5C439944, 0xDAD7EBEA, 0x118B384F,
		0xE0DD8A9A, 0x2B81593F, 0xAD152B91, 0x6649F834,
		0x7B4CC88C, 0xB0101B29, 0x36846987, 0xFDD8BA22,
		0x08F40F5A, 0xC3A8DCFF, 0x453CAE51, 0x8E607DF4,
		0x93654D4C, 0x58399EE9, 0xDEADEC47, 0x15F13FE2,
		0xE4A78D37, 0x2FFB5E92, 0xA96F2C3C, 0x6233FF99,
		0x7F36CF21, 0xB46A1C84, 0x32FE6E2A, 0xF9A2BD8F,
		0x0B220DC1, 0xC07EDE64, 0x46EAACCA, 0x8DB67F6F,
		0x90B34FD7, 0x5BEF9C72, 0xDD7BEEDC, 0x16273D79,
		0xE7718FAC, 0x2C2D5C09, 0xAAB92EA7, 0x61E5FD02,
		0x7CE0CDBA, 0xB7BC1E1F, 0x31286CB1, 0xFA74BF14,
		0x1EB014D8, 0xD5ECC77D, 0x5378B5D3, 0x98246676,
		0x852156CE, 0x4E7D856B, 0xC8E9F7C5, 0x03B52460,
		0xF2E396B5, 0x39BF4510, 0xBF2B37BE, 0x7477E41B,
		0x6972D4A3, 0xA22E0706, 0x24BA75A8, 0xEFE6A60D,
		0x1D661643, 0xD63AC5E6, 0x50AEB748, 0x9BF264ED,
		0x86F75455, 0x4DAB87F0, 0xCB3FF55E, 0x006326FB,
		0xF135942E, 0x3A69478B, 0xBCFD3525, 0x77A1E680,
		0x6AA4D638, 0xA1F8059D, 0x276C7733, 0xEC30A496,
		0x191C11EE, 0xD240C24B, 0x54D4B0E5, 0x9F886340,
		0x828D53F8, 0x49D1805D, 0xCF45F2F3, 0x04192156,
		0xF54F9383, 0x3E134026, 0xB8873288, 0x73DBE12D,
		0x6EDED195, 0xA5820230, 0x2316709E, 0xE84AA33B,
		0x1ACA1375, 0xD196C0D0, 0x5702B27E, 0x9C5E61DB,
		0x815B5163, 0x4A0782C6, 0xCC93F068, 0x07CF23CD,
		0xF6999118, 0x3DC542BD, 0xBB513013, 0x700DE3B6,
		0x6D08D30E, 0xA65400AB, 0x20C07205, 0xEB9CA1A0,
		0x11E81EB4, 0xDAB4CD11, 0x5C20BFBF, 0x977C6C1A,
		0x8A795CA2, 0x41258F07, 0xC7B1FDA9, 0x0CED2E0C,
		0xFDBB9CD9, 0x36E74F7C, 0xB0733DD2, 0x7B2FEE77,
		0x662ADECF, 0xAD760D6A, 0x2BE27FC4, 0xE0BEAC61,
		0x123E1C2F, 0xD962CF8A, 0x5FF6BD24, 0x94AA6E81,
		0x89AF5E39, 0x42F38D9C, 0xC467FF32, 0x0F3B2C97,
		0xFE6D9E42, 0x35314DE7, 0xB3A53F49, 0x78F9ECEC,
		0x65FCDC54, 0xAEA00FF1, 0x28347D5F, 0xE368AEFA,
		0x16441B82, 0xDD18C827, 0x5B8CBA89, 0x90D0692C,
		0x8DD55994, 0x46898A31, 0xC01DF89F, 0x0B412B3A,
		0xFA1799EF, 0x314B4A4A, 0xB7DF38E4, 0x7C83EB41,
		0x6186DBF9, 0xAADA085C, 0x2C4E7AF2, 0xE712A957,
		0x15921919, 0xDECECABC, 0x585AB812, 0x93066BB7,
		0x8E035B0F, 0x455F88AA, 0xC3CBFA04, 0x089729A1,
		0xF9C19B74, 0x329D48D1, 0xB4093A7F, 0x7F55E9DA,
		0x6250D962, 0xA90C0AC7, 0x2F987869, 0xE4C4ABCC
	}, {
		0x00000000, 0xA6770BB4, 0x979F1129, 0x31E81A9D,
		0xF44F2413, 0x52382FA7, 0x63D0353A, 0xC5A73E8E,
		0x33EF4E67, 0x959845D3, 0xA4705F4E, 0x020754FA,
		0xC7A06A74, 0x61D761C0, 0x503F7B5D, 0xF64870E9,
		0x67DE9CCE, 0xC1A9977A, 0xF0418DE7, 0x56368653,
		0x9391B8DD, 0x35E6B369, 0x040EA9F4, 0xA279A240,
		0x5431D2A9, 0xF246D91D, 0xC3AEC380, 0x65D9C834,
		0xA07EF6BA, 0x0609FD0E, 0x37E1E793, 0x9196EC27,
		0xCFBD399C, 0x69CA3228, 0x582228B5, 0xFE552301,
		0x3BF21D8F, 0x9D85163B, 0xAC6D0CA6, 0x0A1A0712,
		0xFC5277FB, 0x5A257C4F, 0x6BCD66D2, 0xCDBA6D66,
		0x081D53E8, 0xAE6A585C, 0x9F8242C1, 0x39F54975,
		0xA863A552, 0x0E14AEE6, 0x3FFCB47B, 0x998BBFCF,
		0x5C2C8141, 0xFA5B8AF5, 0xCBB39068, 0x6DC49BDC,
		0x9B8CEB35, 0x3DFBE081, 0x0C13FA1C, 0xAA64F1A8,
		0x6FC3CF26, 0xC9B4C492, 0xF85CDE0F, 0x5E2BD5BB,
		0x440B7579, 0xE27C7ECD, 0xD3946450, 0x75E36FE4,
		0xB044516A, 0x16335ADE, 0x27DB4043, 0x81AC4BF7,
		0x77E43B1E, 0xD19330AA, 0xE07B2A37, 0x460C2183,
		0x83AB1F0D, 0x25DC14B9, 0x14340E24, 0xB2430590,
		0x23D5E9B7, 0x85A2E203, 0xB44AF89E, 0x123DF32A,
		0xD79ACDA4, 0x71EDC610, 0x4005DC8D, 0xE672D739,
		0x103AA7D0, 0xB64DAC64, 0x87A5B6F9, 0x21D2BD4D,
		0xE47583C3, 0x42028877, 0x73EA92EA, 0xD59D995E,
		0x8BB64CE5, 0x2DC14751, 0x1C295DCC, 0xBA5E5678,
		0x7FF968F6, 0xD98E6342, 0xE86679DF, 0x4E11726B,
		0xB8590282, 0x1E2E0936, 0x2FC613AB, 0x89B1181F,
		0x4C162691, 0xEA612D25, 0xDB8937B8, 0x7DFE3C0C,
		0xEC68D02B, 0x4A1FDB9F, 0x7BF7C102, 0xDD80CAB6,
		0x1827F438, 0xBE50FF8C, 0x8FB8E511, 0x29CFEEA5,
		0xDF879E4C, 0x79F095F8, 0x48188F65, 0xEE6F84D1,
		0x2BC8BA5F, 0x8DBFB1EB, 0xBC57AB76, 0x1A20A0C2,
		0x8816EAF2, 0x2E61E146, 0x1F89FBDB, 0xB9FEF06F,
		0x7C59CEE1, 0xDA2EC555, 0xEBC6DFC8, 0x4DB1D47C,
		0xBBF9A495, 0x1D8EAF21, 0x2C66B5BC, 0x8A11BE08,
		0x4FB68086, 0xE9C18B32, 0xD82991AF, 0x7E5E9A1B,
		0xEFC8763C, 0x49BF7D88, 0x78576715, 0xDE206CA1,
		0x1B87522F, 0xBDF0599B, 0x8C184306, 0x2A6F48B2,
		0xDC27385B, 0x7A5033EF, 0x4BB82972, 0xEDCF22C6,
		0x28681C48, 0x8E1F17FC, 0xBFF70D61, 0x198006D5,
		0x47ABD36E, 0xE1DCD8DA, 0xD034C247, 0x7643C9F3,
		0xB3E4F77D, 0x1593FCC9, 0x247BE654, 0x820CEDE0,
		0x74449D09, 0xD23396BD, 0xE3DB8C20, 0x45AC8794,
		0x800BB91A, 0x267CB2AE, 0x1794A833, 0xB1E3A387,
		0x20754FA0, 0x86024414, 0xB7EA5E89, 0x119D553D,
		0xD43A6BB3, 0x724D6007, 0x43A57A9A, 0xE5D2712E,
		0x139A01C7, 0xB5ED0A73, 0x840510EE, 0x22721B5A,
		0xE7D525D4, 0x41A22E60, 0x704A34FD, 0xD63D3F49,
		0xCC1D9F8B, 0x6A6A943F, 0x5B828EA2, 0xFDF58516,
		0x3852BB98, 0x9E25B02C, 0xAFCDAAB1, 0x09BAA105,
		0xFFF2D1EC, 0x5985DA58, 0x686DC0C5, 0xCE1ACB71,
		0x0BBDF5FF, 0xADCAFE4B, 0x9C22E4D6, 0x3A55EF62,
		0xABC30345, 0x0DB408F1, 0x3C5C126C, 0x9A2B19D8,
		0x5F8C2756, 0xF9FB2CE2, 0xC813367F, 0x6E643DCB,
		0x982C4D22, 0x3E5B4696, 0x0FB35C0B, 0xA9C457BF,
		0x6C636931, 0xCA146285, 0xFBFC7818, 0x5D8B73AC,
		0x03A0A617, 0xA5D7ADA3, 0x943FB73E, 0x3248BC8A,
		0xF7EF8204, 0x519889B0, 0x6070932D, 0xC6079899,
		0x304FE870, 0x9638E3C4, 0xA7D0F959, 0x01A7F2ED,
		0xC400CC63, 0x6277C7D7, 0x539FDD4A, 0xF5E8D6FE,
		0x647E3AD9, 0xC209316D, 0xF3E12BF0, 0x55962044,
		0x90311ECA, 0x3646157E, 0x07AE0FE3, 0xA1D90457,
		0x579174BE, 0xF1E67F0A, 0xC00E6597, 0x66796E23,
		0xA3DE50AD, 0x05A95B19, 0x34414184, 0x92364A30
	}, {
		0x00000000, 0xCCAA009E, 0x4225077D, 0x8E8F07E3,
		0x844A0EFA, 0x48E00E64, 0xC66F0987, 0x0AC50919,
		0xD3E51BB5, 0x1F4F1B2B, 0x91C01CC8, 0x5D6A1C56,
		0x57AF154F, 0x9B0515D1, 0x158A1232, 0xD92012AC,
		0x7CBB312B, 0xB01131B5, 0x3E9E3656, 0xF23436C8,
		0xF8F13FD1, 0x345B3F4F, 0xBAD438AC, 0x767E3832,
		0xAF5E2A9E, 0x63F42A00, 0xED7B2DE3, 0x21D12D7D,
		0x2B142464, 0xE7BE24FA, 0x69312319, 0xA59B2387,
		0xF9766256, 0x35DC62C8, 0xBB53652B, 0x77F965B5,
		0x7D3C6CAC, 0xB1966C32, 0x3F196BD1, 0xF3B36B4F,
		0x2A9379E3, 0xE639797D, 0x68B67E9E, 0xA41C7E00,
		0xAED97719, 0x62737787, 0xECFC7064, 0x205670FA,
		0x85CD537D, 0x496753E3, 0xC7E85400, 0x0B42549E,
		0x01875D87, 0xCD2D5D19, 0x43A25AFA, 0x8F085A64,
		0x562848C8, 0x9A824856, 0x140D4FB5, 0xD8A74F2B,
		0xD2624632, 0x1EC846AC, 0x9047414F, 0x5CED41D1,
		0x299DC2ED, 0xE537C273, 0x6BB8C590, 0xA712C50E,
		0xADD7CC17, 0x617DCC89, 0xEFF2CB6A, 0x2358CBF4,
		0xFA78D958, 0x36D2D9C6, 0xB85DDE25, 0x74F7DEBB,
		0x7E32D7A2, 0xB298D73C, 0x3C17D0DF, 0xF0BDD041,
		0x5526F3C6, 0x998CF358, 0x1703F4BB, 0xDBA9F425,
		0xD16CFD3C, 0x1DC6FDA2, 0x9349FA41, 0x5FE3FADF,
		0x86C3E873, 0x4A69E8ED, 0xC4E6EF0E, 0x084CEF90,
		0x0289E689, 0xCE23E617, 0x40ACE1F4, 0x8C06E16A,
		0xD0EBA0BB, 0x1C41A025, 0x92CEA7C6, 0x5E64A758,
		0x54A1AE41, 0x980BAEDF, 0x1684A93C, 0xDA2EA9A2,
		0x030EBB0E, 0xCFA4BB90, 0x412BBC73, 0x8D81BCED,
		0x8744B5F4, 0x4BEEB56A, 0xC561B289, 0x09CBB217,
		0xAC509190, 0x60FA910E, 0xEE7596ED, 0x22DF9673,
		0x281A9F6A, 0xE4B09FF4, 0x6A3F9817, 0xA6959889,
		0x7FB58A25, 0xB31F8ABB, 0x3D908D58, 0xF13A8DC6,
		0xFBFF84DF, 0x37558441, 0xB9DA83A2, 0x7570833C,
		0x533B85DA, 0x9F918544, 0x111E82A7, 0xDDB48239,
		0xD7718B20, 0x1BDB8BBE, 0x95548C5D, 0x59FE8CC3,
		0x80DE9E6F, 0x4C749EF1, 0xC2FB9912, 0x0E51998C,
		0x04949095, 0xC83E900B, 0x46B197E8, 0x8A1B9776,
		0x2F80B4F1, 0xE32AB46F, 0x6DA5B38C, 0xA10FB312,
		0xABCABA0B, 0x6760BA95, 0xE9EFBD76, 0x2545BDE8,
		0xFC65AF44, 0x30CFAFDA, 0xBE40A839, 0x72EAA8A7,
		0x782FA1BE, 0xB485A120, 0x3A0AA6C3, 0xF6A0A65D,
		0xAA4DE78C, 0x66E7E712, 0xE868E0F1, 0x24C2E06F,
		0x2E07E976, 0xE2ADE9E8, 0x6C22EE0B, 0xA088EE95,
		0x79A8FC39, 0xB502FCA7, 0x3B8DFB44, 0xF727FBDA,
		0xFDE2F2C3, 0x3148F25D, 0xBFC7F5BE, 0x736DF520,
		0xD6F6D6A7, 0x1A5CD639, 0x94D3D1DA, 0x5879D144,
		0x52BCD85D, 0x9E16D8C3, 0x1099DF20, 0xDC33DFBE,
		0x0513CD12, 0xC9B9CD8C, 0x4736CA6F, 0x8B9CCAF1,
		0x8159C3E8, 0x4DF3C376, 0xC37CC495, 0x0FD6C40B,
		0x7AA64737, 0xB60C47A9, 0x3883404A, 0xF42940D4,
		0xFEEC49CD, 0x32464953, 0xBCC94EB0, 0x70634E2E,
		0xA9435C82, 0x65E95C1C, 0xEB665BFF, 0x27CC5B61,
		0x2D095278, 0xE1A352E6, 0x6F2C5505, 0xA386559B,
		0x061D761C, 0xCAB77682, 0x44387161, 0x889271FF,
		0x825778E6, 0x4EFD7878, 0xC0727F9B, 0x0CD87F05,
		0xD5F86DA9, 0x19526D37, 0x97DD6AD4, 0x5B776A4A,
		0x51B26353, 0x9D1863CD, 0x1397642E, 0xDF3D64B0,
		0x83D02561, 0x4F7A25FF, 0xC1F5221C, 0x0D5F2282,
		0x079A2B9B, 0xCB302B05, 0x45BF2CE6, 0x89152C78,
		0x50353ED4, 0x9C9F3E4A, 0x121039A9, 0xDEBA3937,
		0xD47F302E, 0x18D530B0, 0x965A3753, 0x5AF037CD,
		0xFF6B144A, 0x33C114D4, 0xBD4E1337, 0x71E413A9,
		0x7B211AB0, 0xB78B1A2E, 0x39041DCD, 0xF5AE1D53,
		0x2C8E0FFF, 0xE0240F61, 0x6EAB0882, 0xA201081C,
		0xA8C40105, 0x646E019B, 0xEAE10678, 0x264B06E6
	}
};

#endif

typedef struct {

	lzma_dict dict;

	lzma_lz_decoder lz;

	lzma_next_coder next;

	bool next_finished;

	bool this_finished;

	struct {
		size_t pos;
		size_t size;
		uint8_t buffer[LZMA_BUFFER_SIZE];
	} temp;
} lzma_coder;

static void
lz_decoder_reset(lzma_coder *coder)
{
	coder->dict.pos = 0;
	coder->dict.full = 0;
	coder->dict.buf[coder->dict.size - 1] = '\0';
	coder->dict.need_reset = false;
	return;
}

static lzma_ret
decode_buffer(lzma_coder *coder,
		const uint8_t *restrict in, size_t *restrict in_pos,
		size_t in_size, uint8_t *restrict out,
		size_t *restrict out_pos, size_t out_size)
{
	while (true) {

		if (coder->dict.pos == coder->dict.size)
			coder->dict.pos = 0;

		const size_t dict_start = coder->dict.pos;

		coder->dict.limit = coder->dict.pos
				+ my_min(out_size - *out_pos,
					coder->dict.size - coder->dict.pos);

		const lzma_ret ret = coder->lz.code(
				coder->lz.coder, &coder->dict,
				in, in_pos, in_size);

		const size_t copy_size = coder->dict.pos - dict_start;
		assert(copy_size <= out_size - *out_pos);

		if (copy_size > 0)
			memcpy(out + *out_pos, coder->dict.buf + dict_start,
					copy_size);

		*out_pos += copy_size;

		if (coder->dict.need_reset) {
			lz_decoder_reset(coder);

			if (ret != LZMA_OK || *out_pos == out_size)
				return ret;
		} else {

			if (ret != LZMA_OK || *out_pos == out_size
					|| coder->dict.pos < coder->dict.size)
				return ret;
		}
	}
}

static lzma_ret
lz_decode(void *coder_ptr, const lzma_allocator *allocator,
		const uint8_t *restrict in, size_t *restrict in_pos,
		size_t in_size, uint8_t *restrict out,
		size_t *restrict out_pos, size_t out_size,
		lzma_action action)
{
	lzma_coder *coder = coder_ptr;

	if (coder->next.code == NULL)
		return decode_buffer(coder, in, in_pos, in_size,
				out, out_pos, out_size);

	while (*out_pos < out_size) {

		if (!coder->next_finished
				&& coder->temp.pos == coder->temp.size) {
			coder->temp.pos = 0;
			coder->temp.size = 0;

			const lzma_ret ret = coder->next.code(
					coder->next.coder,
					allocator, in, in_pos, in_size,
					coder->temp.buffer, &coder->temp.size,
					LZMA_BUFFER_SIZE, action);

			if (ret == LZMA_STREAM_END)
				coder->next_finished = true;
			else if (ret != LZMA_OK || coder->temp.size == 0)
				return ret;
		}

		if (coder->this_finished) {
			if (coder->temp.size != 0)
				return LZMA_DATA_ERROR;

			if (coder->next_finished)
				return LZMA_STREAM_END;

			return LZMA_OK;
		}

		const lzma_ret ret = decode_buffer(coder, coder->temp.buffer,
				&coder->temp.pos, coder->temp.size,
				out, out_pos, out_size);

		if (ret == LZMA_STREAM_END)
			coder->this_finished = true;
		else if (ret != LZMA_OK)
			return ret;
		else if (coder->next_finished && *out_pos < out_size)
			return LZMA_DATA_ERROR;
	}

	return LZMA_OK;
}

static void
lz_decoder_end(void *coder_ptr, const lzma_allocator *allocator)
{
	lzma_coder *coder = coder_ptr;

	lzma_next_end(&coder->next, allocator);
	lzma_free(coder->dict.buf, allocator);

	if (coder->lz.end != NULL)
		coder->lz.end(coder->lz.coder, allocator);
	else
		lzma_free(coder->lz.coder, allocator);

	lzma_free(coder, allocator);
	return;
}

extern lzma_ret
lzma_lz_decoder_init(lzma_next_coder *next, const lzma_allocator *allocator,
		const lzma_filter_info *filters,
		lzma_ret (*lz_init)(lzma_lz_decoder *lz,
			const lzma_allocator *allocator,
			lzma_vli id, const void *options,
			lzma_lz_options *lz_options))
{

	lzma_coder *coder = next->coder;
	if (coder == NULL) {
		coder = lzma_alloc(sizeof(lzma_coder), allocator);
		if (coder == NULL)
			return LZMA_MEM_ERROR;

		next->coder = coder;
		next->code = &lz_decode;
		next->end = &lz_decoder_end;

		coder->dict.buf = NULL;
		coder->dict.size = 0;
		coder->lz = LZMA_LZ_DECODER_INIT;
		coder->next = LZMA_NEXT_CODER_INIT;
	}

	lzma_lz_options lz_options;
	return_if_error(lz_init(&coder->lz, allocator,
			filters[0].id, filters[0].options, &lz_options));

	if (lz_options.dict_size < 4096)
		lz_options.dict_size = 4096;

	if (lz_options.dict_size > SIZE_MAX - 15)
		return LZMA_MEM_ERROR;

	lz_options.dict_size = (lz_options.dict_size + 15) & ~((size_t)(15));

	if (coder->dict.size != lz_options.dict_size) {
		lzma_free(coder->dict.buf, allocator);
		coder->dict.buf
				= lzma_alloc(lz_options.dict_size, allocator);
		if (coder->dict.buf == NULL)
			return LZMA_MEM_ERROR;

		coder->dict.size = lz_options.dict_size;
	}

	lz_decoder_reset(next->coder);

	if (lz_options.preset_dict != NULL
			&& lz_options.preset_dict_size > 0) {

		const size_t copy_size = my_min(lz_options.preset_dict_size,
				lz_options.dict_size);
		const size_t offset = lz_options.preset_dict_size - copy_size;
		memcpy(coder->dict.buf, lz_options.preset_dict + offset,
				copy_size);
		coder->dict.pos = copy_size;
		coder->dict.full = copy_size;
	}

	coder->next_finished = false;
	coder->this_finished = false;
	coder->temp.pos = 0;
	coder->temp.size = 0;

	return lzma_next_filter_init(&coder->next, allocator, filters + 1);
}

extern uint64_t
lzma_lz_decoder_memusage(size_t dictionary_size)
{
	return sizeof(lzma_coder) + (uint64_t)(dictionary_size);
}

#ifndef LZMA_LZMA_COMMON_H
#define LZMA_LZMA_COMMON_H

#ifndef LZMA_RANGE_COMMON_H
#define LZMA_RANGE_COMMON_H

#define RC_SHIFT_BITS 8
#define RC_TOP_BITS 24
#define RC_TOP_VALUE (UINT32_C(1) << RC_TOP_BITS)
#define RC_BIT_MODEL_TOTAL_BITS 11
#define RC_BIT_MODEL_TOTAL (UINT32_C(1) << RC_BIT_MODEL_TOTAL_BITS)
#define RC_MOVE_BITS 5

#define bit_reset(prob) prob = RC_BIT_MODEL_TOTAL >> 1

#define bittree_reset(probs, bit_levels) for (uint32_t bt_i = 0; bt_i < (1 << (bit_levels)); ++bt_i) bit_reset((probs)[bt_i])

typedef uint16_t probability;

#endif

#define POS_STATES_MAX (1 << LZMA_PB_MAX)

static inline bool
is_lclppb_valid(const lzma_options_lzma *options)
{
	return options->lc <= LZMA_LCLP_MAX && options->lp <= LZMA_LCLP_MAX
			&& options->lc + options->lp <= LZMA_LCLP_MAX
			&& options->pb <= LZMA_PB_MAX;
}

typedef enum {
	STATE_LIT_LIT,
	STATE_MATCH_LIT_LIT,
	STATE_REP_LIT_LIT,
	STATE_SHORTREP_LIT_LIT,
	STATE_MATCH_LIT,
	STATE_REP_LIT,
	STATE_SHORTREP_LIT,
	STATE_LIT_MATCH,
	STATE_LIT_LONGREP,
	STATE_LIT_SHORTREP,
	STATE_NONLIT_MATCH,
	STATE_NONLIT_REP,
} lzma_lzma_state;

#define STATES 12

#define LIT_STATES 7

#define update_literal(state) state = ((state) <= STATE_SHORTREP_LIT_LIT ? STATE_LIT_LIT : ((state) <= STATE_LIT_SHORTREP ? (state) - 3 : (state) - 6))

#define update_match(state) state = ((state) < LIT_STATES ? STATE_LIT_MATCH : STATE_NONLIT_MATCH)

#define update_long_rep(state) state = ((state) < LIT_STATES ? STATE_LIT_LONGREP : STATE_NONLIT_REP)

#define update_short_rep(state) state = ((state) < LIT_STATES ? STATE_LIT_SHORTREP : STATE_NONLIT_REP)

#define is_literal_state(state) ((state) < LIT_STATES)

#define LITERAL_CODER_SIZE 0x300

#define LITERAL_CODERS_MAX (1 << LZMA_LCLP_MAX)

#define literal_subcoder(probs, lc, lp_mask, pos, prev_byte) ((probs)[(((pos) & (lp_mask)) << (lc)) + ((uint32_t)(prev_byte) >> (8U - (lc)))])

static inline void
literal_init(probability (*probs)[LITERAL_CODER_SIZE],
		uint32_t lc, uint32_t lp)
{
	assert(lc + lp <= LZMA_LCLP_MAX);

	const uint32_t coders = 1U << (lc + lp);

	for (uint32_t i = 0; i < coders; ++i)
		for (uint32_t j = 0; j < LITERAL_CODER_SIZE; ++j)
			bit_reset(probs[i][j]);

	return;
}

#define MATCH_LEN_MIN 2

#define LEN_LOW_BITS 3
#define LEN_LOW_SYMBOLS (1 << LEN_LOW_BITS)
#define LEN_MID_BITS 3
#define LEN_MID_SYMBOLS (1 << LEN_MID_BITS)
#define LEN_HIGH_BITS 8
#define LEN_HIGH_SYMBOLS (1 << LEN_HIGH_BITS)
#define LEN_SYMBOLS (LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS + LEN_HIGH_SYMBOLS)

#define MATCH_LEN_MAX (MATCH_LEN_MIN + LEN_SYMBOLS - 1)

#define DIST_STATES 4

#define get_dist_state(len) ((len) < DIST_STATES + MATCH_LEN_MIN ? (len) - MATCH_LEN_MIN : DIST_STATES - 1)

#define DIST_SLOT_BITS 6
#define DIST_SLOTS (1 << DIST_SLOT_BITS)

#define DIST_MODEL_START 4

#define DIST_MODEL_END 14

#define FULL_DISTANCES_BITS (DIST_MODEL_END / 2)
#define FULL_DISTANCES (1 << FULL_DISTANCES_BITS)

#define ALIGN_BITS 4
#define ALIGN_SIZE (1 << ALIGN_BITS)
#define ALIGN_MASK (ALIGN_SIZE - 1)

#define REPS 4

#endif

#ifndef LZMA_RANGE_DECODER_H
#define LZMA_RANGE_DECODER_H

typedef struct {
	uint32_t range;
	uint32_t code;
	uint32_t init_bytes_left;
} lzma_range_decoder;

static inline lzma_ret
rc_read_init(lzma_range_decoder *rc, const uint8_t *restrict in,
		size_t *restrict in_pos, size_t in_size)
{
	while (rc->init_bytes_left > 0) {
		if (*in_pos == in_size)
			return LZMA_OK;

		if (rc->init_bytes_left == 5 && in[*in_pos] != 0x00)
			return LZMA_DATA_ERROR;

		rc->code = (rc->code << 8) | in[*in_pos];
		++*in_pos;
		--rc->init_bytes_left;
	}

	return LZMA_STREAM_END;
}

#define rc_to_local(range_decoder, in_pos) lzma_range_decoder rc = range_decoder; size_t rc_in_pos = (in_pos); uint32_t rc_bound

#define rc_from_local(range_decoder, in_pos) \
do { range_decoder = rc; in_pos = rc_in_pos; \
} while (0)

#define rc_reset(range_decoder) \
do { (range_decoder).range = UINT32_MAX; (range_decoder).code = 0; (range_decoder).init_bytes_left = 5; \
} while (0)

#define rc_is_finished(range_decoder) ((range_decoder).code == 0)

#define rc_normalize(seq) \
do { if (rc.range < RC_TOP_VALUE) { if (unlikely(rc_in_pos == in_size)) { coder->sequence = seq; goto out; } rc.range <<= RC_SHIFT_BITS; rc.code = (rc.code << RC_SHIFT_BITS) | in[rc_in_pos++]; } \
} while (0)

#define rc_if_0(prob, seq) rc_normalize(seq); rc_bound = (rc.range >> RC_BIT_MODEL_TOTAL_BITS) * (prob); if (rc.code < rc_bound)

#define rc_update_0(prob) \
do { rc.range = rc_bound; prob += (RC_BIT_MODEL_TOTAL - (prob)) >> RC_MOVE_BITS; \
} while (0)

#define rc_update_1(prob) \
do { rc.range -= rc_bound; rc.code -= rc_bound; prob -= (prob) >> RC_MOVE_BITS; \
} while (0)

#define rc_bit_last(prob, action0, action1, seq) \
do { rc_if_0(prob, seq) { rc_update_0(prob); action0; } else { rc_update_1(prob); action1; } \
} while (0)

#define rc_bit(prob, action0, action1, seq) rc_bit_last(prob, symbol <<= 1; action0, symbol = (symbol << 1) + 1; action1, seq);

#define rc_bit_case(prob, action0, action1, seq) case seq: rc_bit(prob, action0, action1, seq)

#define rc_direct(dest, seq) \
do { rc_normalize(seq); rc.range >>= 1; rc.code -= rc.range; rc_bound = UINT32_C(0) - (rc.code >> 31); rc.code += rc.range & rc_bound; dest = (dest << 1) + (rc_bound + 1); \
} while (0)

#endif

#if TUKLIB_GNUC_REQ(7, 0)
#pragma GCC diagnostic ignored "-Wimplicit-fallthrough"
#endif

#ifdef HAVE_SMALL

#define seq_4(seq) seq

#define seq_6(seq) seq

#define seq_8(seq) seq

#define seq_len(seq) seq ## _CHOICE, seq ## _CHOICE2, seq ## _BITTREE

#define len_decode(target, ld, pos_state, seq) \
do { \
case seq ## _CHOICE: rc_if_0(ld.choice, seq ## _CHOICE) { rc_update_0(ld.choice); probs = ld.low[pos_state];limit = LEN_LOW_SYMBOLS; target = MATCH_LEN_MIN; } else { rc_update_1(ld.choice); \
case seq ## _CHOICE2: rc_if_0(ld.choice2, seq ## _CHOICE2) { rc_update_0(ld.choice2); probs = ld.mid[pos_state]; limit = LEN_MID_SYMBOLS; target = MATCH_LEN_MIN + LEN_LOW_SYMBOLS; } else { rc_update_1(ld.choice2); probs = ld.high; limit = LEN_HIGH_SYMBOLS; target = MATCH_LEN_MIN + LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS; } } symbol = 1; \
case seq ## _BITTREE: do { rc_bit(probs[symbol], , , seq ## _BITTREE); } while (symbol < limit); target += symbol - limit; \
} while (0)

#else

#define seq_4(seq) seq ## 0, seq ## 1, seq ## 2, seq ## 3

#define seq_6(seq) seq ## 0, seq ## 1, seq ## 2, seq ## 3, seq ## 4, seq ## 5

#define seq_8(seq) seq ## 0, seq ## 1, seq ## 2, seq ## 3, seq ## 4, seq ## 5, seq ## 6, seq ## 7

#define seq_len(seq) seq ## _CHOICE, seq ## _LOW0, seq ## _LOW1, seq ## _LOW2, seq ## _CHOICE2, seq ## _MID0, seq ## _MID1, seq ## _MID2, seq ## _HIGH0, seq ## _HIGH1, seq ## _HIGH2, seq ## _HIGH3, seq ## _HIGH4, seq ## _HIGH5, seq ## _HIGH6, seq ## _HIGH7

#define len_decode(target, ld, pos_state, seq) \
do { symbol = 1; \
case seq ## _CHOICE: rc_if_0(ld.choice, seq ## _CHOICE) { rc_update_0(ld.choice); rc_bit_case(ld.low[pos_state][symbol], , , seq ## _LOW0); rc_bit_case(ld.low[pos_state][symbol], , , seq ## _LOW1); rc_bit_case(ld.low[pos_state][symbol], , , seq ## _LOW2); target = symbol - LEN_LOW_SYMBOLS + MATCH_LEN_MIN; } else { rc_update_1(ld.choice); \
case seq ## _CHOICE2: rc_if_0(ld.choice2, seq ## _CHOICE2) { rc_update_0(ld.choice2); rc_bit_case(ld.mid[pos_state][symbol], , , seq ## _MID0); rc_bit_case(ld.mid[pos_state][symbol], , , seq ## _MID1); rc_bit_case(ld.mid[pos_state][symbol], , , seq ## _MID2); target = symbol - LEN_MID_SYMBOLS + MATCH_LEN_MIN + LEN_LOW_SYMBOLS; } else { rc_update_1(ld.choice2); rc_bit_case(ld.high[symbol], , , seq ## _HIGH0); rc_bit_case(ld.high[symbol], , , seq ## _HIGH1); rc_bit_case(ld.high[symbol], , , seq ## _HIGH2); rc_bit_case(ld.high[symbol], , , seq ## _HIGH3); rc_bit_case(ld.high[symbol], , , seq ## _HIGH4); rc_bit_case(ld.high[symbol], , , seq ## _HIGH5); rc_bit_case(ld.high[symbol], , , seq ## _HIGH6); rc_bit_case(ld.high[symbol], , , seq ## _HIGH7); target = symbol - LEN_HIGH_SYMBOLS + MATCH_LEN_MIN + LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS; } } \
} while (0)

#endif

typedef struct {
	probability choice;
	probability choice2;
	probability low[POS_STATES_MAX][LEN_LOW_SYMBOLS];
	probability mid[POS_STATES_MAX][LEN_MID_SYMBOLS];
	probability high[LEN_HIGH_SYMBOLS];
} lzma_length_decoder;

typedef struct {

	probability literal[LITERAL_CODERS_MAX][LITERAL_CODER_SIZE];

	probability is_match[STATES][POS_STATES_MAX];

	probability is_rep[STATES];

	probability is_rep0[STATES];

	probability is_rep1[STATES];

	probability is_rep2[STATES];

	probability is_rep0_long[STATES][POS_STATES_MAX];

	probability dist_slot[DIST_STATES][DIST_SLOTS];

	probability pos_special[FULL_DISTANCES - DIST_MODEL_END];

	probability pos_align[ALIGN_SIZE];

	lzma_length_decoder match_len_decoder;

	lzma_length_decoder rep_len_decoder;

	lzma_range_decoder rc;

	lzma_lzma_state state;

	uint32_t rep0;
	uint32_t rep1;
	uint32_t rep2;
	uint32_t rep3;

	uint32_t pos_mask;
	uint32_t literal_context_bits;
	uint32_t literal_pos_mask;

	lzma_vli uncompressed_size;

	bool allow_eopm;

	enum {
		LZMA_SEQ_NORMALIZE,
		LZMA_SEQ_IS_MATCH,
		seq_8(LZMA_SEQ_LITERAL),
		seq_8(LZMA_SEQ_LITERAL_MATCHED),
		LZMA_SEQ_LITERAL_WRITE,
		LZMA_SEQ_IS_REP,
		seq_len(LZMA_SEQ_MATCH_LEN),
		seq_6(LZMA_SEQ_DIST_SLOT),
		LZMA_SEQ_DIST_MODEL,
		LZMA_SEQ_DIRECT,
		seq_4(LZMA_SEQ_ALIGN),
		LZMA_SEQ_EOPM,
		LZMA_SEQ_IS_REP0,
		LZMA_SEQ_SHORTREP,
		LZMA_SEQ_IS_REP0_LONG,
		LZMA_SEQ_IS_REP1,
		LZMA_SEQ_IS_REP2,
		seq_len(LZMA_SEQ_REP_LEN),
		LZMA_SEQ_COPY,
	} sequence;

	probability *probs;

	uint32_t symbol;

	uint32_t limit;

	uint32_t offset;

	uint32_t len;
} lzma_lzma1_decoder;

static lzma_ret
lzma_decode(void *coder_ptr, lzma_dict *restrict dictptr,
		const uint8_t *restrict in,
		size_t *restrict in_pos, size_t in_size)
{
	lzma_lzma1_decoder *restrict coder = coder_ptr;

	{
		const lzma_ret ret = rc_read_init(
				&coder->rc, in, in_pos, in_size);
		if (ret != LZMA_STREAM_END)
			return ret;
	}

	lzma_dict dict = *dictptr;

	const size_t dict_start = dict.pos;

	rc_to_local(coder->rc, *in_pos);

	uint32_t state = coder->state;
	uint32_t rep0 = coder->rep0;
	uint32_t rep1 = coder->rep1;
	uint32_t rep2 = coder->rep2;
	uint32_t rep3 = coder->rep3;

	const uint32_t pos_mask = coder->pos_mask;

	probability *probs = coder->probs;
	uint32_t symbol = coder->symbol;
	uint32_t limit = coder->limit;
	uint32_t offset = coder->offset;
	uint32_t len = coder->len;

	const uint32_t literal_pos_mask = coder->literal_pos_mask;
	const uint32_t literal_context_bits = coder->literal_context_bits;

	uint32_t pos_state = dict.pos & pos_mask;

	lzma_ret ret = LZMA_OK;

	bool eopm_is_valid = coder->uncompressed_size == LZMA_VLI_UNKNOWN;

	bool might_finish_without_eopm = false;
	if (coder->uncompressed_size != LZMA_VLI_UNKNOWN
			&& coder->uncompressed_size <= dict.limit - dict.pos) {
		dict.limit = dict.pos + (size_t)(coder->uncompressed_size);
		might_finish_without_eopm = true;
	}

	switch (coder->sequence)
	while (true) {

		pos_state = dict.pos & pos_mask;

	case LZMA_SEQ_NORMALIZE:
	case LZMA_SEQ_IS_MATCH:
		if (unlikely(might_finish_without_eopm
				&& dict.pos == dict.limit)) {

			rc_normalize(LZMA_SEQ_NORMALIZE);

			if (rc_is_finished(rc)) {
				ret = LZMA_STREAM_END;
				goto out;
			}

			if (!coder->allow_eopm) {
				ret = LZMA_DATA_ERROR;
				goto out;
			}

			eopm_is_valid = true;
		}

		rc_if_0(coder->is_match[state][pos_state], LZMA_SEQ_IS_MATCH) {
			rc_update_0(coder->is_match[state][pos_state]);

			probs = literal_subcoder(coder->literal,
					literal_context_bits, literal_pos_mask,
					dict.pos, dict_get(&dict, 0));
			symbol = 1;

			if (is_literal_state(state)) {

#ifdef HAVE_SMALL
	case LZMA_SEQ_LITERAL:
				do {
					rc_bit(probs[symbol], , , LZMA_SEQ_LITERAL);
				} while (symbol < (1 << 8));
#else
				rc_bit_case(probs[symbol], , , LZMA_SEQ_LITERAL0);
				rc_bit_case(probs[symbol], , , LZMA_SEQ_LITERAL1);
				rc_bit_case(probs[symbol], , , LZMA_SEQ_LITERAL2);
				rc_bit_case(probs[symbol], , , LZMA_SEQ_LITERAL3);
				rc_bit_case(probs[symbol], , , LZMA_SEQ_LITERAL4);
				rc_bit_case(probs[symbol], , , LZMA_SEQ_LITERAL5);
				rc_bit_case(probs[symbol], , , LZMA_SEQ_LITERAL6);
				rc_bit_case(probs[symbol], , , LZMA_SEQ_LITERAL7);
#endif
			} else {

				len = (uint32_t)(dict_get(&dict, rep0)) << 1;

				offset = 0x100;

#ifdef HAVE_SMALL
	case LZMA_SEQ_LITERAL_MATCHED:
				do {
					const uint32_t match_bit
							= len & offset;
					const uint32_t subcoder_index
							= offset + match_bit
							+ symbol;

					rc_bit(probs[subcoder_index],
							offset &= ~match_bit,
							offset &= match_bit,
							LZMA_SEQ_LITERAL_MATCHED);

					len <<= 1;

				} while (symbol < (1 << 8));
#else

				uint32_t match_bit;
				uint32_t subcoder_index;

#define d(seq) case seq: match_bit = len & offset; subcoder_index = offset + match_bit + symbol; rc_bit(probs[subcoder_index], offset &= ~match_bit, offset &= match_bit, seq)

				d(LZMA_SEQ_LITERAL_MATCHED0);
				len <<= 1;
				d(LZMA_SEQ_LITERAL_MATCHED1);
				len <<= 1;
				d(LZMA_SEQ_LITERAL_MATCHED2);
				len <<= 1;
				d(LZMA_SEQ_LITERAL_MATCHED3);
				len <<= 1;
				d(LZMA_SEQ_LITERAL_MATCHED4);
				len <<= 1;
				d(LZMA_SEQ_LITERAL_MATCHED5);
				len <<= 1;
				d(LZMA_SEQ_LITERAL_MATCHED6);
				len <<= 1;
				d(LZMA_SEQ_LITERAL_MATCHED7);
#undef d
#endif
			}

			static const lzma_lzma_state next_state[] = {
				STATE_LIT_LIT,
				STATE_LIT_LIT,
				STATE_LIT_LIT,
				STATE_LIT_LIT,
				STATE_MATCH_LIT_LIT,
				STATE_REP_LIT_LIT,
				STATE_SHORTREP_LIT_LIT,
				STATE_MATCH_LIT,
				STATE_REP_LIT,
				STATE_SHORTREP_LIT,
				STATE_MATCH_LIT,
				STATE_REP_LIT
			};
			state = next_state[state];

	case LZMA_SEQ_LITERAL_WRITE:
			if (unlikely(dict_put(&dict, symbol))) {
				coder->sequence = LZMA_SEQ_LITERAL_WRITE;
				goto out;
			}

			continue;
		}

		rc_update_1(coder->is_match[state][pos_state]);

	case LZMA_SEQ_IS_REP:
		rc_if_0(coder->is_rep[state], LZMA_SEQ_IS_REP) {

			rc_update_0(coder->is_rep[state]);
			update_match(state);

			rep3 = rep2;
			rep2 = rep1;
			rep1 = rep0;

			len_decode(len, coder->match_len_decoder,
					pos_state, LZMA_SEQ_MATCH_LEN);

			probs = coder->dist_slot[get_dist_state(len)];
			symbol = 1;

#ifdef HAVE_SMALL
	case LZMA_SEQ_DIST_SLOT:
			do {
				rc_bit(probs[symbol], , , LZMA_SEQ_DIST_SLOT);
			} while (symbol < DIST_SLOTS);
#else
			rc_bit_case(probs[symbol], , , LZMA_SEQ_DIST_SLOT0);
			rc_bit_case(probs[symbol], , , LZMA_SEQ_DIST_SLOT1);
			rc_bit_case(probs[symbol], , , LZMA_SEQ_DIST_SLOT2);
			rc_bit_case(probs[symbol], , , LZMA_SEQ_DIST_SLOT3);
			rc_bit_case(probs[symbol], , , LZMA_SEQ_DIST_SLOT4);
			rc_bit_case(probs[symbol], , , LZMA_SEQ_DIST_SLOT5);
#endif

			symbol -= DIST_SLOTS;
			assert(symbol <= 63);

			if (symbol < DIST_MODEL_START) {

				rep0 = symbol;
			} else {

				limit = (symbol >> 1) - 1;
				assert(limit >= 1 && limit <= 30);
				rep0 = 2 + (symbol & 1);

				if (symbol < DIST_MODEL_END) {

					assert(limit <= 5);
					rep0 <<= limit;
					assert(rep0 <= 96);

					assert((int32_t)(rep0 - symbol - 1)
							>= -1);
					assert((int32_t)(rep0 - symbol - 1)
							<= 82);
					probs = coder->pos_special + rep0
							- symbol - 1;
					symbol = 1;
					offset = 0;
	case LZMA_SEQ_DIST_MODEL:
#ifdef HAVE_SMALL
					do {
						rc_bit(probs[symbol], ,
							rep0 += 1U << offset,
							LZMA_SEQ_DIST_MODEL);
					} while (++offset < limit);
#else
					switch (limit) {
					case 5:
						assert(offset == 0);
						rc_bit(probs[symbol], ,
							rep0 += 1U,
							LZMA_SEQ_DIST_MODEL);
						++offset;
						--limit;
					case 4:
						rc_bit(probs[symbol], ,
							rep0 += 1U << offset,
							LZMA_SEQ_DIST_MODEL);
						++offset;
						--limit;
					case 3:
						rc_bit(probs[symbol], ,
							rep0 += 1U << offset,
							LZMA_SEQ_DIST_MODEL);
						++offset;
						--limit;
					case 2:
						rc_bit(probs[symbol], ,
							rep0 += 1U << offset,
							LZMA_SEQ_DIST_MODEL);
						++offset;
						--limit;
					case 1:

						rc_bit_last(probs[symbol], ,
							rep0 += 1U << offset,
							LZMA_SEQ_DIST_MODEL);
					}
#endif
				} else {

					assert(symbol >= 14);
					assert(limit >= 6);
					limit -= ALIGN_BITS;
					assert(limit >= 2);
	case LZMA_SEQ_DIRECT:

					do {
						rc_direct(rep0, LZMA_SEQ_DIRECT);
					} while (--limit > 0);

					rep0 <<= ALIGN_BITS;
					symbol = 1;
#ifdef HAVE_SMALL
					offset = 0;
	case LZMA_SEQ_ALIGN:
					do {
						rc_bit(coder->pos_align[
								symbol], ,
							rep0 += 1U << offset,
							LZMA_SEQ_ALIGN);
					} while (++offset < ALIGN_BITS);
#else
	case LZMA_SEQ_ALIGN0:
					rc_bit(coder->pos_align[symbol], ,
							rep0 += 1, LZMA_SEQ_ALIGN0);
	case LZMA_SEQ_ALIGN1:
					rc_bit(coder->pos_align[symbol], ,
							rep0 += 2, LZMA_SEQ_ALIGN1);
	case LZMA_SEQ_ALIGN2:
					rc_bit(coder->pos_align[symbol], ,
							rep0 += 4, LZMA_SEQ_ALIGN2);
	case LZMA_SEQ_ALIGN3:

					rc_bit_last(coder->pos_align[symbol], ,
							rep0 += 8, LZMA_SEQ_ALIGN3);
#endif

					if (rep0 == UINT32_MAX) {

						if (!eopm_is_valid) {
							ret = LZMA_DATA_ERROR;
							goto out;
						}

	case LZMA_SEQ_EOPM:

						rc_normalize(LZMA_SEQ_EOPM);
						ret = rc_is_finished(rc)
							? LZMA_STREAM_END
							: LZMA_DATA_ERROR;
						goto out;
					}
				}
			}

			if (unlikely(!dict_is_distance_valid(&dict, rep0))) {
				ret = LZMA_DATA_ERROR;
				goto out;
			}

		} else {
			rc_update_1(coder->is_rep[state]);

			if (unlikely(!dict_is_distance_valid(&dict, 0))) {
				ret = LZMA_DATA_ERROR;
				goto out;
			}

	case LZMA_SEQ_IS_REP0:
			rc_if_0(coder->is_rep0[state], LZMA_SEQ_IS_REP0) {
				rc_update_0(coder->is_rep0[state]);

	case LZMA_SEQ_IS_REP0_LONG:
				rc_if_0(coder->is_rep0_long[state][pos_state],
						LZMA_SEQ_IS_REP0_LONG) {
					rc_update_0(coder->is_rep0_long[
							state][pos_state]);

					update_short_rep(state);

	case LZMA_SEQ_SHORTREP:
					if (unlikely(dict_put(&dict, dict_get(
							&dict, rep0)))) {
						coder->sequence = LZMA_SEQ_SHORTREP;
						goto out;
					}

					continue;
				}

				rc_update_1(coder->is_rep0_long[
						state][pos_state]);

			} else {
				rc_update_1(coder->is_rep0[state]);

	case LZMA_SEQ_IS_REP1:

				rc_if_0(coder->is_rep1[state], LZMA_SEQ_IS_REP1) {
					rc_update_0(coder->is_rep1[state]);

					const uint32_t distance = rep1;
					rep1 = rep0;
					rep0 = distance;

				} else {
					rc_update_1(coder->is_rep1[state]);
	case LZMA_SEQ_IS_REP2:
					rc_if_0(coder->is_rep2[state],
							LZMA_SEQ_IS_REP2) {
						rc_update_0(coder->is_rep2[
								state]);

						const uint32_t distance = rep2;
						rep2 = rep1;
						rep1 = rep0;
						rep0 = distance;

					} else {
						rc_update_1(coder->is_rep2[
								state]);

						const uint32_t distance = rep3;
						rep3 = rep2;
						rep2 = rep1;
						rep1 = rep0;
						rep0 = distance;
					}
				}
			}

			update_long_rep(state);

			len_decode(len, coder->rep_len_decoder,
					pos_state, LZMA_SEQ_REP_LEN);
		}

		assert(len >= MATCH_LEN_MIN);
		assert(len <= MATCH_LEN_MAX);

	case LZMA_SEQ_COPY:

		if (unlikely(dict_repeat(&dict, rep0, &len))) {
			coder->sequence = LZMA_SEQ_COPY;
			goto out;
		}
	}

out:

	dictptr->pos = dict.pos;
	dictptr->full = dict.full;

	rc_from_local(coder->rc, *in_pos);

	coder->state = state;
	coder->rep0 = rep0;
	coder->rep1 = rep1;
	coder->rep2 = rep2;
	coder->rep3 = rep3;

	coder->probs = probs;
	coder->symbol = symbol;
	coder->limit = limit;
	coder->offset = offset;
	coder->len = len;

	if (coder->uncompressed_size != LZMA_VLI_UNKNOWN) {
		coder->uncompressed_size -= dict.pos - dict_start;

		if (coder->uncompressed_size == 0 && ret == LZMA_OK
				&& (coder->sequence == LZMA_SEQ_LITERAL_WRITE
					|| coder->sequence == LZMA_SEQ_SHORTREP
					|| coder->sequence == LZMA_SEQ_COPY))
			ret = LZMA_DATA_ERROR;
	}

	if (ret == LZMA_STREAM_END) {

		rc_reset(coder->rc);
		coder->sequence = LZMA_SEQ_IS_MATCH;
	}

	return ret;
}

static void
lzma_decoder_uncompressed(void *coder_ptr, lzma_vli uncompressed_size,
		bool allow_eopm)
{
	lzma_lzma1_decoder *coder = coder_ptr;
	coder->uncompressed_size = uncompressed_size;
	coder->allow_eopm = allow_eopm;
}

static void
lzma_decoder_reset(void *coder_ptr, const void *opt)
{
	lzma_lzma1_decoder *coder = coder_ptr;
	const lzma_options_lzma *options = opt;

	coder->pos_mask = (1U << options->pb) - 1;

	literal_init(coder->literal, options->lc, options->lp);

	coder->literal_context_bits = options->lc;
	coder->literal_pos_mask = (1U << options->lp) - 1;

	coder->state = STATE_LIT_LIT;
	coder->rep0 = 0;
	coder->rep1 = 0;
	coder->rep2 = 0;
	coder->rep3 = 0;
	coder->pos_mask = (1U << options->pb) - 1;

	rc_reset(coder->rc);

	for (uint32_t i = 0; i < STATES; ++i) {
		for (uint32_t j = 0; j <= coder->pos_mask; ++j) {
			bit_reset(coder->is_match[i][j]);
			bit_reset(coder->is_rep0_long[i][j]);
		}

		bit_reset(coder->is_rep[i]);
		bit_reset(coder->is_rep0[i]);
		bit_reset(coder->is_rep1[i]);
		bit_reset(coder->is_rep2[i]);
	}

	for (uint32_t i = 0; i < DIST_STATES; ++i)
		bittree_reset(coder->dist_slot[i], DIST_SLOT_BITS);

	for (uint32_t i = 0; i < FULL_DISTANCES - DIST_MODEL_END; ++i)
		bit_reset(coder->pos_special[i]);

	bittree_reset(coder->pos_align, ALIGN_BITS);

	const uint32_t num_pos_states = 1U << options->pb;
	bit_reset(coder->match_len_decoder.choice);
	bit_reset(coder->match_len_decoder.choice2);
	bit_reset(coder->rep_len_decoder.choice);
	bit_reset(coder->rep_len_decoder.choice2);

	for (uint32_t pos_state = 0; pos_state < num_pos_states; ++pos_state) {
		bittree_reset(coder->match_len_decoder.low[pos_state],
				LEN_LOW_BITS);
		bittree_reset(coder->match_len_decoder.mid[pos_state],
				LEN_MID_BITS);

		bittree_reset(coder->rep_len_decoder.low[pos_state],
				LEN_LOW_BITS);
		bittree_reset(coder->rep_len_decoder.mid[pos_state],
				LEN_MID_BITS);
	}

	bittree_reset(coder->match_len_decoder.high, LEN_HIGH_BITS);
	bittree_reset(coder->rep_len_decoder.high, LEN_HIGH_BITS);

	coder->sequence = LZMA_SEQ_IS_MATCH;
	coder->probs = NULL;
	coder->symbol = 0;
	coder->limit = 0;
	coder->offset = 0;
	coder->len = 0;

	return;
}

extern lzma_ret
lzma_lzma_decoder_create(lzma_lz_decoder *lz, const lzma_allocator *allocator,
		const lzma_options_lzma *options, lzma_lz_options *lz_options)
{
	if (lz->coder == NULL) {
		lz->coder = lzma_alloc(sizeof(lzma_lzma1_decoder), allocator);
		if (lz->coder == NULL)
			return LZMA_MEM_ERROR;

		lz->code = &lzma_decode;
		lz->reset = &lzma_decoder_reset;
		lz->set_uncompressed = &lzma_decoder_uncompressed;
	}

	lz_options->dict_size = options->dict_size;
	lz_options->preset_dict = options->preset_dict;
	lz_options->preset_dict_size = options->preset_dict_size;

	return LZMA_OK;
}

static lzma_ret
lzma_decoder_init(lzma_lz_decoder *lz, const lzma_allocator *allocator,
		lzma_vli id, const void *options, lzma_lz_options *lz_options)
{
	if (!is_lclppb_valid(options))
		return LZMA_PROG_ERROR;

	lzma_vli uncomp_size = LZMA_VLI_UNKNOWN;
	bool allow_eopm = true;

	if (id == LZMA_FILTER_LZMA1EXT) {
		const lzma_options_lzma *opt = options;

		if (opt->ext_flags & ~LZMA_LZMA1EXT_ALLOW_EOPM)
			return LZMA_OPTIONS_ERROR;

		uncomp_size = opt->ext_size_low
				+ ((uint64_t)(opt->ext_size_high) << 32);
		allow_eopm = (opt->ext_flags & LZMA_LZMA1EXT_ALLOW_EOPM) != 0
				|| uncomp_size == LZMA_VLI_UNKNOWN;
	}

	return_if_error(lzma_lzma_decoder_create(
			lz, allocator, options, lz_options));

	lzma_decoder_reset(lz->coder, options);
	lzma_decoder_uncompressed(lz->coder, uncomp_size, allow_eopm);

	return LZMA_OK;
}

extern lzma_ret
lzma_lzma_decoder_init(lzma_next_coder *next, const lzma_allocator *allocator,
		const lzma_filter_info *filters)
{

	assert(filters[1].init == NULL);

	return lzma_lz_decoder_init(next, allocator, filters,
			&lzma_decoder_init);
}

extern bool
lzma_lzma_lclppb_decode(lzma_options_lzma *options, uint8_t byte)
{
	if (byte > (4 * 5 + 4) * 9 + 8)
		return true;

	options->pb = byte / (9 * 5);
	byte -= options->pb * 9 * 5;
	options->lp = byte / 9;
	options->lc = byte - options->lp * 9;

	return options->lc + options->lp > LZMA_LCLP_MAX;
}

extern uint64_t
lzma_lzma_decoder_memusage_nocheck(const void *options)
{
	const lzma_options_lzma *const opt = options;
	return sizeof(lzma_lzma1_decoder)
			+ lzma_lz_decoder_memusage(opt->dict_size);
}

extern uint64_t
lzma_lzma_decoder_memusage(const void *options)
{
	if (!is_lclppb_valid(options))
		return UINT64_MAX;

	return lzma_lzma_decoder_memusage_nocheck(options);
}

extern lzma_ret
lzma_lzma_props_decode(void **options, const lzma_allocator *allocator,
		const uint8_t *props, size_t props_size)
{
	if (props_size != 5)
		return LZMA_OPTIONS_ERROR;

	lzma_options_lzma *opt
			= lzma_alloc(sizeof(lzma_options_lzma), allocator);
	if (opt == NULL)
		return LZMA_MEM_ERROR;

	if (lzma_lzma_lclppb_decode(opt, props[0]))
		goto error;

	opt->dict_size = read32le(props + 1);

	opt->preset_dict = NULL;
	opt->preset_dict_size = 0;

	*options = opt;

	return LZMA_OK;

error:
	lzma_free(opt, allocator);
	return LZMA_OPTIONS_ERROR;
}

typedef struct {
	enum sequence {
		LZMA2_SEQ_CONTROL,
		LZMA2_SEQ_UNCOMPRESSED_1,
		LZMA2_SEQ_UNCOMPRESSED_2,
		LZMA2_SEQ_COMPRESSED_0,
		LZMA2_SEQ_COMPRESSED_1,
		LZMA2_SEQ_PROPERTIES,
		LZMA2_SEQ_LZMA,
		LZMA2_SEQ_COPY,
	} sequence;

	enum sequence next_sequence;

	lzma_lz_decoder lzma;

	size_t uncompressed_size;

	size_t compressed_size;

	bool need_properties;

	bool need_dictionary_reset;

	lzma_options_lzma options;
} lzma_lzma2_coder;

static lzma_ret
lzma2_decode(void *coder_ptr, lzma_dict *restrict dict,
		const uint8_t *restrict in, size_t *restrict in_pos,
		size_t in_size)
{
	lzma_lzma2_coder *restrict coder = coder_ptr;

	while (*in_pos < in_size || coder->sequence == LZMA2_SEQ_LZMA)
	switch (coder->sequence) {
	case LZMA2_SEQ_CONTROL: {
		const uint32_t control = in[*in_pos];
		++*in_pos;

		if (control == 0x00)
			return LZMA_STREAM_END;

		if (control >= 0xE0 || control == 1) {

			coder->need_properties = true;
			coder->need_dictionary_reset = true;
		} else if (coder->need_dictionary_reset) {
			return LZMA_DATA_ERROR;
		}

		if (control >= 0x80) {

			coder->uncompressed_size = (control & 0x1F) << 16;
			coder->sequence = LZMA2_SEQ_UNCOMPRESSED_1;

			if (control >= 0xC0) {

				coder->need_properties = false;
				coder->next_sequence = LZMA2_SEQ_PROPERTIES;

			} else if (coder->need_properties) {
				return LZMA_DATA_ERROR;

			} else {
				coder->next_sequence = LZMA2_SEQ_LZMA;

				if (control >= 0xA0)
					coder->lzma.reset(coder->lzma.coder,
							&coder->options);
			}
		} else {

			if (control > 2)
				return LZMA_DATA_ERROR;

			coder->sequence = LZMA2_SEQ_COMPRESSED_0;
			coder->next_sequence = LZMA2_SEQ_COPY;
		}

		if (coder->need_dictionary_reset) {

			coder->need_dictionary_reset = false;
			dict_reset(dict);
			return LZMA_OK;
		}

		break;
	}

	case LZMA2_SEQ_UNCOMPRESSED_1:
		coder->uncompressed_size += (uint32_t)(in[(*in_pos)++]) << 8;
		coder->sequence = LZMA2_SEQ_UNCOMPRESSED_2;
		break;

	case LZMA2_SEQ_UNCOMPRESSED_2:
		coder->uncompressed_size += in[(*in_pos)++] + 1U;
		coder->sequence = LZMA2_SEQ_COMPRESSED_0;
		coder->lzma.set_uncompressed(coder->lzma.coder,
				coder->uncompressed_size, false);
		break;

	case LZMA2_SEQ_COMPRESSED_0:
		coder->compressed_size = (uint32_t)(in[(*in_pos)++]) << 8;
		coder->sequence = LZMA2_SEQ_COMPRESSED_1;
		break;

	case LZMA2_SEQ_COMPRESSED_1:
		coder->compressed_size += in[(*in_pos)++] + 1U;
		coder->sequence = coder->next_sequence;
		break;

	case LZMA2_SEQ_PROPERTIES:
		if (lzma_lzma_lclppb_decode(&coder->options, in[(*in_pos)++]))
			return LZMA_DATA_ERROR;

		coder->lzma.reset(coder->lzma.coder, &coder->options);

		coder->sequence = LZMA2_SEQ_LZMA;
		break;

	case LZMA2_SEQ_LZMA: {

		const size_t in_start = *in_pos;

		const lzma_ret ret = coder->lzma.code(coder->lzma.coder,
				dict, in, in_pos, in_size);

		const size_t in_used = *in_pos - in_start;
		if (in_used > coder->compressed_size)
			return LZMA_DATA_ERROR;

		coder->compressed_size -= in_used;

		if (ret != LZMA_STREAM_END)
			return ret;

		if (coder->compressed_size != 0)
			return LZMA_DATA_ERROR;

		coder->sequence = LZMA2_SEQ_CONTROL;
		break;
	}

	case LZMA2_SEQ_COPY: {

		dict_write(dict, in, in_pos, in_size, &coder->compressed_size);
		if (coder->compressed_size != 0)
			return LZMA_OK;

		coder->sequence = LZMA2_SEQ_CONTROL;
		break;
	}

	default:
		assert(0);
		return LZMA_PROG_ERROR;
	}

	return LZMA_OK;
}

static void
lzma2_decoder_end(void *coder_ptr, const lzma_allocator *allocator)
{
	lzma_lzma2_coder *coder = coder_ptr;

	assert(coder->lzma.end == NULL);
	lzma_free(coder->lzma.coder, allocator);

	lzma_free(coder, allocator);

	return;
}

static lzma_ret
lzma2_decoder_init(lzma_lz_decoder *lz, const lzma_allocator *allocator,
		lzma_vli id lzma_attribute((__unused__)), const void *opt,
		lzma_lz_options *lz_options)
{
	lzma_lzma2_coder *coder = lz->coder;
	if (coder == NULL) {
		coder = lzma_alloc(sizeof(lzma_lzma2_coder), allocator);
		if (coder == NULL)
			return LZMA_MEM_ERROR;

		lz->coder = coder;
		lz->code = &lzma2_decode;
		lz->end = &lzma2_decoder_end;

		coder->lzma = LZMA_LZ_DECODER_INIT;
	}

	const lzma_options_lzma *options = opt;

	coder->sequence = LZMA2_SEQ_CONTROL;
	coder->need_properties = true;
	coder->need_dictionary_reset = options->preset_dict == NULL
			|| options->preset_dict_size == 0;

	return lzma_lzma_decoder_create(&coder->lzma,
			allocator, options, lz_options);
}

extern lzma_ret
lzma_lzma2_decoder_init(lzma_next_coder *next, const lzma_allocator *allocator,
		const lzma_filter_info *filters)
{

	assert(filters[1].init == NULL);

	return lzma_lz_decoder_init(next, allocator, filters,
			&lzma2_decoder_init);
}

extern uint64_t
lzma_lzma2_decoder_memusage(const void *options)
{
	return sizeof(lzma_lzma2_coder)
			+ lzma_lzma_decoder_memusage_nocheck(options);
}

extern lzma_ret
lzma_lzma2_props_decode(void **options, const lzma_allocator *allocator,
		const uint8_t *props, size_t props_size)
{
	if (props_size != 1)
		return LZMA_OPTIONS_ERROR;

	if (props[0] & 0xC0)
		return LZMA_OPTIONS_ERROR;

	if (props[0] > 40)
		return LZMA_OPTIONS_ERROR;

	lzma_options_lzma *opt = lzma_alloc(
			sizeof(lzma_options_lzma), allocator);
	if (opt == NULL)
		return LZMA_MEM_ERROR;

	if (props[0] == 40) {
		opt->dict_size = UINT32_MAX;
	} else {
		opt->dict_size = 2 | (props[0] & 1U);
		opt->dict_size <<= props[0] / 2U + 11;
	}

	opt->preset_dict = NULL;
	opt->preset_dict_size = 0;

	*options = opt;

	return LZMA_OK;
}

extern LZMA_API(lzma_bool)
lzma_lzma_preset(lzma_options_lzma *options, uint32_t preset)
{
	const uint32_t level = preset & LZMA_PRESET_LEVEL_MASK;
	const uint32_t flags = preset & ~LZMA_PRESET_LEVEL_MASK;
	const uint32_t supported_flags = LZMA_PRESET_EXTREME;

	if (level > 9 || (flags & ~supported_flags))
		return true;

	options->preset_dict = NULL;
	options->preset_dict_size = 0;

	options->lc = LZMA_LC_DEFAULT;
	options->lp = LZMA_LP_DEFAULT;
	options->pb = LZMA_PB_DEFAULT;

	static const uint8_t dict_pow2[]
			= { 18, 20, 21, 22, 22, 23, 23, 24, 25, 26 };
	options->dict_size = UINT32_C(1) << dict_pow2[level];

	if (level <= 3) {
		options->mode = LZMA_MODE_FAST;
		options->mf = level == 0 ? LZMA_MF_HC3 : LZMA_MF_HC4;
		options->nice_len = level <= 1 ? 128 : 273;
		static const uint8_t depths[] = { 4, 8, 24, 48 };
		options->depth = depths[level];
	} else {
		options->mode = LZMA_MODE_NORMAL;
		options->mf = LZMA_MF_BT4;
		options->nice_len = level == 4 ? 16 : level == 5 ? 32 : 64;
		options->depth = 0;
	}

	if (flags & LZMA_PRESET_EXTREME) {
		options->mode = LZMA_MODE_NORMAL;
		options->mf = LZMA_MF_BT4;
		if (level == 3 || level == 5) {
			options->nice_len = 192;
			options->depth = 0;
		} else {
			options->nice_len = 273;
			options->depth = 512;
		}
	}

	return false;
}
