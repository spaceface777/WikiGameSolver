#if UINTPTR_MAX == 0xffffffffffffffff && !defined(USE_FAST_ARRAY)

typedef void* array;

INLINE unsigned short ARR_LEN(array x) {
	return (uintptr_t)x >> 48;
}

INLINE void* ARR_PTR(array x) {
	return (void*)((uintptr_t)x & 0xFFFFFFFFFFFF);
}

INLINE array ARR(void* ptr, short len) {
	if ((uintptr_t)ptr & 0xFFFF000000000000) {
		fprintf(stderr, "%s: pointer too large", __func__);
		exit(1);
	}
	return (array)((uintptr_t)ptr | ((uintptr_t)len << 48));
}

INLINE bool array_eq(array a, array b) {
	if (ARR_LEN(a) != ARR_LEN(b)) return false;
	return !memcmp(ARR_PTR(a), ARR_PTR(b), ARR_LEN(a));
}

INLINE array array_clone(array s) {
	int	  l	  = ARR_LEN(s);
	char* p	  = ARR_PTR(s);
	char* ptr = malloc(l + 1);
	memcpy(ptr, p, l);
	ptr[l] = 0;
	return ARR(ptr, l);
}

INLINE void array_free(array* str) {
	free(ARR_PTR(*str));
	*str = 0;
}

#define IS_NIL(x) (ARR_PTR(x) == 0)

#elif defined(USE_FAST_ARRAY)

typedef struct {
	void*		   ptr;
	size_t len;
} array;

INLINE size_t ARR_LEN(array x) {
	return x.len;
}

INLINE void* ARR_PTR(array x) {
	return x.ptr;
}

INLINE array ARR(void* ptr, size_t len) {
	return (array){ptr, len};
}

INLINE bool array_eq(array a, array b) {
	if (a.len != b.len) return false;
	return !memcmp(a.ptr, b.ptr, a.len);
}

INLINE array array_clone(array s) {
	char* ptr = (char*)malloc(s.len + 1);
	memcpy(ptr, s.ptr, s.len);
	ptr[s.len] = 0;
	return ARR(ptr, s.len);
}

INLINE void array_free(array* str) {
	free(str->ptr);
	str->ptr = 0;
	str->len = 0;
}

#define IS_NIL(x) ((x).ptr == 0)

#else

typedef struct {
	void*		   ptr;
	unsigned short len;
} array;

INLINE unsigned short ARR_LEN(array x) {
	return x.len;
}

INLINE void* ARR_PTR(array x) {
	return x.ptr;
}

INLINE array ARR(void* ptr, unsigned short len) {
	return (array){ptr, len};
}

INLINE bool array_eq(array a, array b) {
	if (a.len != b.len) return false;
	return !memcmp(a.ptr, b.ptr, a.len);
}

INLINE array array_clone(array s) {
	char* ptr = (char*)malloc(s.len + 1);
	memcpy(ptr, s.ptr, s.len);
	ptr[s.len] = 0;
	return ARR(ptr, s.len);
}

INLINE void array_free(array* str) {
	free(str->ptr);
	str->ptr = 0;
	str->len = 0;
}

#define IS_NIL(x) ((x).ptr == 0)

#endif
