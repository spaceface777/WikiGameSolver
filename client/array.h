#include <string.h>
#include <stdbool.h>

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
    return (array)((uintptr_t)ptr | ((uintptr_t)len<<48));
}

INLINE bool array_eq(array a, array b) {
    if (ARR_LEN(a) != ARR_LEN(b)) return false;
    return !memcmp(ARR_PTR(a), ARR_PTR(b), ARR_LEN(a));
}

INLINE array array_clone(array s) {
    int l = ARR_LEN(s);
	char* p = ARR_PTR(s);
    char* ptr = malloc(l + 1);
    memcpy(ptr, p, l);
    ptr[l] = 0;
    return ARR(ptr, l);
}

INLINE void array_free(array* str) {
	free(ARR_PTR(*str));
	*str = 0;
}
