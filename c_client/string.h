#include <string.h>
#include <stdbool.h>

typedef char* string;

// create a string literal
#define SLIT(x) ((string)((uintptr_t)""x | ((uintptr_t)(sizeof(x) - 1)<<48)))

INLINE unsigned short STR_LEN(string x) {
    return (uintptr_t)x >> 48;
}

INLINE char* STR_PTR(string x) {
    return (char*)((uintptr_t)x & 0xFFFFFFFFFFFF);
}

INLINE string STR(char* ptr, short len) {
    return (string)((uintptr_t)ptr | ((uintptr_t)len<<48));
}

INLINE bool string_eq(string a, string b) {
    if (STR_LEN(a) != STR_LEN(b)) return false;
    return !memcmp(STR_PTR(a), STR_PTR(b), STR_LEN(a));
}

INLINE string string_clone(string s) {
    int l = STR_LEN(s);
	char* p = STR_PTR(s);
    char* ptr = malloc(l + 1);
    memcpy(ptr, p, l);
    ptr[l] = 0;
    return STR(ptr, l);
}

INLINE void string_free(string* str) {
	free(STR_PTR(*str));
	*str = 0;
}

static void __println_wrapper(int count, ...) {
    va_list args;
    va_start(args, count);
    for (int i = 0; i < count - 1; i++) {
        string x = va_arg(args, string);
        printf("%.*s ", STR_LEN(x), STR_PTR(x));
    }
    string x = va_arg(args, string);
    printf("%.*s", STR_LEN(x), STR_PTR(x));
    puts("");
}

#define println(...) __println_wrapper(VA_LENGTH(__VA_ARGS__), __VA_ARGS__)
