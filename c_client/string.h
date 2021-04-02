#include <string.h>
#include <stdbool.h>

typedef struct string string;

// create a string literal
#define SLIT(x) ((string){ .str = ""x, .len = (int)sizeof(x) - 1 })

// create a string from a const char*
#define STR(x) ((string){ .str = (const char*)x, .len = (int)strlen((const char*)x) })

struct string {
    const char* str;
    int len;
};

static inline bool string_eq(string a, string b) {
    if (a.len != b.len) return false;
    return !memcmp(a.str, b.str, a.len);
}

static inline string string_clone(string str) {
    int l = str.len;
    char* ptr = malloc(l + 1);
    memcpy(ptr, str.str, l);
    ptr[l] = 0;
    return (string){ .str = ptr, .len = l };
}

static inline void string_free(string str) {
    // free((void*)str.str);
}

static void __println_wrapper(int count, ...) {
    va_list args;
    va_start(args, count);
    for (int i = 0; i < count - 1; i++) {
        string x = va_arg(args, string);
        printf("%.*s ", x.len, x.str);
    }
    string x = va_arg(args, string);
    printf("%.*s", x.len, x.str);
    puts("");
}

#define println(...) __println_wrapper(VA_LENGTH(__VA_ARGS__), __VA_ARGS__)
