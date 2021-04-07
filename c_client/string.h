#include <string.h>
#include <stdbool.h>

// create a string literal
#define SLIT(x) ((string){ .str = ""x, .len = (int)sizeof(x) - 1, .flags = STR_LITERAL })

// create a string from a const char*
#define STR(x) ((string){ .str = (const char*)x, .len = (int)strlen((const char*)x) })

#define STR_LITERAL (1<<0)
#define STR_FREED (1<<1)

typedef struct string {
    const char* str;
    int len;
	int flags;
} string;

static inline bool string_eq(string a, string b) {
    if (a.len != b.len) return false;
    return !memcmp(a.str, b.str, a.len);
}

static inline string string_clone(string s) {
    int l = s.len;
    char* ptr = malloc(l + 1);
    memcpy(ptr, s.str, l);
    ptr[l] = 0;
    return (string){ .str = ptr, .len = l, .flags = s.flags & ~STR_LITERAL };
}

static inline void string_free(string* str) {
	if (str->flags & STR_FREED) PANIC("string.free: double free detected")
	if (str->flags & STR_LITERAL) return;
	free((void*)str->str);
	str->flags |= STR_FREED;
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
