#include <string.h>
#include <stdbool.h>

typedef char* string;

// create a string literal
#define SLIT(x) ((string)((uintptr_t)""x | ((uintptr_t)(sizeof(x) - 1)<<48)))

#define STR_LEN(x) (ARR_LEN((array)(x)))
#define STR_PTR(x) ((string)ARR_PTR((array)(x)))

#define STR(x, len) ((string)ARR((array)(x), (len)))

#define string_eq(a, b) array_eq((array)(a), (array)(b))

#define string_clone(s) ((string)array_clone((array)(s)))

#define string_free(s) array_free((array*)(s))

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
