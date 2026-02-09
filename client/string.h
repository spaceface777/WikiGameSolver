#if UINTPTR_MAX == 0xffffffffffffffff

// #if defined(USE_FAST_ARRAY)

// #else

// #endif

typedef array string;

// create a string literal
// #define SLIT(x) ((string)((uintptr_t)"" x | ((uintptr_t)(sizeof(x) - 1) << 48)))
#define SLIT(x) (ARR("" x, sizeof(x) - 1))

#define STR_LEN(x) ((int)ARR_LEN((x)))
#define STR_PTR(x) ((const char*)ARR_PTR((array)(x)))

#define STR(x, len) ((string)ARR((x), (len)))

#define string_eq(a, b) array_eq((a), (b))

#define string_clone(s) ((string)array_clone((s)))

#define string_free(s) array_free((s))

#else

typedef struct {
	const char*    ptr;
	unsigned short len;
} string;

#define SLIT(x) ((string){"" x, sizeof(x) - 1})

#define STR_LEN(x) ((x).len)
#define STR_PTR(x) ((x).ptr)

#define STR(x, len) ((string){(x), (unsigned short)(len)})

INLINE bool string_eq(string a, string b) {
	if (a.len != b.len) return false;
	return !memcmp(a.ptr, b.ptr, a.len);
}

INLINE string string_clone(string s) {
	char* ptr = (char*)malloc(s.len + 1);
	memcpy(ptr, s.ptr, s.len);
	ptr[s.len] = 0;
	return (string){ptr, s.len};
}

INLINE void string_free(string* str) {
	free((void*)str->ptr);
	str->ptr = 0;
	str->len = 0;
}

#endif

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
