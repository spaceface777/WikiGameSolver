#define malloc GC_malloc
#define calloc(n, size) GC_malloc((n) * (size))
#define realloc GC_realloc
#define free(x) ((void)x)
#include "map_impl.h"
#undef malloc
#undef calloc
#undef realloc
#undef free


typedef map map_int_int;
typedef map map_int_string;
typedef map map_string_int;
typedef map map_string_string;
typedef map map_string_stringptr;

static inline uint64_t map_hash_int(void* p) {
    return wyhash64(*((int32_t*)(p)), 0U);
}

static inline uint64_t map_hash_string(void* p) {
    string* s = (string*)(p);
    return wyhash(s->p(), s->len, 0U, _wyp);
}

static inline bool map_eq_int(void* a, void* b) {
    return *((int32_t*)(a)) == *((int32_t*)(b));
}

static inline bool map_eq_string(void* a, void* b) {
    string s1 = *(string*)(a);
    string s2 = *(string*)(b);
    return s1 == s2;
}

static inline void map_clone_int(void* dst, void* src) {
    *((int32_t*)(dst)) = *((int32_t*)(src));
}

static inline void map_clone_string(void* dst, void* src) {
    string* s1 = (string*)(dst);
    string* s2 = (string*)(src);
    // *s1 = s2->clone();
    *s1 = *s2;
}

static inline void map_free_nop(void* p) { (void)p; }
static inline void map_free_string(void* p) { (void)p;
    
    // string* s = (string*)(p);
    // s->free();
}

static inline map_int_int new_map_int_int() {
    return new_map(sizeof(int32_t), sizeof(int32_t), map_hash_int, map_eq_int, map_clone_int, map_free_nop);
}

static inline void map_int_int_set(map_int_int* m, int32_t k, int32_t v) {
    map_set(m, &k, &v);
}

static inline int32_t map_int_int_get(map_int_int* m, int32_t k) {
    int32_t def = -1;
    return *(int32_t*)map_get(m, &k, &def);
}

static inline int32_t* map_int_int_get_check(map_int_int* m, int32_t k) {
    return (int32_t*)map_get_check(m, &k);
}

static inline void map_int_int_delete(map_int_int* m, int32_t k) {
    map_delete(m, &k);
}


static inline map_int_string new_map_int_string() {
    return new_map(sizeof(int32_t), sizeof(string), map_hash_int, map_eq_int, map_clone_int, map_free_string);
}

static inline void map_int_string_set(map_int_string* m, int32_t k, string v) {
    map_set(m, &k, &v);
}

static inline string map_int_string_get(map_int_string* m, int32_t k) {
    string def = string("");
    return *(string*)map_get(m, &k, &def);
}

static inline string* map_int_string_get_check(map_int_string* m, int32_t k) {
    return (string*)map_get_check(m, &k);
}

static inline void map_int_string_delete(map_int_string* m, int32_t k) {
    map_delete(m, &k);
}


static inline map_string_int new_map_string_int() {
    return new_map(sizeof(string), sizeof(int32_t), map_hash_string, map_eq_string, map_clone_string, map_free_string);
}

static inline void map_string_int_set(map_string_int* m, string k, int32_t v) {
    map_set(m, &k, &v);
}

static inline int32_t map_string_int_get(map_string_int* m, string k) {
    int32_t def = -1;
    return *(int32_t*)map_get(m, &k, &def);
}

static inline int32_t* map_string_int_get_check(map_string_int* m, string k) {
    return (int32_t*)map_get_check(m, &k);
}

static inline void map_string_int_delete(map_string_int* m, string k) {
    map_delete(m, &k);
}


static inline map_string_string new_map_string_string() {
    return new_map(sizeof(string), sizeof(string), map_hash_string, map_eq_string, map_clone_string, map_free_string);
}

static inline void map_string_string_set(map_string_string* m, string k, string v) {
    map_set(m, &k, &v);
}

static inline string map_string_string_get(map_string_string* m, string k) {
    string def = string("");
    return *(string*)map_get(m, &k, &def);
}

static inline string* map_string_string_get_check(map_string_string* m, string k) {
    return (string*)map_get_check(m, &k);
}

static inline void map_string_string_delete(map_string_string* m, string k) {
    map_delete(m, &k);
}


static inline map_string_stringptr new_map_string_stringptr() {
    return new_map(sizeof(string), sizeof(string*), map_hash_string, map_eq_string, map_clone_string, map_free_string);
}

static inline void map_string_stringptr_set(map_string_stringptr* m, string k, string* v) {
    map_set(m, &k, &v);
}

static inline string* map_string_stringptr_get(map_string_stringptr* m, string k) {
    string* def = NULL;
    return *(string**)map_get(m, &k, &def);
}

static inline string** map_string_stringptr_get_check(map_string_stringptr* m, string k) {
    return (string**)map_get_check(m, &k);
}

static inline void map_string_stringptr_delete(map_string_stringptr* m, string k) {
    map_delete(m, &k);
}

#define FOR_IN_MAP(m, k, ktyp, v, vtyp, body) {                               \
    int _t2 = (m).key_values.len;                                             \
    for (int _t1 = 0; _t1 < _t2; ++_t1 ) {                                    \
        int _t3 = (m).key_values.len - _t2;                                   \
        _t2 = (m).key_values.len;                                             \
        if (_t3 < 0) {                                                        \
            _t1 = -1;                                                         \
            continue;                                                         \
        }                                                                     \
        if (!DenseArray_has_index(&(m).key_values, _t1)) {continue;}          \
        ktyp k = *(ktyp*)DenseArray_key(&(m).key_values, _t1);                \
        vtyp* v = (vtyp*)DenseArray_value(&(m).key_values, _t1);              \
        body                                                                  \
    }                                                                         \
}                                                                                                                                  

#define FOR_IN_MAP_STRING_INT(m, k, v, body) FOR_IN_MAP(m, k, string, v, int, body)
#define FOR_IN_MAP_INT_STRING(m, k, v, body) FOR_IN_MAP(m, k, int, v, string, body)
#define FOR_IN_MAP_INT_INT(m, k, v, body) FOR_IN_MAP(m, k, int, v, int, body)
#define FOR_IN_MAP_STRING_STRINGPTR(m, k, v, body) FOR_IN_MAP(m, k, string, v, string*, body)