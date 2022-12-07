#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <vector>

struct RepIndex {
  int idx, val_idx;
};

static inline void* STRING_H_MALLOC(size_t size) {
  void* res = malloc(size);
#if defined(STRING_ALLOC_LOG)
  fprintf(stderr, "STRING_H_MALLOC(%zu) -> %p\n", size, res);
#endif
  return res;
}

static inline void* STRING_H_REALLOC(void* ptr, size_t size) {
  void* res = realloc(ptr, size);
#if defined(STRING_ALLOC_LOG)
  fprintf(stderr, "STRING_H_REALLOC(%p, %zu) -> %p\n", ptr, size, res);
#endif
  return res;
}

static inline void STRING_H_FREE(void* ptr) {
#if defined(STRING_ALLOC_LOG)
  fprintf(stderr, "STRING_H_FREE(%p)\n", ptr);
#endif
  free(ptr);
}

class string {
 public:
#if UINTPTR_MAX == 0xffffffffffffffff
  uintptr_t ptr : 48;
#else
  uintptr_t ptr;
#endif
  uint16_t len;

  inline string() { LOG; };

  inline string(string &a) : ptr(a.ptr), len(a.len) { LOG; };

  inline string(const char *ptr, uint16_t len)
      : ptr((uintptr_t)ptr), len(len) {
        LOG;
      };

  inline string(const char *ptr)
      : ptr((uintptr_t)ptr), len(ptr == 0 ? 0 : (uint16_t)strlen(ptr)) {
        LOG;
      };

  void free() {
    ::free((void *)(uintptr_t)ptr);
  }

  inline string& operator=(const string &a) {
    LOG;
    if (this == &a)
        return *this;

    ptr = a.ptr;
    len = a.len;
    return *this;
 }

  inline bool operator==(const string &other) const {
    return len == other.len &&
           memcmp((const char *)(uintptr_t)ptr, (const char *)other.ptr, len) == 0;
  }

  inline bool operator==(const char *other) const {
    return strncmp((const char *)(uintptr_t)ptr, other, len) == 0;
  }

  inline bool operator!=(const string &other) const {
    return len != other.len ||
           memcmp((const char *)(uintptr_t)ptr, (const char *)other.ptr, len) != 0;
  }

  inline bool operator<(const string &other) const {
    int cmp = memcmp((const char *)(uintptr_t)ptr, (const char *)other.ptr,
                     len < other.len ? len : other.len);
    return cmp < 0 || (cmp == 0 && len < other.len);
  }

  inline bool operator>(const string &other) const {
    int cmp = memcmp((const char *)(uintptr_t)ptr, (const char *)other.ptr,
                     len < other.len ? len : other.len);
    return cmp > 0 || (cmp == 0 && len > other.len);
  }

  inline bool operator<=(const string &other) const {
    int cmp = memcmp((const char *)(uintptr_t)ptr, (const char *)other.ptr,
                     len < other.len ? len : other.len);
    return cmp < 0 || (cmp == 0 && len <= other.len);
  }

  inline bool operator>=(const string &other) const {
    int cmp = memcmp((const char *)(uintptr_t)ptr, (const char *)other.ptr,
                     len < other.len ? len : other.len);
    return cmp > 0 || (cmp == 0 && len >= other.len);
  }

  inline char operator[](int i) const { return ((const char *)(uintptr_t)ptr)[i]; }
  
  string& operator+=(const string &rhs) {
    LOG;
    // if (is_owned) {
    //   ptr = (uintptr_t)realloc((void *)(uintptr_t)ptr, len + rhs.len);
    // } else {
      char *new_ptr = (char *)STRING_H_MALLOC(len + rhs.len);
      memcpy(new_ptr, (void *)(uintptr_t)ptr, len);
      ptr = (uintptr_t)new_ptr;
    //   is_owned = true;
    // }
    memcpy((void *)(ptr + len), (void *)rhs.ptr, rhs.len);
    len += rhs.len;
    return *this;
  }

  friend string operator+(string lhs, const string& rhs) {
    LOG;
    return lhs += rhs;
  }

  operator char*() const { return (char *)(uintptr_t)ptr; }

  inline const char *p() const { return (const char *)(uintptr_t)ptr; }

  inline bool is_empty() const { return len == 0; }

  // inline void set_owned(bool owned) { is_owned = owned; }

  // inline void to_owned() {
  //   if (!is_owned) {
  //     char *new_ptr = (char *)STRING_H_MALLOC(len + 1);
  //     memcpy(new_ptr, (const char *)(uintptr_t)ptr, len);
  //     new_ptr[len] = 0;
  //     ptr = (uintptr_t)new_ptr;

  //     is_owned = true;
  //   }
  // }

  string clone() const {
    string result;
    char* x = (char*)STRING_H_MALLOC(len+1);
    fprintf(stderr, "clone %p %p %d\n", x, (void *)(uintptr_t)ptr, len);
    memcpy((void *)x, (void *)(uintptr_t)ptr, len);
    x[len] = 0;
    result.ptr = (uintptr_t)x;
    result.len = len;
    // result.is_owned = 1;
    return result;
  }

  string dup() const {
    string result;
    result.ptr = ptr;
    result.len = len;
    // result.is_owned = 0;
    return result;
  }

  string slice(int start, int end) const {
    if (start < 0) start = len + start;
    if (end < 0) end = len + end;
    if (start < 0) start = 0;
    if (end < 0) end = 0;
    if (start > len) start = len;
    if (end > len) end = len;
    if (start > end) start = end;
    return string((const char *)(uintptr_t)ptr + start, end - start);
  }

  string slice(int start) const {
    if (start < 0) start = len + start;
    if (start < 0) start = 0;
    if (start > len) start = len;
    return string((const char *)(uintptr_t)ptr + start, len - start);
  }

  int find(char c, int start = 0) const {
    if (start < 0) start = len + start;
    if (start < 0) start = 0;
    if (start > len) return -1;

    const char *p =
        (const char *)memchr((char *)(uintptr_t)ptr + start, c, len - start);
    if (p == 0) return -1;
    return (int)((uintptr_t)p - ptr);
  }

  int find(const string &p, int start = 0) const {
    if (start < 0) start = len + start;
    if (start < 0) start = 0;
    if (start > len) start = len;
    if (p.len == 0) return start;
    if (p.len > len) return -1;

    const char *s = (const char *)(uintptr_t)ptr;

    int prefix[p.len];
    int j = 0;
    for (int i = 1; i < p.len; i++) {
      while (j > 0 && p[j] != p[i]) j = prefix[j - 1];
      if (p[j] == p[i]) j++;
      prefix[i] = j;
    }
    j = 0;
    for (int i = start; i < len; i++) {
      while (j > 0 && p[j] != s[i]) j = prefix[j - 1];
      if (p[j] == s[i]) j++;
      if (j == p.len) return i - p.len + 1;
    }
    return -1;
  }

  string trim() const {
    int start = 0;
    int end = len;
    while (start < end && isspace(((char *)(uintptr_t)ptr)[start])) start++;
    while (end > start && isspace(((char *)(uintptr_t)ptr)[end - 1])) end--;
    return slice(start, end);
  }
};

static_assert(sizeof(string) == 8, "string should always be 8 bytes");
