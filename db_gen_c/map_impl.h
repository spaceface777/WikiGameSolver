#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef uint64_t (*MapHashFn)(void*);
typedef bool (*MapEqFn)(void*, void*);
typedef void (*MapCloneFn)(void*, void*);
typedef void (*MapFreeFn)(void*);

typedef struct DenseArray DenseArray;
typedef struct map map;
typedef struct multi_return_uint32_t_uint32_t multi_return_uint32_t_uint32_t;

struct DenseArray {
	int key_bytes;
	int value_bytes;
	int cap;
	int len;
	uint32_t deletes;
	uint8_t* all_deleted;
	uint8_t* keys;
	uint8_t* values;
};

struct map {
	int key_bytes;
	int value_bytes;
	uint32_t even_index;
	uint8_t cached_hashbits;
	uint8_t shift;
	DenseArray key_values;
	uint32_t* metas;
	uint32_t extra_metas;
	bool has_string_keys;
	MapHashFn hash_fn;
	MapEqFn key_eq_fn;
	MapCloneFn clone_fn;
	MapFreeFn free_fn;
	int len;
};

struct multi_return_uint32_t_uint32_t {
	uint32_t arg0;
	uint32_t arg1;
};

static void DenseArray_zeros_to_end(DenseArray* d);
static DenseArray new_dense_array(int key_bytes, int value_bytes);
static void* DenseArray_key(DenseArray* d, int i);
static void* DenseArray_value(DenseArray* d, int i);
static bool DenseArray_has_index(DenseArray* d, int i);
static int DenseArray_expand(DenseArray* d);

static void map_free_string(void* pkey);
static void map_free_nop(void* _d1);
static map new_map(int key_bytes, int value_bytes, MapHashFn hash_fn, MapEqFn key_eq_fn, MapCloneFn clone_fn, MapFreeFn free_fn);
static map new_map_init(MapHashFn hash_fn, MapEqFn key_eq_fn, MapCloneFn clone_fn, MapFreeFn free_fn, int n, int key_bytes, int value_bytes, void* keys, void* values);
map map_move(map* m);
void map_clear(map* m);
static multi_return_uint32_t_uint32_t map_key_to_index(map* m, void* pkey);
static multi_return_uint32_t_uint32_t map_meta_less(map* m, uint32_t _index, uint32_t _metas);
static void map_meta_greater(map* m, uint32_t _index, uint32_t _metas, uint32_t kvi);
static void map_ensure_extra_metas(map* m, uint32_t probe_count);
static void map_set(map* m, void* key, void* value);
static void map_expand(map* m);
static void map_rehash(map* m);
static void map_cached_rehash(map* m, uint32_t old_cap);
static void* map_get_and_set(map* m, void* key, void* zero);
static void* map_get(map* m, void* key, void* zero);
static void* map_get_check(map* m, void* key);
static bool map_exists(map* m, void* key);
static void DenseArray_delete(DenseArray* d, int i);
void map_delete(map* m, void* key);
static DenseArray DenseArray_clone(DenseArray* d);
map map_clone(map* m);
void map_free(map* m);

#include "wyhash.h"

#define _IN_MAP(val, m) map_exists(m, val)

#define _const_hashbits 24
#define _const_max_cached_hashbits 16
#define _const_init_log_capicity 5
#define _const_init_capicity 32
#define _const_init_even_index 30
#define _const_extra_metas_inc 4

#define _const_max_load_factor 0.8
#define _const_hash_mask 16777215
#define _const_probe_inc 16777216

void DenseArray_zeros_to_end(DenseArray* d) {
	uint8_t* tmp_value = (uint8_t*)malloc(d->value_bytes);
	uint8_t* tmp_key = (uint8_t*)malloc(d->key_bytes);
	int count = 0;
	for (int i = 0; i < d->len; ++i) {
		if (DenseArray_has_index(d, i)) {
			if (count != i) {
				memcpy(tmp_key, DenseArray_key(d, count), d->key_bytes);
				memcpy(DenseArray_key(d, count), DenseArray_key(d, i), d->key_bytes);
				memcpy(DenseArray_key(d, i), tmp_key, d->key_bytes);
				memcpy(tmp_value, DenseArray_value(d, count), d->value_bytes);
				memcpy(DenseArray_value(d, count), DenseArray_value(d, i), d->value_bytes);
				memcpy(DenseArray_value(d, i), tmp_value, d->value_bytes);
			}
			count++;
		}
	}
	free(tmp_value);
	free(tmp_key);
	d->deletes = 0U;
	free(d->all_deleted);

	d->len = count;
	d->cap = (count < 8 ? (8) : (count));
	d->values = (uint8_t*)realloc(d->values, d->value_bytes * d->cap);
	d->keys = (uint8_t*)realloc(d->keys, d->key_bytes * d->cap);
}
inline DenseArray new_dense_array(int key_bytes, int value_bytes) {
	int cap = 8;
	return ((DenseArray){
		.key_bytes = key_bytes,
		.value_bytes = value_bytes,
		.cap = cap,
		.len = 0,
		.deletes = 0U,
		.all_deleted = 0,
		.keys = (uint8_t*)malloc(cap * key_bytes),
		.values = (uint8_t*)malloc(cap * value_bytes),
	});
}
inline void* DenseArray_key(DenseArray* d, int i) {
	return ((void*)(d->keys + i * d->key_bytes));
}
inline void* DenseArray_value(DenseArray* d, int i) {
	return ((void*)(d->values + i * d->value_bytes));
}
inline bool DenseArray_has_index(DenseArray* d, int i) {
	return d->deletes == 0U || d->all_deleted[i] == 0;
}
inline int DenseArray_expand(DenseArray* d) {
	if (d->cap == d->len) {
		d->cap += d->cap >> 3;
		d->keys = (uint8_t*)realloc(d->keys, d->key_bytes * d->cap);
		d->values = (uint8_t*)realloc(d->values, d->value_bytes * d->cap);
		if (d->deletes != 0U) {
			d->all_deleted = (uint8_t*)realloc(d->all_deleted, d->cap);
			memset(((void*)(d->all_deleted + d->len)), 0, d->cap - d->len);
		}
	}
	int push_index = d->len;
	if (d->deletes != 0U) {
		d->all_deleted[push_index] = 0;
	}
	d->len++;
	return push_index;
}

map new_map(int key_bytes, int value_bytes, MapHashFn hash_fn, MapEqFn key_eq_fn, MapCloneFn clone_fn, MapFreeFn free_fn) {
	int metasize = ((int)(sizeof(uint32_t) * (_const_init_capicity + _const_extra_metas_inc)));
	bool has_string_keys = (int)sizeof(void*) > key_bytes;
	return ((map){
		.key_bytes = key_bytes,
		.value_bytes = value_bytes,
		.even_index = _const_init_even_index,
		.cached_hashbits = _const_max_cached_hashbits,
		.shift = _const_init_log_capicity,
		.key_values = new_dense_array(key_bytes, value_bytes),
		.metas = ((uint32_t*)(calloc(1, metasize))),
		.extra_metas = _const_extra_metas_inc,
		.has_string_keys = has_string_keys,
		.hash_fn = hash_fn,
		.key_eq_fn = key_eq_fn,
		.clone_fn = clone_fn,
		.free_fn = free_fn,
		.len = 0,
	});
}
map new_map_init(MapHashFn hash_fn, MapEqFn key_eq_fn, MapCloneFn clone_fn, MapFreeFn free_fn, int n, int key_bytes, int value_bytes, void* keys, void* values) {
	map out = new_map(key_bytes, value_bytes, hash_fn, key_eq_fn, clone_fn, free_fn);
	uint8_t* pkey = ((uint8_t*)(keys));
	uint8_t* pval = ((uint8_t*)(values));
	for (int _t1 = 0; _t1 < n; ++_t1) {
		map_set(&out, pkey, pval);
		pkey = pkey + key_bytes;
		pval = pval + value_bytes;
	}
	return out;
}
map map_move(map* m) {
	map r = *m;
	memset(m, 0, ((int)(sizeof(map))));
	return r;
}
void map_clear(map* m) {
	m->len = 0;
	m->key_values.len = 0;
}
inline multi_return_uint32_t_uint32_t map_key_to_index(map* m, void* pkey) {
	uint64_t hash = m->hash_fn(pkey);
	uint64_t index = (hash & m->even_index);
	uint64_t meta = ((((hash >> m->shift) & _const_hash_mask)) | _const_probe_inc);
	return (multi_return_uint32_t_uint32_t){.arg0=((uint32_t)(index)), .arg1=((uint32_t)(meta))};
}
inline multi_return_uint32_t_uint32_t map_meta_less(map* m, uint32_t _index, uint32_t _metas) {
	uint32_t index = _index;
	uint32_t meta = _metas;
	for (;;) {
		if (!(meta < m->metas[index])) break;
		index += 2U;
		meta += _const_probe_inc;
	}
	return (multi_return_uint32_t_uint32_t){.arg0=index, .arg1=meta};
}
inline void map_meta_greater(map* m, uint32_t _index, uint32_t _metas, uint32_t kvi) {
	uint32_t meta = _metas;
	uint32_t index = _index;
	uint32_t kv_index = kvi;
	for (;;) {
		if (!(m->metas[index] != 0U)) break;
		if (meta > m->metas[index]) {
			uint32_t tmp_meta = m->metas[index];
			m->metas[index] = meta;
			meta = tmp_meta;
			uint32_t tmp_index = m->metas[index + 1U];
			m->metas[index + 1U] = kv_index;
			kv_index = tmp_index;
		}
		index += 2U;
		meta += _const_probe_inc;
	}
	m->metas[index] = meta;
	m->metas[index + 1U] = kv_index;

	uint32_t probe_count = (meta >> _const_hashbits) - 1U;
	map_ensure_extra_metas(m, probe_count);
}
inline void map_ensure_extra_metas(map* m, uint32_t probe_count) {
	if ((probe_count << 1U) == m->extra_metas) {
		uint32_t size_of_uint32_t = sizeof(uint32_t);
		m->extra_metas += _const_extra_metas_inc;
		uint32_t mem_size = (m->even_index + 2U + m->extra_metas);
		uint8_t* x = (uint8_t*)realloc(((uint8_t*)(m->metas)), ((int)(size_of_uint32_t * mem_size)));
		m->metas = ((uint32_t*)(x));
		memset(m->metas + mem_size - _const_extra_metas_inc, 0, ((int)(sizeof(uint32_t) * _const_extra_metas_inc)));
	}
}
void map_set(map* m, void* key, void* value) {
	float load_factor = ((float)(((uint32_t)(m->len)) << 1U)) / ((float)(m->even_index));
	if (load_factor > _const_max_load_factor) {
		map_expand(m);
	}
	multi_return_uint32_t_uint32_t mr_11138 = map_key_to_index(m, key);
	uint32_t index = mr_11138.arg0;
	uint32_t meta = mr_11138.arg1;
	multi_return_uint32_t_uint32_t mr_11174 = map_meta_less(m, index, meta);
	index = mr_11174.arg0;
	meta = mr_11174.arg1;
	for (;;) {
		if (!(meta == m->metas[index])) break;
		int kv_index = ((int)(m->metas[index + 1U]));
		void* pkey = DenseArray_key(&m->key_values, kv_index);
		if (m->key_eq_fn(key, pkey)) {
			void* pval = DenseArray_value(&m->key_values, kv_index);
			memcpy(pval, value, m->value_bytes);
			return;
		}
		index += 2U;
		meta += _const_probe_inc;
	}
	int kv_index = DenseArray_expand(&m->key_values);
	void* pkey = DenseArray_key(&m->key_values, kv_index);
	void* pvalue = DenseArray_value(&m->key_values, kv_index);
	m->clone_fn(pkey, key);
	memcpy(((uint8_t*)(pvalue)), value, m->value_bytes);
	map_meta_greater(m, index, meta, ((uint32_t)(kv_index)));
	m->len++;
}
void map_expand(map* m) {
	uint32_t old_cap = m->even_index;
	m->even_index = ((m->even_index + 2U) << 1U) - 2U;
	if (m->cached_hashbits == 0) {
		m->shift += _const_max_cached_hashbits;
		m->cached_hashbits = _const_max_cached_hashbits;
		map_rehash(m);
	} else {
		map_cached_rehash(m, old_cap);
		m->cached_hashbits--;
	}
}
void map_rehash(map* m) {
	uint32_t meta_bytes = sizeof(uint32_t) * (m->even_index + 2U + m->extra_metas);
	uint8_t* x = (uint8_t*)realloc(((uint8_t*)(m->metas)), ((int)(meta_bytes)));
	m->metas = ((uint32_t*)(x));
	memset(m->metas, 0, ((int)(meta_bytes)));

	for (int i = 0; i < m->key_values.len; i++) {
		if (!DenseArray_has_index(&m->key_values, i)) {
			continue;
		}
		void* pkey = DenseArray_key(&m->key_values, i);
		multi_return_uint32_t_uint32_t mr_12837 = map_key_to_index(m, pkey);
		uint32_t index = mr_12837.arg0;
		uint32_t meta = mr_12837.arg1;
		multi_return_uint32_t_uint32_t mr_12875 = map_meta_less(m, index, meta);
		index = mr_12875.arg0;
		meta = mr_12875.arg1;
		map_meta_greater(m, index, meta, ((uint32_t)(i)));
	}
}
void map_cached_rehash(map* m, uint32_t old_cap) {
	uint32_t* old_metas = m->metas;
	m->metas = ((uint32_t*)(calloc(m->even_index + 2U + m->extra_metas, sizeof(uint32_t))));
	uint32_t old_extra_metas = m->extra_metas;
	for (uint32_t i = ((uint32_t)(0U)); i <= old_cap + old_extra_metas; i += 2U) {
		if (old_metas[i] == 0U) {
			continue;
		}
		uint32_t old_meta = old_metas[i];
		uint32_t old_probe_count = ((old_meta >> _const_hashbits) - 1U) << 1U;
		uint32_t old_index = ((i - old_probe_count) & (m->even_index >> 1U));
		uint32_t index = (((old_index | (old_meta << m->shift))) & m->even_index);
		uint32_t meta = (((old_meta & _const_hash_mask)) | _const_probe_inc);
		multi_return_uint32_t_uint32_t mr_13674 = map_meta_less(m, index, meta);
		index = mr_13674.arg0;
		meta = mr_13674.arg1;
		uint32_t kv_index = old_metas[i + 1U];
		map_meta_greater(m, index, meta, kv_index);
	}
	free(old_metas);
}
void* map_get_and_set(map* m, void* key, void* zero) {
	for (;;) {
		multi_return_uint32_t_uint32_t mr_14122 = map_key_to_index(m, key);
		uint32_t index = mr_14122.arg0;
		uint32_t meta = mr_14122.arg1;
		for (;;) {
			if (meta == m->metas[index]) {
				int kv_index = ((int)(m->metas[index + 1U]));
				void* pkey = DenseArray_key(&m->key_values, kv_index);
				if (m->key_eq_fn(key, pkey)) {
					void* pval = DenseArray_value(&m->key_values, kv_index);
					return ((uint8_t*)(pval));
				}
			}
			index += 2U;
			meta += _const_probe_inc;
			if (meta > m->metas[index]) {
				break;
			}
		}
		map_set(m, key, zero);
	}
	return ((void*)0);
}
void* map_get(map* m, void* key, void* zero) {
	multi_return_uint32_t_uint32_t mr_14849 = map_key_to_index(m, key);
	uint32_t index = mr_14849.arg0;
	uint32_t meta = mr_14849.arg1;
	for (;;) {
		if (meta == m->metas[index]) {
			int kv_index = ((int)(m->metas[index + 1U]));
			void* pkey = DenseArray_key(&m->key_values, kv_index);
			if (m->key_eq_fn(key, pkey)) {
				void* pval = DenseArray_value(&m->key_values, kv_index);
				return ((uint8_t*)(pval));
			}
		}
		index += 2U;
		meta += _const_probe_inc;
		if (meta > m->metas[index]) {
			break;
		}
	}
	return zero;
}
void* map_get_check(map* m, void* key) {
	multi_return_uint32_t_uint32_t mr_15514 = map_key_to_index(m, key);
	uint32_t index = mr_15514.arg0;
	uint32_t meta = mr_15514.arg1;
	for (;;) {
		if (meta == m->metas[index]) {
			int kv_index = ((int)(m->metas[index + 1U]));
			void* pkey = DenseArray_key(&m->key_values, kv_index);
			if (m->key_eq_fn(key, pkey)) {
				void* pval = DenseArray_value(&m->key_values, kv_index);
				return ((uint8_t*)(pval));
			}
		}
		index += 2U;
		meta += _const_probe_inc;
		if (meta > m->metas[index]) {
			break;
		}
	}
	return 0;
}
bool map_exists(map* m, void* key) {
	multi_return_uint32_t_uint32_t mr_16024 = map_key_to_index(m, key);
	uint32_t index = mr_16024.arg0;
	uint32_t meta = mr_16024.arg1;
	for (;;) {
		if (meta == m->metas[index]) {
			int kv_index = ((int)(m->metas[index + 1U]));
			void* pkey = DenseArray_key(&m->key_values, kv_index);
			if (m->key_eq_fn(key, pkey)) {
				return true;
			}
		}
		index += 2U;
		meta += _const_probe_inc;
		if (meta > m->metas[index]) {
			break;
		}
	}
	return false;
}
inline void DenseArray_delete(DenseArray* d, int i) {
	if (d->deletes == 0U) {
		d->all_deleted = (uint8_t*)calloc(1, d->cap);
	}
	d->deletes++;
	d->all_deleted[i] = 1;
}
void map_delete(map* m, void* key) {
	multi_return_uint32_t_uint32_t mr_16653 = map_key_to_index(m, key);
	uint32_t index = mr_16653.arg0;
	uint32_t meta = mr_16653.arg1;
	multi_return_uint32_t_uint32_t mr_16689 = map_meta_less(m, index, meta);
	index = mr_16689.arg0;
	meta = mr_16689.arg1;
	for (;;) {
		if (!(meta == m->metas[index])) break;
		int kv_index = ((int)(m->metas[index + 1U]));
		void* pkey = DenseArray_key(&m->key_values, kv_index);
		if (m->key_eq_fn(key, pkey)) {
			for (;;) {
				if (!((m->metas[index + 2U] >> _const_hashbits) > 1U)) break;
				m->metas[index] = m->metas[index + 2U] - _const_probe_inc;
				m->metas[index + 1U] = m->metas[index + 3U];
				index += 2U;
			}
			m->len--;
			DenseArray_delete(&m->key_values, kv_index);
			m->metas[index] = 0U;
			m->free_fn(pkey);
			memset(pkey, 0, m->key_bytes);
			if (m->key_values.len <= 32) {
				return;
			}
			if (m->key_values.deletes >= (uint32_t)(m->key_values.len >> 1)) {
				DenseArray_zeros_to_end(&m->key_values);
				map_rehash(m);
			}
			return;
		}
		index += 2U;
		meta += _const_probe_inc;
	}
}
// array map_keys(map* m) {
// 	array keys = __new_array(m->len, 0, m->key_bytes);
// 	uint8_t* item = ((uint8_t*)(keys.data));
// 	if (m->key_values.deletes == 0U) {
// 		for (int i = 0; i < m->key_values.len; i++) {
// 			void* pkey = DenseArray_key(&m->key_values, i);
// 			m->clone_fn(item, pkey);
// 			item = item + m->key_bytes;
// 		}
// 		return keys;
// 	}
// 	for (int i = 0; i < m->key_values.len; i++) {
// 		if (!DenseArray_has_index(&m->key_values, i)) {
// 			continue;
// 		}
// 		void* pkey = DenseArray_key(&m->key_values, i);
// 		m->clone_fn(item, pkey);
// 		item = item + m->key_bytes;
// 	}
// 	return keys;
// }
// array map_values(map* m) {
// 	array values = __new_array(m->len, 0, m->value_bytes);
// 	uint8_t* item = ((uint8_t*)(values.data));
// 	if (m->key_values.deletes == 0U) {
// 		memcpy(item, m->key_values.values, m->value_bytes * m->key_values.len);
// 		return values;
// 	}
// 	for (int i = 0; i < m->key_values.len; i++) {
// 		if (!DenseArray_has_index(&m->key_values, i)) {
// 			continue;
// 		}
// 		void* pvalue = DenseArray_value(&m->key_values, i);
// 		memcpy(item, pvalue, m->value_bytes);
// 		item = item + m->value_bytes;
// 	}
// 	return values;
// }
DenseArray DenseArray_clone(DenseArray* d) {
	DenseArray res = ((DenseArray){
		.key_bytes = d->key_bytes,
		.value_bytes = d->value_bytes,
		.cap = d->cap,
		.len = d->len,
		.deletes = d->deletes,
		.all_deleted = 0,
		.keys = 0,
		.values = 0,
	});
	if (d->deletes != 0U) {
		res.all_deleted = (uint8_t*)malloc(d->cap);
		memcpy(res.all_deleted, d->all_deleted, d->cap);
	}
	res.keys = (uint8_t*)malloc(d->cap * d->key_bytes);
	memcpy(res.keys, d->keys, d->cap * d->key_bytes);
	res.values = (uint8_t*)malloc(d->cap * d->value_bytes);
	memcpy(res.values, d->values, d->cap * d->value_bytes);
	return res;
}
map map_clone(map* m) {
	int metasize = ((int)(sizeof(uint32_t) * (m->even_index + 2U + m->extra_metas)));
	map res = ((map){
		.key_bytes = m->key_bytes,
		.value_bytes = m->value_bytes,
		.even_index = m->even_index,
		.cached_hashbits = m->cached_hashbits,
		.shift = m->shift,
		.key_values = DenseArray_clone(&m->key_values),
		.metas = ((uint32_t*)(malloc(metasize))),
		.extra_metas = m->extra_metas,
		.has_string_keys = m->has_string_keys,
		.hash_fn = m->hash_fn,
		.key_eq_fn = m->key_eq_fn,
		.clone_fn = m->clone_fn,
		.free_fn = m->free_fn,
		.len = m->len,
	});
	memcpy(res.metas, m->metas, metasize);
	if (!m->has_string_keys) {
		return res;
	}
	for (int i = 0; i < m->key_values.len; ++i) {
		if (!DenseArray_has_index(&m->key_values, i)) {
			continue;
		}
		m->clone_fn(DenseArray_key(&res.key_values, i), DenseArray_key(&m->key_values, i));
	}
	return res;
}
void map_free(map* m) {
	free(m->metas);
	if (m->key_values.deletes == 0U) {
		for (int i = 0; i < m->key_values.len; i++) {
			void* pkey = DenseArray_key(&m->key_values, i);
			m->free_fn(pkey);
		}
	} else {
		for (int i = 0; i < m->key_values.len; i++) {
			if (!DenseArray_has_index(&m->key_values, i)) {
				continue;
			}
			void* pkey = DenseArray_key(&m->key_values, i);
			m->free_fn(pkey);
		}
		free(m->key_values.all_deleted);
	}
	free(m->key_values.keys);
	free(m->key_values.values);
}
