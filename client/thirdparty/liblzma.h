#ifndef LZMA_H
#define LZMA_H
#ifndef LZMA_MANUAL_HEADERS
#	include <stddef.h>
#	if !defined(UINT32_C) || !defined(UINT64_C) \
			|| !defined(UINT32_MAX) || !defined(UINT64_MAX)
#if defined(_WIN32) && defined(_MSC_VER) && _MSC_VER < 1800
			typedef unsigned __int8 uint8_t;
			typedef unsigned __int32 uint32_t;
			typedef unsigned __int64 uint64_t;
#else
#ifdef __cplusplus
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS 1
#endif
#ifndef __STDC_CONSTANT_MACROS
#define __STDC_CONSTANT_MACROS 1
#endif
#endif
#include <inttypes.h>
#endif
#ifndef UINT32_C
#if defined(_WIN32) && defined(_MSC_VER)
#define UINT32_C(n) n ## UI32
#else
#define UINT32_C(n) n ## U
#endif
#endif
#ifndef UINT64_C
#if defined(_WIN32) && defined(_MSC_VER)
#define UINT64_C(n) n ## UI64
#else
#include <limits.h>
#if ULONG_MAX == 4294967295UL
#define UINT64_C(n) n ## ULL
#else
#define UINT64_C(n) n ## UL
#endif
#endif
#endif
#ifndef UINT32_MAX
#define UINT32_MAX (UINT32_C(4294967295))
#endif
#ifndef UINT64_MAX
#define UINT64_MAX (UINT64_C(18446744073709551615))
#endif
#	endif
#endif /* ifdef LZMA_MANUAL_HEADERS */
#ifndef LZMA_API_IMPORT
#	if !defined(LZMA_API_STATIC) && defined(_WIN32) && !defined(__GNUC__)
#define LZMA_API_IMPORT __declspec(dllimport)
#	else
#define LZMA_API_IMPORT
#	endif
#endif
#ifndef LZMA_API_CALL
#	if defined(_WIN32) && !defined(__CYGWIN__)
#define LZMA_API_CALL __cdecl
#	else
#define LZMA_API_CALL
#	endif
#endif
#ifndef LZMA_API
#	define LZMA_API(type) LZMA_API_IMPORT type LZMA_API_CALL
#endif
#ifndef lzma_nothrow
#	if defined(__cplusplus)
#if __cplusplus >= 201103L || (defined(_MSVC_LANG) \
				&& _MSVC_LANG >= 201103L)
#define lzma_nothrow noexcept
#else
#define lzma_nothrow throw()
#endif
#	elif defined(__GNUC__) && (__GNUC__ > 3 \
			|| (__GNUC__ == 3 && __GNUC_MINOR__ >= 3))
#define lzma_nothrow __attribute__((__nothrow__))
#	else
#define lzma_nothrow
#	endif
#endif
#if defined(__GNUC__) && __GNUC__ >= 3
#	ifndef lzma_attribute
#define lzma_attribute(attr) __attribute__(attr)
#	endif
#	ifndef lzma_attr_warn_unused_result
#if __GNUC__ == 3 && __GNUC_MINOR__ < 4
#define lzma_attr_warn_unused_result
#endif
#	endif
#else
#	ifndef lzma_attribute
#define lzma_attribute(attr)
#	endif
#endif
#ifndef lzma_attr_pure
#	define lzma_attr_pure lzma_attribute((__pure__))
#endif
#ifndef lzma_attr_const
#	define lzma_attr_const lzma_attribute((__const__))
#endif
#ifndef lzma_attr_warn_unused_result
#	define lzma_attr_warn_unused_result \
		lzma_attribute((__warn_unused_result__))
#endif
#ifdef __cplusplus
extern "C" {
#endif
#define LZMA_H_INTERNAL 1
#define LZMA_VERSION_MAJOR 5
#define LZMA_VERSION_MINOR 3
#define LZMA_VERSION_PATCH 3
#define LZMA_VERSION_STABILITY LZMA_VERSION_STABILITY_ALPHA
#ifndef LZMA_VERSION_COMMIT
#	define LZMA_VERSION_COMMIT ""
#endif
#define LZMA_VERSION_STABILITY_ALPHA 0
#define LZMA_VERSION_STABILITY_BETA 1
#define LZMA_VERSION_STABILITY_STABLE 2
#define LZMA_VERSION (LZMA_VERSION_MAJOR * UINT32_C(10000000) \
		+ LZMA_VERSION_MINOR * UINT32_C(10000) \
		+ LZMA_VERSION_PATCH * UINT32_C(10) \
		+ LZMA_VERSION_STABILITY)
#if LZMA_VERSION_STABILITY == LZMA_VERSION_STABILITY_ALPHA
#	define LZMA_VERSION_STABILITY_STRING "alpha"
#elif LZMA_VERSION_STABILITY == LZMA_VERSION_STABILITY_BETA
#	define LZMA_VERSION_STABILITY_STRING "beta"
#elif LZMA_VERSION_STABILITY == LZMA_VERSION_STABILITY_STABLE
#	define LZMA_VERSION_STABILITY_STRING ""
#else
#	error Incorrect LZMA_VERSION_STABILITY
#endif
#define LZMA_VERSION_STRING_C_(major, minor, patch, stability, commit) \
		#major "." #minor "." #patch stability commit
#define LZMA_VERSION_STRING_C(major, minor, patch, stability, commit) \
		LZMA_VERSION_STRING_C_(major, minor, patch, stability, commit)
#define LZMA_VERSION_STRING LZMA_VERSION_STRING_C( \
		LZMA_VERSION_MAJOR, LZMA_VERSION_MINOR, \
		LZMA_VERSION_PATCH, LZMA_VERSION_STABILITY_STRING, \
		LZMA_VERSION_COMMIT)
#ifndef LZMA_H_INTERNAL_RC
extern LZMA_API(uint32_t) lzma_version_number(void)
		lzma_nothrow lzma_attr_const;
extern LZMA_API(const char *) lzma_version_string(void)
		lzma_nothrow lzma_attr_const;
#endif
typedef unsigned char lzma_bool;
typedef enum {
	LZMA_RESERVED_ENUM      = 0
} lzma_reserved_enum;
typedef enum {
	LZMA_OK                 = 0,
	LZMA_STREAM_END         = 1,
	LZMA_NO_CHECK           = 2,
	LZMA_UNSUPPORTED_CHECK  = 3,
	LZMA_GET_CHECK          = 4,
	LZMA_MEM_ERROR          = 5,
	LZMA_MEMLIMIT_ERROR     = 6,
	LZMA_FORMAT_ERROR       = 7,
	LZMA_OPTIONS_ERROR      = 8,
	LZMA_DATA_ERROR         = 9,
	LZMA_BUF_ERROR          = 10,
	LZMA_PROG_ERROR         = 11,
	LZMA_SEEK_NEEDED        = 12,
	LZMA_RET_INTERNAL1      = 101,
	LZMA_RET_INTERNAL2      = 102,
	LZMA_RET_INTERNAL3      = 103,
	LZMA_RET_INTERNAL4      = 104,
	LZMA_RET_INTERNAL5      = 105,
	LZMA_RET_INTERNAL6      = 106,
	LZMA_RET_INTERNAL7      = 107,
	LZMA_RET_INTERNAL8      = 108
} lzma_ret;
typedef enum {
	LZMA_RUN = 0,
	LZMA_SYNC_FLUSH = 1,
	LZMA_FULL_FLUSH = 2,
	LZMA_FULL_BARRIER = 4,
	LZMA_FINISH = 3
} lzma_action;
typedef struct {
	void *(LZMA_API_CALL *alloc)(void *opaque, size_t nmemb, size_t size);
	void (LZMA_API_CALL *free)(void *opaque, void *ptr);
	void *opaque;
} lzma_allocator;
typedef struct lzma_internal_s lzma_internal;
typedef struct {
	const uint8_t *next_in; /**< Pointer to the next input byte. */
	size_t avail_in;    /**< Number of available input bytes in next_in. */
	uint64_t total_in;  /**< Total number of bytes read by liblzma. */
	uint8_t *next_out;  /**< Pointer to the next output position. */
	size_t avail_out;   /**< Amount of free space in next_out. */
	uint64_t total_out; /**< Total number of bytes written by liblzma. */
	const lzma_allocator *allocator;
	lzma_internal *internal;
	void *reserved_ptr1;
	void *reserved_ptr2;
	void *reserved_ptr3;
	void *reserved_ptr4;
	uint64_t seek_pos;
	uint64_t reserved_int2;
	size_t reserved_int3;
	size_t reserved_int4;
	lzma_reserved_enum reserved_enum1;
	lzma_reserved_enum reserved_enum2;
} lzma_stream;
#define LZMA_STREAM_INIT \
	{ NULL, 0, 0, NULL, 0, 0, NULL, NULL, \
	NULL, NULL, NULL, NULL, 0, 0, 0, 0, \
	LZMA_RESERVED_ENUM, LZMA_RESERVED_ENUM }
extern LZMA_API(lzma_ret) lzma_code(lzma_stream *strm, lzma_action action)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(void) lzma_end(lzma_stream *strm) lzma_nothrow;
extern LZMA_API(void) lzma_get_progress(lzma_stream *strm,
		uint64_t *progress_in, uint64_t *progress_out) lzma_nothrow;
extern LZMA_API(uint64_t) lzma_memusage(const lzma_stream *strm)
		lzma_nothrow lzma_attr_pure;
extern LZMA_API(uint64_t) lzma_memlimit_get(const lzma_stream *strm)
		lzma_nothrow lzma_attr_pure;
extern LZMA_API(lzma_ret) lzma_memlimit_set(
		lzma_stream *strm, uint64_t memlimit) lzma_nothrow;
#define LZMA_VLI_MAX (UINT64_MAX / 2)
#define LZMA_VLI_UNKNOWN UINT64_MAX
#define LZMA_VLI_BYTES_MAX 9
#define LZMA_VLI_C(n) UINT64_C(n)
typedef uint64_t lzma_vli;
#define lzma_vli_is_valid(vli) \
	((vli) <= LZMA_VLI_MAX || (vli) == LZMA_VLI_UNKNOWN)
extern LZMA_API(lzma_ret) lzma_vli_encode(lzma_vli vli, size_t *vli_pos,
		uint8_t *out, size_t *out_pos, size_t out_size) lzma_nothrow;
extern LZMA_API(lzma_ret) lzma_vli_decode(lzma_vli *vli, size_t *vli_pos,
		const uint8_t *in, size_t *in_pos, size_t in_size)
		lzma_nothrow;
extern LZMA_API(uint32_t) lzma_vli_size(lzma_vli vli)
		lzma_nothrow lzma_attr_pure;
typedef enum {
	LZMA_CHECK_NONE     = 0,
	LZMA_CHECK_CRC32    = 1,
	LZMA_CHECK_CRC64    = 4,
	LZMA_CHECK_SHA256   = 10
} lzma_check;
#define LZMA_CHECK_ID_MAX 15
extern LZMA_API(lzma_bool) lzma_check_is_supported(lzma_check check)
		lzma_nothrow lzma_attr_const;
extern LZMA_API(uint32_t) lzma_check_size(lzma_check check)
		lzma_nothrow lzma_attr_const;
#define LZMA_CHECK_SIZE_MAX 64
extern LZMA_API(uint32_t) lzma_crc32(
		const uint8_t *buf, size_t size, uint32_t crc)
		lzma_nothrow lzma_attr_pure;
extern LZMA_API(uint64_t) lzma_crc64(
		const uint8_t *buf, size_t size, uint64_t crc)
		lzma_nothrow lzma_attr_pure;
extern LZMA_API(lzma_check) lzma_get_check(const lzma_stream *strm)
		lzma_nothrow;
#define LZMA_FILTERS_MAX 4
typedef struct {
	lzma_vli id;
	void *options;
} lzma_filter;
extern LZMA_API(lzma_bool) lzma_filter_encoder_is_supported(lzma_vli id)
		lzma_nothrow lzma_attr_const;
extern LZMA_API(lzma_bool) lzma_filter_decoder_is_supported(lzma_vli id)
		lzma_nothrow lzma_attr_const;
extern LZMA_API(lzma_ret) lzma_filters_copy(
		const lzma_filter *src, lzma_filter *dest,
		const lzma_allocator *allocator) lzma_nothrow;
extern LZMA_API(uint64_t) lzma_raw_encoder_memusage(const lzma_filter *filters)
		lzma_nothrow lzma_attr_pure;
extern LZMA_API(uint64_t) lzma_raw_decoder_memusage(const lzma_filter *filters)
		lzma_nothrow lzma_attr_pure;
extern LZMA_API(lzma_ret) lzma_raw_encoder(
		lzma_stream *strm, const lzma_filter *filters)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_raw_decoder(
		lzma_stream *strm, const lzma_filter *filters)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_filters_update(
		lzma_stream *strm, const lzma_filter *filters) lzma_nothrow;
extern LZMA_API(lzma_ret) lzma_raw_buffer_encode(
		const lzma_filter *filters, const lzma_allocator *allocator,
		const uint8_t *in, size_t in_size, uint8_t *out,
		size_t *out_pos, size_t out_size) lzma_nothrow;
extern LZMA_API(lzma_ret) lzma_raw_buffer_decode(
		const lzma_filter *filters, const lzma_allocator *allocator,
		const uint8_t *in, size_t *in_pos, size_t in_size,
		uint8_t *out, size_t *out_pos, size_t out_size) lzma_nothrow;
extern LZMA_API(lzma_ret) lzma_properties_size(
		uint32_t *size, const lzma_filter *filter) lzma_nothrow;
extern LZMA_API(lzma_ret) lzma_properties_encode(
		const lzma_filter *filter, uint8_t *props) lzma_nothrow;
extern LZMA_API(lzma_ret) lzma_properties_decode(
		lzma_filter *filter, const lzma_allocator *allocator,
		const uint8_t *props, size_t props_size) lzma_nothrow;
extern LZMA_API(lzma_ret) lzma_filter_flags_size(
		uint32_t *size, const lzma_filter *filter)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_filter_flags_encode(const lzma_filter *filter,
		uint8_t *out, size_t *out_pos, size_t out_size)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_filter_flags_decode(
		lzma_filter *filter, const lzma_allocator *allocator,
		const uint8_t *in, size_t *in_pos, size_t in_size)
		lzma_nothrow lzma_attr_warn_unused_result;
#define LZMA_FILTER_X86         LZMA_VLI_C(0x04)
#define LZMA_FILTER_POWERPC     LZMA_VLI_C(0x05)
#define LZMA_FILTER_IA64        LZMA_VLI_C(0x06)
#define LZMA_FILTER_ARM         LZMA_VLI_C(0x07)
#define LZMA_FILTER_ARMTHUMB    LZMA_VLI_C(0x08)
#define LZMA_FILTER_SPARC       LZMA_VLI_C(0x09)
#define LZMA_FILTER_ARM64       LZMA_VLI_C(0x3FDB87B33B27000B)
typedef struct {
	uint32_t start_offset;
} lzma_options_bcj;
typedef struct {
	uint32_t width;
#	define LZMA_ARM64_WIDTH_MIN     18
#	define LZMA_ARM64_WIDTH_MAX     28
#	define LZMA_ARM64_WIDTH_DEFAULT 26
} lzma_options_arm64;
#define LZMA_FILTER_DELTA       LZMA_VLI_C(0x03)
typedef enum {
	LZMA_DELTA_TYPE_BYTE
} lzma_delta_type;
typedef struct {
	lzma_delta_type type;
	uint32_t dist;
#	define LZMA_DELTA_DIST_MIN 1
#	define LZMA_DELTA_DIST_MAX 256
	uint32_t reserved_int1;
	uint32_t reserved_int2;
	uint32_t reserved_int3;
	uint32_t reserved_int4;
	void *reserved_ptr1;
	void *reserved_ptr2;
} lzma_options_delta;
#define LZMA_FILTER_LZMA1       LZMA_VLI_C(0x4000000000000001)
#define LZMA_FILTER_LZMA2       LZMA_VLI_C(0x21)
typedef enum {
	LZMA_MF_HC3     = 0x03,
	LZMA_MF_HC4     = 0x04,
	LZMA_MF_BT2     = 0x12,
	LZMA_MF_BT3     = 0x13,
	LZMA_MF_BT4     = 0x14
} lzma_match_finder;
extern LZMA_API(lzma_bool) lzma_mf_is_supported(lzma_match_finder match_finder)
		lzma_nothrow lzma_attr_const;
typedef enum {
	LZMA_MODE_FAST = 1,
	LZMA_MODE_NORMAL = 2
} lzma_mode;
extern LZMA_API(lzma_bool) lzma_mode_is_supported(lzma_mode mode)
		lzma_nothrow lzma_attr_const;
typedef struct {
	uint32_t dict_size;
#	define LZMA_DICT_SIZE_MIN       UINT32_C(4096)
#	define LZMA_DICT_SIZE_DEFAULT   (UINT32_C(1) << 23)
	const uint8_t *preset_dict;
	uint32_t preset_dict_size;
	uint32_t lc;
#	define LZMA_LCLP_MIN    0
#	define LZMA_LCLP_MAX    4
#	define LZMA_LC_DEFAULT  3
	uint32_t lp;
#	define LZMA_LP_DEFAULT  0
	uint32_t pb;
#	define LZMA_PB_MIN      0
#	define LZMA_PB_MAX      4
#	define LZMA_PB_DEFAULT  2
	lzma_mode mode;
	uint32_t nice_len;
	lzma_match_finder mf;
	uint32_t depth;
	uint32_t reserved_int1;
	uint32_t reserved_int2;
	uint32_t reserved_int3;
	uint32_t reserved_int4;
	uint32_t reserved_int5;
	uint32_t reserved_int6;
	uint32_t reserved_int7;
	uint32_t reserved_int8;
	lzma_reserved_enum reserved_enum1;
	lzma_reserved_enum reserved_enum2;
	lzma_reserved_enum reserved_enum3;
	lzma_reserved_enum reserved_enum4;
	void *reserved_ptr1;
	void *reserved_ptr2;
} lzma_options_lzma;
extern LZMA_API(lzma_bool) lzma_lzma_preset(
		lzma_options_lzma *options, uint32_t preset) lzma_nothrow;
#define LZMA_PRESET_DEFAULT     UINT32_C(6)
#define LZMA_PRESET_LEVEL_MASK  UINT32_C(0x1F)
#define LZMA_PRESET_EXTREME       (UINT32_C(1) << 31)
typedef struct {
	uint32_t flags;
	uint32_t threads;
	uint64_t block_size;
	uint32_t timeout;
	uint32_t preset;
	const lzma_filter *filters;
	lzma_check check;
	lzma_reserved_enum reserved_enum1;
	lzma_reserved_enum reserved_enum2;
	lzma_reserved_enum reserved_enum3;
	uint32_t reserved_int1;
	uint32_t reserved_int2;
	uint32_t reserved_int3;
	uint32_t reserved_int4;
	uint64_t memlimit_threading;
	uint64_t memlimit_stop;
	uint64_t reserved_int7;
	uint64_t reserved_int8;
	void *reserved_ptr1;
	void *reserved_ptr2;
	void *reserved_ptr3;
	void *reserved_ptr4;
} lzma_mt;
extern LZMA_API(uint64_t) lzma_easy_encoder_memusage(uint32_t preset)
		lzma_nothrow lzma_attr_pure;
extern LZMA_API(uint64_t) lzma_easy_decoder_memusage(uint32_t preset)
		lzma_nothrow lzma_attr_pure;
extern LZMA_API(lzma_ret) lzma_easy_encoder(
		lzma_stream *strm, uint32_t preset, lzma_check check)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_easy_buffer_encode(
		uint32_t preset, lzma_check check,
		const lzma_allocator *allocator,
		const uint8_t *in, size_t in_size,
		uint8_t *out, size_t *out_pos, size_t out_size) lzma_nothrow;
extern LZMA_API(lzma_ret) lzma_stream_encoder(lzma_stream *strm,
		const lzma_filter *filters, lzma_check check)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(uint64_t) lzma_stream_encoder_mt_memusage(
		const lzma_mt *options) lzma_nothrow lzma_attr_pure;
extern LZMA_API(lzma_ret) lzma_stream_encoder_mt(
		lzma_stream *strm, const lzma_mt *options)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_alone_encoder(
		lzma_stream *strm, const lzma_options_lzma *options)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(size_t) lzma_stream_buffer_bound(size_t uncompressed_size)
		lzma_nothrow;
extern LZMA_API(lzma_ret) lzma_stream_buffer_encode(
		lzma_filter *filters, lzma_check check,
		const lzma_allocator *allocator,
		const uint8_t *in, size_t in_size,
		uint8_t *out, size_t *out_pos, size_t out_size)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_microlzma_encoder(
		lzma_stream *strm, const lzma_options_lzma *options);
#define LZMA_TELL_NO_CHECK              UINT32_C(0x01)
#define LZMA_TELL_UNSUPPORTED_CHECK     UINT32_C(0x02)
#define LZMA_TELL_ANY_CHECK             UINT32_C(0x04)
#define LZMA_IGNORE_CHECK               UINT32_C(0x10)
#define LZMA_CONCATENATED               UINT32_C(0x08)
#define LZMA_FAIL_FAST                  UINT32_C(0x20)
extern LZMA_API(lzma_ret) lzma_stream_decoder(
		lzma_stream *strm, uint64_t memlimit, uint32_t flags)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_stream_decoder_mt(
		lzma_stream *strm, const lzma_mt *options)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_auto_decoder(
		lzma_stream *strm, uint64_t memlimit, uint32_t flags)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_alone_decoder(
		lzma_stream *strm, uint64_t memlimit)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_stream_buffer_decode(
		uint64_t *memlimit, uint32_t flags,
		const lzma_allocator *allocator,
		const uint8_t *in, size_t *in_pos, size_t in_size,
		uint8_t *out, size_t *out_pos, size_t out_size)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_microlzma_decoder(
		lzma_stream *strm, uint64_t comp_size,
		uint64_t uncomp_size, lzma_bool uncomp_size_is_exact,
		uint32_t dict_size);
#define LZMA_STREAM_HEADER_SIZE 12
typedef struct {
	uint32_t version;
	lzma_vli backward_size;
#	define LZMA_BACKWARD_SIZE_MIN 4
#	define LZMA_BACKWARD_SIZE_MAX (LZMA_VLI_C(1) << 34)
	lzma_check check;
	lzma_reserved_enum reserved_enum1;
	lzma_reserved_enum reserved_enum2;
	lzma_reserved_enum reserved_enum3;
	lzma_reserved_enum reserved_enum4;
	lzma_bool reserved_bool1;
	lzma_bool reserved_bool2;
	lzma_bool reserved_bool3;
	lzma_bool reserved_bool4;
	lzma_bool reserved_bool5;
	lzma_bool reserved_bool6;
	lzma_bool reserved_bool7;
	lzma_bool reserved_bool8;
	uint32_t reserved_int1;
	uint32_t reserved_int2;
} lzma_stream_flags;
extern LZMA_API(lzma_ret) lzma_stream_header_encode(
		const lzma_stream_flags *options, uint8_t *out)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_stream_footer_encode(
		const lzma_stream_flags *options, uint8_t *out)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_stream_header_decode(
		lzma_stream_flags *options, const uint8_t *in)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_stream_footer_decode(
		lzma_stream_flags *options, const uint8_t *in)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_stream_flags_compare(
		const lzma_stream_flags *a, const lzma_stream_flags *b)
		lzma_nothrow lzma_attr_pure;
typedef struct {
	uint32_t version;
	uint32_t header_size;
#	define LZMA_BLOCK_HEADER_SIZE_MIN 8
#	define LZMA_BLOCK_HEADER_SIZE_MAX 1024
	lzma_check check;
	lzma_vli compressed_size;
	lzma_vli uncompressed_size;
	lzma_filter *filters;
	uint8_t raw_check[LZMA_CHECK_SIZE_MAX];
	void *reserved_ptr1;
	void *reserved_ptr2;
	void *reserved_ptr3;
	uint32_t reserved_int1;
	uint32_t reserved_int2;
	lzma_vli reserved_int3;
	lzma_vli reserved_int4;
	lzma_vli reserved_int5;
	lzma_vli reserved_int6;
	lzma_vli reserved_int7;
	lzma_vli reserved_int8;
	lzma_reserved_enum reserved_enum1;
	lzma_reserved_enum reserved_enum2;
	lzma_reserved_enum reserved_enum3;
	lzma_reserved_enum reserved_enum4;
	lzma_bool ignore_check;
	lzma_bool reserved_bool2;
	lzma_bool reserved_bool3;
	lzma_bool reserved_bool4;
	lzma_bool reserved_bool5;
	lzma_bool reserved_bool6;
	lzma_bool reserved_bool7;
	lzma_bool reserved_bool8;
} lzma_block;
#define lzma_block_header_size_decode(b) (((uint32_t)(b) + 1) * 4)
extern LZMA_API(lzma_ret) lzma_block_header_size(lzma_block *block)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_block_header_encode(
		const lzma_block *block, uint8_t *out)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_block_header_decode(lzma_block *block,
		const lzma_allocator *allocator, const uint8_t *in)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_block_compressed_size(
		lzma_block *block, lzma_vli unpadded_size)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_vli) lzma_block_unpadded_size(const lzma_block *block)
		lzma_nothrow lzma_attr_pure;
extern LZMA_API(lzma_vli) lzma_block_total_size(const lzma_block *block)
		lzma_nothrow lzma_attr_pure;
extern LZMA_API(lzma_ret) lzma_block_encoder(
		lzma_stream *strm, lzma_block *block)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_block_decoder(
		lzma_stream *strm, lzma_block *block)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(size_t) lzma_block_buffer_bound(size_t uncompressed_size)
		lzma_nothrow;
extern LZMA_API(lzma_ret) lzma_block_buffer_encode(
		lzma_block *block, const lzma_allocator *allocator,
		const uint8_t *in, size_t in_size,
		uint8_t *out, size_t *out_pos, size_t out_size)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_block_uncomp_encode(lzma_block *block,
		const uint8_t *in, size_t in_size,
		uint8_t *out, size_t *out_pos, size_t out_size)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_block_buffer_decode(
		lzma_block *block, const lzma_allocator *allocator,
		const uint8_t *in, size_t *in_pos, size_t in_size,
		uint8_t *out, size_t *out_pos, size_t out_size)
		lzma_nothrow;
typedef struct lzma_index_s lzma_index;
typedef struct {
	struct {
		const lzma_stream_flags *flags;
		const void *reserved_ptr1;
		const void *reserved_ptr2;
		const void *reserved_ptr3;
		lzma_vli number;
		lzma_vli block_count;
		lzma_vli compressed_offset;
		lzma_vli uncompressed_offset;
		lzma_vli compressed_size;
		lzma_vli uncompressed_size;
		lzma_vli padding;
		lzma_vli reserved_vli1;
		lzma_vli reserved_vli2;
		lzma_vli reserved_vli3;
		lzma_vli reserved_vli4;
	} stream;
	struct {
		lzma_vli number_in_file;
		lzma_vli compressed_file_offset;
		lzma_vli uncompressed_file_offset;
		lzma_vli number_in_stream;
		lzma_vli compressed_stream_offset;
		lzma_vli uncompressed_stream_offset;
		lzma_vli uncompressed_size;
		lzma_vli unpadded_size;
		lzma_vli total_size;
		lzma_vli reserved_vli1;
		lzma_vli reserved_vli2;
		lzma_vli reserved_vli3;
		lzma_vli reserved_vli4;
		const void *reserved_ptr1;
		const void *reserved_ptr2;
		const void *reserved_ptr3;
		const void *reserved_ptr4;
	} block;
	union {
		const void *p;
		size_t s;
		lzma_vli v;
	} internal[6];
} lzma_index_iter;
typedef enum {
	LZMA_INDEX_ITER_ANY             = 0,
	LZMA_INDEX_ITER_STREAM          = 1,
	LZMA_INDEX_ITER_BLOCK           = 2,
	LZMA_INDEX_ITER_NONEMPTY_BLOCK  = 3
} lzma_index_iter_mode;
extern LZMA_API(uint64_t) lzma_index_memusage(
		lzma_vli streams, lzma_vli blocks) lzma_nothrow;
extern LZMA_API(uint64_t) lzma_index_memused(const lzma_index *i)
		lzma_nothrow;
extern LZMA_API(lzma_index *) lzma_index_init(const lzma_allocator *allocator)
		lzma_nothrow;
extern LZMA_API(void) lzma_index_end(
		lzma_index *i, const lzma_allocator *allocator) lzma_nothrow;
extern LZMA_API(lzma_ret) lzma_index_append(
		lzma_index *i, const lzma_allocator *allocator,
		lzma_vli unpadded_size, lzma_vli uncompressed_size)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_index_stream_flags(
		lzma_index *i, const lzma_stream_flags *stream_flags)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(uint32_t) lzma_index_checks(const lzma_index *i)
		lzma_nothrow lzma_attr_pure;
extern LZMA_API(lzma_ret) lzma_index_stream_padding(
		lzma_index *i, lzma_vli stream_padding)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_vli) lzma_index_stream_count(const lzma_index *i)
		lzma_nothrow lzma_attr_pure;
extern LZMA_API(lzma_vli) lzma_index_block_count(const lzma_index *i)
		lzma_nothrow lzma_attr_pure;
extern LZMA_API(lzma_vli) lzma_index_size(const lzma_index *i)
		lzma_nothrow lzma_attr_pure;
extern LZMA_API(lzma_vli) lzma_index_stream_size(const lzma_index *i)
		lzma_nothrow lzma_attr_pure;
extern LZMA_API(lzma_vli) lzma_index_total_size(const lzma_index *i)
		lzma_nothrow lzma_attr_pure;
extern LZMA_API(lzma_vli) lzma_index_file_size(const lzma_index *i)
		lzma_nothrow lzma_attr_pure;
extern LZMA_API(lzma_vli) lzma_index_uncompressed_size(const lzma_index *i)
		lzma_nothrow lzma_attr_pure;
extern LZMA_API(void) lzma_index_iter_init(
		lzma_index_iter *iter, const lzma_index *i) lzma_nothrow;
extern LZMA_API(void) lzma_index_iter_rewind(lzma_index_iter *iter)
		lzma_nothrow;
extern LZMA_API(lzma_bool) lzma_index_iter_next(
		lzma_index_iter *iter, lzma_index_iter_mode mode)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_bool) lzma_index_iter_locate(
		lzma_index_iter *iter, lzma_vli target) lzma_nothrow;
extern LZMA_API(lzma_ret) lzma_index_cat(lzma_index *dest, lzma_index *src,
		const lzma_allocator *allocator)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_index *) lzma_index_dup(
		const lzma_index *i, const lzma_allocator *allocator)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_index_encoder(
		lzma_stream *strm, const lzma_index *i)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_index_decoder(
		lzma_stream *strm, lzma_index **i, uint64_t memlimit)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_index_buffer_encode(const lzma_index *i,
		uint8_t *out, size_t *out_pos, size_t out_size) lzma_nothrow;
extern LZMA_API(lzma_ret) lzma_index_buffer_decode(lzma_index **i,
		uint64_t *memlimit, const lzma_allocator *allocator,
		const uint8_t *in, size_t *in_pos, size_t in_size)
		lzma_nothrow;
extern LZMA_API(lzma_ret) lzma_file_info_decoder(
		lzma_stream *strm, lzma_index **dest_index,
		uint64_t memlimit, uint64_t file_size)
		lzma_nothrow;
typedef struct lzma_index_hash_s lzma_index_hash;
extern LZMA_API(lzma_index_hash *) lzma_index_hash_init(
		lzma_index_hash *index_hash, const lzma_allocator *allocator)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(void) lzma_index_hash_end(
		lzma_index_hash *index_hash, const lzma_allocator *allocator)
		lzma_nothrow;
extern LZMA_API(lzma_ret) lzma_index_hash_append(lzma_index_hash *index_hash,
		lzma_vli unpadded_size, lzma_vli uncompressed_size)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_ret) lzma_index_hash_decode(lzma_index_hash *index_hash,
		const uint8_t *in, size_t *in_pos, size_t in_size)
		lzma_nothrow lzma_attr_warn_unused_result;
extern LZMA_API(lzma_vli) lzma_index_hash_size(
		const lzma_index_hash *index_hash)
		lzma_nothrow lzma_attr_pure;
extern LZMA_API(uint64_t) lzma_physmem(void) lzma_nothrow;
extern LZMA_API(uint32_t) lzma_cputhreads(void) lzma_nothrow;
#undef LZMA_H_INTERNAL
#ifdef __cplusplus
}
#endif
#endif /* ifndef LZMA_H */
