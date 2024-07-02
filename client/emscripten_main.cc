#include <stdarg.h>

#include <emscripten/emscripten.h>
#include <emscripten/bind.h>

#include "util.h"
#include "array.h"
#include "string.h"

#include "thirdparty/liblzma.h"

extern "C" {
#pragma GCC diagnostic ignored "-Wreturn-type-c-linkage"
typedef struct Path Path;
typedef struct Node Node;
typedef struct Link Link;
typedef struct Entry Entry;

void load_mem(char* path);
void load_mem2(char* compressed_buf, long compressed_len);
void load_mem3(char* buf);

Entry* find_entry(string name);
Path find_path(string start, string target);
void print_path(Path path);
void path_free(Path* head);

typedef struct DFSState {
	int idx;
	u8 depth;
	u8 limit;
} DFSState;
bool dfs(Entry* entry, string target, DFSState state, Node* path);

struct Path {
	Node* node;
};

struct Node {
	string data;
	Node* next;
};

struct Entry {
	string title;
	array  links;
};

extern int nr_entries;
extern Entry* entries;
extern u8* depths;

}

using namespace emscripten;

Path emscripten_main(string start, string target) {
	depths = (u8*)calloc(nr_entries, sizeof(u8));
	Path path = find_path(start, target);
	free(depths);

	return path;
}

int init(long temp_addr, val cb) {
	char* temp_buf = (char*)temp_addr;

	char* buf = 0;
	puts("decompressing db file...");
	lzma_stream strm = LZMA_STREAM_INIT;
	lzma_ret ret = lzma_stream_decoder(&strm, UINT64_MAX, 0);
	if (ret != LZMA_OK) {
		printf("Error: Cannot initialize decoder\n");
		exit(1);
	}

	const int LZMA_OUT_BUF_SIZE = 1 << 21;

	char* output_buffer = NULL;
	size_t output_size = 0;

	do {
		int nread = cb().as<int>();

		strm.next_in = (uint8_t*)temp_buf;
		strm.avail_in = nread;

		do {
			output_buffer = (char*)realloc(output_buffer, output_size + LZMA_OUT_BUF_SIZE);
			strm.next_out = (uint8_t*)(output_buffer + output_size);
			strm.avail_out = LZMA_OUT_BUF_SIZE;

			// printf("%p=[%02hhx, %02hhx, %02hhx, %02hhx...] %zu       %p=[%02hhx, %02hhx, %02hhx, %02hhx...] %zu\n", strm.next_in, strm.next_in[0], strm.next_in[1], strm.next_in[2], strm.next_in[3], strm.avail_in, strm.next_out, strm.next_out[0], strm.next_out[1], strm.next_out[2], strm.next_out[3], strm.avail_out);

			ret = lzma_code(&strm, LZMA_RUN);
			if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
				printf("Error: Decoding failed: %d\n", ret);
				exit(1);
			}

			output_size += LZMA_OUT_BUF_SIZE - strm.avail_out;
		} while (strm.avail_in > 0);
	} while (ret != LZMA_STREAM_END);

	lzma_end(&strm);
	free(temp_buf);

	buf = output_buffer;

	load_mem3(buf);

	return 123;
}


val search(std::string start_, std::string target_) {
	string start = STR(start_.c_str(), start_.length());
	string target = STR(target_.c_str(), target_.length());

	Path path = emscripten_main(start, target);


	val arr = val::array();

	Node* node = path.node;
	if (!node) {
		println(SLIT("\n\nNo path found."));
		return arr;
	}

	while (node != null) {
		arr.call<void>("push", std::string(STR_PTR(node->data), STR_LEN(node->data)));
		node = node->next;
	}

	return arr;
}

EMSCRIPTEN_BINDINGS(my_module) {
	function("init", &init);
	function("search", &search);
	function("exit", &exit);

#if __has_feature(leak_sanitizer)
    function("check_leaks", &__lsan_do_recoverable_leak_check);
#endif
}
