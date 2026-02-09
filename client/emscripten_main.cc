// Emscripten main entry point for WebAssembly build.
// Provides JS bindings for init() and search() functions.

#include <stdarg.h>
#include <string>

#include <emscripten/bind.h>
#include <emscripten/emscripten.h>

extern "C" {
#pragma GCC diagnostic ignored "-Wreturn-type-c-linkage"

// Include the main client code (which includes graph.c, load.c, search.c, etc.)
// This will define Graph, PathIDs, and all the helper functions.
#define CLIENT_HEADER_ONLY
#include "client.c"

extern Graph G;

#include "thirdparty/liblzma.h"

} // extern "C"

using namespace emscripten;

// ----------------------------------------------------------------------------
// JS-callable init function: decompresses and loads the database
// ----------------------------------------------------------------------------
int init(long temp_addr, val cb) {
	char* temp_buf = (char*)temp_addr;

	puts("decompressing db file...");
	lzma_stream strm = LZMA_STREAM_INIT;
	lzma_ret    ret  = lzma_stream_decoder(&strm, UINT64_MAX, 0);
	if (ret != LZMA_OK) {
		printf("Error: Cannot initialize decoder\n");
		exit(1);
	}

	const int LZMA_OUT_BUF_SIZE = 1 << 21;

	char*  output_buffer = NULL;
	size_t output_size   = 0;

	do {
		int nread = cb().as<int>();

		strm.next_in  = (uint8_t*)temp_buf;
		strm.avail_in = nread;

		do {
			output_buffer  = (char*)realloc(output_buffer, output_size + LZMA_OUT_BUF_SIZE);
			strm.next_out  = (uint8_t*)(output_buffer + output_size);
			strm.avail_out = LZMA_OUT_BUF_SIZE;

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

	graph_load_from_mem(&G, output_buffer, (long)output_size);

	return 123;
}

// ----------------------------------------------------------------------------
// JS-callable search function
// ----------------------------------------------------------------------------
val search(std::string start_, std::string target_) {
	string start  = STR((char*)start_.c_str(), (int)start_.length());
	string target = STR((char*)target_.c_str(), (int)target_.length());

	val arr = val::array();

	PathIDs path_ids = {.len = 0, .ids = {0}};
	bool    ok       = graph_find_path_titles(&G, start, target, MAX_DEPTH, &path_ids);

	if (!ok || path_ids.len == 0) {
		puts("No path found.");
		return arr;
	}

	// First entry: the start title
	{
		u32    id    = path_ids.ids[0];
		string title = G.titles[id];
		arr.call<void>("push", std::string(STR_PTR(title), STR_LEN(title)));
	}

	// Subsequent entries: what link to click (with redirect annotation if applicable)
	for (u32 i = 1; i < path_ids.len; i++) {
		u32 a = path_ids.ids[i - 1];
		u32 b = path_ids.ids[i];

		int ridx = unredir_lookup(&G, a, b);
		if (ridx >= 0 && (u32)ridx < G.nr_redir_titles) {
			// Format: "redirect_title (redirects to dest_title)"
			string      redir_title = G.redir_titles[ridx];
			string      dest_title  = G.titles[b];
			std::string formatted   = std::string(STR_PTR(redir_title), STR_LEN(redir_title)) + " (redirects to " +
									std::string(STR_PTR(dest_title), STR_LEN(dest_title)) + ")";
			arr.call<void>("push", formatted);
		} else {
			// Use the destination title directly
			string title = G.titles[b];
			arr.call<void>("push", std::string(STR_PTR(title), STR_LEN(title)));
		}
	}

	return arr;
}

// ----------------------------------------------------------------------------
// Emscripten bindings
// ----------------------------------------------------------------------------
EMSCRIPTEN_BINDINGS(my_module) {
	function("init", &init);
	function("search", &search);
	function("exit", &exit);

#if __has_feature(leak_sanitizer)
	function("check_leaks", &__lsan_do_recoverable_leak_check);
#endif
}
