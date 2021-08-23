#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
// #include <string.h>

#include "sqlite.h"
#include "util.h"
#include "string.h"
#include "input.h"

#ifdef WIN32
#include <windows.h>
#include <io.h>
#endif

#define DB "../db.sqlite"

typedef struct Path Path;
typedef struct Node Node;
typedef struct Link Link;
typedef struct Entry Entry;

static void load_mem();
static Entry* find_entry(string name);
static Path find_path(string start, string target);
static void print_path(Path path);
static void print_entry(Entry path);
static void path_free(Path head);
static bool dfs(string node, string target, int depth, int limit, Node* path);

struct Path {
	Node* node;
};

struct Node {
	string data;
	Node* next;
};

struct Entry {
	string  title;
	Entry** links;
	u16     nr_links;
	u8      checked_depth;
};

int nr_entries = 0;
Entry* entries;


int cache_hits;
int cache_misses;

int main(int argc, char** argv) {
	sqlite3_initialize();

	load_mem();

	if (argc < 3) {
		while(1) {
			cache_hits = cache_misses = 0;
			putchar('\n');
			string start = input(SLIT("enter a starting entry: "));
			string target = input(SLIT("enter a target entry: "));

			Path path = find_path(start, target);
			print_path(path);
			path_free(path);

			string_free(&start);
			string_free(&target);

			printf("%dh | %dm = %.1f%% \n\n", cache_hits, cache_misses, (double)cache_hits/(cache_hits+cache_misses)*100);
			// reset all depth checks:
			for (int i = 0; i < nr_entries; i++) {
				entries[i].checked_depth = 0;
			}
		}
	} else {
		string start = string_clone(STR(argv[1], strlen(argv[1])));
		string target = string_clone(STR(argv[2], strlen(argv[2])));

		Path path = find_path(start, target);
		print_path(path);
	}

	return 0;
}

static int sort_entries(const Entry* a, const Entry* b) {
	return strncmp(STR_PTR(a->title), STR_PTR(b->title), MAX(STR_LEN(a->title), STR_LEN(b->title)));
}

static void load_mem() {
	sqlite3* db;
	sqlite3_stmt* stmt;

	puts("reading db file into memory...");
	SQL_ASSERT(sqlite3_open(DB, &db) == SQLITE_OK, "cannot open database");

	#pragma region part 1: preload all page names
	sqlite3_stmt* x;
	SQL_ASSERT(sqlite3_prepare_v2(db, QUERY("SELECT count(*) FROM data"), &x, 0) == SQLITE_OK, "failed to prepare stmt");
	if (sqlite3_step(x) == SQLITE_ROW) {
		nr_entries = sqlite3_column_int(x, 0);
	}
	sqlite3_finalize(x);
	entries = calloc(nr_entries, sizeof(Entry));
	Entry** link_cache = calloc(1<<20, sizeof(Entry*));
	SQL_ASSERT(sqlite3_prepare_v2(db, QUERY("SELECT name FROM data"), &stmt, 0) == SQLITE_OK, "failed to prepare stmt");
	for (int i = 0; sqlite3_step(stmt) == SQLITE_ROW; i++) {
		string name = string_clone(STR((char*)sqlite3_column_text(stmt, 0), sqlite3_column_bytes(stmt, 0)));
		entries[i].title = name;
	}
	SQL_ASSERT(sqlite3_reset(stmt) == SQLITE_OK, "failed to reset stmt")
	sqlite3_finalize(stmt);
	qsort(entries, nr_entries, sizeof(Entry), (void*)sort_entries);
	// end part 1
	#pragma endregion

	SQL_ASSERT(sqlite3_prepare_v2(db, QUERY("SELECT * FROM data"), &stmt, 0) == SQLITE_OK, "failed to prepare stmt");
	for (int i = 0; sqlite3_step(stmt) == SQLITE_ROW; i++) {
		if ((i & 0x3ff) == 0) printf("\rloaded %d/%d rows (%0.1f%%)\r", i, nr_entries, (double)i / nr_entries * 100);
		string name = STR((char*)sqlite3_column_text(stmt, 0), sqlite3_column_bytes(stmt, 0));
		Entry* entry = find_entry(name);
		if (!entry) continue;

		string links_str = STR((char*)sqlite3_column_text(stmt, 1), sqlite3_column_bytes(stmt, 1));

		unsigned count = 0;
		unsigned rem_len = STR_LEN(links_str);
		const char* rem = STR_PTR(links_str);
		const char* const start = rem;
		// unsigned start = 0, end = 0;
		// unsigned j;
		// for (j = 0; *p != 0; j++) {
		// 	char ch = *(p++);
		// 	if (ch == '\x01') {
		// 		end = j;
		// 		string link = STR(p_start + start, end - start);
		// 		Entry* fe = find_entry(link);
		// 		if (fe) link_cache[count++] = fe;
		// 		start = end + 1;
		// 	}
		// }
		// end = j;
		// string link = STR(p_start + start, end - start);
		// Entry* fe = find_entry(link);
		// if (fe) {
		// 	link_cache[count++] = fe;
		// }

		bool remaining = true;
		while(remaining) {
			char* ptr = memchr(rem, '\x01', rem_len);
			int ptr_idx = ptr - rem;

			string cur_name;
			if (ptr == null) {
				cur_name = STR((char*)rem, rem_len);
				rem = "";
				remaining = false;
			} else {
				cur_name = STR((char*)rem, ptr_idx);
				rem = ptr + 1;
				rem_len = rem_len - ptr_idx - 1;
			}
			Entry* fe = find_entry(cur_name);
			if (fe) link_cache[count++] = fe;
		}

		entry->nr_links = count;
		entry->links = memdup(link_cache, sizeof(Entry*) * count);
	}
	SQL_ASSERT(sqlite3_reset(stmt) == SQLITE_OK, "failed to reset stmt")
	sqlite3_finalize(stmt);

	sqlite3_close(db);
	free(link_cache);
	puts("\rfinished reading db file into memory!");
}

Entry* find_entry(string name) {
	const int len = STR_LEN(name);
	const char* ptr = STR_PTR(name);

	int l = 0, r = nr_entries - 1;
	while (l <= r) {
        int m = l + (r - l) / 2;
		Entry* e = entries + m;

		const int entry_len = STR_LEN(e->title);
		const char* entry_ptr = STR_PTR(e->title);

		const int cmp = strncmp(ptr, entry_ptr, MAX(len, entry_len));
        if (!cmp) {
			if (string_eq(name, e->title)) {
				return e;
			}
			return null;
		}
        if (cmp > 0) l = m + 1;
        else if (cmp < 0) r = m - 1;
    }
	return null;
}

static Path find_path(string start, string target) {
	// #ifdef WIN32
	// 	LARGE_INTEGER start_time = {0};
	// 	QueryPerformanceCounter(&start_time);
	// #endif

	Entry* start_entry = find_entry(start);
	Entry* target_entry = find_entry(target);
	if (!start_entry) {
		printf("start page `%.*s` not in the database\n", STR_LEN(start), STR_PTR(start));
		return (Path){0};
	}
	if (!target_entry) {
		printf("target page `%.*s` not in the database\n", STR_LEN(target), STR_PTR(target));
		return (Path){0};
	}

	Path path = (Path){ HEAP((Node){ .data = string_clone(start) }) };
	for (int depth = 2; depth < 10; depth++) {
		printf("searching at depth=%d...\n", depth);
		if (dfs(start, target, 0, depth, path.node)) {

			// #ifdef WIN32
			// 	LARGE_INTEGER end_time = {0};
			// 	QueryPerformanceCounter(&end_time);
			// 	printf("%d\n", end_time.QuadPart - start_time.QuadPart);
			// #endif

			return path;
		}
	}
	return path;
}

static inline void print_entry(Entry entry) {
	printf("Entry{ title=%.*s\tlinks=%p\tnr_links=%d\tdepth=%d }\n", STR_LEN(entry.title), STR_PTR(entry.title), entry.links, entry.nr_links, entry.checked_depth);
}

static inline void print_path(Path path) {
	Node* node = path.node;
	while (node != null) {
		println(SLIT(" -> "), node->data);
		node = node->next;
	}
}

static inline void path_free(Path path) {
	Node* tmp;
	Node* node = path.node;
	while (node != null) {
		tmp = node;
		node = node->next;
		string_free(&tmp->data);
		free(tmp);
	}
	path.node = 0;
}

static bool dfs(string node, string target, int depth, int limit, Node* path) {
	if (string_eq(node, target)) {
		path->data = node;
		return true;
	}

	if (limit > depth+1) {
		Entry* entry = find_entry(node);
		int d = limit - depth;
		if (entry->checked_depth >= d) { cache_hits++; return false; } else { cache_misses++; }

		if (!path->next) path->next = HEAP((Node){});

		for (int i = 0; i < entry->nr_links; i++) {
			Entry* child = entry->links[i];
			if (dfs(child->title, target, depth+1, limit, path->next)) {
				string str = string_clone(child->title);
				path->next->data = str;
				return true;
			}
		}
		entry->checked_depth = d;
	}
	return false;
}
