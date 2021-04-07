#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "sqlite.h"
#include "util.h"
#include "string.h"

#define DB "../db.sqlite"

typedef struct Path Path;
typedef struct Node Node;
typedef struct Link Link;

static void load_mem();
static inline string get(string query);
static bool next_result(Link* link);
static Path find_path(string start, string target);
static void print_path(Path path);
static void path_free(Path head);
static bool dfs(string node, string target, int depth, int limit, Node* path);

struct Path {
	Node* node;
};

struct Node {
	string data;
	Node* next;
};

struct Link {
	string page;
	string name;
	string rem;
};

sqlite3* db;
sqlite3_stmt* stmt;

static string input(string prompt) {
	char buf[1024];

	while(1) {
		write(1, prompt.str, prompt.len);

		if (fgets (&buf[0], sizeof(buf), stdin) == null) {
			puts("invalid input, please try again");
			continue;
		}

		int len = strlen(buf) - 1;
		if (buf[len] != '\n') {
			puts("invalid input, please try again");
			continue;
		}

		// Otherwise remove newline and give string back to caller.
		buf[len] = '\0';
		return string_clone((string){ .str = &buf[0], .len = len });
	}
}

static void __at_exit() {
	sqlite3_finalize(stmt);
	sqlite3_close(db);
}

int main(int argc, char** argv) {
	sqlite3_initialize();

	atexit(__at_exit);

	#ifdef NO_MEM
		SQL_ASSERT(sqlite3_open(DB, &db) == SQLITE_OK, "cannot open database");
		SQL_ASSERT(sqlite3_prepare_v2(db, QUERY("SELECT links FROM data WHERE name = ?"), &stmt, 0) == SQLITE_OK, "failed to prepare stmt");
	#else
		load_mem();
	#endif

	if (argc < 3) {
		while(1) {
			string start = input(SLIT("\nenter a starting entry: "));
			string target = input(SLIT("enter a target entry: "));

			Path path = find_path(start, target);
			print_path(path);
			path_free(path);

			string_free(&start);
			string_free(&target);
		}
	} else {
		string start = STR(argv[1]);
		string target = STR(argv[2]);
		// argv elements must not be freed
		start.flags = STR_LITERAL;
		target.flags = STR_LITERAL;

		Path path = find_path(start, target);
		print_path(path);
		path_free(path);
	}

	return 0;
}

#ifndef NO_MEM
static void load_mem() {
	puts("reading db file into memory...");
	sqlite3* fdb;
	SQL_ASSERT(sqlite3_open(DB, &fdb) == SQLITE_OK, "cannot open database");
	SQL_ASSERT(sqlite3_open(":memory:", &db) == SQLITE_OK, "cannot open in-memory database");

	sqlite3_backup* backup = sqlite3_backup_init(db, "main", fdb, "main");
	if (backup) {
		sqlite3_backup_step(backup, -1);
		sqlite3_backup_finish(backup);
	}

	sqlite3_close(fdb);
	SQL_ASSERT(sqlite3_prepare_v2(db, QUERY("SELECT links FROM data WHERE name = ?"), &stmt, 0) == SQLITE_OK, "failed to prepare stmt");
	puts("done reading db file into memory");
}
#endif

static Path find_path(string start, string target) {
	#ifdef WIN32
		LARGE_INTEGER start = {0};
		QueryPerformanceCounter(&start);
	#endif

	string start_query = get(start);
	string target_query = get(target);
	if (start_query.len == 0) {
		printf("start page `%.*s` %d not in the database\n", start.len, start.str, start.len);
		exit(1);
	}
	if (target_query.len == 0) {
		printf("target page `%.*s` not in the database\n", target.len, target.str);
		exit(1);
	}
	string_free(&start_query);
	string_free(&target_query);

	Path path = (Path){ HEAP((Node){ .data = string_clone(start) }) };
	for (int depth = 2; ; depth++) {
		if (dfs(start, target, 0, depth, path.node)) {
			return path;
		}
	}

	#ifdef WIN32
		LARGE_INTEGER end = {0};
		QueryPerformanceCounter(&end);
		printf("%d\n", end.QuadPart - start.QuadPart);
	#endif
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

static inline string get(string query) {
	SQL_ASSERT(sqlite3_bind_text(stmt, 1, query.str, query.len, null) == 0, "failed to bind argument")
	string res;
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		const char* x = (char*)sqlite3_column_text(stmt, 0);
		res = string_clone((string){ .str = x, .len = sqlite3_column_bytes(stmt, 0) });
	} else {
		res = string_clone(SLIT(""));
	}
	SQL_ASSERT(sqlite3_reset(stmt) == SQLITE_OK, "failed to reset stmt")
	return res;
}

static bool next_result(Link* link) {
	string rem = link->rem;
	if (rem.len == 0) return false;

	char* ptr = memchr(rem.str, '\x01', rem.len);
	int ptr_idx = ptr - rem.str;

	char* sep = memchr(rem.str, '|', rem.len);
	int sep_idx = sep - rem.str;

	if (ptr == null) {
		if (sep == null) {
			link->page = rem;
			link->name = SLIT("");
			link->rem = SLIT("");
		} else {
			link->page = (string){ .str = rem.str, .len = sep - rem.str };
			link->name = (string){ .str = sep + 1, .len = rem.len - sep_idx };
			link->rem = SLIT("");
		}
	} else {
		if (sep == null || sep_idx > ptr_idx) {
			link->page = (string){ .str = rem.str, .len = ptr_idx };
			link->name = SLIT("");
			link->rem = (string){ .str = ptr + 1, .len = rem.len - ptr_idx - 1 };
		} else {
			link->page = (string){ .str = rem.str, .len = sep_idx };
			link->name = (string){ .str = sep + 1, .len = ptr_idx - sep_idx - 1 };
			link->rem = (string){ .str = ptr + 1, .len = rem.len - ptr_idx - 1 };
		}
	}

	return true;
}

static bool dfs(string node, string target, int depth, int limit, Node* path) {
	if (string_eq(node, target)) {
		path->data = node;
		return true;
	}
	if (depth > limit) {
		return false;
	}
	// if (CACHE[node] >= limit - depth) {
	// 	return;
	// }

	if (limit > depth+1) {
		string children = get(node);
		Link link = (Link){ .rem = children };
		if (path->next == null) {
			path->next = HEAP((Node){});
		}
		// NOTE: `next_result` does NOT allocate a new string *on purpose* -
		// it creates a pointer to a substring of the original buffer instead.
		while (next_result(&link)) {
			if (dfs(link.page, target, depth+1, limit, path->next)) {
				string str;
				if (link.name.len > 0) {
					int len = link.page.len + link.name.len + 3;
					char* buf = malloc(len + 1);

					memcpy(buf, link.page.str, link.page.len);
					buf[link.page.len] = ' ';
					buf[link.page.len + 1] = '(';
					memcpy(buf + link.page.len + 2, link.name.str, link.name.len);
					buf[link.page.len + link.name.len + 2] = ')';
					buf[link.page.len + link.name.len + 3] = '\0';

					str = (string){ .str = buf, .len = len };
				} else {
					str = string_clone(link.page);
				}
				string_free(&children);
				path->next->data = str;
				return true;
			}
		}
		string_free(&children);
	}
	return false;
}
