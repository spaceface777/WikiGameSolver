#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "thirdparty/sqlite3.c"
#include "thirdparty/sqlite3.h"

#include "util.h"
#include "string.h"

typedef struct Node Node;
typedef struct Link Link;

static inline string get(string query);
static bool next_result(Link* link);
static Node* find_path(string start, string target);
static bool dfs(string node, string target, int depth, int limit, Node* path);

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

int main(void) {
	if (sqlite3_open("../db.sqlite", &db) != SQLITE_OK) {
		PANIC("cannot open database")
	}

	// speeds things up
	sqlite3_exec(db, "PRAGMA locking_mode = EXCLUSIVE", null, null, null);

	if (sqlite3_prepare_v2(db, QUERY("SELECT links FROM data WHERE name = ?"), &stmt, 0) != SQLITE_OK) {
		PANIC("failed to prepare stmt")
	}

	Node* path = find_path(SLIT("Spain"), SLIT("Pokémon"));
	do {
		println(SLIT(" -> "), path->data);
		path = path->next;
	} while (path != null);

	sqlite3_finalize(stmt);
	sqlite3_close(db);

	return 0;
}

static inline string get(string query) {
	ASSERT(sqlite3_bind_text(stmt, 1, query.str, query.len, null) == 0, "failed to bind argument")
	string res = SLIT("");
	if (sqlite3_step(stmt) == SQLITE_ROW) {
		const char* x = sqlite3_column_text(stmt, 0);
		res = string_clone(STR(x));
	}
	ASSERT(sqlite3_reset(stmt) == SQLITE_OK, "failed to reset stmt")
	return res;
} 

static bool next_result(Link* link) {
	int start_len = link->rem.len;
	// printf("`%.*s` `%.*s` | %d\n", link->page.len, link->page.str, link->name.len, link->name.str, link->rem.len);

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
			link->rem = (string){ .str = ptr + 1, .len = rem.len - ptr_idx };
		} else {
			link->page = (string){ .str = rem.str, .len = sep_idx };
			link->name = (string){ .str = sep + 1, .len = ptr_idx - sep_idx - 1 };
			link->rem = (string){ .str = ptr + 1, .len = rem.len - ptr_idx };
		}
	}

	int end_len = link->rem.len;
	int exp_len = start_len - link->page.len - (link->name.len > 0 ? link->name.len + 1 : 0) - 1;
	
	printf("\nctx: %c%c%c%c%c%c%c%c%c%c\n", *(link->rem.str-6), *(link->rem.str-5), *(link->rem.str-4), *(link->rem.str-3), *(link->rem.str-2), *(link->rem.str-1), *(link->rem.str), *(link->rem.str+1), *(link->rem.str+2), *(link->rem.str+3));
	printf("%d | %d ", exp_len, end_len, *link->rem.str);
	printf("`%.*s` `%.*s`\n", link->page.len, link->page.str, link->name.len, link->name.str);
	if (exp_len != end_len) {
	} else {
		puts(" -> as expected");
	}

	return true;
}

static Node* find_path(string start, string target) {
	if (get(start).len == 0) {
		printf("start page `%.*s` not in the database", start.len, start.str);
		exit(1);
	}
	if (get(target).len == 0) {
		printf("target page `%.*s` not in the database", target.len, target.str);
		exit(1);
	}
	Node* path = HEAP((Node){0});
	for (int depth = 2; ; depth++) {
		if (dfs(start, target, 0, depth, path)) {
			return path;
		}
		puts("Increasing depth...");
	}
}

static bool dfs(string node, string target, int depth, int limit, Node* path) {
	// printf("dfs(%d) - %d %.*s -> %d %.*s\n", depth, node.len, node.len, node.str, target.len, target.len, target.str);
	
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
		while (next_result(&link)) {
			bool x = dfs(link.page, target, depth+1, limit, path->next);
			if (x) {
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
					// return str;
				}

				string_free(children);
				path->data = node;
				return true;
			}
		}
		string_free(children);
	}
	return false;
}
