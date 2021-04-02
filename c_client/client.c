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

    string res = get(SLIT("123"));
    println("got:", res);
    Link link = (Link){ .rem = res };
    while (next_result(&link)) {
        printf(" -> %.*s\n", link.page.len, link.page.str);
        if (link.name.len > 0) {
            printf(" (%.*s)\n", link.name.len, link.name.str);
        } else {
            puts("");
        }
    }

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
    println(res);
    return res;
} 

static bool next_result(Link* link) {
    string rem = link->rem;
    if (rem.len == 0) return false;

    char* ptr = memchr(link->rem.str, '\x01', link->rem.len);
    int ptr_idx = ptr - rem.str;

    char* sep = memchr(link->rem.str, '|', link->rem.len);
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
        } else {
            link->page = (string){ .str = rem.str, .len = sep_idx };
            link->name = (string){ .str = sep + 1, .len = ptr_idx - sep_idx - 1 };
        }
        link->rem = (string){ .str = ptr + 1, .len = rem.len - ptr_idx };
    }
    return true;
}

static bool dfs(string node, string target, int depth, int limit, Node* path) {
	if (string_eq(node, target)) {
        path->next = HEAP((Node){.data = string_clone(node)});
		return true;
	}
	if (depth > limit) {
        return false;
	}
	// if (CACHE[node] >= limit - depth) {
	// 	return;
	// }

	// if (limit > depth+1) {

	// 	for _, child := range children {
	// 		res := dfs(child, target, depth+1, limit, path)
	// 		if len(res) > 0 {
	// 			return res
	// 		}
	// 	}
	// }
}
