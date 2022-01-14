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
#endif

typedef struct Path Path;
typedef struct Node Node;
typedef struct Link Link;
typedef struct Entry Entry;

static Entry* find_entry(string name);

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

static int sort_entries(const Entry* a, const Entry* b) {
	return strncmp(STR_PTR(a->title), STR_PTR(b->title), MAX(STR_LEN(a->title), STR_LEN(b->title)));
}

int main(int argc, char** argv) {
	if (argc < 3) {
		printf("usage: %s <input db> <output db>", argv[0]);
		exit(1);
	}
	
	sqlite3_initialize();

	sqlite3* db;
	sqlite3_stmt* stmt;

	puts("reading db file into memory...");
	SQL_ASSERT(sqlite3_open(argv[1], &db) == SQLITE_OK, "cannot open database");

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



    /////////////////////////////////

    FILE* f = fopen(argv[2], "wb");

	#define FWRITE(e, s, c) do { \
		int _c; \
		if ((_c = fwrite(e, s, c, f)) != (c)) { \
			fprintf(stderr, "failed to write to file: %s (expected %d, wrote %d)\n", strerror(errno), c, _c); \
		} \
	} while(0)

	FWRITE(&nr_entries, sizeof(int), 1);

	for (int i = 0; i < nr_entries; i++) {
		Entry* e = &entries[i];

		u16 l = STR_LEN(e->title);
		FWRITE(&l, sizeof(u16), 1);

		char* buf = STR_PTR(e->title);
		FWRITE(buf, 1, l);

		FWRITE(&e->nr_links, sizeof(u16), 1);
		for (int j = 0; j < e->nr_links; j++) {
			int l = e->links[j] - entries;
			FWRITE(&l, sizeof(u32), 1);
		}
	}
	fclose(f);
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
