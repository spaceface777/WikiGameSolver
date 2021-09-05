#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "util.h"
#include "string.h"
#include "input.h"
#include "time.h"

typedef struct Path Path;
typedef struct Node Node;
typedef struct Link Link;
typedef struct Entry Entry;

static void load_mem();
static Entry* find_entry(string name);
static Path find_path(string start, string target);
static void print_path(Path path);
static void path_free(Path head);
static bool dfs(Entry* entry, string target, int depth, int limit, Node* path);

struct Path {
	Node* node;
};

struct Node {
	string data;
	Node* next;
};

struct Entry {
	string  title;
	int*    links;
	u16     nr_links : 13;
	u8      checked_depth : 3;
	u32     index;
	u16     __reserved;
};

int nr_entries = 0;
Entry* entries;

int cache_hits;
int cache_misses;

int main(int argc, char** argv) {
	TIME_INIT();
	load_mem();

	if (argc < 3) {
		while(1) {
			cache_hits = cache_misses = 0;
			putchar('\n');
			string start = input(SLIT("enter a starting entry: "));
			string target = input(SLIT("enter a target entry: "));
			
			u64 start_time = get_monotonic_time();
			Path path = find_path(start, target);
			u64 end_time = get_monotonic_time();

			print_path(path);

			println(SLIT("\nSearch took"), format_time(end_time - start_time));

			path_free(path);
			string_free(&start);
			string_free(&target);

			// printf("%dh | %dm = %.1f%% \n\n", cache_hits, cache_misses, (double)cache_hits/(cache_hits+cache_misses)*100);
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

static void load_mem() {
	puts("reading db file into memory...");

	FILE* f = fopen("db.bin", "rb");

	#define FREAD(e, s, c) do { \
		int _c; \
		if ((_c = fread(e, s, c, f)) != (c)) { \
			fprintf(stderr, "failed to write to file: %s (expected %d, wrote %d)\n", strerror(errno), c, _c); \
		} \
	} while(0)

	FREAD(&nr_entries, sizeof(int), 1);
	entries = malloc(sizeof(Entry) * nr_entries);

	for (int i = 0; i < nr_entries; i++) {
		Entry* e = &entries[i];
		e->index = i;

		u16 l;
		FREAD(&l, sizeof(u16), 1);
		char* buf = malloc(l+1); 
		buf[l] = '\0';
		FREAD(buf, 1, l);
		e->title = STR(buf, l);

		u16 nr_links;
		FREAD(&nr_links, sizeof(u16), 1);
		e->nr_links = nr_links;
		e->links = malloc(sizeof(int) * e->nr_links);
		for (int j = 0; j < e->nr_links; j++) {
			FREAD(&e->links[j], sizeof(u32), 1);
		}
	}
	fclose(f);










	f = fopen("db2.bin", "wb");

	#define FWRITE(e, s, c) do { \
		int _c; \
		if ((_c = fwrite(e, s, c, f)) != (c)) { \
			fprintf(stderr, "failed to write to file: %s (expected %d, wrote %d)\n", strerror(errno), c, _c); \
		} \
	} while(0)

	FWRITE(&nr_entries, sizeof(int), 1);

	for (int i = 0; i < nr_entries; i++) {
		Entry* e = entries + i;

		u16 l = STR_LEN(e->title);
		FWRITE(&l, sizeof(u16), 1);

		char* buf = STR_PTR(e->title);
		FWRITE(&buf, 1, l);

		u16 nr_links = e->nr_links;
		FWRITE(&nr_links, sizeof(u16), 1);
		for (int j = 0; j < e->nr_links; j++) {
			FWRITE(e->links + j, sizeof(u32), 1);
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

static Path find_path(string start, string target) {
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
		if (dfs(start_entry, target, 0, depth, path.node))
			return path;
	}
	return path;
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

static bool dfs(Entry* entry, string target, int depth, int limit, Node* path) {
	string node = entry->title;
	if (string_eq(node, target)) {
		path->data = node;
		return true;
	}

	if (limit > depth+1) {
		int d = limit - depth;
		if (entry->checked_depth >= d) { cache_hits++; return false; }
		cache_misses++;
		entry->checked_depth = d;

		if (!path->next) path->next = HEAP((Node){});

		for (int i = 0; i < entry->nr_links; i++) {
			Entry* child = entries + entry->links[i];
			if (dfs(child, target, depth+1, limit, path->next)) {
				string str = string_clone(child->title);
				path->next->data = str;
				return true;
			}
		}
	}
	return false;
}
