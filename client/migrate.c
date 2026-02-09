#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "array.h"
#include "string.h"
#include "util.h"

typedef struct Entry {
	string title;
	array  links;
} Entry;

static int current_version_hdr = 0;

static int    nr_entries = 0;
static Entry* entries;

#define DUMP_FORMAT_VERSION 1

static void load_mem(char* path) {
	puts("reading db file into memory...");

	FILE* file = fopen(path, "rb");
	if (file == NULL) {
		fprintf(stderr, "error: could not open db file: %s\n", strerror(errno));
		exit(1);
	}

	fseek(file, 0, SEEK_END);
	long file_len = ftell(file);
	fseek(file, 0, SEEK_SET);

	char* file_buf = malloc(file_len);
	if ((long)fread(file_buf, 1, file_len, file) != file_len) {
		fprintf(stderr, "error: could not read db file: %s\n", strerror(errno));
		exit(1);
	}
	fclose(file);

	puts("Processing data...");

	char* p = file_buf;

	unsigned int magic = *(unsigned int*)p;
	p += sizeof(magic);
	if (magic != *(unsigned int*)"WIKI") {
		fputs("error: invalid magic\n", stderr);
		exit(1);
	}

	unsigned int version = *(unsigned int*)p;
	current_version_hdr  = version;
	p += sizeof(version);
	u8 dump_format = version & 0xff;
	if (dump_format != DUMP_FORMAT_VERSION) {
		if (dump_format > DUMP_FORMAT_VERSION) {
			fputs("error: database file is newer than this program; update your client.\n", stderr);
		} else {
			fputs("error: database file is older than this program; update your database.\n", stderr);
		}
		exit(1);
	}
	int32_t dump_date = version >> 8;
	printf("[info] database file date: 20%02d.%02d.%02d\n", dump_date / 10000, (dump_date / 100) % 100,
		   dump_date % 100);
	memcpy(&nr_entries, p, sizeof(int32_t));
	entries = malloc(sizeof(Entry) * nr_entries);
	p += sizeof(int32_t);

	// uint32_t total_links;
	p += sizeof(uint32_t);
	// uint32_t total_title_bytes;
	p += sizeof(uint32_t);

	for (int i = 0; i < nr_entries; i++) {
		Entry* e = &entries[i];

		u16 nr_links;
		memcpy(&nr_links, p, sizeof(u16));
		e->links = ARR(0, nr_links);
		p += sizeof(u16);
	}

	int padding_needed = nr_entries % 4;
	if (padding_needed) {
		p += sizeof(u16) * (4 - padding_needed);
	}

	for (int i = 0; i < nr_entries; i++) {
		Entry* e        = &entries[i];
		u16    nr_links = ARR_LEN(e->links);
		e->links        = ARR(p, nr_links);
		p += nr_links * sizeof(u32);
	}
	for (int i = 0; i < nr_entries; i++) {
		Entry* e = &entries[i];

		u16 l;
		memcpy(&l, p, sizeof(u16));
		p += sizeof(u16);
		e->title = STR(0, l);
	}
	for (int i = 0; i < nr_entries; i++) {
		Entry* e = &entries[i];

		u16 l    = STR_LEN(e->title);
		e->title = STR(p, l);
		p += l;
	}
}

int main(int argc, char** argv) {
	if (argc != 3) {
		fprintf(stderr, "error: invalid arguments\n");
		fprintf(stderr, "usage: %s [input db] [output db]\n", argv[0]);
		exit(1);
	}

	load_mem(argv[1]);

	// remove duplicate links in each entry
	for (int i = 0; i < nr_entries; i++) {
		Entry* e         = &entries[i];
		u16    num_links = ARR_LEN(e->links);
		u32*   links     = ARR_PTR(e->links);
		if (num_links == 0) continue;
		int j = 0;
		for (int k = 1; k < num_links; k++) {
			if (links[k] != links[j]) {
				links[++j] = links[k];
			}
		}
		e->links = ARR(links, j + 1);
	}

	write_new(argv[2]);

	return 0;
}
