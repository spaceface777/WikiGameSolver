#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "lzma.h"

#include "array.h"
#include "string.h"
#include "util.h"

typedef struct Entry {
	string title;
	array  links;
	i32	   incoming_count;
	i32	   old_id;
} Entry;

static int current_version_hdr = 0;

static int	  nr_entries = 0;
static Entry* entries;
static Entry* new_entries;

static Entry* reverse_entries;

void load_mem(char* path);
void load_mem2(char* compressed_buf, long compressed_len);
void load_mem3(char* buf);

#define DUMP_FORMAT_VERSION 1
void load_mem(char* path) {
	puts("reading db file into memory...");

	FILE* compressed = fopen(path, "rb");
	if (compressed == NULL) {
		fprintf(stderr, "error: could not open db file: %s\n", strerror(errno));
		exit(1);
	}

	fseek(compressed, 0, SEEK_END);
	long compressed_len = ftell(compressed);
	fseek(compressed, 0, SEEK_SET);

	char* compressed_buf = malloc(compressed_len);
	if ((long)fread(compressed_buf, 1, compressed_len, compressed) != compressed_len) {
		fprintf(stderr, "error: could not read db file: %s\n", strerror(errno));
		exit(1);
	}
	fclose(compressed);

	load_mem2(compressed_buf, compressed_len);
}

void load_mem2(char* compressed_buf, long compressed_len) {
	char* buf = 0;
#ifndef NO_COMPRESSION
	{
		unsigned int magic = *(unsigned int*)compressed_buf;
		if (magic != *(unsigned int*)"WIKI") {
			puts("decompressing db file...");
			lzma_stream strm = LZMA_STREAM_INIT;
			lzma_ret	ret	 = lzma_stream_decoder(&strm, UINT64_MAX, 0);
			if (ret != LZMA_OK) {
				printf("Error: Cannot initialize decoder\n");
				exit(1);
			}

			char*  output_buffer = NULL;
			size_t output_size	 = 0;
			size_t input_pos	 = 0;

			const int LZMA_OUT_BUF_SIZE = 1 << 24;

			do {
				strm.next_in  = (uint8_t*)(compressed_buf + input_pos);
				strm.avail_in = compressed_len - input_pos;

				output_buffer  = (char*)realloc(output_buffer, output_size + LZMA_OUT_BUF_SIZE);
				strm.next_out  = (uint8_t*)(output_buffer + output_size);
				strm.avail_out = LZMA_OUT_BUF_SIZE;

				ret = lzma_code(&strm, LZMA_RUN);
				if (ret != LZMA_OK && ret != LZMA_STREAM_END) {
					printf("Error: Decoding failed: %d\n", ret);
					exit(1);
				}

				output_size += LZMA_OUT_BUF_SIZE - strm.avail_out;
				input_pos += strm.next_in - (uint8_t*)(compressed_buf + input_pos);
			} while (ret != LZMA_STREAM_END);

			lzma_end(&strm);

			buf = output_buffer;
			free(compressed_buf);
		} else {
#endif
			buf = compressed_buf;
#ifndef NO_COMPRESSION
		}
	}
	load_mem3(buf);
#endif
}
void load_mem3(char* buf) {
	puts("Processing data...");

	char* p = buf;

	unsigned int magic = *(unsigned int*)p;
	p += sizeof(magic);
	if (magic != *(unsigned int*)"WIKI") {
		fputs("error: invalid magic\n", stderr);
		exit(1);
	}

	unsigned int version = *(unsigned int*)p;
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
		Entry* e		= &entries[i];
		u16	   nr_links = ARR_LEN(e->links);
		e->links		= ARR(p, nr_links);
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

		u16 l	 = STR_LEN(e->title);
		e->title = STR(p, l);
		p += l;
	}
}

static void write_new(char* path) {
	puts("writing new db file...");

	FILE* f = fopen(path, "wb");
	if (f == NULL) {
		fprintf(stderr, "error: could not open db file for writing: %s\n", strerror(errno));
		exit(1);
	}

	char* buf = (char*)malloc(16 << 20);
	setvbuf(f, buf, _IOFBF, 16 << 20);

	if (fwrite("WIKI", 1, 4, f) != 4) {
		perror("header");
		exit(1);
	}

	uint32_t version = current_version_hdr;
	if (fwrite(&version, sizeof(version), 1, f) != 1) {
		perror("version");
		exit(1);
	}

	int32_t num_entries = (int32_t)nr_entries;
	if (fwrite(&num_entries, sizeof(num_entries), 1, f) != 1) {
		perror("num_entries");
		exit(1);
	}

	uint32_t total_links	   = 0;
	uint32_t total_title_bytes = 0;
	for (int i = 0; i < nr_entries; i++) {
		Entry* e = &new_entries[i];
		total_links += ARR_LEN(e->links);
		total_title_bytes += STR_LEN(e->title);
	}

	if (fwrite(&total_links, sizeof(total_links), 1, f) != 1) {
		perror("total_links");
		exit(1);
	}

	if (fwrite(&total_title_bytes, sizeof(total_title_bytes), 1, f) != 1) {
		perror("fwrite");
		exit(1);
	}

	uint32_t last_num_links = 0;
	for (int i = nr_entries - 1; i >= 0; i--) {
		Entry*	 e		   = &new_entries[i];
		uint16_t num_links = ARR_LEN(e->links);
		if (fwrite(&num_links, sizeof(num_links), 1, f) != 1) {
			perror("fwrite");
			exit(1);
		}
		// uint32_t delta = (int32_t)num_links - (int32_t)last_num_links;
		// if (fwrite(&delta, sizeof(delta), 1, f) != 1) {
		// 	perror("fwrite");
		// 	exit(1);
		// }
		// last_num_links = num_links;
	}

	int padding_needed = nr_entries % 4;
	if (padding_needed) {
		uint16_t zero = 0;
		for (int i = 0; i < 4 - padding_needed; i++) {
			if (fwrite(&zero, sizeof(zero), 1, f) != 1) {
				perror("fwrite");
				exit(1);
			}
		}
	}

	for (int i = 0; i < nr_entries; i++) {
		Entry*	 e		   = &new_entries[i];
		uint16_t num_links = ARR_LEN(e->links);
		if (fwrite(ARR_PTR(e->links), sizeof(u32), num_links, f) != num_links) {
			perror("fwrite");
			exit(1);
		}
		// u32* links = ARR_PTR(e->links);
		// u32 last_link = 0;
		// for (int j = 0; j < num_links; j++) {
		// 	u32 current_link = links[j];
		// 	u32 delta = current_link - last_link;
		// 	if (fwrite(&delta, sizeof(u32), 1, f) != 1) {
		// 		perror("fwrite");
		// 		exit(1);
		// 	}
		// 	last_link = current_link;
	}

	for (int i = 0; i < nr_entries; i++) {
		Entry*	 e		   = &new_entries[i];
		uint16_t title_len = (uint16_t)STR_LEN(e->title);
		if (title_len > 255) {
			fprintf(stderr, "error: title too long: %s\n", STR_PTR(e->title));
			exit(1);
		}
		// if (fwrite(&title_len, sizeof(title_len), 1, f) != 1) {
		// 	perror("fwrite");
		// 	exit(1);
		// }
		uint8_t title_len_u8 = (uint8_t)title_len;
		if (fwrite(&title_len_u8, sizeof(title_len_u8), 1, f) != 1) {
			perror("fwrite");
			exit(1);
		}
		// uint32_t title_len_u32 = (uint32_t)title_len;
		// if (fwrite(&title_len_u32, sizeof(title_len_u32), 1, f) != 1) {
		// 	perror("fwrite");
		// 	exit(1);
		// }
	}

	for (int i = 0; i < nr_entries; i++) {
		Entry*	 e		   = &new_entries[i];
		uint16_t title_len = (uint16_t)STR_LEN(e->title);
		if (fwrite(STR_PTR(e->title), 1, title_len, f) != title_len) {
			perror("fwrite");
			exit(1);
		}
	}

	fflush(f);
	sync();
}

Entry* find_entry(string name) {
	const int	len = STR_LEN(name);
	const char* ptr = STR_PTR(name);

	int l = 0, r = nr_entries - 1;
	while (l <= r) {
		int	   m = l + (r - l) / 2;
		Entry* e = entries + m;

		const int	entry_len = STR_LEN(e->title);
		const char* entry_ptr = STR_PTR(e->title);

		int cmp = memcmp(ptr, entry_ptr, MIN(len, entry_len));
		if (cmp == 0) cmp = (len < entry_len) ? -1 : (len > entry_len);
		if (cmp == 0) return e;
		else if (cmp > 0) l = m + 1;
		else if (cmp < 0) r = m - 1;
	}
	return null;
}

int compare_entries_by_incoming_desc(const void* a, const void* b) {
	Entry* ea = (Entry*)a;
	Entry* eb = (Entry*)b;

	// i64 ia = find_entry(ea->title) - entries;
	// i64 ib = find_entry(eb->title) - entries;

	// // printf("gsort: comparing %.*s (%lld) to %.*s (%lld)\n", STR_LEN(ea->title), STR_PTR(ea->title), ia,
	// STR_LEN(eb->title), STR_PTR(eb->title), ib);

	// if (ia < 0 || ia >= nr_entries || ib < 0 || ib >= nr_entries) {
	// 	fprintf(stderr, "error: invalid entry pointer in sort\n");
	// 	exit(1);
	// }

	// u64 ca = incoming_count[ia];
	// u64 cb = incoming_count[ib];

	i64 ca = ea->incoming_count;
	i64 cb = eb->incoming_count;

	if (ca > cb) return -1;
	if (ca < cb) return 1;

	// stable sort: if counts are equal, sort by old id asc
	if (ea->old_id < eb->old_id) return -1;
	if (ea->old_id > eb->old_id) return 1;

	return 0;
}

int compare_u32_asc(const void* a, const void* b) {
	u32 va = *(u32*)a;
	u32 vb = *(u32*)b;
	if (va < vb) return -1;
	if (va > vb) return 1;
	return 0;
}

int main(int argc, char** argv) {
	if (argc != 3) {
		fprintf(stderr, "error: invalid arguments\n");
		fprintf(stderr, "usage: %s [input db] [output db]\n", argv[0]);
		exit(1);
	}

	load_mem(argv[1]);

	for (int i = 0; i < nr_entries; i++) {
		entries[i].old_id = i;
	}

	fprintf(stderr, "[info] loaded %d entries\n", nr_entries);

	// 1. verify that entries are sorted
	for (int i = 1; i < nr_entries; i++) {
		Entry* prev = &entries[i - 1];
		Entry* curr = &entries[i];
		int cmp = memcmp(STR_PTR(prev->title), STR_PTR(curr->title), MIN(STR_LEN(prev->title), STR_LEN(curr->title)));
		if (cmp == 0)
			cmp = (STR_LEN(prev->title) < STR_LEN(curr->title)) ? -1 : (STR_LEN(prev->title) > STR_LEN(curr->title));

		if (cmp > 0) {
			fprintf(stderr, "error: ENTRIES ARE NOT SORTED: entry %d (%.*s) comes after entry %d (%.*s)\n", i - 1,
					STR_LEN(prev->title), STR_PTR(prev->title), i, STR_LEN(curr->title), STR_PTR(curr->title));
			exit(1);
		}
	}
	fprintf(stderr, "[info] input file entries are sorted\n");

	// 2. verify that find_entry works correctly
	for (int i = 0; i < nr_entries; i++) {
		Entry* e  = &entries[i];
		Entry* e2 = find_entry(e->title);
		if (!e2) {
			fprintf(stderr, "error: SEARCH IS BROKEN: could not find entry %.*s in entries\n", STR_LEN(e->title),
					STR_PTR(e->title));
			exit(1);
		}

		if (e2 != e) {
			fprintf(stderr, "error: SEARCH IS BROKEN: entry %.*s found at wrong location\n", STR_LEN(e->title),
					STR_PTR(e->title));
			exit(1);
		}

		if (e2 - entries != i) {
			fprintf(stderr, "error: SEARCH IS BROKEN: entry %.*s found at wrong index %d (should be %ld)\n",
					STR_LEN(e->title), STR_PTR(e->title), i, e2 - entries);
			exit(1);
		}

		if (e->title != e2->title) {
			fprintf(stderr, "error: SEARCH IS BROKEN: title string mismatch (%.*s != %.*s)\n", STR_LEN(e->title),
					STR_PTR(e->title), STR_LEN(e2->title), STR_PTR(e2->title));
			exit(1);
		}
	}
	fprintf(stderr, "[info] input file search function works correctly\n");

	// 3. verify that all link ids are valid and strictly ascending
	for (int i = 0; i < nr_entries; i++) {
		Entry* e		 = &entries[i];
		u16	   num_links = ARR_LEN(e->links);
		u32*   links	 = ARR_PTR(e->links);
		i64	   last_link = -1;
		for (int j = 0; j < num_links; j++) {
			i64 link = links[j];
			if (link >= nr_entries) {
				fprintf(stderr, "error: invalid link id %lld in entry %d\n", link, i);
				exit(1);
			}
			if (link <= last_link) {
				fprintf(stderr, "error: non-strictly ascending link id %lld in entry %d\n", link, i);
				fprintf(stderr, "       last link was %lld\n", last_link);
				exit(1);
			}
			last_link = link;
		}
	}

	fprintf(stderr, "[info] all input file sanity checks successful\n");

	new_entries = calloc(nr_entries, sizeof(Entry));
	memcpy(new_entries, entries, sizeof(Entry) * nr_entries);

	// // count incoming links for each entry
	// // incoming_count = calloc(nr_entries, sizeof(u64));
	// for (int i = 0; i < nr_entries; i++) {
	// 	Entry* e = &new_entries[i];
	// 	u16 num_links = ARR_LEN(e->links);
	// 	u32* links = ARR_PTR(e->links);
	// 	for (int j = 0; j < num_links; j++) {
	// 		u32 link = links[j];
	// 		if (link >= (u32)nr_entries) {
	// 			fprintf(stderr, "error: invalid link id %u in entry %d\n", link, i);
	// 			exit(1);
	// 		}
	// 		// incoming_count[link]++;
	// 		new_entries[link].incoming_count++;
	// 	}
	// }
	// fprintf(stderr, "[info] counted incoming links\n");

	// // sort entries by incoming link count
	// qsort(new_entries, nr_entries, sizeof(Entry), compare_entries_by_incoming_desc);
	// fprintf(stderr, "[info] sorted entries by incoming link count\n");

	// int* old_to_new_id = calloc(nr_entries, sizeof(int));
	// for (int i = 0; i < nr_entries; i++) {
	// 	Entry* ne = &new_entries[i];
	// 	Entry* e = find_entry(ne->title);
	// 	if (e == null) {
	// 		fprintf(stderr, "error: could not find entry %.*s in old entries\n", STR_LEN(ne->title),
	// STR_PTR(ne->title)); 		exit(1);
	// 	}
	// 	int old_id = e - entries;
	// 	old_to_new_id[old_id] = i;
	// }
	// fprintf(stderr, "[info] computed old to new id mapping\n");

	// // remap links to new ids
	// for (int i = 0; i < nr_entries; i++) {
	// 	Entry* e = &new_entries[i];
	// 	u16 num_links = ARR_LEN(e->links);
	// 	u32* links = ARR_PTR(e->links);
	// 	for (int j = 0; j < num_links; j++) {
	// 		u32 old_link = links[j];
	// 		if (old_link >= (u32)nr_entries) {
	// 			fprintf(stderr, "error: invalid link id %u in entry %d\n", old_link, i);
	// 			exit(1);
	// 		}
	// 		u32 new_link = old_to_new_id[old_link];
	// 		links[j] = new_link;
	// 	}
	// 	// sort links numeric asc
	// 	qsort(links, num_links, sizeof(u32), compare_u32_asc);
	// }
	// fprintf(stderr, "[info] remapped links to new ids\n");

	// // printf("10 most linked-to pages:\n");
	// // for (int i = 0; i < 10; i++) {
	// // 	Entry* ne = &new_entries[i];
	// // 	Entry* e = find_entry(ne->title);
	// // 	int old_id = e - entries;
	// // 	i64 count = ne->incoming_count;
	// // 	printf("%3d. %.*s (%li incoming links)\n", i+1, STR_LEN(ne->title), STR_PTR(ne->title), count);
	// // }

	// // {
	// // 	// find page with most outgoing links
	// // 	int most_outgoing_id = 0;
	// // 	u64 most_outgoing_count = 0;
	// // 	for (int i = 0; i < nr_entries; i++) {
	// // 		Entry* e = &new_entries[i];
	// // 		u16 num_links = ARR_LEN(e->links);
	// // 		if (num_links > most_outgoing_count) {
	// // 			most_outgoing_count = num_links;
	// // 			most_outgoing_id = i;
	// // 		}
	// // 	}

	// // 	printf("\n\n\nmost outgoing page:\n");
	// // 	printf("1. %.*s (%li outgoing links)\n", STR_LEN(new_entries[most_outgoing_id].title),
	// STR_PTR(new_entries[most_outgoing_id].title), most_outgoing_count);

	// // 	Entry* e = &new_entries[most_outgoing_id];
	// // 	u16 num_links = ARR_LEN(e->links);
	// // 	u32* links = ARR_PTR(e->links);
	// // 	printf("outgoing links:\n");
	// // 	for (int j = 0; j < MIN(num_links, 20); j++) {
	// // 		u32 link = links[j];
	// // 		printf("   %5d. [%d] %.*s\n", j+1, link, STR_LEN(new_entries[link].title),
	// STR_PTR(new_entries[link].title));
	// // 	}
	// // 	if (num_links > 20) {
	// // 		printf("   ... and %d others\n", num_links - 20);
	// // 	}
	// // }

	entries = new_entries;

	// free(old_to_new_id);
	// free(incoming_count);

	fprintf(stderr, "\n");
	write_new(argv[2]);

	fprintf(stderr, "[info] all done!\n");

	return 0;
}
