
#include <gc/gc.h>

#include <libxml/parser.h>
#include <libxml/xmlreader.h>
#include <unistd.h>

#include <stdint.h>
#include <stdlib.h>

#include <iostream>
#include <map>
#include <set>

void nop(void* p) {
	(void)p;
}

// #define STRING_MALLOC GC_malloc
// #define STRING_REALLOC GC_realloc
// #define STRING_FREE GC_free
#define STRING_FREE nop

#include "string.h"

#include "map.h"

static int       DUMP_DATE           = 221201;
static const int DUMP_FORMAT_VERSION = 2;

map_string_string    string_data = new_map_string_string();
map_string_stringptr link_map    = new_map_string_stringptr();
typedef map          map_string_u8ptr;

static inline map_string_u8ptr new_map_string_u8ptr() {
	return new_map(sizeof(string), sizeof(uint8_t*), map_hash_string, map_eq_string, map_clone_string, map_free_string);
}

static inline void map_string_u8ptr_set(map_string_u8ptr* m, string k, uint8_t* v) {
	map_set(m, &k, &v);
}

static inline uint8_t** map_string_u8ptr_get_check(map_string_u8ptr* m, string k) {
	return (uint8_t**)map_get_check(m, &k);
}

map_string_u8ptr  link_flag_map                  = new_map_string_u8ptr();
map_string_string redirects                      = new_map_string_string();
static bool       g_prune_unused_redirect_titles = false;

enum LINK_FLAGS : uint8_t {
	LINK_IS_RENAME  = 1 << 0,
	LINK_IS_INFOBOX = 1 << 1,
};

static void print_usage(const char* argv0) {
	std::cerr << "Usage: " << argv0 << " [YYYY-MM-DD] [--prune-unused-redirect-titles]\n";
	std::cerr << "  --prune-unused-redirect-titles  Keep only redirect titles referenced by unredirect edges.\n";
}

static bool parse_dump_date(const char* s, int* out_dump_date) {
	if (strlen(s) != 10 || s[4] != '-' || s[7] != '-') return false;

	int year, month, day;
	if (sscanf(s, "%4d-%2d-%2d", &year, &month, &day) != 3) return false;
	if (year < 2000 || year > 2099 || month < 1 || month > 12 || day < 1 || day > 31) return false;

	*out_dump_date = (year - 2000) * 10000 + month * 100 + day;
	return true;
}

// return: 0 = continue, 1 = exit success, -1 = exit error
static int parse_cli_args(int argc, char** argv) {
	bool has_date = false;

	for (int i = 1; i < argc; i++) {
		std::string_view arg = argv[i];
		if (arg == "--help" || arg == "-h") {
			print_usage(argv[0]);
			return 1;
		}
		if (arg == "--prune-unused-redirect-titles") {
			g_prune_unused_redirect_titles = true;
			continue;
		}
		if (!arg.empty() && arg[0] == '-') {
			std::cerr << "Unknown option: " << arg << std::endl;
			print_usage(argv[0]);
			return -1;
		}
		if (has_date) {
			std::cerr << "Only one date argument (YYYY-MM-DD) is supported." << std::endl;
			print_usage(argv[0]);
			return -1;
		}
		int parsed = 0;
		if (!parse_dump_date(argv[i], &parsed)) {
			std::cerr << "Invalid date format. Use YYYY-MM-DD." << std::endl;
			return -1;
		}
		DUMP_DATE = parsed;
		has_date  = true;
	}
	return 0;
}

static inline string get_string(string s) {
	string* p = map_string_string_get_check(&string_data, s);
	if (p) return *p;
	s = s.clone();
	map_string_string_set(&string_data, s, s);
	return s;
}

static inline constexpr std::size_t find_in_range(std::string_view sv, std::string_view needle, std::size_t start = 0,
												  std::size_t end = std::string_view::npos) {
	if (start > sv.size()) return std::string_view::npos;
	end = std::min(end, sv.size());
	if (end < start) return std::string_view::npos;

	// optimization: use memchr for single-char needles
	if (needle.size() == 1) {
		const char* p = (const char*)memchr(sv.data() + start, needle[0], end - start);
		return p ? (std::size_t)(p - sv.data()) : std::string_view::npos;
	}

	const auto local = sv.substr(start, end - start).find(needle);
	return (local == std::string_view::npos) ? std::string_view::npos : start + local;
}

static inline std::string_view trim_ascii(std::string_view s) {
	while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\n' || s.front() == '\r')) {
		s.remove_prefix(1);
	}
	while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\n' || s.back() == '\r')) {
		s.remove_suffix(1);
	}
	return s;
}

static inline bool ascii_ci_equal(std::string_view a, std::string_view b) {
	if (a.size() != b.size()) return false;
	for (size_t i = 0; i < a.size(); i++) {
		unsigned char ca = (unsigned char)a[i];
		unsigned char cb = (unsigned char)b[i];
		if (tolower(ca) != tolower(cb)) return false;
	}
	return true;
}

static inline void collect_links_in_range(std::string_view article, xmlChar* article_, std::size_t start,
										  std::size_t end, bool is_infobox, std::map<string, uint8_t>& out) {
	if (start >= end || end > article.size()) return;

	std::size_t last = start;
	while (true) {
		std::size_t link_start = find_in_range(article, "[[", last, end);
		if (link_start == std::string::npos || link_start >= end) break;

		std::size_t link_end = find_in_range(article, "]]", link_start + 2, end);
		if (link_end == std::string::npos || link_end > end) break;
		if (link_start + 2 >= article.size()) break;

		article_[link_start + 2] = (xmlChar)toupper((unsigned char)article_[link_start + 2]);

		std::string_view raw_target = "";
		std::string_view raw_label  = "";
		std::size_t      pipe_idx   = find_in_range(article, "|", link_start + 2, link_end);
		if (pipe_idx != std::string::npos) {
			raw_target = std::string_view(article.data() + link_start + 2, pipe_idx - link_start - 2);
			raw_label  = std::string_view(article.data() + pipe_idx + 1, link_end - pipe_idx - 1);
		} else {
			raw_target = std::string_view(article.data() + link_start + 2, link_end - link_start - 2);
		}

		std::size_t hash_idx = find_in_range(raw_target, "#");
		if (hash_idx != std::string::npos) {
			raw_target = std::string_view(raw_target.data(), hash_idx);
		}

		std::string_view target = trim_ascii(raw_target);
		if (target.empty()) {
			last = link_end + 2;
			continue;
		}

		uint8_t flags = 0;
		if (is_infobox) flags |= LINK_IS_INFOBOX;
		if (pipe_idx != std::string::npos) {
			std::string_view label = trim_ascii(raw_label);
			if (!ascii_ci_equal(target, label)) flags |= LINK_IS_RENAME;
		}

		string key = get_string(target);
		auto   it  = out.find(key);
		if (it == out.end()) {
			out[key] = flags;
		} else {
			it->second |= flags;
		}
		last = link_end + 2;
	}
}

int parse_xml() {
	xmlParserCtxtPtr parser_context = xmlNewParserCtxt();
	if (!parser_context) {
		std::cerr << "Failed to create XML parser context." << std::endl;
		exit(1);
	}

	xmlTextReaderPtr reader = xmlReaderForFd(STDIN_FILENO, nullptr, nullptr, 0);
	if (!reader) {
		std::cerr << "Failed to create XML reader." << std::endl;
		xmlFreeParserCtxt(parser_context);
		exit(1);
	}

	bool in_page = false;

	string                    page_title = "";
	std::map<string, uint8_t> page_links;

	size_t count = 0;

	while (true) {
		int result = xmlTextReaderRead(reader);
		if (result == 0) {
			// End of document reached.
			break;
		} else if (result == -1) {
			// Error occurred.
			std::cerr << "Error reading XML document." << std::endl;
			break;
		}

		// Process the current node.
		switch (xmlTextReaderNodeType(reader)) {
		case XML_READER_TYPE_ELEMENT: {
			const xmlChar* tag = xmlTextReaderConstName(reader);

			if (!in_page) {
				if (xmlStrcmp(tag, (const xmlChar*)"page") == 0) in_page = true;
				break;
			} else {
				if (xmlStrcmp(tag, (const xmlChar*)"title") == 0) {
					xmlTextReaderRead(reader);
					const xmlChar* title = xmlTextReaderConstValue(reader);
					page_title           = get_string((const char*)title);
				}

				else if (xmlStrcmp(tag, (const xmlChar*)"text") == 0) {
					xmlTextReaderRead(reader);
					xmlChar*         article_ = (xmlChar*)xmlTextReaderConstValue(reader);
					std::string_view article  = (const char*)article_;

					size_t last_end = 0, link_start = 0;
					while ((link_start = find_in_range(article, "[[", last_end)) != std::string::npos) {
						size_t info_start = find_in_range(article, "{{", last_end, link_start);
						if (info_start != std::string::npos) {
							size_t infoEnd = info_start + 2;
							int    n       = 1;
							while (n > 0) {
								size_t nextOpen  = find_in_range(article, "{{", infoEnd);
								size_t nextClose = find_in_range(article, "}}", infoEnd);
								if (nextClose == std::string::npos) break;
								if (nextOpen != std::string::npos && nextOpen < nextClose) {
									n++;
									infoEnd = nextOpen + 2;
								} else {
									n--;
									infoEnd = nextClose + 2;
								}
							}

							collect_links_in_range(article, article_, info_start, infoEnd, true, page_links);
							last_end = infoEnd;
							continue;
						}

						size_t tag_start = find_in_range(article, "<", last_end, link_start);
						if (tag_start != std::string::npos) {
							// strip <!-- comment --> s
							size_t comment_start = find_in_range(article, "<!--", last_end, link_start);
							if (comment_start != std::string::npos) {
								size_t comment_end = find_in_range(article, "-->", comment_start + 4);
								if (comment_end == std::string::npos) break;
								last_end = comment_end + 3;
								continue;
							}

							// strip <ref> and <nowiki>
							size_t tag_end = find_in_range(article, ">", tag_start + 1);
							if (tag_end != std::string::npos) {
								std::string_view full_opening_tag =
									std::string_view(article.data() + tag_start + 1, tag_end - tag_start - 1);
								size_t           space_idx = find_in_range(full_opening_tag, " ");
								std::string_view tag_name  = space_idx == std::string::npos
																 ? full_opening_tag
																 : full_opening_tag.substr(0, space_idx);
								if (tag_name == "ref" || tag_name == "nowiki") {
									if (full_opening_tag.size() > 0 && full_opening_tag.back() == '/') {
										// self-closing tag
										last_end = tag_end + 1;
										continue;
									}
									std::string_view closing_tag = tag_name == "ref" ? "</ref>" : "</nowiki>";
									size_t closing_tag_start     = find_in_range(article, closing_tag, tag_end + 1);
									if (closing_tag_start != std::string::npos) {
										last_end = closing_tag_start + closing_tag.size();
										continue;
									} else {
										break;
									}
								}
							}
						}

						size_t end = find_in_range(article, "]]", link_start);
						if (end == std::string::npos) break;
						collect_links_in_range(article, article_, link_start, end + 2, false, page_links);

						last_end = end + 2;
					}
				}

				else if (xmlStrcmp(tag, (const xmlChar*)"ns") == 0) {
					xmlTextReaderRead(reader);
					int ns = atoi((const char*)xmlTextReaderConstValue(reader));
					if (ns != 0) in_page = false;
				}

				else if (xmlStrcmp(tag, (const xmlChar*)"redirect") == 0) {
					const char* title_ = (const char*)xmlTextReaderGetAttribute(reader, (const xmlChar*)"title");
					string      title  = title_;
					char*       hash   = (char*)memchr(title_, '#', title.len);
					if (hash) title = std::string_view(title_, hash - title_);
					map_string_string_set(&redirects, page_title, get_string(title));

					in_page = false;
				}

				break;
			}
		}
		case XML_READER_TYPE_END_ELEMENT: {
			const xmlChar* end_tag = xmlTextReaderConstName(reader);
			if (in_page && xmlStrcmp(end_tag, (const xmlChar*)"page") == 0) {
				in_page = false;

				string*  linkptr = (string*)GC_malloc(sizeof(string) * (page_links.size() + 1));
				uint8_t* flagptr = (uint8_t*)GC_malloc(sizeof(uint8_t) * (page_links.size() + 1));
				size_t   i       = 0;
				for (auto& kv : page_links) {
					linkptr[i] = kv.first;
					flagptr[i] = kv.second;
					i++;
				}
				linkptr[i] = nullptr;
				flagptr[i] = 0;
				map_string_stringptr_set(&link_map, page_title, linkptr);
				map_string_u8ptr_set(&link_flag_map, page_title, flagptr);

				page_links.clear();
				count++;
			}

			break;
		}
		}
	}
	// Clean up.
	xmlFreeTextReader(reader);
	xmlFreeParserCtxt(parser_context);

	return count;
}

struct LinkWithFlags {
	int     id;
	uint8_t flags;
};

struct PageLinks {
	int            n;
	int            cap;
	LinkWithFlags* edges;
};

PageLinks* links;
string*    titles;
int        page_count;

static inline int int_cmp(const void* a, const void* b) {
	int x = *(const int*)a;
	int y = *(const int*)b;
	if (x < y) return -1;
	if (x > y) return 1;
	return 0;
}

static inline int edge_cmp(const void* a, const void* b) {
	int x = ((const LinkWithFlags*)a)->id;
	int y = ((const LinkWithFlags*)b)->id;
	if (x < y) return -1;
	if (x > y) return 1;
	return 0;
}

static inline int int_bsearch(const int* a, int n, int x) {
	int l = 0, r = n - 1;
	while (l <= r) {
		int m = (l + r) / 2;
		int v = a[m];
		if (v == x) return 1;
		if (v < x) l = m + 1;
		else r = m - 1;
	}
	return 0;
}

static inline uint64_t dedupe_sorted_links(PageLinks* l) {
	if (l->n <= 1) return 0;
	uint64_t removed = 0;
	int      j       = 0;
	for (int k = 1; k < l->n; k++) {
		if (l->edges[k].id != l->edges[j].id) {
			l->edges[++j] = l->edges[k];
		} else {
			if (l->edges[k].flags < l->edges[j].flags) l->edges[j].flags = l->edges[k].flags;
			removed++;
		}
	}
	l->n = j + 1;
	return removed;
}

static inline int string_cmp_qsort(const void* a, const void* b) {
	const string* x = (const string*)a;
	const string* y = (const string*)b;
	if (*x < *y) return -1;
	if (*x > *y) return 1;
	return 0;
}

/* ---------------------------------------------
   unredirect db (built after trimming)
   --------------------------------------------- */

struct Cand {
	int      dest;
	uint16_t redir_len;
	string   redir_title;
	uint32_t redir_in;
};

struct UnredirTmp {
	uint32_t src;
	uint32_t dest;
	string   redir_title;
};

struct UnredirEdge {
	uint32_t src;
	uint32_t dest;
	uint32_t redir_idx;
};

static UnredirEdge* unredir_edges = nullptr;
static uint32_t     unredir_n     = 0;

static string*  redir_titles       = nullptr; /* filtered + sorted */
static uint32_t redir_titles_n     = 0;
static uint32_t redir_titles_bytes = 0;

static inline int cand_cmp(const void* a, const void* b) {
	const Cand* x = (const Cand*)a;
	const Cand* y = (const Cand*)b;
	if (x->dest < y->dest) return -1;
	if (x->dest > y->dest) return 1;
	if (x->redir_len < y->redir_len) return -1;
	if (x->redir_len > y->redir_len) return 1;
	/* higher incoming first */
	if (x->redir_in > y->redir_in) return -1;
	if (x->redir_in < y->redir_in) return 1;
	if (x->redir_title < y->redir_title) return -1;
	if (x->redir_title > y->redir_title) return 1;
	return 0;
}

static inline int unredir_edge_cmp(const void* a, const void* b) {
	const UnredirEdge* x = (const UnredirEdge*)a;
	const UnredirEdge* y = (const UnredirEdge*)b;
	if (x->src < y->src) return -1;
	if (x->src > y->src) return 1;
	if (x->dest < y->dest) return -1;
	if (x->dest > y->dest) return 1;
	if (x->redir_idx < y->redir_idx) return -1;
	if (x->redir_idx > y->redir_idx) return 1;
	return 0;
}

static int bsearch_redir_titles(const string& t) {
	int l = 0, r = (int)redir_titles_n - 1;
	while (l <= r) {
		int m = (l + r) / 2;
		if (redir_titles[m] == t) return m;
		if (redir_titles[m] < t) l = m + 1;
		else r = m - 1;
	}
	return -1;
}

int bsearch(std::string title) {
	int l = 0, r = page_count - 1;
	while (l <= r) {
		int m = (l + r) / 2;
		if (titles[m] == title) return m;
		if (titles[m] < title) l = m + 1;
		else r = m - 1;
	}
	return -1;
}

std::vector<int> empty_pages;

int trim_empty_pages() {
	for (int i = 0; i < page_count; i++) {
		PageLinks* l = links + i;
		if (l->n == 0) empty_pages.push_back(i);
	}

	fprintf(stderr, "Empty pages: %d / %d\n", (int)empty_pages.size(), page_count);
	if (empty_pages.empty()) return 0;

	for (int i = 0; i < page_count; i++) {
		for (int j = 0; j < links[i].n; j++) {
			int  l = links[i].edges[j].id;
			auto b = std::lower_bound(empty_pages.begin(), empty_pages.end(), l);
			if (b != empty_pages.end() && *b == l) links[i].edges[j].id = -1;
		}
		int j = 0;
		for (int k = 0; k < links[i].n; k++) {
			if (links[i].edges[k].id != -1) links[i].edges[j++] = links[i].edges[k];
		}
		links[i].n = j;
	}

	int* old_id_to_new_id = (int*)GC_malloc(page_count * sizeof(int));
	for (int i = 0; i < page_count; i++) old_id_to_new_id[i] = i;

	for (int i = 0; i < (int)empty_pages.size(); i++) {
		int id = empty_pages[i];
		int m  = (i == (int)empty_pages.size() - 1) ? page_count : empty_pages[i + 1];
		for (int j = id; j < m; j++) {
			old_id_to_new_id[j] -= i + 1;
		}
	}

	int        l       = page_count - (int)empty_pages.size();
	string*    titles_ = (string*)GC_malloc(l * sizeof(string));
	PageLinks* links_  = (PageLinks*)GC_malloc(l * sizeof(PageLinks));
	memset(links_, 0, l * sizeof(PageLinks));

	int titles_len = 0;
	int links_len  = 0;
	for (int i = 0, b = 0; i < page_count; i++) {
		if (b < (int)empty_pages.size() && empty_pages[b] == i) {
			b++;
			continue;
		}
		titles_[titles_len++] = titles[i];
		links_[links_len++]   = links[i];
	}

	GC_free(titles);
	GC_free(links);
	titles     = titles_;
	links      = links_;
	page_count = l;

	for (int j = 0; j < links_len; j++) {
		for (int k = 0; k < links[j].n; k++) {
			int* q = &links[j].edges[k].id;
			*q     = old_id_to_new_id[*q];
		}
	}

	GC_free(old_id_to_new_id);

	int s = (int)empty_pages.size();
	empty_pages.clear();
	return s;
}

void write_db() {
	fprintf(stderr, "Writing db...\n");
	FILE* f   = stdout;
	char* buf = (char*)GC_malloc(16 << 20);
	setvbuf(f, buf, _IOFBF, 16 << 20);

	if (fwrite("WIKI", 1, 4, f) != 4) {
		perror("header");
		exit(1);
	}

	uint32_t version = (DUMP_DATE << 8) | DUMP_FORMAT_VERSION;
	if (fwrite(&version, sizeof(version), 1, f) != 1) {
		perror("version");
		exit(1);
	}

	int32_t num_titles = (int32_t)page_count;
	if (fwrite(&num_titles, sizeof(num_titles), 1, f) != 1) {
		perror("num_titles");
		exit(1);
	}

	uint32_t total_links = 0;
	for (int i = 0; i < page_count; i++) {
		total_links += (uint32_t)links[i].n;
	}
	if (fwrite(&total_links, sizeof(total_links), 1, f) != 1) {
		perror("total_links");
		exit(1);
	}

	uint32_t total_title_bytes = 0;
	for (int i = 0; i < page_count; i++) {
		total_title_bytes += (uint32_t)titles[i].len;
	}
	if (fwrite(&total_title_bytes, sizeof(total_title_bytes), 1, f) != 1) {
		perror("fwrite");
		exit(1);
	}

	uint32_t outdegree_pad_u16 = (page_count % 4) ? (uint32_t)(4 - (page_count % 4)) : 0u;
	uint32_t redir_len_pad     = (4u - (redir_titles_n & 3u)) & 3u;

	for (int i = 0; i < page_count; i++) {
		uint16_t num_links = (uint16_t)links[i].n;
		if (fwrite(&num_links, sizeof(num_links), 1, f) != 1) {
			perror("fwrite");
			exit(1);
		}
	}

	{
		char zeros[8] = {0};
		if (outdegree_pad_u16) {
			if (fwrite(zeros, sizeof(uint16_t), outdegree_pad_u16, f) != outdegree_pad_u16) {
				perror("fwrite");
				exit(1);
			}
		}
	}

	for (int i = 0; i < page_count; i++) {
		for (int j = 0; j < links[i].n; j++) {
			int32_t link = links[i].edges[j].id;
			char*   p    = (char*)&link;
			if (p[3] != 0) {
				perror("link overflow");
			}
			if (fwrite(&link, 4, 1, f) != 1) {
				perror("fwrite");
				exit(1);
			}
		}
	}

	for (int i = 0; i < page_count; i++) {
		uint16_t title_len = (uint16_t)titles[i].len;
		if (fwrite(&title_len, sizeof(title_len), 1, f) != 1) {
			perror("fwrite");
			exit(1);
		}
	}

	for (int i = 0; i < page_count; i++) {
		if (fwrite(titles[i], 1, titles[i].len, f) != titles[i].len) {
			perror("fwrite");
			exit(1);
		}
	}

	/* ------------------------------
	   format v2 extension (append-only):
	   [u32 unredir_n]
	   [u32 redir_titles_n]
	   [u32 redir_titles_bytes]
	   [ (u32 src,u32 dest,u32 redir_idx) * unredir_n ]
	   [ u8 redir_title_len * redir_titles_n ]
	   [ padding to 4 bytes ]
	   [ redir_titles bytes ]
	   ------------------------------ */

	{
		uint32_t n      = unredir_n;
		uint32_t rt     = redir_titles_n;
		uint32_t rbytes = redir_titles_bytes;

		if (fwrite(&n, sizeof(n), 1, f) != 1) {
			perror("unredir_n");
			exit(1);
		}
		if (fwrite(&rt, sizeof(rt), 1, f) != 1) {
			perror("redir_titles_n");
			exit(1);
		}
		if (fwrite(&rbytes, sizeof(rbytes), 1, f) != 1) {
			perror("redir_titles_bytes");
			exit(1);
		}

		for (uint32_t i = 0; i < unredir_n; i++) {
			if (fwrite(&unredir_edges[i].src, sizeof(uint32_t), 1, f) != 1) {
				perror("unredir");
				exit(1);
			}
			if (fwrite(&unredir_edges[i].dest, sizeof(uint32_t), 1, f) != 1) {
				perror("unredir");
				exit(1);
			}
			if (fwrite(&unredir_edges[i].redir_idx, sizeof(uint32_t), 1, f) != 1) {
				perror("unredir");
				exit(1);
			}
		}

		for (uint32_t i = 0; i < redir_titles_n; i++) {
			if (redir_titles[i].len > 255) {
				fprintf(stderr, "redirect title too long for u8 len: %.*s\n", (int)redir_titles[i].len,
						(const char*)redir_titles[i].p());
				exit(1);
			}
			uint8_t l = (uint8_t)redir_titles[i].len;
			if (fwrite(&l, 1, 1, f) != 1) {
				perror("redir_title_len");
				exit(1);
			}
		}

		/* pad to 4 bytes */
		{
			char zeros[8] = {0};
			if (redir_len_pad) {
				if (fwrite(zeros, 1, redir_len_pad, f) != redir_len_pad) {
					perror("redir_title_len_pad");
					exit(1);
				}
			}
		}

		for (uint32_t i = 0; i < redir_titles_n; i++) {
			if (fwrite(redir_titles[i], 1, redir_titles[i].len, f) != redir_titles[i].len) {
				perror("redir_title_bytes");
				exit(1);
			}
		}
	}

	/* ------------------------------
	   section 5 (append-only):
	   [ u8 link_flags[total_links] ]
	   flags bitfield per flattened edge in section 2 order.
	   ------------------------------ */
	for (int i = 0; i < page_count; i++) {
		for (int j = 0; j < links[i].n; j++) {
			uint8_t flags = links[i].edges[j].flags;
			if (fwrite(&flags, 1, 1, f) != 1) {
				perror("link_flags");
				exit(1);
			}
		}
	}

	uint64_t header_bytes = 4u + (uint64_t)sizeof(version) + (uint64_t)sizeof(num_titles) +
							(uint64_t)sizeof(total_links) + (uint64_t)sizeof(total_title_bytes);
	uint64_t outdegree_bytes =
		(uint64_t)page_count * (uint64_t)sizeof(uint16_t) + (uint64_t)outdegree_pad_u16 * (uint64_t)sizeof(uint16_t);
	uint64_t edge_bytes             = (uint64_t)total_links * 4u;
	uint64_t title_len_bytes        = (uint64_t)page_count * (uint64_t)sizeof(uint16_t);
	uint64_t title_bytes            = (uint64_t)total_title_bytes;
	uint64_t v2_header_bytes        = 3u * (uint64_t)sizeof(uint32_t);
	uint64_t v2_unredir_tuple_bytes = (uint64_t)unredir_n * 3u * (uint64_t)sizeof(uint32_t);
	uint64_t v2_redir_len_bytes     = (uint64_t)redir_titles_n + (uint64_t)redir_len_pad;
	uint64_t v2_redir_title_bytes   = (uint64_t)redir_titles_bytes;
	uint64_t v2_total_bytes   = v2_header_bytes + v2_unredir_tuple_bytes + v2_redir_len_bytes + v2_redir_title_bytes;
	uint64_t link_flags_bytes = (uint64_t)total_links;
	uint64_t total_output_bytes =
		header_bytes + outdegree_bytes + edge_bytes + title_len_bytes + title_bytes + v2_total_bytes + link_flags_bytes;

	int value_width = 1;
	for (uint64_t t = total_output_bytes; t >= 10; t /= 10) {
		value_width++;
	}
	auto print_size_stat = [&](const char* label, uint64_t bytes) {
		double pct = (total_output_bytes == 0) ? 0.0 : (100.0 * (double)bytes / (double)total_output_bytes);
		fprintf(stderr, "  %-32s %*llu (%.2f%%)\n", label, value_width, (unsigned long long)bytes, pct);
	};

	fprintf(stderr, "Output size stats (bytes):\n");
	print_size_stat("header:", header_bytes);
	print_size_stat("section1_outdegree_u16_plus_pad:", outdegree_bytes);
	print_size_stat("section2_edges_u32:", edge_bytes);
	print_size_stat("section3_title_lens_u16:", title_len_bytes);
	print_size_stat("section4_title_bytes:", title_bytes);
	print_size_stat("section5_v2_total:", v2_total_bytes);
	print_size_stat("  section5_v2_header:", v2_header_bytes);
	print_size_stat("  section5_unredir_tuples:", v2_unredir_tuple_bytes);
	print_size_stat("  section5_redir_lens_plus_pad:", v2_redir_len_bytes);
	print_size_stat("  section5_redir_title_bytes:", v2_redir_title_bytes);
	print_size_stat("section6_link_flags:", link_flags_bytes);
	print_size_stat("total_output_bytes:", total_output_bytes);

	fflush(f);
	sync();
	GC_free(buf);
}

static const int MAX_REDIRECT_HOPS = 128;

int resolve_link_id_len(const string& t, int* out_redir_len) {
	// Follow: t -> redirects[t] -> redirects[...] ... until a real page is found
	// Returns: final page id, and number of redirect hops taken.
	std::set<string> seen;
	string           cur = t;

	for (int hop = 0; hop < MAX_REDIRECT_HOPS; ++hop) {
		int id = bsearch(cur);
		if (id != -1) {
			if (out_redir_len) *out_redir_len = hop;
			return id;
		}

		string* p = map_string_string_get_check(&redirects, cur);
		if (!p) return -1;

		if (!seen.insert(cur).second) return -1;
		cur = *p;
	}
	return -1;
}

int resolve_link_id(const string& t) {
	// Follow: t -> redirects[t] -> redirects[...] ... until a real page is found
	// Stops on: page found, no redirect, cycle, or hop cap.
	std::set<string> seen;
	string           cur = t;

	for (int hop = 0; hop < MAX_REDIRECT_HOPS; ++hop) {
		// If this title exists as a real page, we’re done.
		int id = bsearch(cur);
		if (id != -1) return id;

		// Otherwise try to follow a redirect.
		string* p = map_string_string_get_check(&redirects, cur);
		if (!p) return -1; // no redirect and not a real page → missing

		// Cycle guard
		if (!seen.insert(cur).second) return -1;

		cur = *p; // follow to next hop
	}
	// Too many hops → treat as invalid to avoid pathological chains
	return -1;
}

static inline int is_redirect_title(const string& t) {
	string* p = map_string_string_get_check(&redirects, t);
	return p != nullptr;
}

static void build_unredirect_db() {
	fprintf(stderr, "Building unredirect db...\n");

	/* pass 1: count incoming links to redirect titles (only from surviving pages) */
	map_string_int redir_in = new_map_string_int();

	FOR_IN_MAP_STRING_STRINGPTR(link_map, title, links_, {
		int src = bsearch(title);
		if (src == -1) continue;
		string* ll = *links_;
		for (int i = 0; ll[i].p() != nullptr; i++) {
			if (!is_redirect_title(ll[i])) continue;
			int32_t* c = map_string_int_get_check(&redir_in, ll[i]);
			if (c) {
				(*c)++;
			} else {
				map_string_int_set(&redir_in, ll[i], 1);
			}
		}
	})

	/* pass 2: choose 0/1 redirect witness per (src,dest) when no direct link exists */
	UnredirTmp* tmp     = nullptr;
	uint32_t    tmp_n   = 0;
	uint32_t    tmp_cap = 0;

	FOR_IN_MAP_STRING_STRINGPTR(link_map, title, links_, {
		int src = bsearch(title);
		if (src == -1) continue;

		/* per-page scratch */
		int* direct     = nullptr;
		int  direct_n   = 0;
		int  direct_cap = 0;

		Cand* cand     = nullptr;
		int   cand_n   = 0;
		int   cand_cap = 0;

		string* ll = *links_;
		for (int i = 0; ll[i].p() != nullptr; i++) {
			int redir_len = 0;
			int dest      = resolve_link_id_len(ll[i], &redir_len);
			if (dest == -1) continue;

			if (redir_len == 0) {
				if (direct_n == direct_cap) {
					direct_cap = direct_cap * 2 + 16;
					direct     = (int*)GC_realloc(direct, sizeof(int) * direct_cap);
				}
				direct[direct_n++] = dest;
			} else {
				if (cand_n == cand_cap) {
					cand_cap = cand_cap * 2 + 32;
					cand     = (Cand*)GC_realloc(cand, sizeof(Cand) * cand_cap);
				}

				int      in = 0;
				int32_t* p  = map_string_int_get_check(&redir_in, ll[i]);
				if (p) in = (int)(*p);

				cand[cand_n].dest        = dest;
				cand[cand_n].redir_len   = (uint16_t)redir_len;
				cand[cand_n].redir_title = ll[i]; /* first hop the user clicks */
				cand[cand_n].redir_in    = (uint32_t)in;
				cand_n++;
			}
		}

		if (direct_n) {
			qsort(direct, (size_t)direct_n, sizeof(int), int_cmp);
			/* uniq */
			int j = 0;
			for (int k = 1; k < direct_n; k++) {
				if (direct[k] != direct[j]) direct[++j] = direct[k];
			}
			direct_n = j + 1;
		}

		if (cand_n == 0) continue;

		qsort(cand, (size_t)cand_n, sizeof(Cand), cand_cmp);

		/* iterate groups by dest, skip if direct exists, choose best candidate */
		{
			int i = 0;
			while (i < cand_n) {
				int dest = cand[i].dest;
				int j    = i + 1;
				while (j < cand_n && cand[j].dest == dest) j++;

				if (!int_bsearch(direct, direct_n, dest)) {
					/* pick minimal redirect chain length (sorted), then highest incoming (sorted), then alpha */
					if (tmp_n == tmp_cap) {
						tmp_cap = tmp_cap * 2 + 1024;
						tmp     = (UnredirTmp*)GC_realloc(tmp, sizeof(UnredirTmp) * tmp_cap);
					}
					tmp[tmp_n].src         = (uint32_t)src;
					tmp[tmp_n].dest        = (uint32_t)dest;
					tmp[tmp_n].redir_title = cand[i].redir_title;
					tmp_n++;
				}

				i = j;
			}
		}
	})

	fprintf(stderr, "Unredirect tuples (pre-table): %u\n", tmp_n);

	unredir_edges = nullptr;
	unredir_n     = tmp_n;

	if (tmp_n) {
		unredir_edges = (UnredirEdge*)GC_malloc(sizeof(UnredirEdge) * tmp_n);
	}

	redir_titles       = nullptr;
	redir_titles_n     = 0;
	redir_titles_bytes = 0;

	/* build redirect title table (pruned or full) */
	if (g_prune_unused_redirect_titles) {
		if (tmp_n) {
			string* r = (string*)GC_malloc(sizeof(string) * tmp_n);
			for (uint32_t i = 0; i < tmp_n; i++) r[i] = tmp[i].redir_title;

			qsort(r, (size_t)tmp_n, sizeof(string), string_cmp_qsort);

			/* uniq */
			uint32_t n = 0;
			for (uint32_t i = 0; i < tmp_n; i++) {
				if (n == 0 || !(r[i] == r[n - 1])) r[n++] = r[i];
			}

			redir_titles       = (string*)GC_malloc(sizeof(string) * n);
			redir_titles_n     = n;
			redir_titles_bytes = 0;

			for (uint32_t i = 0; i < n; i++) {
				redir_titles[i] = r[i];
				redir_titles_bytes += (uint32_t)redir_titles[i].len;
			}
		}
	} else {
		string*  r     = nullptr;
		uint32_t r_n   = 0;
		uint32_t r_cap = 0;

		FOR_IN_MAP(redirects, redir_title, string, redir_target, string, {
			(void)redir_target;
			if (r_n == r_cap) {
				r_cap = r_cap * 2 + 1024;
				r     = (string*)GC_realloc(r, sizeof(string) * r_cap);
			}
			r[r_n++] = redir_title;
		})

		if (r_n) {
			qsort(r, (size_t)r_n, sizeof(string), string_cmp_qsort);

			/* uniq */
			uint32_t n = 0;
			for (uint32_t i = 0; i < r_n; i++) {
				if (n == 0 || !(r[i] == r[n - 1])) r[n++] = r[i];
			}

			redir_titles       = (string*)GC_malloc(sizeof(string) * n);
			redir_titles_n     = n;
			redir_titles_bytes = 0;

			for (uint32_t i = 0; i < n; i++) {
				redir_titles[i] = r[i];
				redir_titles_bytes += (uint32_t)redir_titles[i].len;
			}
		}
	}

	/* materialize final unredirect edges with redir_idx, then sort */
	for (uint32_t i = 0; i < tmp_n; i++) {
		int ridx = bsearch_redir_titles(tmp[i].redir_title);
		if (ridx == -1) {
			fprintf(stderr, "internal error: missing redirect title\n");
			exit(1);
		}
		unredir_edges[i].src       = tmp[i].src;
		unredir_edges[i].dest      = tmp[i].dest;
		unredir_edges[i].redir_idx = (uint32_t)ridx;
	}

	if (unredir_n) qsort(unredir_edges, (size_t)unredir_n, sizeof(UnredirEdge), unredir_edge_cmp);

	/* sanity: ensure at most one per (src,dest) */
	for (uint32_t i = 1; i < unredir_n; i++) {
		if (unredir_edges[i].src == unredir_edges[i - 1].src && unredir_edges[i].dest == unredir_edges[i - 1].dest) {
			fprintf(stderr, "internal error: duplicate unredirect for (%u,%u)\n", unredir_edges[i].src,
					unredir_edges[i].dest);
			exit(1);
		}
	}

	fprintf(stderr, "Unredirect edges: %u\n", unredir_n);
	fprintf(stderr, "Redirect titles used: %u (%u bytes)\n", redir_titles_n, redir_titles_bytes);
}

int main(int argc, char** argv) {
	int parse_status = parse_cli_args(argc, argv);
	if (parse_status == 1) return 0;
	if (parse_status == -1) return 1;

	fprintf(stderr, "Options: prune_unused_redirect_titles=%s\n", g_prune_unused_redirect_titles ? "on" : "off");
	fprintf(stderr, "Graph includes all links; per-edge flags encode infobox/rename hints in trailing section 5.\n");
	if (!g_prune_unused_redirect_titles) {
		fprintf(stderr, "Redirect title pruning is disabled (default).\n");
	}

	GC_INIT();
	xmlMemSetup(GC_free, GC_malloc, GC_realloc, GC_strdup);

	page_count = parse_xml();

	titles = (string*)GC_malloc(page_count * sizeof(string));
	links  = (PageLinks*)GC_malloc(page_count * sizeof(PageLinks));
	memset(links, 0, page_count * sizeof(PageLinks));

	{
		int i = 0;
		FOR_IN_MAP_STRING_STRINGPTR(link_map, title, _, {
			(void)_;
			titles[i++] = title;
		})
	}

	std::sort(titles, titles + page_count);

	FOR_IN_MAP_STRING_STRINGPTR(link_map, title, links_, {
		int idx = bsearch(title);
		if (idx == -1) continue;
		string*   ll      = *links_;
		uint8_t** flagspp = map_string_u8ptr_get_check(&link_flag_map, title);
		if (!flagspp) {
			fprintf(stderr, "internal error: missing link flags for page\n");
			exit(1);
		}
		uint8_t* lf = *flagspp;

		PageLinks* l = links + idx;

		for (int i = 0; ll[i].p() != nullptr; i++) {
			int link_idx = resolve_link_id(ll[i]);
			if (link_idx == -1) continue;

			if (l->n == l->cap) {
				l->cap   = l->cap * 2 + 1;
				l->edges = (LinkWithFlags*)GC_realloc(l->edges, l->cap * sizeof(LinkWithFlags));
			}

			l->edges[l->n].id    = link_idx;
			l->edges[l->n].flags = lf[i];
			l->n++;
		}

		if (l->n) qsort(l->edges, (size_t)l->n, sizeof(LinkWithFlags), edge_cmp);
	})

	while (1) {
		int n = trim_empty_pages();
		fprintf(stderr, "Trimmed %d empty pages\n\n", n);
		if (n == 0) break;
	}

	// remove duplicate links in each page
	uint64_t duplicates_removed = 0;
	for (int i = 0; i < page_count; i++) {
		PageLinks* l = links + i;
		duplicates_removed += dedupe_sorted_links(l);
	}
	fprintf(stderr, "Removed %llu spurious duplicate links\n", duplicates_removed);

	/* build redirect witness table for edges that are only possible via redirects */
	build_unredirect_db();

	write_db();

	return 0;
}
