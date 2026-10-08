
#include <gc/gc.h>

#include "wiki_links.h"
#include <libxml/parser.h>
#include <libxml/xmlreader.h>
#include <unistd.h>

#include <stdint.h>
#include <stdlib.h>

#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>
#include <vector>

namespace meta
{
	inline void need(bool ok, const char* message) {
		if (!ok) throw std::runtime_error(message);
	}

	inline void number(std::vector<unsigned char>& b, uint64_t n, unsigned bytes) {
		for (unsigned i = 0; i < bytes; i++) b.push_back((unsigned char)(n >> (i * 8)));
	}

	inline void text(std::vector<unsigned char>& b, const std::string& s) {
		need(s.size() <= 65535, "metadata string too long");
		number(b, s.size(), 2);
		b.insert(b.end(), s.begin(), s.end());
	}

	inline uint64_t decimal(const std::string& s) {
		need(!s.empty(), "missing decimal");
		uint64_t n = 0;
		for (char c : s) {
			need(c >= '0' && c <= '9' && n <= (UINT64_MAX - (c - '0')) / 10, "invalid decimal");
			n = n * 10 + c - '0';
		}
		return n;
	}

	inline std::string value(xmlTextReaderPtr r) {
		const xmlChar* p = xmlTextReaderConstValue(r);
		return p ? (const char*)p : "";
	}

	inline std::string attribute(xmlTextReaderPtr r, const char* key) {
		xmlChar*    p = xmlTextReaderGetAttribute(r, (const xmlChar*)key);
		std::string s = p ? (const char*)p : "";
		if (p) xmlFree(p);
		return s;
	}

	struct Page {
		uint64_t    id = 0, revision = 0;
		int32_t     ns     = 0;
		bool        has_id = false, has_ns = false, has_revision = false, redirect = false;
		unsigned    revisions = 0, title_elements = 0;
		std::string title;

		void reset() {
			*this = Page();
		}
	};

	inline std::vector<unsigned char> encode(const Page& p) {
		need(p.has_id && p.id != 0 && p.title_elements == 1 && !p.title.empty() && p.has_ns,
			 "page lacks unique ID, title or namespace");
		need(p.revisions == 1, "page must contain exactly one selected revision");
		need(p.has_revision ? p.revision != 0 : p.revision == 0, "invalid revision presence or ID");
		std::vector<unsigned char> b;
		number(b, p.id, 8);
		number(b, (uint32_t)p.ns, 4);
		unsigned flags = (p.has_revision ? 1 : 0) | (p.redirect ? 8 : 0);
		number(b, flags, 1);
		number(b, p.revision, 8);
		text(b, p.title);
		return b;
	}

	// A spool stores exact page records from the graph's XML reader, before pruning.
	inline void spoolSite(FILE* f, const std::vector<unsigned char>& site) {
		need(!site.empty() && site.size() <= 65535, "missing or oversized siteinfo");
		const unsigned char magic[4] = {'S', 'I', 'N', 'F'};
		unsigned char       len[4];
		for (int i = 0; i < 4; i++) len[i] = (unsigned char)(site.size() >> (8 * i));
		need(fwrite(magic, 1, 4, f) == 4 && fwrite(len, 1, 4, f) == 4 &&
				 fwrite(site.data(), 1, site.size(), f) == site.size(),
			 "siteinfo spool write failed");
	}

	inline void spool(FILE* f, const Page& p) {
		auto b = encode(p);
		need(b.size() < 65536, "page record exceeds spool limit");
		unsigned char len[4];
		for (int i = 0; i < 4; i++) len[i] = (unsigned char)(b.size() >> (8 * i));
		need(fwrite(len, 1, 4, f) == 4 && fwrite(b.data(), 1, b.size(), f) == b.size(), "spool write failed");
	}

	// Observe the same reader and selected revision as the graph generator.
	struct Observer {
		Page                                                             page;
		bool                                                             inside = false, revision = false, site = false;
		std::string                                                      field, site_field;
		std::string                                                      wiki, lang, site_case;
		std::vector<unsigned char>                                       site_bytes;
		std::vector<std::tuple<int32_t, std::string, std::string, bool>> namespaces;
		bool                                                             site_done = false;


		wiki_links::Config config() const {
			wiki_links::Config result;
			result.capitalized = site_case == "first-letter";
			for (const auto& [id, casing, name, alias] : namespaces)
				result.add_namespace(id, name, casing.empty() ? result.capitalized : casing == "first-letter", alias);
			return result;
		}

		void sealSite() {
			need(!wiki.empty() && !site_case.empty(), "missing wiki or title case");
			text(site_bytes, wiki);
			text(site_bytes, lang);
			text(site_bytes, site_case);
			need(namespaces.size() <= 65535, "too many namespaces");
			number(site_bytes, namespaces.size(), 2);
			for (const auto& ns : namespaces) {
				number(site_bytes, (uint32_t)std::get<0>(ns), 4);
				text(site_bytes, std::get<1>(ns));
				text(site_bytes, std::get<2>(ns));
				number(site_bytes, std::get<3>(ns), 1);
			}
			site_done = true;
		}

		void event(xmlTextReaderPtr r) {
			const char* name  = (const char*)xmlTextReaderConstLocalName(r);
			int         depth = xmlTextReaderDepth(r), type = xmlTextReaderNodeType(r);
			if (type == XML_READER_TYPE_ELEMENT) {
				if (depth == 0 && std::string(name) == "mediawiki") lang = attribute(r, "xml:lang");
				if (depth == 1 && std::string(name) == "siteinfo") site = true;
				if (site && depth == 2 && (std::string(name) == "dbname" || std::string(name) == "case"))
					site_field = name;
				if (site && depth == 3 && (std::string(name) == "namespace" || std::string(name) == "ns")) {
					auto key = attribute(r, "key");
					if (key.empty()) key = attribute(r, "id");
					need(!key.empty(), "namespace lacks key or id");
					size_t used   = 0;
					auto   parsed = std::stoll(key, &used);
					need(used == key.size() && parsed >= INT32_MIN && parsed <= INT32_MAX, "invalid namespace key");
					int32_t id = (int32_t)parsed;
					namespaces.emplace_back(id, attribute(r, "case"), std::string(), std::string(name) == "ns");
				}
				if (depth == 1 && std::string(name) == "page") {
					page.reset();
					inside   = true;
					revision = false;
				}
				if (!inside) return;
				if (depth == 2 && std::string(name) == "revision") {
					need(++page.revisions == 1, "multiple selected revisions on one page");
					revision = true;
				}
				if (depth == 2 && std::string(name) == "redirect") page.redirect = true;
				if (depth == 2 && std::string(name) == "title")
					need(++page.title_elements == 1, "duplicate page title element");
				if (depth == 2 && std::string(name) == "ns") need(!page.has_ns, "duplicate page namespace element");
				if ((depth == 2 &&
					 (std::string(name) == "title" || std::string(name) == "ns" || std::string(name) == "id")) ||
					(revision && depth == 3 && std::string(name) == "id"))
					field = name;
			} else if (type == XML_READER_TYPE_TEXT || type == XML_READER_TYPE_CDATA) {
				std::string s = value(r);
				if (site) {
					if (depth == 3 && site_field == "dbname") wiki += s;
					if (depth == 3 && site_field == "case") site_case += s;
					if (depth == 4 && !namespaces.empty()) std::get<2>(namespaces.back()) += s;
				}
				if (!inside) return;
				if (field == "title" && depth == 3) page.title += s;
				else if (field == "ns" && depth == 3) {
					size_t used = 0;
					auto   ns   = std::stoll(s, &used);
					need(used == s.size() && ns >= INT32_MIN && ns <= INT32_MAX, "invalid page namespace");
					page.ns     = (int32_t)ns;
					page.has_ns = true;
				} else if (field == "id" && depth == 3) {
					need(!page.has_id, "duplicate page ID element");
					page.id     = decimal(s);
					page.has_id = true;
				} else if (field == "id" && depth == 4 && revision) {
					need(!page.has_revision, "duplicate revision ID");
					page.revision     = decimal(s);
					page.has_revision = true;
				}
			} else if (type == XML_READER_TYPE_END_ELEMENT) {
				if (site && depth == 2) site_field.clear();
				if (site && depth == 1 && std::string(name) == "siteinfo") {
					site = false;
					sealSite();
				}
				if (depth == 3 || depth == 2) field.clear();
				if (depth == 2 && std::string(name) == "revision") revision = false;
				if (depth == 1 && std::string(name) == "page") inside = false;
			}
		}
	};
} // namespace meta


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
static std::string g_meta_spool_path;
static FILE* g_meta_spool = nullptr;
static meta::Observer g_meta_observer;
static wiki_links::Config g_parser_config;
// A rolling monthly export can contain different page IDs with the same title.
// Retain their identities, but do not choose a graph owner from export order.
static std::set<string> g_ambiguous_titles;
static void note_owned_title(const string& title) {
	if (map_string_stringptr_get_check(&link_map, title) || map_string_string_get_check(&redirects, title))
		g_ambiguous_titles.insert(title);
}

enum LINK_FLAGS : uint8_t {
	LINK_IS_RENAME  = 1 << 0,
	LINK_IS_INFOBOX = 1 << 1,
};

static void print_usage(const char* argv0) {
	std::cerr << "Usage: " << argv0 << " [YYYY-MM-DD] [--prune-unused-redirect-titles] [--meta-spool PATH]\n";
	std::cerr << "  --prune-unused-redirect-titles  Keep only redirect titles referenced by unredirect edges.\n";
	std::cerr << "  --meta-spool PATH  Save page IDs, revisions, titles, and siteinfo for a sidecar.\n";
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
		if (arg == "--meta-spool" && i + 1 < argc) {
			g_meta_spool_path = argv[++i];
			continue;
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
	unsigned selected_revisions = 0;

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
			exit(1);
		}

		int depth = xmlTextReaderDepth(reader);
		const xmlChar* name = xmlTextReaderConstLocalName(reader);
		int type = xmlTextReaderNodeType(reader);
		if (type == XML_READER_TYPE_ELEMENT && depth == 1 && xmlStrEqual(name, (const xmlChar*)"page"))
			selected_revisions = 0;
		if (type == XML_READER_TYPE_ELEMENT && depth == 2 && xmlStrEqual(name, (const xmlChar*)"revision") &&
			++selected_revisions > 1) {
			std::cerr << "Multiple selected revisions on one page." << std::endl;
			exit(1);
		}
		// Record the same XML stream before graph pruning.
		if (g_meta_spool && type == XML_READER_TYPE_END_ELEMENT && depth == 1 &&
			xmlStrEqual(name, (const xmlChar*)"page"))
			meta::spool(g_meta_spool, g_meta_observer.page);
		g_meta_observer.event(reader);
		if (g_meta_observer.site_done) {
			g_parser_config = g_meta_observer.config();
			if (g_meta_spool) meta::spoolSite(g_meta_spool, g_meta_observer.site_bytes);
			g_meta_observer.site_done = false;
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
					if (xmlTextReaderIsEmptyElement(reader) || xmlTextReaderRead(reader) != 1 ||
						!xmlTextReaderConstValue(reader)) {
						std::cerr << "Missing page title." << std::endl;
						exit(1);
					}
					g_meta_observer.event(reader);
					page_title = get_string((const char*)xmlTextReaderConstValue(reader));
					g_parser_config.current_title = g_meta_observer.page.title;
				}

				else if (xmlStrcmp(tag, (const xmlChar*)"text") == 0) {
					if (xmlTextReaderIsEmptyElement(reader)) break;
					if (xmlTextReaderRead(reader)!=1) break;
					const xmlChar* article = xmlTextReaderConstValue(reader);
					if (!article) break;
					for (const auto& link : wiki_links::parse((const char*)article, g_parser_config)) {
						page_links[get_string(std::string_view(link.first))] = link.second;
					}
				}

				else if (xmlStrcmp(tag, (const xmlChar*)"ns") == 0) {
					if (xmlTextReaderIsEmptyElement(reader) || xmlTextReaderRead(reader) != 1 ||
						!xmlTextReaderConstValue(reader)) {
						std::cerr << "Missing page namespace." << std::endl;
						exit(1);
					}
					g_meta_observer.event(reader);
					int ns = atoi((const char*)xmlTextReaderConstValue(reader));
					if (ns != 0) in_page = false;
				}

				else if (xmlStrcmp(tag, (const xmlChar*)"redirect") == 0) {
					auto raw_target = meta::attribute(reader, "title");
					auto target = wiki_links::title(raw_target, g_parser_config);
					if (!target.valid) throw std::runtime_error("invalid monthly redirect target");
					if (target.text.empty()) target.text = g_parser_config.current_title;
					note_owned_title(page_title);
					map_string_string_set(&redirects, page_title, get_string(std::string_view(target.text)));

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
				note_owned_title(page_title);
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
		if (g_ambiguous_titles.count(cur)) return -1;
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
		if (g_ambiguous_titles.count(cur)) return -1;
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
	if (g_ambiguous_titles.count(t)) return 0;
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
			if (g_ambiguous_titles.count(redir_title)) continue;
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

static void finish_metadata() {
	if (!g_meta_spool) return;
	auto read_number = [](unsigned bytes) {
		uint64_t value = 0;
		for (unsigned i = 0; i < bytes; ++i) {
			int c = fgetc(g_meta_spool);
			meta::need(c != EOF, "truncated identity spool");
			value |= uint64_t(c) << (8 * i);
		}
		return value;
	};
	meta::need(fseek(g_meta_spool, 12, SEEK_SET) == 0, "identity spool seek failed");
	uint64_t site_size = read_number(4);
	meta::need(fseek(g_meta_spool, site_size, SEEK_CUR) == 0, "identity spool seek failed");
	std::vector<unsigned char> owners(page_count);
	uint64_t count = 0, ns0 = 0, redirects = 0, missing = 0, last_id = 0;
	for (;;) {
		int first = fgetc(g_meta_spool);
		if (first == EOF) break;
		uint64_t size = first | (read_number(3) << 8);
		meta::need(size >= 23 && size < 65536, "invalid identity record size");
		std::vector<unsigned char> record(size);
		meta::need(fread(record.data(), 1, size, g_meta_spool) == size, "truncated identity record");
		uint64_t id = 0;
		for (unsigned i = 0; i < 8; ++i) id |= uint64_t(record[i]) << (8 * i);
		meta::need(id > last_id, "page IDs must increase");
		last_id = id;
		bool article_namespace = !record[8] && !record[9] && !record[10] && !record[11];
		unsigned char flags = record[12];
		uint16_t length = record[21] | (uint16_t(record[22]) << 8);
		meta::need(length && length + 23u == size, "invalid identity title");
		int index = article_namespace && !(flags & 8)
			? bsearch(std::string((const char*)record.data() + 23, length)) : -1;
		flags |= index >= 0 ? 16 : 32;
		if (index >= 0) {
			meta::need(!owners[index], "ambiguous graph owner");
			owners[index] = 1;
		}
		long end = ftell(g_meta_spool);
		meta::need(end >= 0 && fseek(g_meta_spool, end - size + 12, SEEK_SET) == 0 &&
			fputc(flags, g_meta_spool) != EOF && fseek(g_meta_spool, end, SEEK_SET) == 0,
			"identity ownership write failed");
		++count;
		ns0 += article_namespace;
		redirects += !!(flags & 8);
		missing += !(flags & 1);
	}
	meta::need(!ferror(g_meta_spool) && std::count(owners.begin(), owners.end(), 0) == 0,
		"incomplete graph ownership");
	std::vector<unsigned char> footer;
	meta::number(footer, 0, 4);
	for (auto value : {count, ns0, redirects, missing}) meta::number(footer, value, 8);
	meta::need(fseek(g_meta_spool, 0, SEEK_END) == 0 &&
		fwrite(footer.data(), 1, footer.size(), g_meta_spool) == footer.size() && fclose(g_meta_spool) == 0,
		"identity spool close failed");
	g_meta_spool = nullptr;
}

int main(int argc, char** argv) {
	int parse_status = parse_cli_args(argc, argv);
	if (parse_status == 1) return 0;
	if (parse_status == -1) return 1;

	fprintf(stderr, "Options: prune_unused_redirect_titles=%s\n", g_prune_unused_redirect_titles ? "on" : "off");
	fprintf(stderr, "Graph uses static article links; flags describe normalized labels and template context.\n");
	if (!g_prune_unused_redirect_titles) {
		fprintf(stderr, "Redirect title pruning is disabled (default).\n");
	}

	GC_INIT();
	xmlMemSetup(GC_free, GC_malloc, GC_realloc, GC_strdup);

	if (!g_meta_spool_path.empty()) {
		g_meta_spool = fopen(g_meta_spool_path.c_str(), "w+b");
		if (!g_meta_spool) { perror("meta spool"); return 1; }
		std::vector<unsigned char> header;
		meta::number(header, wiki_links::parser_policy, 4);
		meta::number(header, wiki_links::unicode_version(), 4);
		if (fwrite(header.data(), 1, header.size(), g_meta_spool) != header.size()) return 1;
	}
	try {
		page_count = parse_xml();
	} catch (const std::exception& e) {
		std::cerr << "Metadata input: " << e.what() << std::endl;
		return 1;
	}

	titles = (string*)GC_malloc(page_count * sizeof(string));
	links  = (PageLinks*)GC_malloc(page_count * sizeof(PageLinks));
	memset(links, 0, page_count * sizeof(PageLinks));

	{
		int i = 0;
		FOR_IN_MAP_STRING_STRINGPTR(link_map, title, _, {
			(void)_;
			if (!g_ambiguous_titles.count(title)) titles[i++] = title;
		})
		page_count = i;
		fprintf(stderr, "Quarantined ambiguous monthly titles: %zu\n", g_ambiguous_titles.size());
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
	try {
		meta::need(!ferror(stdout), "graph output failed");
		finish_metadata();
	} catch (const std::exception& e) {
		std::cerr << e.what() << std::endl;
		return 1;
	}
	return 0;
}
