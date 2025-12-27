
#include <gc/gc.h>

#include <libxml/parser.h>
#include <libxml/xmlreader.h>
#include <unistd.h>
#include <stdlib.h>

#include <stdint.h>

#include <algorithm>
#include <cassert>
#include <iostream>
#include <set>


void nop(void* p) { (void)p; }
// #define STRING_MALLOC GC_malloc
// #define STRING_REALLOC GC_realloc
// #define STRING_FREE GC_free
#define STRING_FREE nop

#include "string.h"
#include "map.h"

static int DUMP_DATE = 221201;
static const int DUMP_FORMAT_VERSION = 4;

map_string_string string_data = new_map_string_string();
map_string_stringptr link_map = new_map_string_stringptr();
map_string_string redirects   = new_map_string_string();

static inline string get_string(string s) {
    string* p = map_string_string_get_check(&string_data, s);
    if (p) return *p;
    s = s.clone();
    map_string_string_set(&string_data, s, s);
    return s;
}

static inline constexpr std::size_t find_in_range(std::string_view sv,
                                    std::string_view needle,
                                    std::size_t start = 0,
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

    string page_title = "";
    std::set<string> links_strs;


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
                        page_title = get_string((const char*)title);
                    }

                    else if (xmlStrcmp(tag, (const xmlChar*)"text") == 0) {
                        xmlTextReaderRead(reader);
                        xmlChar* article_ = (xmlChar*)xmlTextReaderConstValue(reader);
                        std::string_view article = (const char*)article_;

                        size_t last_end = 0, link_start = 0;
link_loop:
                        while ((link_start = find_in_range(article, "[[", last_end)) != std::string::npos) {
                            size_t info_start = find_in_range(article, "{{", last_end, link_start);
                            if (info_start != std::string::npos) {
                                size_t infoEnd = info_start + 2;
                                int n = 1;
                                while (n > 0) {
                                    size_t nextOpen = find_in_range(article, "{{", infoEnd);
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

                                // strip <ref>, <nowiki>, <gallery>, etc. tags
                                size_t tag_end = find_in_range(article, ">", tag_start + 1);
                                if (tag_end != std::string::npos) {
                                    std::string_view full_opening_tag = std::string_view(article.data() + tag_start + 1, tag_end - tag_start - 1);
                                    size_t space_idx = find_in_range(full_opening_tag, " ");
                                    std::string_view tag_name = space_idx == std::string::npos ? full_opening_tag : full_opening_tag.substr(0, space_idx);
                                    if (tag_name == "ref" || tag_name == "nowiki" || tag_name == "gallery") {
                                        if (full_opening_tag.size() > 0 && full_opening_tag.back() == '/') {
                                            // self-closing tag 
                                            last_end = tag_end + 1;
                                            continue;
                                        }
                                        char closing_tag_buf[tag_name.size() + 3];
                                        closing_tag_buf[0] = '<'; closing_tag_buf[1] = '/';
                                        memcpy(closing_tag_buf + 2, tag_name.data(), tag_name.size());
                                        closing_tag_buf[tag_name.size() + 2] = '>';
                                        std::string_view closing_tag = std::string_view(closing_tag_buf, tag_name.size() + 3);
                                        size_t closing_tag_start = find_in_range(article, closing_tag, tag_end + 1);
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

                            article_[link_start + 2] = toupper(article_[link_start + 2]);

                            std::string_view link = "";

                            size_t pipe_idx = find_in_range(article, "|", link_start, end);
                            if (pipe_idx != std::string::npos) {
                                link = std::string_view(article.data() + link_start + 2, pipe_idx - link_start - 2);
                            } else {
                                link = std::string_view(article.data() + link_start + 2, end - link_start - 2);
                            }

                            size_t hash_idx = find_in_range(link, "#");
                            if (hash_idx != std::string::npos) {
                                link = std::string_view(link.data(), hash_idx);
                            }

                            links_strs.insert(get_string(link));

                            last_end = end + 2;
                        }
linkLoopEnd:
                    }

                    else if (xmlStrcmp(tag, (const xmlChar*)"ns") == 0) {
                        xmlTextReaderRead(reader);
                        int ns = atoi((const char*)xmlTextReaderConstValue(reader));
                        if (ns != 0) in_page = false;
                    }

                    else if (xmlStrcmp(tag, (const xmlChar*)"redirect") == 0) {
                        const char* title_ = (const char*)xmlTextReaderGetAttribute(reader, (const xmlChar*)"title");
                        string title = title_;
                        char* hash = (char*)memchr(title_, '#', title.len);
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

                    string* linkptr = (string*)GC_malloc(sizeof(string) * (links_strs.size()+1));
                    size_t i = 0;
                    for (auto& link : links_strs) linkptr[i++] = link;
                    linkptr[i] = nullptr;
                    map_string_stringptr_set(&link_map, page_title, linkptr);

                    links_strs.clear();
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


struct PageLinks { int n; int cap; int* ids; };
PageLinks* links;
string* titles;
int page_count;
uint32_t* rev_counts;
uint32_t* rev_offsets;
int32_t* rev_edges;
uint32_t rev_total_links;

static inline int int_cmp(const void* a, const void* b) {
    int x = *(const int*)a;
    int y = *(const int*)b;
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
    int dest;
    uint16_t redir_len;
    string redir_title;
    uint32_t redir_in;
};

struct UnredirTmp {
    uint32_t src;
    uint32_t dest;
    string redir_title;
};

struct UnredirEdge {
    uint32_t src;
    uint32_t dest;
    uint32_t redir_idx;
};

static UnredirEdge* unredir_edges = nullptr;
static uint32_t unredir_n = 0;

static string* redir_titles = nullptr; /* filtered + sorted */
static uint32_t redir_titles_n = 0;
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

static uint32_t* g_indeg;
static string* g_titles;

static int cmp_indeg_desc(const void* a, const void* b) {
    int ia = *(const int*)a;
    int ib = *(const int*)b;

    uint32_t da = g_indeg[ia];
    uint32_t db = g_indeg[ib];

    if (da != db) return (da < db) ? 1 : -1;  // desc

    if (g_titles[ia] < g_titles[ib]) return -1;
    if (g_titles[ia] > g_titles[ib]) return 1;
    return 0;
}

void renumber_by_indegree() {
    fprintf(stderr, "Renumbering by indegree...\n");

    uint32_t* indeg = (uint32_t*)GC_malloc(page_count * sizeof(uint32_t));
    memset(indeg, 0, page_count * sizeof(uint32_t));

    for (int src = 0; src < page_count; src++) {
        PageLinks* l = links + src;
        for (int j = 0; j < l->n; j++) {
            indeg[l->ids[j]]++;
        }
    }

    int* order = (int*)GC_malloc(page_count * sizeof(int));
    for (int i = 0; i < page_count; i++) order[i] = i;

    g_indeg = indeg;
    g_titles = titles;
    qsort(order, page_count, sizeof(int), cmp_indeg_desc);

    int* old_to_new = (int*)GC_malloc(page_count * sizeof(int));
    for (int new_id = 0; new_id < page_count; new_id++) {
        int old_id = order[new_id];
        old_to_new[old_id] = new_id;
    }

    for (int old_src = 0; old_src < page_count; old_src++) {
        PageLinks* l = links + old_src;
        for (int j = 0; j < l->n; j++) {
            l->ids[j] = old_to_new[l->ids[j]];
        }
        std::sort(l->ids, l->ids + l->n);
    }

    if (unredir_edges) {
        for (uint32_t i = 0; i < unredir_n; i++) {
            unredir_edges[i].src = (uint32_t)old_to_new[unredir_edges[i].src];
            unredir_edges[i].dest = (uint32_t)old_to_new[unredir_edges[i].dest];
        }

        qsort(unredir_edges, (size_t)unredir_n, sizeof(UnredirEdge), unredir_edge_cmp);
    }

    string* titles_ = (string*)GC_malloc(page_count * sizeof(string));
    PageLinks* links_ = (PageLinks*)GC_malloc(page_count * sizeof(PageLinks));

    for (int new_id = 0; new_id < page_count; new_id++) {
        int old_id = order[new_id];
        titles_[new_id] = titles[old_id];
        links_[new_id] = links[old_id];
    }

    GC_free(titles);
    GC_free(links);
    titles = titles_;
    links = links_;

    GC_free(old_to_new);
    GC_free(order);
    GC_free(indeg);
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
        if (l->n == 0) {
            empty_pages.push_back(i);
        }
    }

    fprintf(stderr, "Empty pages: %d / %d\n", (int)empty_pages.size(), page_count);

    if (empty_pages.size() == 0) return 0;

    for (int i = 0; i < page_count; i++) {
        for (int j = 0; j < links[i].n; j++) {
            int l = links[i].ids[j];
            auto b = std::lower_bound(empty_pages.begin(), empty_pages.end(), l);
            if (b != empty_pages.end() && *b == l) {
                links[i].ids[j] = -1;
            }
        }
        int j = 0;
        for (int k = 0; k < links[i].n; k++) {
            if (links[i].ids[k] != -1) {
                links[i].ids[j++] = links[i].ids[k];
            }
        }
        links[i].n = j;
    }

    int* old_id_to_new_id = (int*)GC_malloc(page_count * sizeof(int));
    for (int i = 0; i < page_count; i++) {
        old_id_to_new_id[i] = i;
    }

    for (int i = 0; i < (int)empty_pages.size(); i++) {
        int id = empty_pages[i];
        int m = 0;
        if (i == (int)empty_pages.size()-1) {
            m = page_count;
        } else {
            m = empty_pages[i+1];
        }
        for (int j = id; j < m; j++) {
            old_id_to_new_id[j] -= i+1;
        }
    }

    int l = page_count - empty_pages.size();
    string* titles_ = (string*)GC_malloc(l * sizeof(string));
    PageLinks* links_ = (PageLinks*)GC_malloc(l * sizeof(PageLinks));
    memset(links_, 0, l * sizeof(PageLinks));
    int titles_len = 0;
    int links_len = 0;

    for (int i=0, b=0; i < page_count; i++) {
        if (b < (int)empty_pages.size() && empty_pages[b] == i) {
            b++;
            continue;
        }
        titles_[titles_len++] = titles[i];
        links_[links_len++] = links[i];
    }
    GC_free(titles);
    GC_free(links);
    titles = titles_;
    links = links_;
    page_count = l;

    for (int j = 0; j < links_len; j++) {
        for (int k = 0; k < links[j].n; k++) {
            int* q = &links[j].ids[k];
            *q = old_id_to_new_id[*q];
        }
        
    }

    GC_free(old_id_to_new_id);

    int s = empty_pages.size();
    empty_pages.clear();
    return s;
}

void build_reverse_links() {
    fprintf(stderr, "Building reverse db...\n");

    rev_counts = (uint32_t*)GC_malloc(page_count * sizeof(uint32_t));
    memset(rev_counts, 0, page_count * sizeof(uint32_t));

    rev_total_links = 0;
    for (int src = 0; src < page_count; src++) {
        PageLinks* l = links + src;
        rev_total_links += (uint32_t)l->n;
        for (int j = 0; j < l->n; j++) {
            int dst = l->ids[j];
            rev_counts[dst]++;
        }
    }

    rev_offsets = (uint32_t*)GC_malloc((page_count + 1) * sizeof(uint32_t));
    rev_offsets[0] = 0;
    for (int i = 0; i < page_count; i++) {
        rev_offsets[i + 1] = rev_offsets[i] + rev_counts[i];
    }

    rev_edges = (int32_t*)GC_malloc(rev_total_links * sizeof(int32_t));

    {
        uint32_t* cur = (uint32_t*)GC_malloc(page_count * sizeof(uint32_t));
        for (int i = 0; i < page_count; i++) cur[i] = rev_offsets[i];

        for (int src = 0; src < page_count; src++) {
            PageLinks* l = links + src;
            for (int j = 0; j < l->n; j++) {
                int dst = l->ids[j];
                rev_edges[cur[dst]++] = (int32_t)src;
            }
        }

        GC_free(cur);
    }

    // Sort incoming lists for each destination page.
    for (int dst = 0; dst < page_count; dst++) {
        uint32_t a = rev_offsets[dst];
        uint32_t b = rev_offsets[dst + 1];
        if (b > a + 1) {
            std::sort(rev_edges + a, rev_edges + b);
            for (uint32_t k = a + 1; k < b; k++) {
                assert(rev_edges[k - 1] < rev_edges[k]);
            }
        }
    }
}

void write_db() {
    fprintf(stderr, "Writing db...\n");
    FILE* f = stdout;
    char* buf = (char*)GC_malloc(16<<20);
    setvbuf(f, buf, _IOFBF, 16<<20);

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

    if (fwrite(&rev_total_links, sizeof(rev_total_links), 1, f) != 1) {
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

    for (int i = 0; i < page_count; i++) {
        uint32_t num_links = rev_counts[i];
        if (fwrite(&num_links, sizeof(num_links), 1, f) != 1) {
            perror("fwrite");
            exit(1);
        }
    }

    for (int dst = 0; dst < page_count; dst++) {
        uint32_t a = rev_offsets[dst];
        uint32_t b = rev_offsets[dst + 1];
        for (uint32_t k = a; k < b; k++) {
            int32_t src = rev_edges[k];
            char* p = (char*)&src;
            if (p[3] != 0) {
                perror("link overflow");
            }
            if (fwrite(&src, 4, 1, f) != 1) {
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
        uint32_t n = unredir_n;
        uint32_t rt = redir_titles_n;
        uint32_t rbytes = redir_titles_bytes;

        if (fwrite(&n, sizeof(n), 1, f) != 1) { perror("unredir_n"); exit(1); }
        if (fwrite(&rt, sizeof(rt), 1, f) != 1) { perror("redir_titles_n"); exit(1); }
        if (fwrite(&rbytes, sizeof(rbytes), 1, f) != 1) { perror("redir_titles_bytes"); exit(1); }

        for (uint32_t i = 0; i < unredir_n; i++) {
            if (fwrite(&unredir_edges[i].src, sizeof(uint32_t), 1, f) != 1) { perror("unredir"); exit(1); }
            if (fwrite(&unredir_edges[i].dest, sizeof(uint32_t), 1, f) != 1) { perror("unredir"); exit(1); }
            if (fwrite(&unredir_edges[i].redir_idx, sizeof(uint32_t), 1, f) != 1) { perror("unredir"); exit(1); }
        }

        for (uint32_t i = 0; i < redir_titles_n; i++) {
            if (redir_titles[i].len > 255) {
                fprintf(stderr, "redirect title too long for u8 len: %.*s\n",
                        (int)redir_titles[i].len, (const char*)redir_titles[i].p());
                exit(1);
            }
            uint8_t l = (uint8_t)redir_titles[i].len;
            if (fwrite(&l, 1, 1, f) != 1) { perror("redir_title_len"); exit(1); }
        }

        /* pad to 4 bytes */
        {
            char zeros[8] = {0};
            uint32_t pad = (4 - (redir_titles_n & 3)) & 3;
            if (pad) {
                if (fwrite(zeros, 1, pad, f) != pad) { perror("redir_title_len_pad"); exit(1); }
            }
        }

        for (uint32_t i = 0; i < redir_titles_n; i++) {
            if (fwrite(redir_titles[i], 1, redir_titles[i].len, f) != redir_titles[i].len) {
                perror("redir_title_bytes");
                exit(1);
            }
        }
    }

    fflush(f);
    sync();
    GC_free(buf);
}

static const int MAX_REDIRECT_HOPS = 128;

int resolve_link_id_len(const string& t, int* out_redir_len) {
    // Follow: t -> redirects[t] -> redirects[...] ... until a real page is found
    // Returns: final page id, and number of redirect hops taken.
    std::set<string> seen;
    string cur = t;

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
    string cur = t;

    for (int hop = 0; hop < MAX_REDIRECT_HOPS; ++hop) {
        // If this title exists as a real page, we’re done.
        int id = bsearch(cur);
        if (id != -1) return id;

        // Otherwise try to follow a redirect.
        string* p = map_string_string_get_check(&redirects, cur);
        if (!p) return -1;            // no redirect and not a real page → missing

        // Cycle guard
        if (!seen.insert(cur).second) return -1;

        cur = *p;                     // follow to next hop
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
            int* c = map_string_int_get_check(&redir_in, ll[i]);
            if (c) {
                (*c)++;
            } else {
                map_string_int_set(&redir_in, ll[i], 1);
            }
        }
    })

    /* pass 2: choose 0/1 redirect witness per (src,dest) when no direct link exists */
    UnredirTmp* tmp = nullptr;
    uint32_t tmp_n = 0;
    uint32_t tmp_cap = 0;

    FOR_IN_MAP_STRING_STRINGPTR(link_map, title, links_, {
        int src = bsearch(title);
        if (src == -1) continue;

        /* per-page scratch */
        int* direct = nullptr;
        int direct_n = 0;
        int direct_cap = 0;

        Cand* cand = nullptr;
        int cand_n = 0;
        int cand_cap = 0;

        string* ll = *links_;
        for (int i = 0; ll[i].p() != nullptr; i++) {
            int redir_len = 0;
            int dest = resolve_link_id_len(ll[i], &redir_len);
            if (dest == -1) continue;

            if (redir_len == 0) {
                if (direct_n == direct_cap) {
                    direct_cap = direct_cap * 2 + 16;
                    direct = (int*)GC_realloc(direct, sizeof(int) * direct_cap);
                }
                direct[direct_n++] = dest;
            } else {
                if (cand_n == cand_cap) {
                    cand_cap = cand_cap * 2 + 32;
                    cand = (Cand*)GC_realloc(cand, sizeof(Cand) * cand_cap);
                }

                int in = 0;
                int* p = map_string_int_get_check(&redir_in, ll[i]);
                if (p) in = *p;

                cand[cand_n].dest = dest;
                cand[cand_n].redir_len = (uint16_t)redir_len;
                cand[cand_n].redir_title = ll[i]; /* first hop the user clicks */
                cand[cand_n].redir_in = (uint32_t)in;
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
                int j = i + 1;
                while (j < cand_n && cand[j].dest == dest) j++;

                if (!int_bsearch(direct, direct_n, dest)) {
                    /* pick minimal redirect chain length (sorted), then highest incoming (sorted), then alpha */
                    if (tmp_n == tmp_cap) {
                        tmp_cap = tmp_cap * 2 + 1024;
                        tmp = (UnredirTmp*)GC_realloc(tmp, sizeof(UnredirTmp) * tmp_cap);
                    }
                    tmp[tmp_n].src = (uint32_t)src;
                    tmp[tmp_n].dest = (uint32_t)dest;
                    tmp[tmp_n].redir_title = cand[i].redir_title;
                    tmp_n++;
                }

                i = j;
            }
        }
    })

    fprintf(stderr, "Unredirect tuples (pre-table): %u\n", tmp_n);

    if (tmp_n == 0) {
        unredir_edges = nullptr;
        unredir_n = 0;
        redir_titles = nullptr;
        redir_titles_n = 0;
        redir_titles_bytes = 0;
        return;
    }

    /* build filtered redirect title table from tmp[].redir_title */
    {
        string* r = (string*)GC_malloc(sizeof(string) * tmp_n);
        for (uint32_t i = 0; i < tmp_n; i++) r[i] = tmp[i].redir_title;

        qsort(r, (size_t)tmp_n, sizeof(string), string_cmp_qsort);

        /* uniq */
        uint32_t n = 0;
        for (uint32_t i = 0; i < tmp_n; i++) {
            if (n == 0 || !(r[i] == r[n - 1])) r[n++] = r[i];
        }

        redir_titles = (string*)GC_malloc(sizeof(string) * n);
        redir_titles_n = n;
        redir_titles_bytes = 0;

        for (uint32_t i = 0; i < n; i++) {
            redir_titles[i] = r[i];
            redir_titles_bytes += (uint32_t)redir_titles[i].len;
        }
    }

    /* materialize final unredirect edges with redir_idx, then sort */
    unredir_edges = (UnredirEdge*)GC_malloc(sizeof(UnredirEdge) * tmp_n);
    unredir_n = tmp_n;

    for (uint32_t i = 0; i < tmp_n; i++) {
        int ridx = bsearch_redir_titles(tmp[i].redir_title);
        if (ridx == -1) {
            fprintf(stderr, "internal error: missing redirect title\n");
            exit(1);
        }
        unredir_edges[i].src = tmp[i].src;
        unredir_edges[i].dest = tmp[i].dest;
        unredir_edges[i].redir_idx = (uint32_t)ridx;
    }

    qsort(unredir_edges, (size_t)unredir_n, sizeof(UnredirEdge), unredir_edge_cmp);

    /* sanity: ensure at most one per (src,dest) */
    for (uint32_t i = 1; i < unredir_n; i++) {
        if (unredir_edges[i].src == unredir_edges[i - 1].src &&
            unredir_edges[i].dest == unredir_edges[i - 1].dest) {
            fprintf(stderr, "internal error: duplicate unredirect for (%u,%u)\n",
                    unredir_edges[i].src, unredir_edges[i].dest);
            exit(1);
        }
    }

    fprintf(stderr, "Unredirect edges: %u\n", unredir_n);
    fprintf(stderr, "Redirect titles used: %u (%u bytes)\n", redir_titles_n, redir_titles_bytes);
}

int main(int argc, char** argv) {
    if (argc > 1) {
        // argv[1] = "YYYY-MM-DD"
        if (strlen(argv[1]) != 10 || argv[1][4] != '-' || argv[1][7] != '-') {
            std::cerr << "Invalid date format. Use YYYY-MM-DD." << std::endl;
            return 1;
        }
        int year, month, day;
        if (sscanf(argv[1], "%4d-%2d-%2d", &year, &month, &day) != 3) {
            std::cerr << "Invalid date format. Use YYYY-MM-DD." << std::endl;
            return 1;
        }
        if (year < 2000 || year > 2099 || month < 1 || month > 12 || day < 1 || day > 31) {
            std::cerr << "Invalid date." << std::endl;
            return 1;
        }
        DUMP_DATE = (year - 2000) * 10000 + month * 100 + day;
    }

    GC_INIT();
    xmlMemSetup(GC_free, GC_malloc, GC_realloc, GC_strdup);

    page_count = parse_xml();

    titles = (string*)GC_malloc(page_count * sizeof(string));
    links = (PageLinks*)GC_malloc(page_count * sizeof(PageLinks));
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
        string* ll = *links_;

        PageLinks* l = links + idx;

        for (int i = 0; ll[i].p() != nullptr; i++) {
            int link_idx = resolve_link_id(ll[i]);
            if (link_idx == -1) continue;

            if (l->n == l->cap) {
                l->cap = l->cap * 2 + 1;
                l->ids = (int*)GC_realloc(l->ids, l->cap * sizeof(int));
            }

            l->ids[l->n++] = link_idx;
        }

        std::sort(l->ids, l->ids + l->n);
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
        if (l->n == 0) continue;
        int j = 0;
        for (int k = 1; k < l->n; k++) {
            if (l->ids[k] != l->ids[j]) {
                l->ids[++j] = l->ids[k];
            } else {
                duplicates_removed++;
            }
        }
        l->n = j + 1;
    }
    fprintf(stderr, "Removed %llu spurious duplicate links\n", duplicates_removed);

    /* build redirect witness table for edges that are only possible via redirects */
    build_unredirect_db();

    renumber_by_indegree();

    build_reverse_links();

    write_db();

    return 0;
}
