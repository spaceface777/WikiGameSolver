
#include <gc/gc.h>

#include <libxml/parser.h>
#include <libxml/xmlreader.h>
#include <unistd.h>

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
static const int DUMP_FORMAT_VERSION = 1;

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

static inline bool ieq(char a, char b) {
    if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
    if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
    return a == b;
}

static size_t find_ci(const std::string& s, size_t from, const char* needle) {
    size_t nlen = strlen(needle);
    for (size_t i = from; i + nlen <= s.size(); ++i) {
        size_t j = 0;
        for (; j < nlen; ++j) {
            if (!ieq(s[i + j], needle[j])) break;
        }
        if (j == nlen) return i;
    }
    return std::string::npos;
}

// Skip nested {{ ... }}; returns index *after* the closing "}}", or s.size() if unmatched.
static size_t skip_template(const std::string& s, size_t open) {
    size_t pos = open + 2;
    int depth = 1;
    while (pos < s.size() && depth > 0) {
        size_t o = s.find("{{", pos);
        size_t c = s.find("}}", pos);
        if (c == std::string::npos) return s.size(); // unmatched -> skip to end
        if (o != std::string::npos && o < c) {
            depth++;
            pos = o + 2;
        } else {
            depth--;
            pos = c + 2;
        }
    }
    return pos;
}

// Skip <!-- ... --> comments; returns index after "-->", or s.size() if unmatched.
static size_t skip_comment(const std::string& s, size_t open) {
    size_t end = s.find("-->", open + 4);
    return (end == std::string::npos) ? s.size() : end + 3;
}

// Skip a tag that may have attributes and either a paired or self-closing form.
// Example tags: <ref ...>...</ref>, <ref .../>, <nowiki>...</nowiki>
// Returns index after the closing tag (or "/>"), or s.size() if unmatched.
static size_t skip_tag_pair_or_selfclose(const std::string& s, size_t lt_pos, const char* tagname) {
    // Find the end of the start tag: '>'
    size_t gt = s.find('>', lt_pos + 1);
    if (gt == std::string::npos) return s.size();

    // If it’s self-closing like <ref .../>, skip just that.
    if (gt > lt_pos + 1 && s[gt - 1] == '/') return gt + 1;

    // Otherwise, find the closing tag </tagname>
    std::string endtag = std::string("</") + tagname + ">";
    size_t close = find_ci(s, gt + 1, endtag.c_str());
    return (close == std::string::npos) ? s.size() : (close + endtag.size());
}

// Returns true if we skipped something and advanced last_end.
static bool maybe_skip_skippable(const std::string& s, size_t& last_end, size_t next_link_pos) {
    // Look for the earliest skippable opener between last_end and next_link_pos.
    size_t tmpl = s.find("{{", last_end);
    size_t cmt  = s.find("<!--", last_end);
    size_t ref  = find_ci(s, last_end, "<ref");
    size_t nwk  = find_ci(s, last_end, "<nowiki");

    auto minpos = [&](size_t a, size_t b){ return (a == std::string::npos) ? b : ((b == std::string::npos) ? a : std::min(a,b)); };
    size_t earliest = minpos(minpos(tmpl, cmt), minpos(ref, nwk));

    if (earliest != std::string::npos && (next_link_pos == std::string::npos || earliest < next_link_pos)) {
        size_t after = earliest;
        if (earliest == tmpl)      after = skip_template(s, earliest);
        else if (earliest == cmt)  after = skip_comment(s, earliest);
        else if (earliest == ref)  after = skip_tag_pair_or_selfclose(s, earliest, "ref");
        else if (earliest == nwk)  after = skip_tag_pair_or_selfclose(s, earliest, "nowiki");

        // Guard against no progress
        if (after <= earliest) after = earliest + 1;
        last_end = after;
        return true;
    }
    return false;
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
                        const xmlChar* v = xmlTextReaderConstValue(reader);
                        if (!v) break;
                        std::string article(reinterpret_cast<const char*>(v));  // safe, we won't mutate libxml's buffer

                        size_t last_end = 0;

                        while (true) {
                            size_t start = article.find("[[", last_end);

                            // If a skippable block begins before the next link, skip it and restart.
                            if (maybe_skip_skippable(article, last_end, start)) continue;
                            if (start == std::string::npos) break;

                            size_t end = article.find("]]", start + 2);
                            if (end == std::string::npos) break;

                            // Determine the 'target' segment limits (before '|' and before '#')
                            size_t pipe = article.find('|', start + 2);
                            if (pipe == std::string::npos || pipe > end) pipe = end;
                            size_t hash = article.find('#', start + 2);
                            if (hash == std::string::npos || hash > pipe) hash = pipe;

                            // // (9) Namespace colon check only within the *target* segment (start+2 .. pipe/hash)
                            // size_t colon = article.find(':', start + 2);
                            // if (colon != std::string::npos && colon < pipe) {
                            //     last_end = end + 2;
                            //     continue; // skip namespaced links like File:, Category:, etc.
                            // }

                            // Extract link target
                            std::string_view link(article.data() + start + 2, hash - (start + 2));
                            if (!link.empty()) {
                                links_strs.insert(get_string(link));
                            }

                            last_end = end + 2;
                        }
                    }

                    else if (xmlStrcmp(tag, (const xmlChar*)"ns") == 0) {
                        xmlTextReaderRead(reader);
                        int ns = atoi((const char*)xmlTextReaderConstValue(reader));
                        if (ns != 0) in_page = false;
                    }

                    else if (xmlStrcmp(tag, (const xmlChar*)"redirect") == 0) {
                        xmlChar* title_ = xmlTextReaderGetAttribute(reader, (const xmlChar*)"title");
                        string title = (const char*)title_;
                        char* hash = (char*)memchr(title_, '#', title.len);
                        if (hash) {
                            std::cerr << "Redirect with hash: " << title << std::endl;
                        }
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

    for (int i = 0; i < page_count; i++) {
        uint16_t num_links = (uint16_t)links[i].n;
        if (fwrite(&num_links, sizeof(num_links), 1, f) != 1) {
            perror("fwrite");
            exit(1);
        }
    }

    char zeros[8] = {0};
    int padding_needed = page_count % 4;
    if (padding_needed) {
        if (fwrite(zeros, 2, 4-padding_needed, f) != 4-padding_needed) {
            perror("fwrite");
            exit(1);
        }
    }

    for (int i = 0; i < page_count; i++) {
        for (int j = 0; j < links[i].n; j++) {
            int32_t link = links[i].ids[j];
            char* p = (char*)&link;
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

    fflush(f);
    sync();
    GC_free(buf);
}

static const int MAX_REDIRECT_HOPS = 128;

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

    write_db();

    return 0;
}
