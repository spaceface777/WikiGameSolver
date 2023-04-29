
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

map_string_string string_data = new_map_string_string();
map_string_stringptr link_map = new_map_string_stringptr();

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
                xmlChar* tag = xmlTextReaderName(reader);

                if (!in_page) {
                    if (xmlStrcmp(tag, (const xmlChar*)"page") == 0) in_page = true;
                    break;
                } else {
                    if (xmlStrcmp(tag, (const xmlChar*)"title") == 0) {
                        xmlTextReaderRead(reader);
                        const xmlChar* title = xmlTextReaderValue(reader);
                        page_title = get_string((const char*)title);
                        xmlFree((void*)title);
                    }

                    if (xmlStrcmp(tag, (const xmlChar*)"text") == 0) {
                        xmlTextReaderRead(reader);
                        xmlChar* article_ = xmlTextReaderValue(reader);
                        std::string_view article = (const char*)article_;

                        size_t last_end = 0, start = 0;
                        while ((start = article.find("[[", last_end)) != std::string::npos) {
                            size_t infoStart = article.find("{{", last_end);
                            if (infoStart != std::string::npos && infoStart < start) {
                                size_t infoEnd = infoStart + 2;
                                int n = 1;
                                while (n > 0) {
                                    size_t nextOpen = article.find("{{", infoEnd);
                                    size_t nextClose = article.find("}}", infoEnd);
                                    if (nextClose == std::string::npos) break;
                                    if (nextOpen < nextClose) {
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

                            size_t end = article.find("]]", start);
                            if (end == std::string::npos) break;

                            char* colon = (char*)memchr(article.data() + start, ':', end - start);
                            if (colon) {
                                last_end = end + 2;
                                continue;
                            }

                            article_[start + 2] = toupper(article_[start + 2]);

                            std::string_view link = "";

                            char* pipe = (char*)memchr(article.data() + start, '|', end - start);
                            if (pipe) {
                                size_t pipe_idx = pipe - article.data();
                                link = std::string_view(article.data() + start + 2, pipe_idx - start - 2);
                            } else {
                                link = std::string_view(article.data() + start + 2, end - start - 2);
                            }

                            links_strs.insert(get_string(link));

                            last_end = end + 2;
                        }

                        xmlFree(article_);
                    }

                    if (xmlStrcmp(tag, (const xmlChar*)"ns") == 0) {
                        xmlTextReaderRead(reader);
                        int ns = atoi((const char*)xmlTextReaderValue(reader));
                        if (ns != 0) in_page = false;
                    }

                    break;
                }

                xmlFree(tag);
            }
            case XML_READER_TYPE_END_ELEMENT: {
                xmlChar* end_tag = xmlTextReaderName(reader);
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

    uint32_t dump_date = 221201;
    uint8_t format_ver = 1;
    uint32_t version = dump_date << 8 | format_ver;
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

    for (int i = 0; i < page_count; i++) {
        for (int j = 0; j < links[i].n; j++) {
            int32_t link = links[i].ids[j];
            if (fwrite(&link, sizeof(link), 1, f) != 1) {
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

int main() {
    GC_INIT();
    xmlMemSetup(GC_free, GC_malloc, GC_realloc, GC_strdup);

    page_count = parse_xml();

    titles = (string*)GC_malloc(page_count * sizeof(string));
    links = (PageLinks*)GC_malloc(page_count * sizeof(PageLinks));

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
            int link_idx = bsearch(ll[i].p());
            if (link_idx == -1) continue;
            // ll[i].free();

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

    write_db();

    return 0;
}
