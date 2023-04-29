#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>

#define LOG // fprintf(stderr, "%s:%d %s\n", __FILE__, __LINE__, __PRETTY_FUNCTION__);

#define HTTP_READ_BUF_SIZE 16 * 1024 * 1024
#include "string.h"
#include "http.h"
#include "json.h"
#include "map.h"
#include "zlib.h"
// #include "miniz.h"


#define MIRROR_DOMAIN "laotzu.ftp.acc.umu.se"
#define MIRROR_BASE "/mirror/wikimedia.org/dumps"
#define MIRROR_PORT 80

// #define MIRROR_DOMAIN "localhost"
// #define MIRROR_BASE ""
// #define MIRROR_PORT 3000

#define MIRROR_INDEX MIRROR_BASE "/index.json"

string target_wiki;
string redirecttable_url = MIRROR_BASE;
string pagetable_url = MIRROR_BASE;
string pagelinkstable_url = MIRROR_BASE;

void read_dump_index();
void process_pages();
void process_redirects();
void process_links();
int  trim_empty_pages();
void write_db();

map_string_int title_to_old_id;
map_int_string old_id_to_title;
map_int_int old_id_to_new_id;
map_int_int redirects;

int page_count = 0;
string* titles;
int* old_ids;
struct PageLinks { int n; int cap; int* ids; };
PageLinks* links;

size_t out_len = HTTP_READ_BUF_SIZE*4;
const char* out;

int main(int argc, char **argv) {
    out = (const char*)malloc(out_len);
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <wiki>\n", argv[0]);
        target_wiki = "enwiki";
    } else {
        target_wiki = string(argv[1]) + "wiki";
    }

    title_to_old_id = new_map_string_int();
    old_id_to_title = new_map_int_string();
    old_id_to_new_id = new_map_int_int();
    redirects = new_map_int_int();

    fprintf(stderr, "Processing wiki %.*s...\n", (int)target_wiki.len, target_wiki.p());

    read_dump_index();
    process_pages();
    process_redirects();

    free(old_ids);
    map_free(&old_id_to_title);
    map_free(&title_to_old_id);
    links = (PageLinks*)calloc(page_count, sizeof(PageLinks));

    process_links();

    while (1) {
        int n = trim_empty_pages();
        fprintf(stderr, "\nTrimmed %d empty pages\n", n);
        if (n == 0) break;
    }

    write_db();

    for (int i = 0; i < page_count; i++) {
        free(links[i].ids);
    }
    free(links);
    for (int i = 0; i < page_count; i++) {
        titles[i].free();
    }
    free(titles);
    map_free(&redirects);
    map_free(&old_id_to_new_id);
    free((void*)out);

    return 0;
}

void read_dump_index() {
    HTTPClient res = http_get(MIRROR_DOMAIN, MIRROR_PORT, MIRROR_INDEX);
    while (!res.done) {
        int n = http_read(&res);
    }

    json_value_s* root = json_parse(res.buf, res.content_length);
    json_object_s* obj = json_value_as_object(root);
    json_object_element_s *el;
    for (el = obj->start; el != 0; el = el->next) {
        if (string(el->name->string, el->name->string_size) == string("wikis")) break;
    }
    
    json_object_s* wikis = json_value_as_object(el->value);
    el = wikis->start;
    while (string(el->name->string, el->name->string_size) != target_wiki) {
        el = el->next;
    }

    json_object_s* wiki = json_value_as_object(el->value);
    el = wiki->start;
    for (el = wiki->start; el != 0; el = el->next) {
        if (string(el->name->string, el->name->string_size) == string("jobs")) break;
    }
    wiki = json_value_as_object(el->value);

    for (el = wiki->start; el != 0; el = el->next) {
        string s = string(el->name->string, el->name->string_size);
        if (s == string("pagelinkstable")) {
            json_object_s* job = json_value_as_object(el->value);
            json_object_element_s *el2;
            for (el2 = job->start; el2 != 0; el2 = el2->next) {
                if (string(el2->name->string, el2->name->string_size) == string("files")) break;
            }
            el2 = json_value_as_object(el2->value)->start;
            for (el2 = json_value_as_object(el2->value)->start; el2 != 0; el2 = el2->next) {
                if (string(el2->name->string, el2->name->string_size) == string("url")) break;
            }
            pagelinkstable_url += string(json_value_as_string(el2->value)->string, json_value_as_string(el2->value)->string_size);
        } else if (s == string("pagetable")) {
            json_object_s* job = json_value_as_object(el->value);
            json_object_element_s *el2;
            for (el2 = job->start; el2 != 0; el2 = el2->next) {
                if (string(el2->name->string, el2->name->string_size) == string("files")) break;
            }
            el2 = json_value_as_object(el2->value)->start;
            for (el2 = json_value_as_object(el2->value)->start; el2 != 0; el2 = el2->next) {
                if (string(el2->name->string, el2->name->string_size) == string("url")) break;
            }
            pagetable_url += string(json_value_as_string(el2->value)->string, json_value_as_string(el2->value)->string_size);
        } else if (s == string("redirecttable")) {
            json_object_s* job = json_value_as_object(el->value);
            json_object_element_s *el2;
            for (el2 = job->start; el2 != 0; el2 = el2->next) {
                if (string(el2->name->string, el2->name->string_size) == string("files")) break;
            }
            el2 = json_value_as_object(el2->value)->start;
            for (el2 = json_value_as_object(el2->value)->start; el2 != 0; el2 = el2->next) {
                if (string(el2->name->string, el2->name->string_size) == string("url")) break;
            }
            redirecttable_url += string(json_value_as_string(el2->value)->string, json_value_as_string(el2->value)->string_size);
        }
    }

    free(root);
    http_free(&res);
}

int title_to_new_id(string title) {
    string* p = std::lower_bound(titles, titles+page_count, title);

    if (p != titles+page_count && *p == title) {
        return p - titles;
    }
    return -1;
}

static inline int read_lines(const char* buf, int len, void (*callback)(const char*, int)) {
    const char* start = buf;
    while (true) {
        const char* end = (const char*)memchr(start, '\n', len - (start - buf));
        if (end == 0) break;
        callback(start, end - start);
        start = end + 1;
    }
    return len - (start - buf);
}

void process_pages() {
    fprintf(stderr, "\n\n%.*s\n", (int)pagetable_url.len, pagetable_url.p());
    HTTPClient res = http_get(MIRROR_DOMAIN, MIRROR_PORT, pagetable_url);
    fprintf(stderr, "res.len = %lluM\n", res.content_length >> 20);
    
    z_stream strm = {0};
    inflateInit2(&strm, 16+MAX_WBITS);

    strm.avail_out = out_len;
    strm.next_out = (Bytef*)out;

    while (!res.done) {
        size_t n = http_read(&res);
        char* buf_ = res.buf;

        strm.avail_in = n;
        strm.next_in = (Bytef*)buf_;

        while (strm.avail_in > 0) {
            int ret = inflate(&strm, Z_NO_FLUSH);
            if (ret != Z_OK && ret != Z_STREAM_END) {
                fprintf(stderr, "Error: %d: %s\n", ret, strm.msg);
                exit(1);
            }
            int rem = read_lines(out, out_len - strm.avail_out, [](const char* p, int len) {
                if (memcmp(p, "INSERT INTO `page` VALUES ", 26) != 0) { return; }
                p += 27;
                len -= 29;

                int id;
                int ns;
                string title;
                bool is_redirect;

                int s = 0;
                int n = 0;
                bool in_quote = false;
                for (int i = 0; i < len; i++) {
                    char c = p[i];
                    if (c == '\'') {
                        int j = i - 1;
                        bool escaped = true;
                        while (j >= 0 && p[j] == '\\') {
                            escaped = !escaped;
                            j--;
                        }
                        if (!escaped) {
                            continue;
                        }
                        in_quote = !in_quote;
                    }
                    if (!in_quote) {
                        if (c == ',') {
                            int j = i - 1;
                            bool escaped = true;
                            while (j >= 0 && p[j] == '\\') {
                                escaped = !escaped;
                                j--;
                            }
                            if (!escaped) {
                                continue;
                            }
                            if (n == 0) {
                                id = atoi(p + s);
                            } else if (n == 1) {
                                ns = atoi(p + s);
                            } else if (n == 2) {
                                char* clean_title = (char*)malloc(i - s - 1);
                                int l = 0;
                                int ss = s+1;
                                while (ss < i && isspace(p[ss])) ss++;
                                for (int j = ss; j < i-1; j++) {
                                    if (p[j] == '\\' && (p[j+1] == '\\' || p[j+1] == '\'' || p[j+1] == '"')) {
                                        j++;
                                        clean_title[l++] = p[j];
                                    } else if (p[j] == '_') {
                                        clean_title[l++] = ' ';
                                    } else {
                                        clean_title[l++] = p[j];
                                    }
                                }
                                while (l > 0 && isspace(clean_title[l-1])) l--;
                                clean_title[l] = 0;
                                title = string(clean_title, l);
                            } else if (n == 4) {
                                is_redirect = p[s] == '1';
                            }
                            n++;
                            s = i + 1;
                        } else if ((i == len - 1) || (c == ')' && p[i+1] == ',' && p[i+2] == '(')) {
                            if (n != 11) {
                                fprintf(stderr, "PARSE error: n = %d\n", n);
                                return;
                            }
                            if (ns == 0 && !is_redirect) {
                                // fprintf(stderr, "%d -> %.*s\n", id, (int)title.len, title.p());
                                map_int_string_set(&old_id_to_title, id, title);
                                map_string_int_set(&title_to_old_id, title, id);
                            }
                            s = 0;
                            n = 0;
                            i += 2;
                            s = i + 1;
                        }
                    }
                }
            });
            if (rem > 0) {
                memmove((void*)out, out + out_len - strm.avail_out - rem, rem);
                strm.avail_out = out_len - rem;
                strm.next_out = (Bytef*)out + rem;
            } else {
                strm.avail_out = out_len;
                strm.next_out = (Bytef*)out;
            }
        }
    }

    http_free(&res);
    fprintf(stderr, "%d pages\n", old_id_to_title.len);

}

map_int_int redirects_old;
void process_redirects() {
    redirects_old = new_map_int_int();

    fprintf(stderr, "\n\n%.*s\n", (int)redirecttable_url.len, redirecttable_url.p());
    HTTPClient res = http_get(MIRROR_DOMAIN, MIRROR_PORT, redirecttable_url);
    fprintf(stderr, "res.len = %lluM\n", res.content_length >> 20);
    
    z_stream strm = {0};
    inflateInit2(&strm, 16+MAX_WBITS);

    strm.avail_out = out_len;
    strm.next_out = (Bytef*)out;

    while (!res.done) {
        size_t n = http_read(&res);
        char* buf_ = res.buf;

        strm.avail_in = n;
        strm.next_in = (Bytef*)buf_;

        while (strm.avail_in > 0) {
            int ret = inflate(&strm, Z_NO_FLUSH);
            if (ret != Z_OK && ret != Z_STREAM_END) {
                fprintf(stderr, "Error: %d: %s\n", ret, strm.msg);
                exit(1);
            }
            int rem = read_lines(out, out_len - strm.avail_out, [](const char* p, int len) {
                if (memcmp(p, "INSERT INTO `redirect` VALUES ", 30) != 0) { return; }
                p += 31;
                len -= 33;

                int source_id;
                int ns;
                string title;

                int s = 0;
                int n = 0;
                bool in_quote = false;
                for (int i = 0; i < len; i++) {
                    char c = p[i];
                    if (c == '\'') {
                        int j = i - 1;
                        bool escaped = true;
                        while (j >= 0 && p[j] == '\\') {
                            escaped = !escaped;
                            j--;
                        }
                        if (!escaped) {
                            continue;
                        }
                        in_quote = !in_quote;
                    }
                    if (!in_quote) {
                        if (c == ',') {
                            int j = i - 1;
                            bool escaped = true;
                            while (j >= 0 && p[j] == '\\') {
                                escaped = !escaped;
                                j--;
                            }
                            if (!escaped) {
                                continue;
                            }
                            if (n == 0) {
                                source_id = atoi(p + s);
                            } else if (n == 1) {
                                ns = atoi(p + s);
                            } else if (n == 2) {
                                char* clean_title = (char*)malloc(i - s - 1);
                                int l = 0;
                                int ss = s+1;
                                while (ss < i && isspace(p[ss])) ss++;
                                for (int j = ss; j < i-1; j++) {
                                    if (p[j] == '\\' && (p[j+1] == '\\' || p[j+1] == '\'' || p[j+1] == '"')) {
                                        j++;
                                        clean_title[l++] = p[j];
                                    } else if (p[j] == '_') {
                                        clean_title[l++] = ' ';
                                    } else {
                                        clean_title[l++] = p[j];
                                    }
                                }
                                while (l > 0 && isspace(clean_title[l-1])) l--;
                                clean_title[l] = 0;
                                title = string(clean_title, l);
                            }
                            n++;
                            s = i + 1;
                        } else if ((i == len - 1) || (c == ')' && p[i+1] == ',' && p[i+2] == '(')) {
                            if (n != 4) {
                                fprintf(stderr, "PARSE error: n = %d\n", n);
                                return;
                            }

                            if (ns == 0) {
                                if (map_int_string_get_check(&old_id_to_title, source_id)) {
                                    int* target_id = map_string_int_get_check(&title_to_old_id, title);
                                    if (target_id) {
                                        map_int_int_set(&redirects_old, source_id, *target_id);
                                    }
                                }
                            }

                            s = 0;
                            n = 0;
                            i += 2;
                            s = i + 1;
                            title.free();
                        }
                    }
                }
            });
            if (rem > 0) {
                memmove((void*)out, out + out_len - strm.avail_out - rem, rem);
                strm.avail_out = out_len - rem;
                strm.next_out = (Bytef*)out + rem;
            } else {
                strm.avail_out = out_len;
                strm.next_out = (Bytef*)out;
            }
        }
    }

    fprintf(stderr, "%d redirects\n", redirects_old.len);
    http_free(&res);

    FOR_IN_MAP_INT_INT(redirects_old, old_source_id, old_target_id, {
        int target_id = *old_target_id;
        int nr_redirects = 0;

        int* t;
        while ((t = map_int_int_get_check(&redirects_old, target_id))) {
            target_id = *t;
            nr_redirects++;
            if (target_id == old_source_id || nr_redirects > 100) {
				target_id = -1;
                break;
            }
        }
        if (target_id != -1) {
            map_int_int_set(&redirects_old, old_source_id, target_id);
        } else {
            map_int_int_delete(&redirects_old, old_source_id);
        }
    })

    page_count = title_to_old_id.len;    
    titles = (string*)calloc(page_count, sizeof(string));
    old_ids = (int*)calloc(page_count, sizeof(int));
    
    int i = 0;
    FOR_IN_MAP_STRING_INT(title_to_old_id, title, old_id, {
        titles[i] = title;
        old_ids[i] = *old_id;
        i++;
    })
    std::sort(titles, titles + page_count, [](const string& a, const string& b) {
        return a < b;
    });
    for (int i = 0; i < title_to_old_id.len; i++) {
        old_ids[i] = *map_string_int_get_check(&title_to_old_id, titles[i]);
    }

    for (int new_id = 0; new_id < title_to_old_id.len; new_id++) {
        map_int_int_set(&old_id_to_new_id, old_ids[new_id], new_id);
    }

    FOR_IN_MAP_INT_INT(redirects_old, old_source_id, old_target_id, {
        map_int_int_set(&redirects, old_source_id, *map_int_int_get_check(&old_id_to_new_id, *old_target_id));
    })

    map_free(&redirects_old);
}

void process_links() {
    fprintf(stderr, "\n\n%.*s\n", (int)pagelinkstable_url.len, pagelinkstable_url.p());
    HTTPClient res = http_get(MIRROR_DOMAIN, MIRROR_PORT, pagelinkstable_url);
    fprintf(stderr, "res.len = %lluM\n", res.content_length >> 20);
    
    z_stream strm = {0};
    inflateInit2(&strm, 16+MAX_WBITS);

    strm.avail_out = out_len;
    strm.next_out = (Bytef*)out;

    uint64_t nr_links = 0;

    while (!res.done) {
        size_t n = http_read(&res);
        char* buf_ = res.buf;

        strm.avail_in = n;
        strm.next_in = (Bytef*)buf_;

        while (strm.avail_in > 0) {
            int ret = inflate(&strm, Z_NO_FLUSH);
            if (ret != Z_OK && ret != Z_STREAM_END) {
                fprintf(stderr, "Error: %d: %s\n", ret, strm.msg);
                exit(1);
            }
            int rem = read_lines(out, out_len - strm.avail_out, [](const char* p, int len) {
                if (memcmp(p, "INSERT INTO `pagelinks` VALUES ", 31) != 0) { return; }
                p += 32;
                len -= 34;

                int source_id;
                int ns;
                string title;

                int s = 0;
                int n = 0;
                bool in_quote = false;
                for (int i = 0; i < len; i++) {
                    char c = p[i];
                    if (c == '\'') {
                        int j = i - 1;
                        bool escaped = true;
                        while (j >= 0 && p[j] == '\\') {
                            escaped = !escaped;
                            j--;
                        }
                        if (!escaped) {
                            continue;
                        }
                        in_quote = !in_quote;
                    }
                    if (!in_quote) {
                        if (c == ',') {
                            int j = i - 1;
                            bool escaped = true;
                            while (j >= 0 && p[j] == '\\') {
                                escaped = !escaped;
                                j--;
                            }
                            if (!escaped) {
                                continue;
                            }
                            if (n == 0) {
                                source_id = atoi(p + s);
                            } else if (n == 1) {
                                ns = atoi(p + s);
                            } else if (n == 2) {
                                char* clean_title = (char*)malloc(i - s - 1);
                                int l = 0;
                                int ss = s+1;
                                while (ss < i && isspace(p[ss])) ss++;
                                for (int j = ss; j < i-1; j++) {
                                    if (p[j] == '\\' && (p[j+1] == '\\' || p[j+1] == '\'' || p[j+1] == '"')) {
                                        j++;
                                        clean_title[l++] = p[j];
                                    } else if (p[j] == '_') {
                                        clean_title[l++] = ' ';
                                    } else {
                                        clean_title[l++] = p[j];
                                    }
                                }
                                while (l > 0 && isspace(clean_title[l-1])) l--;
                                clean_title[l] = 0;
                                title = string(clean_title, l);
                            }
                            n++;
                            s = i + 1;
                        } else if ((i == len - 1) || (c == ')' && p[i+1] == ',' && p[i+2] == '(')) {
                            if (n != 3) {
                                fprintf(stderr, "PARSE error: n = %d\n", n);
                                return;
                            }

                            if (ns == 0) {
                                bool found = false;
                                int* redirect_id = map_int_int_get_check(&redirects, source_id);
                                if (redirect_id) {
                                    source_id = *redirect_id;
                                    found = true;
                                } else {
                                    int* new_id = map_int_int_get_check(&old_id_to_new_id, source_id);
                                    if (new_id) {
                                        source_id = *new_id;
                                        found = true;
                                    }
                                }
                                if (found) {
                                    int target_id = title_to_new_id(title);
                                    if (target_id != -1 && source_id != target_id) {
                                        PageLinks* l = links + source_id;
                                        if (l->n == l->cap) {
                                            l->cap = l->cap * 2 + 1;
                                            l->ids = (int*)realloc(l->ids, l->cap * sizeof(int));
                                        }

                                        l->ids[l->n++] = target_id;
                                    }
                                }
                            }

                            s = 0;
                            n = 0;
                            i += 2;
                            s = i + 1;
                            title.free();
                        }
                    }
                }
            });
            if (rem > 0) {
                memmove((void*)out, out + out_len - strm.avail_out - rem, rem);
                strm.avail_out = out_len - rem;
                strm.next_out = (Bytef*)out + rem;
            } else {
                strm.avail_out = out_len;
                strm.next_out = (Bytef*)out;
            }
        }
    }

    http_free(&res);

    for (int i = 0; i < page_count; i++) {
        PageLinks* l = links + i;
        if (l->n > 0) {
            qsort(l->ids, l->n, sizeof(int), [](const void* a, const void* b) {
                return *(int*)a - *(int*)b;
            });
        }
    }
}

int trim_empty_pages() {
    std::vector<int> empty_pages;

    for (int i = 0; i < page_count; i++) {
        PageLinks* l = links + i;
        if (l->n == 0) {
            empty_pages.push_back(i);
        }
    }

    fprintf(stderr, "Empty pages: %d / %d\n", (int)empty_pages.size(), page_count);

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

    int* old_id_to_new_id = (int*)calloc(page_count, sizeof(int));
    for (int i = 0; i < page_count; i++) {
        old_id_to_new_id[i] = i;
    }

    for (int i = 0; i < empty_pages.size(); i++) {
        int id = empty_pages[i];
        int m = 0;
        if (i == empty_pages.size()-1) {
            m = page_count;
        } else {
            m = empty_pages[i+1];
        }
        for (int j = id; j < m; j++) {
            old_id_to_new_id[j] -= i+1;
        }
    }

    int l = page_count - empty_pages.size();
    string* titles_ = (string*)malloc(l * sizeof(string));
    PageLinks* links_ = (PageLinks*)malloc(l * sizeof(PageLinks));
    int titles_len = 0;
    int links_len = 0;

    for (int i=0, b=0; i < page_count; i++) {
        if (b < empty_pages.size() && empty_pages[b] == i) {
            b++;
            continue;
        }
        titles_[titles_len++] = titles[i];
        links_[links_len++] = links[i];
    }
    free(titles);
    free(links);
    titles = titles_;
    links = links_;
    page_count = l;

    for (int j = 0; j < links_len; j++) {
        for (int k = 0; k < links[j].n; k++) {
            int* q = &links[j].ids[k];
            *q = old_id_to_new_id[*q];
        }
        
    }

    free(old_id_to_new_id);

    return empty_pages.size();
}

void write_db() {
    fprintf(stderr, "Writing db...\n");
    FILE* f = stdout;
    char* buf = (char*)malloc(16<<20);
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
    free(buf);
}
