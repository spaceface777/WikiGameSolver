#pragma once
// Static wikitext only: no template expansion or rendered-anchor guarantee.
#include "wiki_html_entities.h"
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <unicode/uchar.h>
#include <unicode/unorm2.h>
#include <unicode/ustring.h>
#include <unicode/utf8.h>
#include <vector>

namespace wiki_links
{
	inline constexpr unsigned parser_policy = 1;

	inline uint32_t unicode_version() {
		UVersionInfo version;
		u_getUnicodeVersion(version);
		return uint32_t(version[0]) | (uint32_t(version[1]) << 8) | (uint32_t(version[2]) << 16) |
			   (uint32_t(version[3]) << 24);
	}

	inline constexpr uint8_t alternate_label = 1, template_context = 2;

	struct Namespace {
		int32_t     id;
		std::string name;
		bool        capitalized = true, alias = false;
	};

	struct Config {
		bool                   capitalized = true;
		std::string            current_title;
		std::vector<Namespace> namespaces{{-2, "Media"},       {-1, "Special"},       {1, "Talk"},
										  {2, "User"},         {3, "User talk"},      {4, "Project"},
										  {5, "Project talk"}, {6, "File"},           {6, "Image", true, true},
										  {7, "File talk"},    {8, "MediaWiki"},      {9, "MediaWiki talk"},
										  {10, "Template"},    {11, "Template talk"}, {12, "Help"},
										  {13, "Help talk"},   {14, "Category"},      {15, "Category talk"}};

		void add_namespace(int32_t id, std::string name, bool capitalized_, bool alias) {
			if (id == 0) {
				capitalized = capitalized_;
				return;
			}
			if (!alias)
				for (auto& n : namespaces)
					if (n.id == id && !n.alias) n.alias = true;
			namespaces.push_back({id, std::move(name), capitalized_, alias});
		}
	};

	inline bool starts(std::string_view text, size_t p, std::string_view token) {
		return p <= text.size() && token.size() <= text.size() - p && text.compare(p, token.size(), token) == 0;
	}

	inline std::string trim(std::string s) {
		auto a = s.find_first_not_of(" \t\n\r"), b = s.find_last_not_of(" \t\n\r");
		return a == std::string::npos ? std::string() : s.substr(a, b - a + 1);
	}

	inline void append_utf8(std::string& out, UChar32 cp) {
		char    bytes[4];
		int32_t at    = 0;
		UBool   error = false;
		U8_APPEND(bytes, at, 4, cp, error);
		if (error) throw std::runtime_error("invalid Unicode scalar");
		out.append(bytes, at);
	}

	inline std::string unicode(std::string_view input, bool fold = false) {
		if (std::all_of(input.begin(), input.end(), [](unsigned char c) { return c < 128; })) {
			std::string out(input);
			if (fold)
				for (char& c : out)
					if (c >= 'A' && c <= 'Z') c += 32;
			return out;
		}
		if (input.size() > INT32_MAX) throw std::runtime_error("Unicode input too long");
		UErrorCode         error  = U_ZERO_ERROR;
		int32_t            length = 0;
		std::vector<UChar> source(input.size() + 1);
		u_strFromUTF8(source.data(), source.size(), &length, input.data(), input.size(), &error);
		if (U_FAILURE(error)) return {};
		error                      = U_ZERO_ERROR;
		const UNormalizer2* nfc    = unorm2_getNFCInstance(&error);
		int32_t             needed = unorm2_normalize(nfc, source.data(), length, nullptr, 0, &error);
		if (error != U_BUFFER_OVERFLOW_ERROR && U_FAILURE(error)) return {};
		error = U_ZERO_ERROR;
		std::vector<UChar> normalized(needed + 1);
		length = unorm2_normalize(nfc, source.data(), length, normalized.data(), normalized.size(), &error);
		if (U_FAILURE(error)) return {};
		if (fold) {
			error  = U_ZERO_ERROR;
			needed = u_strFoldCase(nullptr, 0, normalized.data(), length, U_FOLD_CASE_DEFAULT, &error);
			if (error != U_BUFFER_OVERFLOW_ERROR && U_FAILURE(error)) return {};
			error = U_ZERO_ERROR;
			std::vector<UChar> folded(needed + 1);
			length =
				u_strFoldCase(folded.data(), folded.size(), normalized.data(), length, U_FOLD_CASE_DEFAULT, &error);
			if (U_FAILURE(error)) return {};
			normalized.swap(folded);
		}
		error = U_ZERO_ERROR;
		std::string out(size_t(length) * 4 + 1, '\0');
		int32_t     bytes = 0;
		u_strToUTF8(out.data(), out.size(), &bytes, normalized.data(), length, &error);
		if (U_FAILURE(error)) return {};
		out.resize(bytes);
		return out;
	}

	inline std::string decode_entities(std::string_view input) {
		std::string out;
		out.reserve(input.size());
		for (size_t p = 0; p < input.size();) {
			if (input[p] != '&') {
				out += input[p++];
				continue;
			}
			auto end = input.find(';', p + 1);
			if (end == std::string_view::npos || end - p > 64) {
				out += input[p++];
				continue;
			}
			auto        name = input.substr(p + 1, end - p - 1);
			std::string value;
			if (!name.empty() && name[0] == '#') {
				size_t   at   = 1;
				unsigned base = 10;
				if (at < name.size() && (name[at] == 'x' || name[at] == 'X')) {
					base = 16;
					++at;
				}
				uint32_t cp    = 0;
				bool     valid = at < name.size();
				for (; at < name.size() && valid; ++at) {
					unsigned c = (unsigned char)name[at], digit = 99;
					if (c >= '0' && c <= '9') digit = c - '0';
					else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
					else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
					if (digit >= base || cp > (0x10ffff - digit) / base) valid = false;
					else cp = cp * base + digit;
				}
				if (valid && cp > 0 && cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff)) append_utf8(value, cp);
			} else {
				auto it = std::lower_bound(std::begin(entities), std::end(entities), name,
										   [](const Entity& e, std::string_view n) { return e.name < n; });
				if (it != std::end(entities) && it->name == name) value = it->value;
			}
			if (value.empty()) {
				out += input[p++];
				continue;
			}
			out += value;
			p = end + 1;
		}
		return out;
	}

	inline bool whitespace(UChar32 c) {
		return c == '_' || c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == 0xa0 || c == 0x1680 || c == 0x180e ||
			   (c >= 0x2000 && c <= 0x200a) || c == 0x2028 || c == 0x2029 || c == 0x202f || c == 0x205f || c == 0x3000;
	}

	struct Title {
		std::string text;
		int32_t     name_space = 0;
		bool        valid      = false;
	};

	inline Title title(std::string_view raw, const Config& config = {}) {
		std::string decoded = unicode(decode_entities(raw));
		if (decoded.empty()) return {};
		std::string text;
		bool        pending = false;
		for (int32_t p = 0; p < (int32_t)decoded.size();) {
			UChar32 cp;
			U8_NEXT(decoded.data(), p, (int32_t)decoded.size(), cp);
			if (cp < 0 || cp == 0xfffd) return {};
			if (cp == 0x200e || cp == 0x200f || (cp >= 0x202a && cp <= 0x202e)) continue;
			if (whitespace(cp)) {
				pending = !text.empty();
				continue;
			}
			if (pending) {
				text += ' ';
				pending = false;
			}
			append_utf8(text, cp);
		}
		if (!text.empty() && text[0] == ':') text = trim(text.substr(1));
		auto fragment = text.find('#');
		if (fragment != std::string::npos) text = trim(text.substr(0, fragment));
		// A fragment-only link is valid, but does not name another article.
		if (text.empty()) return {"", 0, fragment != std::string::npos};
		int32_t     ns          = 0;
		bool        capitalized = config.capitalized;
		std::string prefix;
		auto        colon = text.find(':');
		if (colon != std::string::npos) {
			auto name = unicode(trim(text.substr(0, colon)), true);
			for (const auto& entry : config.namespaces)
				if (unicode(entry.name, true) == name) {
					ns          = entry.id;
					capitalized = entry.capitalized;
					text        = trim(text.substr(colon + 1));
					prefix      = entry.name;
					for (const auto& canonical : config.namespaces)
						if (canonical.id == ns && !canonical.alias) {
							prefix = canonical.name;
							break;
						}
					break;
				}
		}
		if (text.empty() || text.size() > (ns == -1 ? 512u : 255u) || text[0] == ':' ||
			text.find_first_of("[]{}<>|\x01\x7f") != std::string::npos)
			return {};
		for (size_t p = 0; p < text.size(); ++p) {
			unsigned char c = text[p];
			if (c < 32) return {};
			if (c == '%' && p + 2 < text.size() && std::isxdigit((unsigned char)text[p + 1]) &&
				std::isxdigit((unsigned char)text[p + 2]))
				return {};
			if (c == '&') {
				// MediaWiki rejects entity-shaped names, not arbitrary ampersand/semicolon pairs.
				// Literal punctuation in titles such as "B, S & T; 4" remains valid.
				size_t e = p + 1;
				while (e < text.size()) {
					unsigned char next = text[e];
					if (!((next >= 'A' && next <= 'Z') || (next >= 'a' && next <= 'z') ||
						  (next >= '0' && next <= '9') || next >= 128))
						break;
					++e;
				}
				if (e > p + 1 && e < text.size() && text[e] == ';') return {};
			}
		}
		if (text == "." || text == ".." || starts(text, 0, "./") || starts(text, 0, "../") ||
			text.find("/./") != std::string::npos || text.find("/../") != std::string::npos ||
			(text.size() >= 2 && text.compare(text.size() - 2, 2, "/.") == 0) ||
			(text.size() >= 3 && text.compare(text.size() - 3, 3, "/..") == 0) || text.find("~~~") != std::string::npos)
			return {};
		if (capitalized) {
			int32_t p = 0;
			UChar32 cp;
			U8_NEXT(text.data(), p, (int32_t)text.size(), cp);
			auto upper = u_totitle(cp);
			if (upper != cp) {
				std::string replacement;
				append_utf8(replacement, upper);
				text = replacement + text.substr(p);
			}
		}
		return {prefix.empty() ? text : prefix + ":" + text, ns, true};
	}

	inline bool ascii_equal(std::string_view a, std::string_view b) {
		if (a.size() != b.size()) return false;
		for (size_t i = 0; i < a.size(); ++i) {
			unsigned char x = a[i], y = b[i];
			if (x >= 'A' && x <= 'Z') x += 32;
			if (y >= 'A' && y <= 'Z') y += 32;
			if (x != y) return false;
		}
		return true;
	}

	inline std::string active_text(std::string_view input) {
		std::string out;
		out.reserve(input.size());
		for (size_t p = 0; p < input.size();) {
			if (starts(input, p, "<!--")) {
				auto end = input.find("-->", p + 4);
				if (end == std::string_view::npos) break;
				p = end + 3;
				continue;
			}
			if (input[p] == '<') {
				size_t name_begin = p + 1, name_end = name_begin;
				while (name_end < input.size() && ((input[name_end] >= 'a' && input[name_end] <= 'z') ||
												   (input[name_end] >= 'A' && input[name_end] <= 'Z')))
					++name_end;
				auto name       = input.substr(name_begin, name_end - name_begin);
				bool protected_ = false;
				for (auto literal : {"nowiki", "pre", "source", "syntaxhighlight", "math"})
					if (ascii_equal(name, literal)) protected_ = true;
				if (protected_ && name_end < input.size() &&
					(input[name_end] == '>' || input[name_end] == '/' || input[name_end] == ' ' ||
					 input[name_end] == '\t' || input[name_end] == '\n')) {
					size_t end   = name_end;
					char   quote = 0;
					for (; end < input.size(); ++end) {
						char c = input[end];
						if (quote) {
							if (c == quote) quote = 0;
						} else if (c == '\'' || c == '"') quote = c;
						else if (c == '>') break;
					}
					if (end == input.size()) break;
					size_t before = end;
					while (before > name_end &&
						   (input[before - 1] == ' ' || input[before - 1] == '\t' || input[before - 1] == '\n'))
						--before;
					out += '\x01';
					if (before > name_end && input[before - 1] == '/') {
						p = end + 1;
						continue;
					}
					std::string closing = "</" + std::string(name) + ">";
					size_t      close   = end + 1;
					for (; close < input.size(); ++close)
						if (input[close] == '<' && close + closing.size() <= input.size() &&
							ascii_equal(input.substr(close, closing.size()), closing))
							break;
					if (close == input.size()) break;
					p = close + closing.size();
					continue;
				}
				// Tag attributes are not navigable wikitext. Reference contents remain active.
				size_t tag_name = name_begin;
				if (tag_name < input.size() && input[tag_name] == '/') ++tag_name;
				if (tag_name < input.size() && ((input[tag_name] >= 'a' && input[tag_name] <= 'z') ||
												(input[tag_name] >= 'A' && input[tag_name] <= 'Z'))) {
					size_t end   = tag_name;
					char   quote = 0;
					for (; end < input.size(); ++end) {
						char c = input[end];
						if (quote) {
							if (c == quote) quote = 0;
						} else if (c == '\'' || c == '"') quote = c;
						else if (c == '>') break;
					}
					if (end < input.size()) {
						out += '\x01';
						p = end + 1;
						continue;
					}
				}
			}
			out += input[p++];
		}
		return out;
	}

	struct Span {
		size_t   begin, end;
		unsigned kind;
	};

	inline std::vector<Span> spans(std::string_view text) {
		std::vector<Span> open, complete;
		for (size_t p = 0; p < text.size();) {
			if (starts(text, p, "{{{")) {
				open.push_back({p, 0, 3});
				p += 3;
			} else if (starts(text, p, "{{")) {
				open.push_back({p, 0, 2});
				p += 2;
			} else if (!open.empty() && starts(text, p, open.back().kind == 3 ? "}}}" : "}}")) {
				auto span = open.back();
				open.pop_back();
				p += span.kind;
				span.end = p;
				complete.push_back(span);
			} else ++p;
		}
		std::sort(complete.begin(), complete.end(), [](const Span& a, const Span& b) { return a.begin < b.begin; });
		return complete;
	}

	inline size_t top_pipe(std::string_view text) {
		auto   balanced = spans(text);
		size_t next     = 0;
		for (size_t p = 0; p < text.size(); ++p) {
			while (next < balanced.size() && balanced[next].begin < p) ++next;
			if (next < balanced.size() && balanced[next].begin == p) {
				p = balanced[next].end - 1;
				continue;
			}
			if (text[p] == '|') return p;
		}
		return std::string_view::npos;
	}

	inline bool defaults(std::string_view input, std::string& out, unsigned depth = 0) {
		if (depth > 32) return false;
		auto   balanced = spans(input);
		size_t next     = 0;
		for (size_t p = 0; p < input.size();) {
			while (next < balanced.size() && balanced[next].begin < p) ++next;
			if (starts(input, p, "{{{")) {
				if (next == balanced.size() || balanced[next].begin != p || balanced[next].kind != 3) return false;
				auto end    = balanced[next].end;
				auto inside = input.substr(p + 3, end - p - 6);
				auto pipe   = top_pipe(inside);
				if (pipe == std::string_view::npos || !defaults(inside.substr(pipe + 1), out, depth + 1)) return false;
				p = end;
				continue;
			}
			if (starts(input, p, "{{")) return false;
			out += input[p++];
		}
		return true;
	}

	inline std::string pipe_label(const Title& target) {
		std::string label = target.text;
		if (target.name_space != 0) {
			auto colon = label.find(':');
			if (colon != std::string::npos) label.erase(0, colon + 1);
		}
		if (!label.empty() && label.back() == ')') {
			auto open = label.rfind(" (");
			if (open != std::string::npos) label.resize(open);
		} else {
			auto comma = label.find(',');
			if (comma != std::string::npos) label.resize(comma);
		}
		return trim(label);
	}

	inline std::map<std::string, uint8_t> parse(std::string_view input, const Config& config = {}) {
		std::map<std::string, uint8_t> links;
		std::string                    text     = active_text(input);
		auto                           balanced = spans(text);
		std::vector<size_t>            active;
		size_t                         next_span = 0;
		for (size_t p = 0; p < text.size();) {
			auto at = text.find("[[", p);
			if (at == std::string::npos) break;
			auto end = text.find("]]", at + 2);
			if (end == std::string::npos) break;
			auto nested = text.find("[[", at + 2);
			if (nested != std::string::npos && nested < end) {
				p = nested;
				continue;
			}
			auto        inside = std::string_view(text).substr(at + 2, end - at - 2);
			auto        pipe   = top_pipe(inside);
			auto        raw    = inside.substr(0, pipe);
			std::string resolved;
			if (!defaults(raw, resolved)) {
				p = end + 2;
				continue;
			}
			auto target = title(resolved, config);
			if (!target.valid) {
				p = end + 2;
				continue;
			}
			if (target.name_space != 0) {
				p = end + 2;
				continue;
			}
			if (target.text.empty()) {
				p = end + 2;
				continue;
			}
			if (!config.current_title.empty() && target.text == config.current_title) {
				p = end + 2;
				continue;
			}
			while (!active.empty() && active.back() <= at) active.pop_back();
			while (next_span < balanced.size() && balanced[next_span].begin <= at) {
				const auto& span = balanced[next_span++];
				if (span.kind == 2 && span.end > end + 1) active.push_back(span.end);
			}
			uint8_t flags = !active.empty() && active.front() >= end + 2 ? template_context : 0;
			if (pipe != std::string_view::npos) {
				auto label = trim(std::string(inside.substr(pipe + 1)));
				if (label.empty()) label = pipe_label(target);
				if (unicode(label, true) != unicode(target.text, true)) flags |= alternate_label;
			}
			auto [it, added] = links.emplace(target.text, flags);
			if (!added) it->second = std::min(it->second, flags);
			p = end + 2;
		}
		return links;
	}

} // namespace wiki_links
