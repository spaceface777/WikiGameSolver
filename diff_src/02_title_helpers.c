/************ Title helpers (prefix/suffix heuristics) ************/

static int title_has_prefix(TitleRef t, const char* s) {
	size_t sl = strlen(s);
	if ((size_t)t.len < sl) return 0;
	return memcmp(t.ptr, s, sl) == 0;
}

static int title_has_suffix(TitleRef t, const char* s) {
	size_t sl = strlen(s);
	if ((size_t)t.len < sl) return 0;
	return memcmp(t.ptr + (t.len - (uint16_t)sl), s, sl) == 0;
}

static int title_is_year_page(TitleRef t) {
	if (t.len != 4) return 0;
	for (int i = 0; i < 4; i++) {
		unsigned char c = (unsigned char)t.ptr[i];
		if (!isdigit(c)) return 0;
	}
	return 1;
}

static int title_starts_with_year_in(TitleRef t) {
	// "2015 in aviation", "1979 in music", etc.
	if (t.len < 7) return 0;
	for (int i = 0; i < 4; i++) {
		unsigned char c = (unsigned char)t.ptr[i];
		if (!isdigit(c)) return 0;
	}
	// must have " in " starting at pos 4: "YYYY in ..."
	return (t.ptr[4] == ' ' && t.ptr[5] == 'i' && t.ptr[6] == 'n');
}

static int title_is_cheese_like(TitleRef t) {
	// Very cheap heuristics for "teleport hubs".
	// Tweak freely: these are meant for "no-cheese PageRank" and similar stats.
	if (title_has_prefix(t, "List of ")) return 1;
	if (title_has_prefix(t, "Index of ")) return 1;
	if (title_has_prefix(t, "Timeline of ")) return 1;
	if (title_has_prefix(t, "Deaths in ")) return 1;
	if (title_has_suffix(t, " (disambiguation)")) return 1;
	if (title_is_year_page(t)) return 1;
	if (title_starts_with_year_in(t)) return 1;
	return 0;
}
