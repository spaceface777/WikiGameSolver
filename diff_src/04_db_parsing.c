/************ DB parsing ************/

static int db_parse(WikiDB* db) {
	const uint8_t* p   = db->buf;
	const uint8_t* end = db->buf + db->buf_len;

	if ((size_t)(end - p) < 4) return 0;
	if (!(p[0] == 'W' && p[1] == 'I' && p[2] == 'K' && p[3] == 'I')) {
		fprintf(stderr, "error: invalid magic\n");
		return 0;
	}
	p += 4;

	if ((size_t)(end - p) < 4) return 0;
	db->version_raw		 = read_u32(&p);
	db->dump_format		 = (uint8_t)(db->version_raw & 0xffu);
	db->dump_date_yymmdd = (int32_t)(db->version_raw >> 8);

	if ((size_t)(end - p) < 4) return 0;
	db->nr_entries = read_i32(&p);
	if (db->nr_entries <= 0) {
		fprintf(stderr, "error: nr_entries <= 0\n");
		return 0;
	}

	if ((size_t)(end - p) < 8) return 0;
	db->total_links		  = read_u32(&p);
	db->total_title_bytes = read_u32(&p);

	db->entries = (Entry*)xmalloc((size_t)db->nr_entries * sizeof(Entry));
	memset(db->entries, 0, (size_t)db->nr_entries * sizeof(Entry));

	// Read nr_links table
	for (int32_t i = 0; i < db->nr_entries; i++) {
		if ((size_t)(end - p) < 2) return 0;
		uint16_t nl				= read_u16(&p);
		db->entries[i].nr_links = nl;
		db->entries[i].links	= NULL;
	}

	// padding to multiple of 4 entries (u16)
	int padding_needed = db->nr_entries % 4;
	if (padding_needed) {
		size_t skip = (size_t)(4 - padding_needed) * sizeof(uint16_t);
		if ((size_t)(end - p) < skip) return 0;
		p += skip;
	}

	// Link arrays
	for (int32_t i = 0; i < db->nr_entries; i++) {
		uint16_t nl	  = db->entries[i].nr_links;
		size_t	 need = (size_t)nl * sizeof(uint32_t);
		if ((size_t)(end - p) < need) return 0;
		db->entries[i].links = (uint32_t*)p;
		p += need;
	}

	// title lengths
	for (int32_t i = 0; i < db->nr_entries; i++) {
		if ((size_t)(end - p) < 2) return 0;
		uint16_t l				 = read_u16(&p);
		db->entries[i].title_len = l;
		db->entries[i].title	 = NULL;
	}

	// title bytes blob
	for (int32_t i = 0; i < db->nr_entries; i++) {
		uint16_t l = db->entries[i].title_len;
		if ((size_t)(end - p) < l) return 0;
		db->entries[i].title = (const char*)p;
		p += l;
	}

	// ok if extra bytes exist (future fields), but normally p==end
	return 1;
}

static int db_load_xz(WikiDB* db, const char* path) {
	memset(db, 0, sizeof(*db));

	size_t	 in_len = 0;
	uint8_t* in		= read_entire_file(path, &in_len);
	if (!in) return 0;

	size_t	 out_len = 0;
	uint8_t* out	 = xz_decompress_mem(in, in_len, &out_len);
	free(in);
	if (!out) return 0;

	db->buf		= out;
	db->buf_len = out_len;

	if (!db_parse(db)) {
		fprintf(stderr, "error: failed parsing %s\n", path);
		return 0;
	}
	return 1;
}

static void db_free(WikiDB* db) {
	if (db->entries) free(db->entries);
	if (db->buf) free(db->buf);
	memset(db, 0, sizeof(*db));
}

static TitleRef db_title_ref(const WikiDB* db, int32_t idx) {
	TitleRef t;
	t.ptr = db->entries[idx].title;
	t.len = db->entries[idx].title_len;
	return t;
}
