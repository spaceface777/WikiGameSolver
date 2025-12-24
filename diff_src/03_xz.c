/************ xz decompression (liblzma) ************/

static uint8_t* read_entire_file(const char* path, size_t* out_len) {
	FILE* fp = fopen(path, "rb");
	if (!fp) {
		fprintf(stderr, "error: open %s: %s\n", path, strerror(errno));
		return NULL;
	}
	if (fseeko(fp, 0, SEEK_END) != 0) {
		fprintf(stderr, "error: seek %s\n", path);
		fclose(fp);
		return NULL;
	}
	off_t sz = ftello(fp);
	if (sz < 0) {
		fprintf(stderr, "error: ftello %s\n", path);
		fclose(fp);
		return NULL;
	}
	if (fseeko(fp, 0, SEEK_SET) != 0) {
		fprintf(stderr, "error: seek start %s\n", path);
		fclose(fp);
		return NULL;
	}
	uint8_t* buf = (uint8_t*)xmalloc((size_t)sz);
	size_t	 rd	 = fread(buf, 1, (size_t)sz, fp);
	fclose(fp);
	if (rd != (size_t)sz) {
		fprintf(stderr, "error: short read %s\n", path);
		free(buf);
		return NULL;
	}
	*out_len = rd;
	return buf;
}

static uint8_t* xz_decompress_mem(const uint8_t* in, size_t in_len, size_t* out_len) {
	lzma_stream strm = LZMA_STREAM_INIT;
	lzma_ret	ret	 = lzma_stream_decoder(&strm, UINT64_MAX, 0);
	if (ret != LZMA_OK) die("lzma_stream_decoder failed");

	size_t	 cap	 = 64u * 1024u * 1024u; // grow as needed
	uint8_t* out	 = (uint8_t*)xmalloc(cap);
	size_t	 out_pos = 0;

	strm.next_in  = in;
	strm.avail_in = in_len;

	while (1) {
		if (out_pos == cap) {
			cap = cap + cap / 2 + 1;
			out = (uint8_t*)xrealloc(out, cap);
		}
		strm.next_out  = out + out_pos;
		strm.avail_out = cap - out_pos;

		ret		= lzma_code(&strm, LZMA_FINISH);
		out_pos = cap - strm.avail_out;

		if (ret == LZMA_STREAM_END) break;
		if (ret != LZMA_OK) {
			fprintf(stderr, "error: lzma_code failed (%d)\n", (int)ret);
			lzma_end(&strm);
			free(out);
			return NULL;
		}
		// If no progress and no output space, loop will realloc above.
	}

	lzma_end(&strm);
	*out_len = out_pos;
	out		 = (uint8_t*)xrealloc(out, out_pos ? out_pos : 1);
	return out;
}
