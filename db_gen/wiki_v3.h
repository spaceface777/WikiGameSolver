#pragma once
// WIKI v3 writer: the v2 sections in the same order, re-encoded so the outer zstd stream compresses them well.
// Every section is a u32 byte length followed by its bytes. See graph_load_v3() in client/load.c.
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace wiki_v3
{
	enum { GAP_CONTEXTS = 26, MAX_REFS = 3, REF_WINDOW = 16, HASHES = 8, CANDIDATES = 64, BLOCK = 65536 };

	struct Graph {
		uint32_t                             version; // (date << 8) | 3
		std::vector<uint32_t>                offsets; // N+1
		std::vector<uint32_t>                edges;   // strictly increasing per node
		std::vector<std::string_view>        titles, redir_titles;
		std::vector<std::array<uint32_t, 3>> unredir; // sorted (src, dest, redir_idx)
		std::vector<uint8_t>                 flags;   // one per edge
	};

	using Bytes = std::vector<uint8_t>;

	inline int ilog2(uint64_t x) {
		return 63 - __builtin_clzll(x);
	}

	inline void varint(Bytes& b, uint32_t x) {
		for (; x >= 128; x >>= 7) b.push_back(uint8_t(x | 128));
		b.push_back(uint8_t(x));
	}

	struct Bits {
		Bytes    bytes;
		uint64_t acc = 0;
		int      n   = 0;

		void put(uint32_t v, int k) {
			for (int i = k - 1; i >= 0; i--) {
				acc = acc << 1 | ((v >> i) & 1);
				if (++n == 8) bytes.push_back(uint8_t(acc)), acc = 0, n = 0;
			}
		}

		Bytes& done() {
			if (n) bytes.push_back(uint8_t(acc << (8 - n))), acc = 0, n = 0;
			return bytes;
		}
	};

	// x >= 1: values 1..7 are their own symbol; larger values send their top 3 bits as the symbol, the rest raw.
	inline void put_gap(Bytes& sym, Bits& low, uint32_t x) {
		int k = ilog2(x);
		if (k <= 2) return sym.push_back(uint8_t(x));
		sym.push_back(uint8_t(8 + 4 * (k - 3) + ((x >> (k - 2)) & 3)));
		low.put(x, k - 2);
	}

	inline int gap_context(size_t j, uint32_t prev) {
		return j ? 1 + std::min(ilog2(prev + 1ull), GAP_CONTEXTS - 2) : 0;
	}

	inline uint32_t mix(uint32_t x) {
		x ^= x >> 16, x *= 0x7feb352d, x ^= x >> 15, x *= 0x846ca68b;
		return x ^ (x >> 16);
	}

	inline Bytes front_coded(const std::vector<std::string_view>& titles) {
		Bytes            out;
		std::string_view prev;
		for (auto t : titles) {
			if (t.find('\n') != t.npos) throw std::runtime_error("title contains a newline");
			size_t p = 0;
			while (p < 255 && p < t.size() && p < prev.size() && t[p] == prev[p]) p++;
			out.push_back(uint8_t(p));
			out.insert(out.end(), t.begin() + p, t.end());
			out.push_back('\n');
			prev = t;
		}
		return out;
	}

	inline void write(FILE* f, const Graph& g) {
		uint32_t N = uint32_t(g.titles.size()), L = uint32_t(g.edges.size()), title_bytes = 0;
		auto     deg = [&](uint32_t i) { return g.offsets[i + 1] - g.offsets[i]; };
		for (auto t : g.titles) title_bytes += uint32_t(t.size());
		uint32_t R = uint32_t(g.redir_titles.size()), redir_bytes = 0;
		for (auto t : g.redir_titles) redir_bytes += uint32_t(t.size());
		uint32_t head[] = {g.version, N, L, title_bytes, uint32_t(g.unredir.size()), R, redir_bytes};
		if (fwrite("WIKI", 1, 4, f) != 4 || fwrite(head, 4, 7, f) != 7) throw std::runtime_error("v3 write failed");
		auto section = [&](const Bytes& b) {
			if (b.size() > UINT32_MAX) throw std::runtime_error("v3 section exceeds 4 GiB");
			uint32_t n = uint32_t(b.size());
			if (fwrite(&n, 4, 1, f) != 1 || fwrite(b.data(), 1, n, f) != n) throw std::runtime_error("v3 write failed");
		};

		// Degrees, then in-degrees: the reader ranks targets by in-degree, most linked first.
		Bytes                 degrees, in_degrees;
		std::vector<uint32_t> indeg(N), rank(N), order(N);
		for (uint32_t i = 0; i < N; i++) {
			if (deg(i) > 65535) throw std::runtime_error("outdegree exceeds u16");
			degrees.push_back(uint8_t(deg(i))), degrees.push_back(uint8_t(deg(i) >> 8));
			for (uint32_t k = g.offsets[i]; k < g.offsets[i + 1]; k++)
				if (k > g.offsets[i] && g.edges[k] <= g.edges[k - 1])
					throw std::runtime_error("adjacency not strictly sorted");
		}
		for (auto e : g.edges) indeg[e]++;
		for (auto x : indeg) varint(in_degrees, x);
		for (uint32_t i = 0; i < N; i++) order[i] = i;
		std::stable_sort(order.begin(), order.end(), [&](uint32_t a, uint32_t b) { return indeg[a] > indeg[b]; });
		for (uint32_t i = 0; i < N; i++) rank[order[i]] = i;

		section(degrees);
		section(in_degrees);

		// Edges: each list copies from up to MAX_REFS earlier lists, then codes its remaining targets' rank gaps.
		// Written in blocks of BLOCK nodes so the reader buffers one block's sections at a time.
		Bytes              ref_counts, refs, mask_syms;
		std::vector<Bytes> syms(GAP_CONTEXTS);
		Bits               low;
		uint32_t           buckets = 1;
		while (buckets < N) buckets *= 2;
		std::vector<uint32_t> heads(size_t(HASHES) * buckets, ~0u), next(size_t(HASHES) * N), sig(size_t(HASHES) * N);
		std::vector<uint32_t> seen(N, ~0u), candidates, residual, positions, excluded;
		std::vector<char>     taken;
		for (uint32_t i = 0; i < N; i++) {
			const uint32_t* cur = &g.edges[g.offsets[i]];
			uint32_t        d = deg(i), nrefs = 0;
			double          link_bits = d ? std::log2(double(N) / d) + 2 : 0;
			taken.assign(d, 0);
			for (int round = 0; round < MAX_REFS; round++) {
				candidates.clear();
				uint32_t stamp = i * MAX_REFS + round;
				auto     add   = [&](uint32_t r) {
					if (r < i && seen[r] != stamp) seen[r] = stamp, candidates.push_back(r);
				};
				for (uint32_t z = 1; z <= REF_WINDOW && z <= i; z++) add(i - z);
				for (int h = 0; h < HASHES; h++) {
					uint32_t q = ~0u;
					for (uint32_t j = 0; j < d; j++)
						if (!taken[j]) q = std::min(q, mix(cur[j] + 0x9e3779b9u * h));
					uint32_t e = q == ~0u ? ~0u : heads[size_t(h) * buckets + (q & (buckets - 1))];
					for (int found = 0; e != ~0u && found < CANDIDATES; e = next[size_t(h) * N + e])
						if (sig[size_t(h) * N + e] == q) add(e), found++;
				}
				// Pick the reference that saves the most estimated bits.
				double   best     = 0;
				uint32_t best_ref = ~0u;
				for (auto r : candidates) {
					uint32_t rd = deg(r), shared = 0, fresh = 0;
					for (uint32_t a = 0, k = g.offsets[r]; k < g.offsets[r + 1]; k++) {
						while (a < d && cur[a] < g.edges[k]) a++;
						if (a < d && cur[a] == g.edges[k]) shared++, fresh += !taken[a++];
					}
					uint32_t small = std::min(shared, rd - shared);
					double   cost  = std::lgamma(rd + 1.0) - std::lgamma(small + 1.0) - std::lgamma(rd - small + 1.0);
					double   gain  = fresh * link_bits - cost / std::log(2.0) - 2 * std::log2(2.0 + i - r) - 8;
					if (fresh && gain > best) best = gain, best_ref = r;
				}
				if (best_ref == ~0u) break;
				// Mask: positions in the reference list that this list also contains; send the smaller side.
				uint32_t r = best_ref, rd = deg(r), shared = 0;
				positions.clear(), excluded.clear();
				for (uint32_t a = 0, k = 0; k < rd; k++) {
					uint32_t v = g.edges[g.offsets[r] + k];
					while (a < d && cur[a] < v) a++;
					if (a < d && cur[a] == v) taken[a++] = 1, positions.push_back(k), shared++;
					else excluded.push_back(k);
				}
				if (excluded.size() < positions.size()) positions.swap(excluded);
				varint(refs, i - r), varint(refs, shared);
				uint32_t prev = ~0u;
				for (auto p : positions) put_gap(mask_syms, low, p - prev), prev = p;
				nrefs++;
			}
			ref_counts.push_back(uint8_t(nrefs));
			residual.clear();
			for (uint32_t j = 0; j < d; j++)
				if (!taken[j]) residual.push_back(rank[cur[j]]);
			std::sort(residual.begin(), residual.end());
			uint32_t prev = ~0u;
			for (size_t j = 0; j < residual.size(); j++)
				put_gap(syms[gap_context(j, prev)], low, residual[j] - prev), prev = residual[j];
			for (int h = 0; h < HASHES; h++) {
				uint32_t q = ~0u;
				for (uint32_t j = 0; j < d; j++) q = std::min(q, mix(cur[j] + 0x9e3779b9u * h));
				size_t slot            = size_t(h) * buckets + (q & (buckets - 1));
				sig[size_t(h) * N + i] = q, next[size_t(h) * N + i] = heads[slot], heads[slot] = i;
			}
			if ((i + 1) % BLOCK && i + 1 < N) continue;
			for (auto* s : {&ref_counts, &refs, &mask_syms}) section(*s), s->clear();
			for (auto& s : syms) section(s), s.clear();
			section(low.done()), low.bytes.clear();
		}
		section(front_coded(g.titles));

		// Redirect annotations: each target's used aliases (most used first), then per link to such a target one bit,
		// and the alias rank when the bit is set.
		std::vector<uint32_t>              dest(R, ~0u), uses(R), alias_rank(R);
		std::vector<std::vector<uint32_t>> aliases(N);
		for (auto& [s, t, a] : g.unredir) {
			if (a >= R || (dest[a] != ~0u && dest[a] != t)) throw std::runtime_error("redirect title has two targets");
			dest[a] = t, uses[a]++;
		}
		for (uint32_t a = 0; a < R; a++)
			if (dest[a] != ~0u) aliases[dest[a]].push_back(a);
		Bytes alias_lists, alias_ranks;
		Bits  alias_bits;
		for (auto& list : aliases) {
			std::stable_sort(list.begin(), list.end(), [&](uint32_t a, uint32_t b) { return uses[a] > uses[b]; });
			varint(alias_lists, uint32_t(list.size()));
			for (uint32_t k = 0; k < list.size(); k++) varint(alias_lists, list[k]), alias_rank[list[k]] = k;
		}
		size_t u = 0;
		for (uint32_t s = 0; s < N; s++)
			for (uint32_t k = g.offsets[s]; k < g.offsets[s + 1]; k++) {
				if (aliases[g.edges[k]].empty()) continue;
				bool has = u < g.unredir.size() && g.unredir[u][0] == s && g.unredir[u][1] == g.edges[k];
				alias_bits.put(has, 1);
				if (has) varint(alias_ranks, alias_rank[g.unredir[u++][2]]);
			}
		if (u != g.unredir.size()) throw std::runtime_error("unredir entry without a matching edge");
		section(alias_lists);
		section(alias_bits.done());
		section(alias_ranks);
		section(front_coded(g.redir_titles));

		// Flags: XOR each bit with its majority value over the target's incoming links, then one bitmap per bit
		// that is still set anywhere.
		Bytes predicted(N), planes(1);
		for (int b = 0; b < 8; b++) {
			std::vector<uint32_t> ones(N);
			for (uint32_t k = 0; k < L; k++) ones[g.edges[k]] += g.flags[k] >> b & 1;
			for (uint32_t i = 0; i < N; i++) predicted[i] |= uint8_t(2 * ones[i] > indeg[i]) << b;
		}
		for (uint32_t k = 0; k < L; k++) planes[0] |= g.flags[k] ^ predicted[g.edges[k]];
		for (int b = 0; b < 8; b++) {
			if (!(planes[0] >> b & 1)) continue;
			size_t at = planes.size();
			planes.resize(at + (L + 7) / 8);
			for (uint32_t k = 0; k < L; k++)
				planes[at + k / 8] |= ((g.flags[k] ^ predicted[g.edges[k]]) >> b & 1) << (k % 8);
		}
		section(predicted);
		section(planes);
	}
} // namespace wiki_v3
