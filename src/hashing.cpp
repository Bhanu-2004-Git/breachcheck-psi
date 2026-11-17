#include "hashing.h"

#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <cstring>

namespace bcpsi {

static uint32_t take_bits(const uint8_t* buf, std::size_t bit_off, std::size_t nbits) {
    uint64_t v = 0;
    for (std::size_t i = 0; i < nbits; ++i) {
        std::size_t b = bit_off + i;
        v |= uint64_t((buf[b >> 3] >> (b & 7)) & 1u) << i;
    }
    return uint32_t(v);
}

DerivedItem derive_item(const oprf::Output& o, const std::array<uint8_t, 16>& seed, std::size_t num_bins) {
    static const char kDom[] = "BCPSI-v1-derive";
    crypto_hash_sha512_state st;
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, reinterpret_cast<const uint8_t*>(kDom), sizeof(kDom) - 1);
    crypto_hash_sha512_update(&st, seed.data(), seed.size());
    crypto_hash_sha512_update(&st, o.data(), o.size());
    uint8_t h[64];
    crypto_hash_sha512_final(&st, h);
    DerivedItem it;
    for (std::size_t s = 0; s < 5; ++s) {
        it.felts[s] = take_bits(h, 20 * s, 20);          // bits   0..99  -> item
        it.pad[s] = take_bits(h, 104 + 20 * s, 20);      // bits 104..203 -> pad
    }
    for (std::size_t i = 0; i < kNumHashes; ++i) {       // bytes 26..49 -> bins
        uint64_t v;
        std::memcpy(&v, h + 26 + 8 * i, 8);
        it.bins[i] = uint32_t(v % num_bins);
    }
    return it;
}

oprf::Bytes credential_hash(const std::string& username, const std::string& password) {
    std::string u(username);
    std::transform(u.begin(), u.end(), u.begin(), [](unsigned char c) { return char(std::tolower(c)); });
    std::string in = "cred" + u;
    in.push_back('\0');
    in += password;
    oprf::Bytes out(crypto_hash_sha256_BYTES);
    crypto_hash_sha256(out.data(), reinterpret_cast<const uint8_t*>(in.data()), in.size());
    return out;
}

std::array<uint32_t, 5> label_to_felts(uint64_t label48) {
    std::array<uint32_t, 5> f{};
    label48 &= (1ull << kLabelBits) - 1;
    for (std::size_t s = 0; s < 5; ++s) {
        std::size_t lo = 20 * s;
        f[s] = lo < 64 ? uint32_t((label48 >> lo) & 0xFFFFF) : 0;
    }
    return f;
}

bool felts_to_label(const std::array<uint32_t, 5>& f, uint64_t& label48) {
    // Reassemble 100 bits; low 48 = label, high 52 must be zero.
    uint64_t lo = 0;   // bits 0..63
    uint64_t hi = 0;   // bits 64..99
    for (std::size_t s = 0; s < 5; ++s) {
        uint64_t v = f[s] & 0xFFFFF;
        if (f[s] > 0xFFFFF) return false;
        std::size_t off = 20 * s;
        if (off < 64) {
            lo |= v << off;
            if (off + 20 > 64) hi |= v >> (64 - off);
        } else {
            hi |= v << (off - 64);
        }
    }
    label48 = lo & ((1ull << kLabelBits) - 1);
    return (lo >> kLabelBits) == 0 && hi == 0;
}

bool cuckoo_insert(const std::vector<DerivedItem>& items, std::size_t num_bins, CuckooTable& out,
                   std::mt19937_64& rng, std::size_t max_evictions) {
    out.slot_owner.assign(num_bins, -1);
    out.item_bin.assign(items.size(), 0);
    out.evictions = 0;
    for (std::size_t idx = 0; idx < items.size(); ++idx) {
        int32_t cur = int32_t(idx);
        bool placed = false;
        for (std::size_t step = 0; step <= max_evictions && !placed; ++step) {
            const auto& b = items[cur].bins;
            for (std::size_t h = 0; h < kNumHashes; ++h)
                if (out.slot_owner[b[h]] == -1) {
                    out.slot_owner[b[h]] = cur;
                    out.item_bin[cur] = b[h];
                    placed = true;
                    break;
                }
            if (placed) break;
            uint32_t victim_bin = b[rng() % kNumHashes];       // random-walk eviction
            int32_t victim = out.slot_owner[victim_bin];
            out.slot_owner[victim_bin] = cur;
            out.item_bin[cur] = victim_bin;
            cur = victim;
            ++out.evictions;
        }
        if (!placed) return false;
    }
    return true;
}

}  // namespace bcpsi
