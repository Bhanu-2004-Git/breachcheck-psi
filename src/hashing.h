// Item derivation from OPRF outputs, bin hashing and client cuckoo hashing
// (Part 2, Sec. 2.2-2.3).
#pragma once
#include <array>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "oprf.h"
#include "params.h"

namespace bcpsi {

// One OPRF output expanded into everything the PSI layer needs.
struct DerivedItem {
    std::array<uint32_t, 5> felts{};     // 100-bit item hat{o}, 5 x 20 bits
    std::array<uint32_t, 5> pad{};       // 100-bit label pad, 5 x 20 bits
    std::array<uint32_t, kNumHashes> bins{};
};

// SHA-512("BCPSI-v1-derive" || table_seed || o) -> item, pad, 3 bin indices.
DerivedItem derive_item(const oprf::Output& o, const std::array<uint8_t, 16>& table_seed, std::size_t num_bins);

// Credential hash x = SHA-256("cred" || lower(username) || 0x00 || password).
oprf::Bytes credential_hash(const std::string& username, const std::string& password);

// 48-bit label <-> 5 felts of the 100-bit value (label || 0^52), little-endian bits.
std::array<uint32_t, 5> label_to_felts(uint64_t label48);
bool felts_to_label(const std::array<uint32_t, 5>& felts, uint64_t& label48);   // false if check bits != 0

// Cuckoo table: bin -> index of the client item placed there (-1 = empty).
struct CuckooTable {
    std::vector<int32_t> slot_owner;
    std::vector<uint32_t> item_bin;      // bin chosen for each item
    std::size_t evictions = 0;
};
// Returns false on failure (after max_evictions random-walk steps).
bool cuckoo_insert(const std::vector<DerivedItem>& items, std::size_t num_bins, CuckooTable& out,
                   std::mt19937_64& rng, std::size_t max_evictions = 1000);

}  // namespace bcpsi
