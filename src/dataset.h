// Deterministic synthetic breach corpus and client credential sets.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "oprf.h"

namespace bcpsi {

struct Record {
    oprf::Bytes x;        // credential hash (32 bytes)
    uint64_t label = 0;   // 48 bits: breach id (32) | days since 2000 (16)
};

struct ClientSet {
    std::vector<oprf::Bytes> items;          // credential hashes, real items only
    std::vector<int64_t> expected_index;     // index into server records, -1 = non-member
};

std::vector<Record> make_server_records(std::size_t n, uint64_t seed);
// k planted members chosen from the server records plus (m_real - k) fresh non-members.
ClientSet make_client_set(const std::vector<Record>& server, std::size_t m_real, std::size_t k, uint64_t seed);

}  // namespace bcpsi
