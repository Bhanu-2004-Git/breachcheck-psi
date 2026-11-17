// Non-private comparison points.
//  (A) Plaintext lookup: the client sends its credential hashes in the clear
//      and the server answers from a hash table. No query privacy at all.
//  (B) k-anonymity prefix lookup (HIBP / Google Password Checkup v1 style):
//      the client sends a short hash prefix, the server returns the whole
//      bucket (suffixes + labels) and the client matches locally. Leaks the
//      prefix bits of every queried credential.
#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "dataset.h"
#include "protocol.h"

namespace bcpsi {

struct BaselineResult {
    std::vector<int> found;          // per client item: 1 found, 0 not
    std::vector<uint64_t> labels;
};

class PlaintextBaseline {
public:
    Metrics build(const std::vector<Record>& records);
    BaselineResult query(const std::vector<oprf::Bytes>& items, Metrics& m) const;
private:
    std::unordered_map<std::string, uint64_t> table_;
};

class KAnonBaseline {
public:
    explicit KAnonBaseline(int prefix_bits) : prefix_bits_(prefix_bits) {}
    Metrics build(const std::vector<Record>& records);
    BaselineResult query(const std::vector<oprf::Bytes>& items, Metrics& m) const;
    int prefix_bits() const { return prefix_bits_; }
private:
    int prefix_bits_;
    std::vector<std::vector<std::pair<std::string, uint64_t>>> buckets_;   // suffix, label
};

}  // namespace bcpsi
