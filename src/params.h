// Parameter sets for the HE-based unbalanced labeled PSI (Part 2, Section 3).
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace bcpsi {

constexpr std::size_t kFeltBits = 20;     // bits of an item per plaintext slot
constexpr std::size_t kItemBits = 100;    // sigma: OPRF-derived item length
constexpr std::size_t kLabelBits = 48;    // 32-bit breach id + 16-bit date
constexpr std::size_t kLabelCheckBits = kItemBits - kLabelBits;  // 52 zero bits
constexpr std::size_t kNumHashes = 3;     // cuckoo hash functions

struct ParamSet {
    std::string name;
    std::size_t N = 8192;                 // ring degree
    std::vector<int> coeff_bits;          // last entry = special (key-switching) prime
    uint64_t t = 0;                       // plaintext prime, t = 1 mod 2N
    std::size_t n_server = 0;             // server set size (n_max in the manifest)
    std::size_t m_client = 256;           // client set size after padding (m_max)
    std::size_t f = 5;                    // felts per item
    std::size_t d = 63;                   // max items per partition (poly degree)
    std::size_t window_base = 8;          // powers v^{i * base^j} are uploaded
    std::size_t alpha = 0;                // partitions per bin (0 = derive from n)
    int flood_bits = 0;                   // log2 of flooding-noise magnitude (0 = off)
    bool labeled = true;

    std::size_t bins() const { return N / f; }
    std::size_t capacity() const { return alpha * d; }
    std::size_t window_digits() const;      // number of base-b digits needed for d
    std::size_t query_ciphertexts() const { return (window_base - 1) * window_digits(); }
    int log2_q_total() const;
    int log2_q_data() const;                 // coeff modulus without special prime
};

// Smallest alpha such that P[some bin overflows alpha*d] <= 2^-40 under simple
// hashing of k*n balls into B bins (binomial tail, union bound over bins).
std::size_t derive_alpha(std::size_t n, std::size_t bins, std::size_t d, std::size_t k = kNumHashes,
                         double log2_target = -40.0);
double log2_overflow_probability(std::size_t n, std::size_t bins, std::size_t capacity,
                                 std::size_t k = kNumHashes);
double log2_false_positive(const ParamSet& p);   // per query, union over m items, alpha parts

// Named sets: "T" (tests, n=2^12), "S" (n=2^16), "M" (n=2^20, main design),
// "L" (N=16384, n=2^20). Optional override of n.
ParamSet get_paramset(const std::string& name, std::size_t n_override = 0);

std::string describe(const ParamSet& p);

}  // namespace bcpsi
