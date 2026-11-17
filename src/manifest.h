// Signed public manifest (Part 2, Sec. 2.1): parameters, OPRF public key,
// table seed, n_max and database version, signed with Ed25519.
#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "oprf.h"
#include "params.h"

namespace bcpsi {

struct Manifest {
    std::string set_name;
    uint32_t N = 0, f = 0, d = 0, alpha = 0, window_base = 0, flood_bits = 0, labeled = 0;
    std::vector<int> coeff_bits;
    uint64_t t = 0, n_max = 0, m_max = 0, db_version = 0, timestamp = 0;
    std::array<uint8_t, 16> table_seed{};
    oprf::Element oprf_pk{};

    std::vector<uint8_t> serialize() const;
    static Manifest deserialize(const std::vector<uint8_t>& b);
    static Manifest from_params(const ParamSet& p);
    // True iff all fields a client pins (ring, moduli, item layout, window) match.
    bool matches_pinned(const ParamSet& pinned, std::string* why = nullptr) const;
};

struct SignedManifest {
    std::vector<uint8_t> body;
    std::array<uint8_t, 64> signature{};
};

struct SigningKey {
    std::array<uint8_t, 32> pk{};
    std::array<uint8_t, 64> sk{};
    static SigningKey generate();
};

SignedManifest sign_manifest(const Manifest& m, const SigningKey& key);
// Returns false if the signature does not verify.
bool verify_manifest(const SignedManifest& sm, const std::array<uint8_t, 32>& signer_pk, Manifest& out);

}  // namespace bcpsi
