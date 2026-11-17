// Wire messages and shared helpers (Part 2, Fig. 2).
#pragma once
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "seal/seal.h"
#include "oprf.h"
#include "params.h"

namespace bcpsi {

using Metrics = std::map<std::string, double>;

struct OprfRequest { std::vector<oprf::Element> blinded; };
struct OprfResponse { std::vector<oprf::Element> evaluated; oprf::Proof proof; };

// Phase 2: everything is a serialized SEAL object (seeded where SEAL allows).
struct QueryRequest {
    std::string public_key;               // pk_C (seeded)
    std::string relin_keys;               // rlk_C (seeded)
    std::vector<std::string> powers;      // Enc_skC(v^{i*b^j}) (seeded), index (j*(b-1) + i-1)
};

// Phase 3: 2*alpha ciphertexts at the last level, bit-packed (see pack_ciphertexts).
struct QueryResponse {
    std::string packed;
    std::size_t num_ciphertexts = 0;
};

std::size_t size_bytes(const OprfRequest& r);
std::size_t size_bytes(const OprfResponse& r);
std::size_t size_bytes(const QueryRequest& r);
std::size_t size_bytes(const QueryResponse& r);

seal::SEALContext make_context(const ParamSet& p);

// Bit-packs size-2 ciphertexts at the last level (one prime q0) using
// ceil(log2 q0) bits per coefficient; unpack validates every coefficient < q0.
std::string pack_ciphertexts(const seal::SEALContext& ctx, const std::vector<seal::Ciphertext>& cts);
std::vector<seal::Ciphertext> unpack_ciphertexts(const seal::SEALContext& ctx, const std::string& blob,
                                                 std::size_t expected_count);

template <class T> std::string seal_save(const T& obj) {
    std::stringstream ss;
    obj.save(ss, seal::compr_mode_type::none);
    return ss.str();
}

}  // namespace bcpsi
