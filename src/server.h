// Server S: offline preprocessing (Fig. 1) and online evaluation (Fig. 2,
// phases 1 and 3) of the HE-based unbalanced labeled PSI.
#pragma once
#include <array>
#include <memory>
#include <vector>

#include "dataset.h"
#include "hashing.h"
#include "manifest.h"
#include "protocol.h"
#include "zt.h"

namespace bcpsi {

// Instrumentation only: lets tests/benchmarks measure the noise budget at
// intermediate server steps with the *client's* decryptor. Never used in a
// real deployment (the server does not hold sk_C).
struct NoiseProbe {
    seal::Decryptor* decryptor = nullptr;
    Metrics budgets;   // name -> min invariant noise budget (bits)
};

class Server {
public:
    Server(const ParamSet& p, unsigned threads, uint64_t db_version = 1);

    Metrics preprocess(const std::vector<Record>& records);   // must be called once
    const SignedManifest& signed_manifest() const { return manifest_; }
    const std::array<uint8_t, 32>& signer_public_key() const { return signer_.pk; }
    const ParamSet& params() const { return p_; }
    Metrics memory_usage() const;

    OprfResponse oprf(const OprfRequest& req, Metrics& m) const;
    QueryResponse answer(const QueryRequest& q, Metrics& m, NoiseProbe* probe = nullptr) const;

    // Test hook: add 1 to every slot of every label result (simulates a server
    // that corrupts labels) so the client's 52-bit redundancy check can be tested.
    void set_tamper_labels(bool on) { tamper_labels_ = on; }
    void set_threads(unsigned t) { threads_ = t; }
    void set_flood_bits(int b) { p_.flood_bits = b; }

private:
    void flood(seal::Ciphertext& ct, const seal::Encryptor& enc) const;

    ParamSet p_;
    unsigned threads_;
    uint64_t db_version_;
    seal::SEALContext ctx_;
    std::unique_ptr<seal::BatchEncoder> encoder_;
    std::unique_ptr<seal::Evaluator> evaluator_;
    Zt zt_;
    oprf::KeyPair oprf_key_;
    SigningKey signer_;
    std::array<uint8_t, 16> table_seed_{};
    SignedManifest manifest_;

    // P coefficients, raw (randomized per query): [(p*(d+1) + e) * N + slot]
    std::vector<uint32_t> p_coeffs_;
    // L coefficients as plaintexts: index p*d + e; e = 0 coefficient form, e >= 1 NTT form.
    std::vector<seal::Plaintext> l_plain_;
    std::vector<uint8_t> l_zero_;
    bool tamper_labels_ = false;
};

}  // namespace bcpsi
