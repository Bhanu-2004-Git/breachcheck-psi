// Client C (Fig. 2): manifest check, VOPRF, encrypted windowed query, decode.
#pragma once
#include <array>
#include <memory>
#include <optional>
#include <random>
#include <vector>

#include "hashing.h"
#include "manifest.h"
#include "protocol.h"
#include "zt.h"

namespace bcpsi {

struct MatchResult {
    bool found = false;
    bool label_ok = false;   // 52 redundancy bits were zero
    uint64_t label = 0;
    int partition = -1;
};

class Client {
public:
    Client(const ParamSet& pinned, const std::array<uint8_t, 32>& signer_pk);

    bool accept_manifest(const SignedManifest& sm, std::string* why = nullptr);
    OprfRequest start(const std::vector<oprf::Bytes>& credential_hashes, Metrics& m);
    bool finish_oprf(const OprfResponse& resp, Metrics& m);   // false = DLEQ proof rejected
    QueryRequest build_query(Metrics& m);
    std::vector<MatchResult> decode(const QueryResponse& resp, Metrics& m);   // one per real item
    void erase_secrets();

    seal::Decryptor* decryptor() { return decryptor_.get(); }
    const seal::SEALContext& context() const { return ctx_; }
    std::size_t cuckoo_evictions() const { return cuckoo_.evictions; }

private:
    ParamSet p_;
    std::array<uint8_t, 32> signer_pk_;
    std::optional<Manifest> manifest_;
    seal::SEALContext ctx_;
    std::unique_ptr<seal::BatchEncoder> encoder_;
    std::unique_ptr<seal::KeyGenerator> keygen_;
    std::unique_ptr<seal::Decryptor> decryptor_;
    Zt zt_;
    std::mt19937_64 rng_;

    std::size_t real_count_ = 0;
    std::vector<oprf::Bytes> inputs_;      // padded to m_max
    std::vector<oprf::Scalar> blinds_;
    std::vector<oprf::Element> blinded_;
    std::vector<DerivedItem> items_;
    CuckooTable cuckoo_;
};

}  // namespace bcpsi
