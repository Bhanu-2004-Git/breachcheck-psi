#include "client.h"

#include <sodium.h>

#include <sstream>
#include <stdexcept>

#include "util.h"

namespace bcpsi {

static uint64_t seed64() {
    uint64_t v;
    randombytes_buf(&v, sizeof v);
    return v;
}

Client::Client(const ParamSet& pinned, const std::array<uint8_t, 32>& signer_pk)
    : p_(pinned), signer_pk_(signer_pk), ctx_(make_context(pinned)), zt_(pinned.t), rng_((oprf::init(), seed64())) {
    encoder_ = std::make_unique<seal::BatchEncoder>(ctx_);
}

bool Client::accept_manifest(const SignedManifest& sm, std::string* why) {
    Manifest m;
    if (!verify_manifest(sm, signer_pk_, m)) {
        if (why) *why = "bad signature";
        return false;
    }
    if (!m.matches_pinned(p_, why)) return false;
    p_.alpha = m.alpha;
    p_.n_server = m.n_max;
    p_.labeled = m.labeled != 0;
    manifest_ = m;
    return true;
}

OprfRequest Client::start(const std::vector<oprf::Bytes>& xs, Metrics& m) {
    if (!manifest_) throw std::logic_error("start: manifest not accepted");
    if (xs.size() > p_.m_client) throw std::invalid_argument("start: too many credentials");
    Timer t;
    real_count_ = xs.size();
    inputs_ = xs;
    while (inputs_.size() < p_.m_client) {     // pad with random dummies (fixed shape)
        oprf::Bytes dummy(32);
        randombytes_buf(dummy.data(), dummy.size());
        inputs_.push_back(dummy);
    }
    blinds_.resize(inputs_.size());
    blinded_.resize(inputs_.size());
    OprfRequest req;
    for (std::size_t i = 0; i < inputs_.size(); ++i) {
        blinds_[i] = oprf::random_scalar();
        blinded_[i] = oprf::blind(inputs_[i], blinds_[i], oprf::kVOPRF);
    }
    req.blinded = blinded_;
    m["cli.oprf_blind_ms"] = t.ms();
    return req;
}

bool Client::finish_oprf(const OprfResponse& resp, Metrics& m) {
    Timer t;
    if (resp.evaluated.size() != blinded_.size()) return false;
    if (!oprf::verify_proof(manifest_->oprf_pk, blinded_, resp.evaluated, resp.proof)) return false;
    m["cli.oprf_verify_ms"] = t.ms();
    t.reset();
    items_.resize(inputs_.size());
    for (std::size_t i = 0; i < inputs_.size(); ++i) {
        auto o = oprf::finalize(inputs_[i], blinds_[i], resp.evaluated[i]);
        items_[i] = derive_item(o, manifest_->table_seed, p_.bins());
    }
    m["cli.oprf_finalize_ms"] = t.ms();
    return true;
}

QueryRequest Client::build_query(Metrics& m) {
    const std::size_t N = p_.N, B = p_.bins(), base = p_.window_base, D = p_.window_digits();
    Timer t;
    if (!cuckoo_insert(items_, B, cuckoo_, rng_)) throw std::runtime_error("cuckoo hashing failed");
    std::vector<uint64_t> v(N);
    for (auto& x : v) x = rng_() & ((1u << kFeltBits) - 1);    // empty bins: random felts
    for (std::size_t i = 0; i < items_.size(); ++i) {
        uint32_t b = cuckoo_.item_bin[i];
        for (std::size_t s = 0; s < p_.f; ++s) v[b * p_.f + s] = items_[i].felts[s];
    }
    m["cli.cuckoo_ms"] = t.ms();

    t.reset();
    keygen_ = std::make_unique<seal::KeyGenerator>(ctx_);
    decryptor_ = std::make_unique<seal::Decryptor>(ctx_, keygen_->secret_key());
    QueryRequest q;
    q.public_key = seal_save(keygen_->create_public_key());
    q.relin_keys = seal_save(keygen_->create_relin_keys());
    m["cli.keygen_ms"] = t.ms();

    t.reset();
    seal::Encryptor enc(ctx_, keygen_->secret_key());
    std::vector<uint64_t> pv(N);
    seal::Plaintext pt;
    uint64_t scale = 1;
    for (std::size_t j = 0; j < D; ++j, scale *= base) {
        for (std::size_t i = 1; i < base; ++i) {
            const uint64_t e = i * scale;
            for (std::size_t s = 0; s < N; ++s) pv[s] = zt_.pow(v[s], e);
            encoder_->encode(pv, pt);
            q.powers.push_back(seal_save(enc.encrypt_symmetric(pt)));
        }
    }
    m["cli.encrypt_ms"] = t.ms();
    return q;
}

std::vector<MatchResult> Client::decode(const QueryResponse& resp, Metrics& m) {
    const std::size_t A = p_.alpha, f = p_.f;
    Timer t;
    const std::size_t expected = p_.labeled ? 2 * A : A;
    auto cts = unpack_ciphertexts(ctx_, resp.packed, expected);
    m["cli.unpack_ms"] = t.ms();
    t.reset();
    double min_budget = 1e9;
    std::vector<MatchResult> res(real_count_);
    std::vector<uint64_t> vals;
    seal::Plaintext pt;
    for (std::size_t pp = 0; pp < A; ++pp) {
        min_budget = std::min<double>(min_budget, decryptor_->invariant_noise_budget(cts[pp]));
        decryptor_->decrypt(cts[pp], pt);
        encoder_->decode(pt, vals);
        std::vector<uint64_t> lvals;
        bool have_l = false;
        for (std::size_t i = 0; i < real_count_; ++i) {
            if (res[i].found) continue;
            const uint32_t b = cuckoo_.item_bin[i];
            bool zero = true;
            for (std::size_t s = 0; s < f; ++s) zero &= (vals[b * f + s] == 0);
            if (!zero) continue;
            res[i].found = true;
            res[i].partition = int(pp);
            if (!p_.labeled) continue;
            if (!have_l) {
                min_budget = std::min<double>(min_budget, decryptor_->invariant_noise_budget(cts[A + pp]));
                decryptor_->decrypt(cts[A + pp], pt);
                encoder_->decode(pt, lvals);
                have_l = true;
            }
            std::array<uint32_t, 5> lf;
            bool in_range = true;
            for (std::size_t s = 0; s < f; ++s) {
                uint64_t x = lvals[b * f + s];
                in_range &= x < (1u << kFeltBits);
                lf[s] = uint32_t(x) ^ items_[i].pad[s];
            }
            res[i].label_ok = in_range && felts_to_label(lf, res[i].label);
        }
    }
    m["cli.decode_ms"] = t.ms();
    m["noise.client_min_budget"] = min_budget;
    return res;
}

void Client::erase_secrets() {
    decryptor_.reset();
    keygen_.reset();
    for (auto& b : blinds_) sodium_memzero(b.data(), b.size());
}

}  // namespace bcpsi
