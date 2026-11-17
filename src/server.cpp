#include "server.h"

#include <sodium.h>

#include <atomic>
#include <cstring>
#include <ctime>
#include <random>
#include <sstream>
#include <stdexcept>

#include "util.h"

namespace bcpsi {

Server::Server(const ParamSet& p, unsigned threads, uint64_t db_version)
    : p_(p), threads_(threads), db_version_(db_version), ctx_(make_context(p)), zt_(p.t) {
    oprf::init();
    encoder_ = std::make_unique<seal::BatchEncoder>(ctx_);
    evaluator_ = std::make_unique<seal::Evaluator>(ctx_);
    oprf_key_ = oprf::generate_key_pair();
    signer_ = SigningKey::generate();
    randombytes_buf(table_seed_.data(), table_seed_.size());
}

static uint64_t rand_u64() {
    uint64_t v;
    randombytes_buf(&v, sizeof v);
    return v;
}

Metrics Server::preprocess(const std::vector<Record>& records) {
    Metrics m;
    const std::size_t n = records.size(), N = p_.N, B = p_.bins(), d = p_.d, A = p_.alpha, f = p_.f;
    if (n > p_.n_server) throw std::invalid_argument("preprocess: more records than n_max");
    if (f != 5) throw std::invalid_argument("preprocess: f must be 5");

    // 1. OPRF-evaluate every record with k (Fig. 1, blue box) and derive items.
    Timer t;
    std::vector<DerivedItem> items(n);
    parallel_for(n, threads_, [&](std::size_t i, unsigned) {
        auto o = oprf::evaluate(oprf_key_.sk, records[i].x, oprf::kVOPRF);
        items[i] = derive_item(o, table_seed_, B);
    });
    m["pre.oprf_ms"] = t.ms();

    // 2. Simple hashing into all candidate bins + collision-aware partitioning.
    t.reset();
    std::vector<uint8_t> count(B * A, 0);
    std::vector<uint32_t> felt(B * A * d * f), lab(B * A * d * f);
    std::vector<uint32_t> first_open(B, 0);
    std::size_t collisions_skipped = 0, insertions = 0;
    auto idx = [&](std::size_t b, std::size_t pp, std::size_t k, std::size_t s) {
        return (((b * A + pp) * d + k) * f) + s;
    };
    for (std::size_t i = 0; i < n; ++i) {
        const auto& it = items[i];
        std::array<uint32_t, 5> lf = label_to_felts(records[i].label);
        for (std::size_t s = 0; s < 5; ++s) lf[s] ^= it.pad[s];
        for (std::size_t h = 0; h < kNumHashes; ++h) {
            uint32_t b = it.bins[h];
            bool dup = false;
            for (std::size_t g = 0; g < h; ++g) dup |= (it.bins[g] == b);
            if (dup) continue;
            bool placed = false;
            for (std::size_t pp = first_open[b]; pp < A && !placed; ++pp) {
                uint8_t& c = count[b * A + pp];
                if (c >= d) continue;
                bool collide = false;
                for (std::size_t k = 0; k < c && !collide; ++k)
                    for (std::size_t s = 0; s < 5; ++s)
                        if (felt[idx(b, pp, k, s)] == it.felts[s]) { collide = true; break; }
                if (collide) { ++collisions_skipped; continue; }
                for (std::size_t s = 0; s < 5; ++s) {
                    felt[idx(b, pp, c, s)] = it.felts[s];
                    lab[idx(b, pp, c, s)] = lf[s];
                }
                ++c;
                placed = true;
                ++insertions;
            }
            if (!placed) throw std::runtime_error("preprocess: bin overflow (increase alpha)");
            while (first_open[b] < A && count[b * A + first_open[b]] >= d) ++first_open[b];
        }
    }
    std::size_t max_load = 0;
    for (std::size_t b = 0; b < B; ++b) {
        std::size_t load = 0;
        for (std::size_t pp = 0; pp < A; ++pp) load += count[b * A + pp];
        max_load = std::max(max_load, load);
    }
    m["pre.binning_ms"] = t.ms();
    m["pre.insertions"] = double(insertions);
    m["pre.max_bin_load"] = double(max_load);
    m["pre.capacity"] = double(A * d);
    m["pre.collisions_skipped"] = double(collisions_skipped);

    // 3. Per (partition, bin, slot): roots polynomial P and interpolation L.
    t.reset();
    p_coeffs_.assign(A * (d + 1) * N, 0);
    std::vector<uint32_t> l_coeffs(p_.labeled ? A * d * N : 0, 0);
    parallel_for(A, threads_, [&](std::size_t pp, unsigned) {
        std::mt19937_64 rng(rand_u64());
        std::vector<uint64_t> roots(d), xs, ys;
        for (std::size_t b = 0; b < B; ++b) {
            std::size_t c = count[b * A + pp];
            for (std::size_t s = 0; s < 5; ++s) {
                std::size_t slot = b * f + s;
                xs.clear(); ys.clear();
                for (std::size_t k = 0; k < c; ++k) {
                    roots[k] = felt[idx(b, pp, k, s)];
                    xs.push_back(felt[idx(b, pp, k, s)]);
                    ys.push_back(lab[idx(b, pp, k, s)]);
                }
                for (std::size_t k = c; k < d; ++k) roots[k] = rng() % p_.t;   // dummy roots
                auto P = zt_.roots_poly(roots);
                for (std::size_t e = 0; e <= d; ++e) p_coeffs_[(pp * (d + 1) + e) * N + slot] = uint32_t(P[e]);
                if (p_.labeled && c > 0) {
                    auto L = zt_.interpolate(xs, ys);
                    for (std::size_t e = 0; e < L.size(); ++e) l_coeffs[(pp * d + e) * N + slot] = uint32_t(L[e]);
                }
            }
        }
    });
    m["pre.poly_ms"] = t.ms();
    felt.clear(); felt.shrink_to_fit();
    lab.clear(); lab.shrink_to_fit();

    // 4. Encode label coefficients as (NTT) plaintexts.
    t.reset();
    if (p_.labeled) {
        l_plain_.assign(A * d, seal::Plaintext());
        l_zero_.assign(A * d, 0);
        auto first = ctx_.first_parms_id();
        parallel_for(A * d, threads_, [&](std::size_t i, unsigned) {
            std::vector<uint64_t> v(N);
            bool zero = true;
            for (std::size_t j = 0; j < N; ++j) { v[j] = l_coeffs[i * N + j]; zero &= (v[j] == 0); }
            l_zero_[i] = zero;
            if (zero) return;
            encoder_->encode(v, l_plain_[i]);
            if (i % d != 0) evaluator_->transform_to_ntt_inplace(l_plain_[i], first);
        });
    }
    m["pre.encode_ms"] = t.ms();

    // 5. Signed manifest.
    Manifest man = Manifest::from_params(p_);
    man.db_version = db_version_;
    man.timestamp = uint64_t(std::time(nullptr));
    man.table_seed = table_seed_;
    man.oprf_pk = oprf_key_.pk;
    manifest_ = sign_manifest(man, signer_);
    return m;
}

Metrics Server::memory_usage() const {
    Metrics m;
    m["mem.p_coeffs_MB"] = double(p_coeffs_.size() * sizeof(uint32_t)) / 1e6;
    double l = 0;
    for (const auto& pt : l_plain_) l += double(pt.dyn_array().size() * sizeof(uint64_t));
    m["mem.l_plain_MB"] = l / 1e6;
    return m;
}

OprfResponse Server::oprf(const OprfRequest& req, Metrics& m) const {
    Timer t;
    OprfResponse r;
    if (req.blinded.size() != p_.m_client) throw std::runtime_error("oprf: wrong batch size");
    r.evaluated.resize(req.blinded.size());
    for (std::size_t i = 0; i < req.blinded.size(); ++i) r.evaluated[i] = oprf::blind_evaluate(oprf_key_.sk, req.blinded[i]);
    m["srv.oprf_eval_ms"] = t.ms();
    t.reset();
    r.proof = oprf::generate_proof(oprf_key_.sk, oprf_key_.pk, req.blinded, r.evaluated);
    m["srv.oprf_proof_ms"] = t.ms();
    return r;
}

// Rerandomize with a fresh public-key encryption of zero and add uniform
// flooding noise in [-2^b, 2^b) to c0 (Part 2, step 5).
void Server::flood(seal::Ciphertext& ct, const seal::Encryptor& enc) const {
    seal::Ciphertext z;
    enc.encrypt_zero(ct.parms_id(), z);
    evaluator_->add_inplace(ct, z);
    const int b = p_.flood_bits;
    if (b <= 0) return;
    auto cd = ctx_.get_context_data(ct.parms_id());
    const auto& mods = cd->parms().coeff_modulus();
    const std::size_t N = p_.N, L = std::size_t(b) / 64 + 1, top_bits = std::size_t(b) % 64;
    std::vector<uint64_t> rnd(N * (L + 1));
    randombytes_buf(rnd.data(), rnd.size() * sizeof(uint64_t));
    uint64_t* c0 = ct.data(0);
    for (std::size_t i = 0; i < N; ++i) {
        uint64_t* limbs = &rnd[i * (L + 1)];
        limbs[L - 1] &= top_bits ? ((1ull << top_bits) - 1) : 0;   // value < 2^b
        bool negative = limbs[L] & 1;
        for (std::size_t j = 0; j < mods.size(); ++j) {
            const uint64_t q = mods[j].value();
            unsigned __int128 r = 0;
            for (std::size_t l = L; l-- > 0;) r = ((r << 64) | limbs[l]) % q;
            uint64_t e = uint64_t(r);
            if (negative && e) e = q - e;
            uint64_t& c = c0[j * N + i];
            c += e;
            if (c >= q) c -= q;
        }
    }
}

QueryResponse Server::answer(const QueryRequest& q, Metrics& m, NoiseProbe* probe) const {
    const std::size_t N = p_.N, d = p_.d, A = p_.alpha, base = p_.window_base, D = p_.window_digits();
    auto first = ctx_.first_parms_id();
    auto record_budget = [&](const std::string& name, const seal::Ciphertext& ct) {
        if (!probe || !probe->decryptor) return;
        double b = probe->decryptor->invariant_noise_budget(ct);
        auto it = probe->budgets.find(name);
        if (it == probe->budgets.end() || b < it->second) probe->budgets[name] = b;
    };

    // Load and validate (SEAL's load() runs is_valid_for(); we also check level/size).
    Timer t;
    seal::PublicKey pk;
    seal::RelinKeys rlk;
    {
        std::stringstream s1(q.public_key), s2(q.relin_keys);
        pk.load(ctx_, s1);
        rlk.load(ctx_, s2);
    }
    if (q.powers.size() != p_.query_ciphertexts()) throw std::runtime_error("answer: wrong number of ciphertexts");
    std::vector<seal::Ciphertext> base_ct(q.powers.size());
    for (std::size_t i = 0; i < q.powers.size(); ++i) {
        std::stringstream ss(q.powers[i]);
        base_ct[i].load(ctx_, ss);
        if (base_ct[i].parms_id() != first || base_ct[i].size() != 2 || base_ct[i].is_ntt_form())
            throw std::runtime_error("answer: ciphertext not fresh at first level");
    }
    m["srv.load_ms"] = t.ms();
    for (const auto& c : base_ct) record_budget("noise.fresh", c);

    // Powers v^1..v^d from the windowed upload: v^{e} = prod_j v^{digit_j * base^j}.
    t.reset();
    std::vector<seal::Ciphertext> pw(d + 1);
    std::size_t ctct = 0;
    std::vector<std::size_t> jobs;
    for (std::size_t e = 1; e <= d; ++e) jobs.push_back(e);
    std::atomic<std::size_t> ctct_a{0};
    parallel_for(jobs.size(), threads_, [&](std::size_t ji, unsigned) {
        std::size_t e = jobs[ji], rest = e;
        std::vector<const seal::Ciphertext*> factors;
        for (std::size_t j = 0; j < D; ++j, rest /= base) {
            std::size_t digit = rest % base;
            if (digit) factors.push_back(&base_ct[j * (base - 1) + digit - 1]);
        }
        pw[e] = *factors[0];
        for (std::size_t k = 1; k < factors.size(); ++k) {
            evaluator_->multiply_inplace(pw[e], *factors[k]);
            evaluator_->relinearize_inplace(pw[e], rlk);
            ctct_a.fetch_add(1);
        }
    });
    ctct = ctct_a.load();
    m["srv.powers_ms"] = t.ms();
    m["ops.ct_ct_mult"] = double(ctct);
    for (std::size_t e = 1; e <= d; ++e) record_budget("noise.powers", pw[e]);
    t.reset();
    for (std::size_t e = 1; e <= d; ++e) evaluator_->transform_to_ntt_inplace(pw[e]);
    m["srv.powers_ntt_ms"] = t.ms();

    // Per-partition evaluation of r_p * P_p(v) and L_p(v).
    t.reset();
    const std::size_t outs = p_.labeled ? 2 * A : A;
    std::vector<seal::Ciphertext> out(outs);
    std::atomic<uint64_t> encode_ns{0}, mul_ns{0}, plain_mults{0};
    seal::Encryptor zero_enc(ctx_, pk);
    parallel_for(A, threads_, [&](std::size_t pp, unsigned) {
        std::vector<uint64_t> r(N), tmp(N);
        {
            std::vector<uint64_t> raw(N);
            randombytes_buf(raw.data(), N * sizeof(uint64_t));
            for (std::size_t j = 0; j < N; ++j) r[j] = 1 + raw[j] % (p_.t - 1);   // nonzero mask
        }
        seal::Plaintext pt;
        seal::Ciphertext acc, prod;
        bool have = false;
        for (std::size_t e = 1; e <= d; ++e) {
            Timer te;
            const uint32_t* c = &p_coeffs_[(pp * (d + 1) + e) * N];
            for (std::size_t j = 0; j < N; ++j) tmp[j] = zt_.mul(r[j], c[j]);
            pt = seal::Plaintext();
            encoder_->encode(tmp, pt);
            evaluator_->transform_to_ntt_inplace(pt, first);
            encode_ns += uint64_t(te.ms() * 1e6);
            te.reset();
            if (pt.is_zero()) continue;
            if (!have) { evaluator_->multiply_plain(pw[e], pt, acc); have = true; }
            else { evaluator_->multiply_plain(pw[e], pt, prod); evaluator_->add_inplace(acc, prod); }
            plain_mults++;
            mul_ns += uint64_t(te.ms() * 1e6);
        }
        if (have) evaluator_->transform_from_ntt_inplace(acc);
        else zero_enc.encrypt_zero(acc);
        {
            const uint32_t* c = &p_coeffs_[(pp * (d + 1)) * N];
            for (std::size_t j = 0; j < N; ++j) tmp[j] = zt_.mul(r[j], c[j]);
            pt = seal::Plaintext();
            encoder_->encode(tmp, pt);
            if (!pt.is_zero()) evaluator_->add_plain_inplace(acc, pt);
        }
        out[pp] = acc;
        if (!p_.labeled) return;
        have = false;
        Timer te;
        for (std::size_t e = 1; e < d; ++e) {
            if (l_zero_[pp * d + e]) continue;
            if (!have) { evaluator_->multiply_plain(pw[e], l_plain_[pp * d + e], acc); have = true; }
            else { evaluator_->multiply_plain(pw[e], l_plain_[pp * d + e], prod); evaluator_->add_inplace(acc, prod); }
            plain_mults++;
        }
        if (have) evaluator_->transform_from_ntt_inplace(acc);
        else zero_enc.encrypt_zero(acc);
        if (!l_zero_[pp * d]) evaluator_->add_plain_inplace(acc, l_plain_[pp * d]);
        if (tamper_labels_) {
            std::vector<uint64_t> ones(N, 1);
            pt = seal::Plaintext();
            encoder_->encode(ones, pt);
            evaluator_->add_plain_inplace(acc, pt);
        }
        mul_ns += uint64_t(te.ms() * 1e6);
        out[A + pp] = acc;
    });
    m["srv.partitions_ms"] = t.ms();
    m["srv.part_encode_cpu_ms"] = double(encode_ns.load()) / 1e6;
    m["srv.part_mult_cpu_ms"] = double(mul_ns.load()) / 1e6;
    m["ops.plain_mult"] = double(plain_mults.load());
    for (std::size_t i = 0; i < outs; ++i) record_budget("noise.evaluated", out[i]);

    // Rerandomize + flood, then switch to the last level and pack.
    t.reset();
    auto last = ctx_.last_parms_id();
    parallel_for(outs, threads_, [&](std::size_t i, unsigned) {
        flood(out[i], zero_enc);
    });
    for (std::size_t i = 0; i < outs; ++i) record_budget("noise.flooded", out[i]);
    parallel_for(outs, threads_, [&](std::size_t i, unsigned) { evaluator_->mod_switch_to_inplace(out[i], last); });
    m["srv.flood_modswitch_ms"] = t.ms();
    for (std::size_t i = 0; i < outs; ++i) record_budget("noise.final", out[i]);
    t.reset();
    QueryResponse resp;
    resp.packed = pack_ciphertexts(ctx_, out);
    resp.num_ciphertexts = outs;
    m["srv.pack_ms"] = t.ms();
    m["srv.total_answer_ms"] = m["srv.load_ms"] + m["srv.powers_ms"] + m["srv.powers_ntt_ms"] +
                               m["srv.partitions_ms"] + m["srv.flood_modswitch_ms"] + m["srv.pack_ms"];
    return resp;
}

}  // namespace bcpsi
