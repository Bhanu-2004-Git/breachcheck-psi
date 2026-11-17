// Correctness and security-property tests. Usage: bcpsi_tests [--quick]
// Exit code 0 iff every check passes. Output is also parsed by scripts/.
#include <sodium.h>

#include <cmath>
#include <functional>
#include <iostream>
#include <random>
#include <sstream>

#include "baseline.h"
#include "client.h"
#include "server.h"
#include "util.h"

using namespace bcpsi;
using oprf::from_hex;
using oprf::to_hex;

static int g_checks = 0, g_failed = 0;
#define CHECK(cond)                                                                       \
    do {                                                                                  \
        ++g_checks;                                                                       \
        if (!(cond)) {                                                                    \
            ++g_failed;                                                                   \
            std::cout << "    FAILED: " #cond "  (" << __FILE__ << ":" << __LINE__ << ")\n"; \
        }                                                                                 \
    } while (0)

template <class E, class F> static bool throws(F&& f) {
    try { f(); } catch (const E&) { return true; } catch (...) { return false; }
    return false;
}

struct TestCase { std::string name; std::function<void()> fn; bool slow; };
static std::vector<TestCase>& registry() { static std::vector<TestCase> r; return r; }
#define TEST(name, slow)                                         \
    static void name();                                          \
    static bool reg_##name = (registry().push_back({#name, name, slow}), true); \
    static void name()

template <class A> static A arr(const std::string& hex) {
    A a{};
    auto b = from_hex(hex);
    std::copy(b.begin(), b.end(), a.begin());
    return a;
}

// ---------------------------------------------------------------------------
// 1. OPRF / VOPRF against RFC 9497 Appendix A (ristretto255-SHA512).
// ---------------------------------------------------------------------------
TEST(rfc9497_oprf_mode_vectors, false) {
    auto seed = from_hex("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");
    auto info = from_hex("74657374206b6579");
    auto kp = oprf::derive_key_pair(seed, info, oprf::kOPRF);
    CHECK(to_hex(kp.sk) == "5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e");
    struct V { const char *in, *blinded, *eval, *out; };
    V vs[] = {{"00", "609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c",
               "7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e",
               "527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6"},
              {"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a", "da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418",
               "b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25",
               "f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73"}};
    auto blind = arr<oprf::Scalar>("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706");
    for (const auto& v : vs) {
        auto in = from_hex(v.in);
        auto b = oprf::blind(in, blind, oprf::kOPRF);
        CHECK(to_hex(b) == v.blinded);
        auto e = oprf::blind_evaluate(kp.sk, b);
        CHECK(to_hex(e) == v.eval);
        CHECK(to_hex(oprf::finalize(in, blind, e)) == v.out);
        CHECK(to_hex(oprf::evaluate(kp.sk, in, oprf::kOPRF)) == v.out);
    }
}

TEST(rfc9497_voprf_mode_vectors_incl_batched_proof, false) {
    auto seed = from_hex("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");
    auto kp = oprf::derive_key_pair(seed, from_hex("74657374206b6579"), oprf::kVOPRF);
    CHECK(to_hex(kp.sk) == "e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909");
    CHECK(to_hex(kp.pk) == "c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e");
    auto b1 = arr<oprf::Scalar>("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706");
    auto b2 = arr<oprf::Scalar>("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e");
    // Test vector 1 (batch 1)
    {
        auto in = from_hex("00");
        auto B = oprf::blind(in, b1, oprf::kVOPRF);
        CHECK(to_hex(B) == "863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945");
        auto E = oprf::blind_evaluate(kp.sk, B);
        CHECK(to_hex(E) == "aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e");
        auto r = arr<oprf::Scalar>("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e");
        auto pr = oprf::generate_proof(kp.sk, kp.pk, {B}, {E}, &r);
        CHECK(to_hex(pr.c) + to_hex(pr.s) ==
              "ddef93772692e535d1a53903db24367355cc2cc78de93b3be5a8ffcc6985dd066d4346421d17bf5117a2a1ff0fcb2a759f58a539dfbe857a40bce4cf49ec600d");
        CHECK(oprf::verify_proof(kp.pk, {B}, {E}, pr));
        CHECK(to_hex(oprf::finalize(in, b1, E)) ==
              "b58cfbe118e0cb94d79b5fd6a6dafb98764dff49c14e1770b566e42402da1a7da4d8527693914139caee5bd03903af43a491351d23b430948dd50cde10d32b3c");
    }
    // Test vector 3 (batch 2)
    {
        auto in1 = from_hex("00"), in2 = from_hex("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");
        auto B1 = oprf::blind(in1, b1, oprf::kVOPRF), B2 = oprf::blind(in2, b2, oprf::kVOPRF);
        CHECK(to_hex(B2) == "90a0145ea9da29254c3a56be4fe185465ebb3bf2a1801f7124bbbadac751e654");
        auto E1 = oprf::blind_evaluate(kp.sk, B1), E2 = oprf::blind_evaluate(kp.sk, B2);
        CHECK(to_hex(E2) == "cc5ac221950a49ceaa73c8db41b82c20372a4c8d63e5dded2db920b7eee36a2a");
        auto r = arr<oprf::Scalar>("419c4f4f5052c53c45f3da494d2b67b220d02118e0857cdbcf037f9ea84bbe0c");
        auto pr = oprf::generate_proof(kp.sk, kp.pk, {B1, B2}, {E1, E2}, &r);
        CHECK(to_hex(pr.c) + to_hex(pr.s) ==
              "cc203910175d786927eeb44ea847328047892ddf8590e723c37205cb74600b0a5ab5337c8eb4ceae0494c2cf89529dcf94572ed267473d567aeed6ab873dee08");
        CHECK(oprf::verify_proof(kp.pk, {B1, B2}, {E1, E2}, pr));
        CHECK(to_hex(oprf::finalize(in2, b2, E2)) ==
              "8a9a2f3c7f085b65933594309041fc1898d42d0858e59f90814ae90571a6df60356f4610bf816f27afdd84f47719e480906d27ecd994985890e5f539e7ea74b6");
    }
}

// ---------------------------------------------------------------------------
// 2. DLEQ soundness checks (the client must reject a cheating server).
// ---------------------------------------------------------------------------
TEST(dleq_rejects_wrong_key_and_tampering, false) {
    auto kp = oprf::generate_key_pair(), other = oprf::generate_key_pair();
    std::vector<oprf::Element> C, D, Dbad;
    for (int i = 0; i < 64; ++i) {
        oprf::Bytes in{uint8_t(i), 1, 2, 3};
        C.push_back(oprf::blind(in, oprf::random_scalar(), oprf::kVOPRF));
        D.push_back(oprf::blind_evaluate(kp.sk, C.back()));
        // key-partitioning attack: one evaluation under a different key
        Dbad.push_back(i == 17 ? oprf::blind_evaluate(other.sk, C.back()) : D.back());
    }
    auto pr = oprf::generate_proof(kp.sk, kp.pk, C, D);
    CHECK(oprf::verify_proof(kp.pk, C, D, pr));
    CHECK(!oprf::verify_proof(other.pk, C, D, pr));                    // wrong committed key
    CHECK(!oprf::verify_proof(kp.pk, C, Dbad, oprf::generate_proof(kp.sk, kp.pk, C, Dbad)));
    auto pr2 = pr; pr2.s[3] ^= 1;
    CHECK(!oprf::verify_proof(kp.pk, C, D, pr2));                      // forged proof
    auto D2 = D; std::swap(D2[0], D2[1]);
    CHECK(!oprf::verify_proof(kp.pk, C, D2, pr));                      // reordered outputs
    oprf::Element bad{}; bad.fill(0xFF);
    CHECK(throws<std::runtime_error>([&] { oprf::blind_evaluate(kp.sk, bad); }));   // invalid point
}

TEST(oprf_blinded_equals_direct_evaluation, false) {
    auto kp = oprf::generate_key_pair();
    for (int i = 0; i < 20; ++i) {
        oprf::Bytes in(32);
        randombytes_buf(in.data(), in.size());
        auto r = oprf::random_scalar();
        auto out = oprf::finalize(in, r, oprf::blind_evaluate(kp.sk, oprf::blind(in, r, oprf::kVOPRF)));
        CHECK(out == oprf::evaluate(kp.sk, in, oprf::kVOPRF));
    }
}

// ---------------------------------------------------------------------------
// 3. Z_t polynomial arithmetic, label encoding, parameters, cuckoo hashing.
// ---------------------------------------------------------------------------
TEST(zt_roots_poly_and_interpolation, false) {
    Zt zt(1097729);
    std::mt19937_64 rng(1);
    for (uint64_t a = 1; a < 2000; ++a) CHECK(zt.mul(a, zt.inv(a)) == 1);
    for (int trial = 0; trial < 50; ++trial) {
        std::size_t k = 1 + rng() % 63;
        std::vector<uint64_t> xs, ys;
        while (xs.size() < k) {
            uint64_t x = rng() % zt.t();
            if (std::find(xs.begin(), xs.end(), x) == xs.end()) { xs.push_back(x); ys.push_back(rng() % zt.t()); }
        }
        auto P = zt.roots_poly(xs);
        CHECK(P.size() == k + 1 && P.back() == 1);
        auto L = zt.interpolate(xs, ys);
        bool roots_ok = true, interp_ok = true;
        for (std::size_t i = 0; i < k; ++i) {
            roots_ok &= zt.eval(P, xs[i]) == 0;
            interp_ok &= zt.eval(L, xs[i]) == ys[i];
        }
        CHECK(roots_ok);
        CHECK(interp_ok);
        uint64_t y;
        do { y = rng() % zt.t(); } while (std::find(xs.begin(), xs.end(), y) != xs.end());
        CHECK(zt.eval(P, y) != 0);   // P vanishes only on its roots (t prime)
    }
}

TEST(label_encoding_roundtrip_and_check_bits, false) {
    std::mt19937_64 rng(2);
    for (int i = 0; i < 1000; ++i) {
        uint64_t l = rng() & ((1ull << 48) - 1), out = 0;
        auto f = label_to_felts(l);
        CHECK(felts_to_label(f, out) && out == l);
        auto g = f;
        g[2 + rng() % 3] ^= 1u << (rng() % 20);
        if (g[2] >> 8 == f[2] >> 8 && g[3] == f[3] && g[4] == f[4]) continue;   // flipped a label bit only
        CHECK(!felts_to_label(g, out));
    }
}

TEST(parameter_derivation_matches_design, false) {
    CHECK(get_paramset("T").alpha == 2);
    CHECK(get_paramset("S").alpha == 4);
    CHECK(get_paramset("M").alpha == 37);
    CHECK(get_paramset("L").alpha == 20);
    // regression: mean bin load far above the first candidate capacities
    auto big = get_paramset("M", 1u << 22);
    CHECK(big.alpha >= 3 * big.n_server / (big.bins() * big.d));
    CHECK(log2_overflow_probability(big.n_server, big.bins(), big.capacity()) <= -40);
    CHECK(log2_overflow_probability(big.n_server, big.bins(), 63) > 0);
    for (const char* s : {"S", "M", "L"}) {
        auto p = get_paramset(s);
        CHECK(log2_overflow_probability(p.n_server, p.bins(), p.capacity()) <= -40);
        CHECK(log2_false_positive(p) <= -40);
        CHECK(p.window_digits() == 2 && p.query_ciphertexts() == 14);
        CHECK(p.t % (2 * p.N) == 1);
        CHECK(p.log2_q_total() <= (p.N == 8192 ? 218 : 438));
    }
}

TEST(cuckoo_hashing_never_fails_at_load_016, true) {
    std::mt19937_64 rng(3);
    std::array<uint8_t, 16> seed{};
    std::size_t failures = 0, max_ev = 0;
    const int trials = 2000;
    for (int t = 0; t < trials; ++t) {
        std::vector<DerivedItem> items(256);
        for (auto& it : items) {
            oprf::Output o;
            for (auto& b : o) b = uint8_t(rng());
            it = derive_item(o, seed, 1638);
        }
        CuckooTable tab;
        if (!cuckoo_insert(items, 1638, tab, rng)) ++failures;
        max_ev = std::max(max_ev, tab.evictions);
    }
    std::cout << "    cuckoo: " << trials << " trials, failures=" << failures << ", max evictions=" << max_ev << "\n";
    CHECK(failures == 0);
}

// ---------------------------------------------------------------------------
// 4. Manifest signature and pinning.
// ---------------------------------------------------------------------------
TEST(manifest_signature_and_pinning, false) {
    oprf::init();
    auto p = get_paramset("T");
    auto key = SigningKey::generate(), other = SigningKey::generate();
    Manifest m = Manifest::from_params(p), out;
    auto sm = sign_manifest(m, key);
    CHECK(verify_manifest(sm, key.pk, out) && out.matches_pinned(p));
    CHECK(!verify_manifest(sm, other.pk, out));
    auto bad = sm; bad.body[40] ^= 1;
    CHECK(!verify_manifest(bad, key.pk, out));
    Manifest wrong = m; wrong.t = 65537;
    std::string why;
    CHECK(!wrong.matches_pinned(p, &why) && why == "plaintext modulus");
    Client c(p, key.pk);
    CHECK(!c.accept_manifest(sign_manifest(wrong, key), &why));
    CHECK(c.accept_manifest(sm, &why));
}

// ---------------------------------------------------------------------------
// 5. End-to-end protocol runs.
// ---------------------------------------------------------------------------
struct Outcome { std::size_t tp = 0, fn = 0, fp = 0, label_err = 0; Metrics m; std::size_t up = 0, down = 0; };

static Outcome run_query(const Server& srv, const std::vector<Record>& recs, const ClientSet& cs, NoiseProbe* probe = nullptr) {
    Outcome o;
    Client cl(srv.params(), srv.signer_public_key());
    if (!cl.accept_manifest(srv.signed_manifest())) throw std::runtime_error("manifest");
    auto req = cl.start(cs.items, o.m);
    auto oresp = srv.oprf(req, o.m);
    if (!cl.finish_oprf(oresp, o.m)) throw std::runtime_error("proof");
    auto q = cl.build_query(o.m);
    if (probe) probe->decryptor = cl.decryptor();
    auto resp = srv.answer(q, o.m, probe);
    auto res = cl.decode(resp, o.m);
    o.up = size_bytes(req) + size_bytes(q);
    o.down = size_bytes(oresp) + size_bytes(resp);
    for (std::size_t i = 0; i < res.size(); ++i) {
        bool member = cs.expected_index[i] >= 0;
        if (member && res[i].found) {
            ++o.tp;
            if (srv.params().labeled && (!res[i].label_ok || res[i].label != recs[cs.expected_index[i]].label)) ++o.label_err;
        }
        if (member && !res[i].found) ++o.fn;
        if (!member && res[i].found) ++o.fp;
    }
    return o;
}

TEST(e2e_tiny_set_scenarios, false) {
    auto p = get_paramset("T");
    auto recs = make_server_records(p.n_server, 11);
    Server srv(p, 2);
    srv.preprocess(recs);
    struct Sc { const char* name; std::size_t m, k; } scs[] = {
        {"k=8 of 20", 20, 8}, {"all 256 members", 256, 256}, {"no members", 256, 0}, {"single member", 1, 1},
        {"single non-member", 1, 0}, {"k=32 of 256", 256, 32}};
    uint64_t seed = 100;
    for (const auto& sc : scs) {
        auto cs = make_client_set(recs, sc.m, sc.k, seed++);
        auto o = run_query(srv, recs, cs);
        std::cout << "    " << sc.name << ": tp=" << o.tp << " fn=" << o.fn << " fp=" << o.fp << " label_err=" << o.label_err << "\n";
        CHECK(o.tp == sc.k && o.fn == 0 && o.fp == 0 && o.label_err == 0);
    }
}

TEST(e2e_multi_partition_set_S, true) {
    auto p = get_paramset("S");   // n = 2^16, alpha = 4
    auto recs = make_server_records(p.n_server, 12);
    Server srv(p, 2);
    srv.preprocess(recs);
    for (int rep = 0; rep < 3; ++rep) {
        auto cs = make_client_set(recs, 256, 64, 200 + rep);
        auto o = run_query(srv, recs, cs);
        std::cout << "    S rep " << rep << ": tp=" << o.tp << " fn=" << o.fn << " fp=" << o.fp << " label_err=" << o.label_err << "\n";
        CHECK(o.tp == 64 && o.fn == 0 && o.fp == 0 && o.label_err == 0);
    }
}

TEST(e2e_unlabeled_mode, false) {
    auto p = get_paramset("T");
    p.labeled = false;
    auto recs = make_server_records(p.n_server, 13);
    Server srv(p, 2);
    srv.preprocess(recs);
    auto cs = make_client_set(recs, 256, 40, 300);
    auto o = run_query(srv, recs, cs);
    CHECK(o.tp == 40 && o.fn == 0 && o.fp == 0);
}

TEST(no_false_positives_over_10k_nonmembers, true) {
    auto p = get_paramset("T");
    auto recs = make_server_records(p.n_server, 14);
    Server srv(p, 2);
    srv.preprocess(recs);
    std::size_t fp = 0, total = 0;
    for (int rep = 0; rep < 40; ++rep) {
        auto cs = make_client_set(recs, 256, 0, 1000 + rep);
        fp += run_query(srv, recs, cs).fp;
        total += 256;
    }
    std::cout << "    non-members tested=" << total << " false positives=" << fp << "\n";
    CHECK(fp == 0);
}

TEST(tampered_labels_are_detected, false) {
    auto p = get_paramset("T");
    auto recs = make_server_records(p.n_server, 15);
    Server srv(p, 2);
    srv.preprocess(recs);
    srv.set_tamper_labels(true);
    auto cs = make_client_set(recs, 64, 16, 400);
    Client cl(p, srv.signer_public_key());
    CHECK(cl.accept_manifest(srv.signed_manifest()));
    Metrics m;
    auto req = cl.start(cs.items, m);
    CHECK(cl.finish_oprf(srv.oprf(req, m), m));
    auto res = cl.decode(srv.answer(cl.build_query(m), m), m);
    std::size_t found = 0, rejected = 0;
    for (const auto& r : res) { found += r.found; rejected += r.found && !r.label_ok; }
    std::cout << "    found=" << found << " labels rejected=" << rejected << "\n";
    CHECK(found == 16 && rejected == 16);
}

TEST(malformed_queries_are_rejected, false) {
    auto p = get_paramset("T");
    auto recs = make_server_records(p.n_server, 16);
    Server srv(p, 2);
    srv.preprocess(recs);
    Client cl(p, srv.signer_public_key());
    CHECK(cl.accept_manifest(srv.signed_manifest()));
    Metrics m;
    auto cs = make_client_set(recs, 10, 2, 500);
    auto req = cl.start(cs.items, m);
    CHECK(cl.finish_oprf(srv.oprf(req, m), m));
    auto q = cl.build_query(m);
    CHECK(srv.answer(q, m).num_ciphertexts == 2 * p.alpha);   // well-formed query is accepted

    auto q1 = q; q1.powers.pop_back();
    CHECK(throws<std::exception>([&] { srv.answer(q1, m); }));                    // wrong count
    auto q2 = q; q2.powers[3].resize(q2.powers[3].size() / 2);
    CHECK(throws<std::exception>([&] { srv.answer(q2, m); }));                    // truncated
    auto q3 = q; for (int i = 0; i < 16; ++i) q3.powers[5][q3.powers[5].size() / 2 + i] = char(0xFF);
    CHECK(throws<std::exception>([&] { srv.answer(q3, m); }));                    // coefficient >= q
    auto q4 = q; q4.relin_keys = q.public_key;
    CHECK(throws<std::exception>([&] { srv.answer(q4, m); }));                    // wrong object type
    // ciphertext produced under a different parameter set (N=16384)
    auto pl = get_paramset("L");
    auto ctxL = make_context(pl);
    seal::KeyGenerator kg(ctxL);
    seal::Encryptor encL(ctxL, kg.secret_key());
    seal::Plaintext zero("0");
    auto q5 = q; q5.powers[0] = seal_save(encL.encrypt_symmetric(zero));
    CHECK(throws<std::exception>([&] { srv.answer(q5, m); }));
    // OPRF request of the wrong size
    OprfRequest small{std::vector<oprf::Element>(req.blinded.begin(), req.blinded.begin() + 10)};
    CHECK(throws<std::exception>([&] { srv.oprf(small, m); }));
    // Response tampering on the client side: wrong length / out-of-range coefficient
    auto resp = srv.answer(q, m);
    auto r1 = resp; r1.packed.pop_back();
    CHECK(throws<std::exception>([&] { cl.decode(r1, m); }));
    auto r2 = resp; for (int i = 0; i < 7; ++i) r2.packed[i] = char(0xFF);
    CHECK(throws<std::exception>([&] { cl.decode(r2, m); }));
}

TEST(fixed_shape_messages_and_work, false) {
    // Leakage check: sizes and operation counts must not depend on how many
    // credentials the client has or how many of them are breached.
    auto p = get_paramset("T");
    auto recs = make_server_records(p.n_server, 17);
    Server srv(p, 2);
    srv.preprocess(recs);
    std::vector<Outcome> os;
    for (auto [mreal, k] : std::vector<std::pair<std::size_t, std::size_t>>{{1, 0}, {1, 1}, {100, 50}, {256, 0}, {256, 256}})
        os.push_back(run_query(srv, recs, make_client_set(recs, mreal, k, 600 + mreal + k)));
    for (const auto& o : os) {
        CHECK(o.up == os[0].up);
        CHECK(o.down == os[0].down);
        CHECK(o.m.at("ops.ct_ct_mult") == os[0].m.at("ops.ct_ct_mult"));
        CHECK(o.m.at("ops.plain_mult") == os[0].m.at("ops.plain_mult"));
    }
    std::cout << "    up=" << os[0].up << " B, down=" << os[0].down << " B, ct*ct=" << os[0].m.at("ops.ct_ct_mult")
              << ", pt*ct=" << os[0].m.at("ops.plain_mult") << " for every client set\n";
}

TEST(noise_budget_positive_after_flooding, false) {
    auto p = get_paramset("T");
    auto recs = make_server_records(p.n_server, 18);
    Server srv(p, 1);
    srv.preprocess(recs);
    NoiseProbe probe;
    auto o = run_query(srv, recs, make_client_set(recs, 256, 30, 700), &probe);
    for (const auto& [k, v] : probe.budgets) std::cout << "    " << k << " = " << v << " bits\n";
    std::cout << "    client-side min budget = " << o.m.at("noise.client_min_budget") << " bits\n";
    CHECK(probe.budgets.at("noise.final") >= 5);
    CHECK(o.tp == 30 && o.fp == 0 && o.label_err == 0);
}

TEST(nonmatching_slots_are_masked_uniformly, false) {
    // r_p masking: decrypted non-matching slots of R_p should be uniform over
    // Z_t \ {0}. Chi-square over 64 equal buckets of the top bits.
    auto p = get_paramset("T");
    auto recs = make_server_records(p.n_server, 19);
    Server srv(p, 1);
    srv.preprocess(recs);
    Client cl(p, srv.signer_public_key());
    CHECK(cl.accept_manifest(srv.signed_manifest()));
    Metrics m;
    auto req = cl.start(make_client_set(recs, 256, 0, 800).items, m);
    CHECK(cl.finish_oprf(srv.oprf(req, m), m));
    auto resp = srv.answer(cl.build_query(m), m);
    auto cts = unpack_ciphertexts(cl.context(), resp.packed, resp.num_ciphertexts);
    seal::BatchEncoder enc(cl.context());
    seal::Plaintext pt;
    std::vector<uint64_t> vals;
    cl.decryptor()->decrypt(cts[0], pt);
    enc.decode(pt, vals);
    std::vector<double> bucket(64, 0);
    std::size_t zeros = 0, used = p.bins() * p.f;
    for (std::size_t j = 0; j < used; ++j) {
        if (vals[j] == 0) ++zeros;
        bucket[std::min<std::size_t>(63, vals[j] * 64 / p.t)] += 1;
    }
    double expect = double(used) / 64, chi2 = 0;
    for (double b : bucket) chi2 += (b - expect) * (b - expect) / expect;
    std::cout << "    zero slots=" << zeros << "/" << used << ", chi2(63 dof)=" << chi2 << "\n";
    CHECK(chi2 < 110);      // p ~ 1e-4 critical value for 63 dof
    CHECK(zeros < 10);      // expected ~ used * d / t ~ 0.5
}

TEST(baselines_agree_with_psi, false) {
    auto p = get_paramset("T");
    auto recs = make_server_records(p.n_server, 20);
    auto cs = make_client_set(recs, 256, 64, 900);
    PlaintextBaseline pb;
    pb.build(recs);
    KAnonBaseline kb(4);
    kb.build(recs);
    Metrics m;
    auto r1 = pb.query(cs.items, m), r2 = kb.query(cs.items, m);
    for (std::size_t i = 0; i < cs.items.size(); ++i) {
        bool member = cs.expected_index[i] >= 0;
        CHECK(r1.found[i] == member && r2.found[i] == member);
        if (member) CHECK(r1.labels[i] == recs[cs.expected_index[i]].label && r2.labels[i] == r1.labels[i]);
    }
}

int main(int argc, char** argv) {
    bool quick = argc > 1 && std::string(argv[1]) == "--quick";
    oprf::init();
    Timer total;
    int failed_tests = 0, run = 0;
    for (const auto& t : registry()) {
        if (quick && t.slow) { std::cout << "[ SKIP ] " << t.name << "\n"; continue; }
        int before = g_failed;
        Timer tt;
        std::cout << "[ RUN  ] " << t.name << "\n" << std::flush;
        try { t.fn(); } catch (const std::exception& e) { ++g_failed; std::cout << "    EXCEPTION: " << e.what() << "\n"; }
        bool ok = g_failed == before;
        failed_tests += !ok;
        ++run;
        std::cout << (ok ? "[  OK  ] " : "[ FAIL ] ") << t.name << " (" << int(tt.ms()) << " ms)\n";
    }
    std::cout << "\n" << run << " tests, " << g_checks << " checks, " << g_failed << " failed checks, " << failed_tests
              << " failed tests (" << total.ms() / 1000 << " s)\n";
    return g_failed ? 1 : 0;
}
