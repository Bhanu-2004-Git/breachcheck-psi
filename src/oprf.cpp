#include "oprf.h"

#include <sodium.h>

#include <cstring>
#include <stdexcept>

namespace bcpsi::oprf {

static const char* kIdentifier = "ristretto255-SHA512";

void init() {
    static bool done = false;
    if (!done) {
        if (sodium_init() < 0) throw std::runtime_error("sodium_init failed");
        done = true;
    }
}

static void append(Bytes& out, const void* p, std::size_t n) {
    const uint8_t* b = static_cast<const uint8_t*>(p);
    out.insert(out.end(), b, b + n);
}
static void append(Bytes& out, const std::string& s) { append(out, s.data(), s.size()); }
static void append_i2osp2(Bytes& out, std::size_t v) {
    out.push_back(uint8_t(v >> 8));
    out.push_back(uint8_t(v));
}
static void append_lp(Bytes& out, const uint8_t* p, std::size_t n) {   // I2OSP(len,2) || data
    append_i2osp2(out, n);
    append(out, p, n);
}

Bytes context_string(Mode mode) {
    Bytes c;
    append(c, std::string("OPRFV1-"));
    c.push_back(uint8_t(mode));
    append(c, std::string("-"));
    append(c, std::string(kIdentifier));
    return c;
}

static std::array<uint8_t, 64> sha512(const Bytes& in) {
    std::array<uint8_t, 64> h;
    crypto_hash_sha512(h.data(), in.data(), in.size());
    return h;
}

// RFC 9380 Section 5.3.1 with H = SHA-512 (b_in_bytes = 64, s_in_bytes = 128).
Bytes expand_message_xmd_sha512(const Bytes& msg, const Bytes& dst, std::size_t len) {
    const std::size_t b = 64, s = 128;
    const std::size_t ell = (len + b - 1) / b;
    if (ell > 255 || len > 65535 || dst.size() > 255) throw std::invalid_argument("expand_message_xmd");
    Bytes dst_prime(dst);
    dst_prime.push_back(uint8_t(dst.size()));
    Bytes msg_prime(s, 0);
    append(msg_prime, msg.data(), msg.size());
    append_i2osp2(msg_prime, len);
    msg_prime.push_back(0);
    append(msg_prime, dst_prime.data(), dst_prime.size());
    auto b0 = sha512(msg_prime);
    Bytes in1(b0.begin(), b0.end());
    in1.push_back(1);
    append(in1, dst_prime.data(), dst_prime.size());
    auto bi = sha512(in1);
    Bytes out(bi.begin(), bi.end());
    for (std::size_t i = 2; i <= ell; ++i) {
        Bytes in;
        for (std::size_t j = 0; j < b; ++j) in.push_back(b0[j] ^ bi[j]);
        in.push_back(uint8_t(i));
        append(in, dst_prime.data(), dst_prime.size());
        bi = sha512(in);
        out.insert(out.end(), bi.begin(), bi.end());
    }
    out.resize(len);
    return out;
}

Element hash_to_group(const Bytes& input, Mode mode) {
    Bytes dst;
    append(dst, std::string("HashToGroup-"));
    auto ctx = context_string(mode);
    append(dst, ctx.data(), ctx.size());
    Bytes u = expand_message_xmd_sha512(input, dst, 64);
    Element e;
    crypto_core_ristretto255_from_hash(e.data(), u.data());
    return e;
}

Scalar hash_to_scalar(const Bytes& input, const Bytes& dst) {
    Bytes u = expand_message_xmd_sha512(input, dst, 64);
    Scalar s;
    crypto_core_ristretto255_scalar_reduce(s.data(), u.data());
    return s;
}

static Bytes dst_with_context(const std::string& prefix, Mode mode) {
    Bytes dst;
    append(dst, prefix);
    auto ctx = context_string(mode);
    append(dst, ctx.data(), ctx.size());
    return dst;
}

Scalar random_scalar() {
    Scalar s;
    do {
        crypto_core_ristretto255_scalar_random(s.data());
    } while (sodium_is_zero(s.data(), s.size()));
    return s;
}

static bool is_zero(const Scalar& s) { return sodium_is_zero(s.data(), s.size()) == 1; }

KeyPair derive_key_pair(const Bytes& seed, const Bytes& info, Mode mode) {
    Bytes derive_input(seed);
    append_lp(derive_input, info.data(), info.size());
    Bytes dst = dst_with_context("DeriveKeyPair", mode);
    for (int counter = 0; counter < 256; ++counter) {
        Bytes in(derive_input);
        in.push_back(uint8_t(counter));
        Scalar sk = hash_to_scalar(in, dst);
        if (!is_zero(sk)) {
            KeyPair kp{sk, {}};
            crypto_scalarmult_ristretto255_base(kp.pk.data(), sk.data());
            return kp;
        }
    }
    throw std::runtime_error("DeriveKeyPairError");
}

KeyPair generate_key_pair() {
    KeyPair kp{random_scalar(), {}};
    crypto_scalarmult_ristretto255_base(kp.pk.data(), kp.sk.data());
    return kp;
}

Element blind(const Bytes& input, const Scalar& r, Mode mode) {
    Element p = hash_to_group(input, mode), out;
    if (crypto_scalarmult_ristretto255(out.data(), r.data(), p.data()) != 0)
        throw std::runtime_error("InvalidInputError");
    return out;
}

static Output finalize_hash(const Bytes& input, const Element& unblinded) {
    Bytes h;
    append_lp(h, input.data(), input.size());
    append_lp(h, unblinded.data(), unblinded.size());
    append(h, std::string("Finalize"));
    return sha512(h);
}

Output finalize(const Bytes& input, const Scalar& r, const Element& evaluated) {
    Scalar rinv;
    if (crypto_core_ristretto255_scalar_invert(rinv.data(), r.data()) != 0)
        throw std::runtime_error("finalize: zero blind");
    Element n;
    if (crypto_scalarmult_ristretto255(n.data(), rinv.data(), evaluated.data()) != 0)
        throw std::runtime_error("finalize: invalid evaluated element");
    return finalize_hash(input, n);
}

Element blind_evaluate(const Scalar& sk, const Element& blinded) {
    if (!crypto_core_ristretto255_is_valid_point(blinded.data()))
        throw std::runtime_error("DeserializeError: invalid blinded element");
    Element out;
    if (crypto_scalarmult_ristretto255(out.data(), sk.data(), blinded.data()) != 0)
        throw std::runtime_error("DeserializeError: identity");
    return out;
}

Output evaluate(const Scalar& sk, const Bytes& input, Mode mode) {
    Element p = hash_to_group(input, mode), e;
    if (crypto_scalarmult_ristretto255(e.data(), sk.data(), p.data()) != 0)
        throw std::runtime_error("InvalidInputError");
    return finalize_hash(input, e);
}

// ---- DLEQ -----------------------------------------------------------------
static Element add(const Element& a, const Element& b) {
    Element r;
    crypto_core_ristretto255_add(r.data(), a.data(), b.data());
    return r;
}
static Element mul(const Scalar& s, const Element& p) {
    Element r;
    if (crypto_scalarmult_ristretto255(r.data(), s.data(), p.data()) != 0) r.fill(0);  // identity
    return r;
}
static Element mul_base(const Scalar& s) {
    Element r;
    if (crypto_scalarmult_ristretto255_base(r.data(), s.data()) != 0) r.fill(0);
    return r;
}
static bool is_identity(const Element& e) { return sodium_is_zero(e.data(), e.size()) == 1; }
static Element add_id(const Element& a, const Element& b) {   // handles identity encoding (all zero)
    if (is_identity(a)) return b;
    if (is_identity(b)) return a;
    return add(a, b);
}

static std::array<uint8_t, 64> composite_seed(const Element& B) {
    Bytes seed_dst;
    append(seed_dst, std::string("Seed-"));
    auto ctx = context_string(kVOPRF);
    append(seed_dst, ctx.data(), ctx.size());
    Bytes t;
    append_lp(t, B.data(), B.size());
    append_lp(t, seed_dst.data(), seed_dst.size());
    return sha512(t);
}

static Scalar composite_di(const std::array<uint8_t, 64>& seed, std::size_t i, const Element& Ci,
                           const Element& Di) {
    Bytes t;
    append_lp(t, seed.data(), seed.size());
    append_i2osp2(t, i);
    append_lp(t, Ci.data(), Ci.size());
    append_lp(t, Di.data(), Di.size());
    append(t, std::string("Composite"));
    return hash_to_scalar(t, dst_with_context("HashToScalar-", kVOPRF));
}

static Scalar challenge(const Element& B, const Element& M, const Element& Z, const Element& t2,
                        const Element& t3) {
    Bytes t;
    for (const Element* e : {&B, &M, &Z, &t2, &t3}) append_lp(t, e->data(), e->size());
    append(t, std::string("Challenge"));
    return hash_to_scalar(t, dst_with_context("HashToScalar-", kVOPRF));
}

Proof generate_proof(const Scalar& k, const Element& pk, const std::vector<Element>& C,
                     const std::vector<Element>& D, const Scalar* fixed_r) {
    if (C.size() != D.size() || C.empty()) throw std::invalid_argument("generate_proof");
    auto seed = composite_seed(pk);
    Element M{};  // identity
    for (std::size_t i = 0; i < C.size(); ++i) M = add_id(mul(composite_di(seed, i, C[i], D[i]), C[i]), M);
    Element Z = mul(k, M);
    Scalar r = fixed_r ? *fixed_r : random_scalar();
    Element t2 = mul_base(r), t3 = mul(r, M);
    Proof pr;
    pr.c = challenge(pk, M, Z, t2, t3);
    Scalar ck;
    crypto_core_ristretto255_scalar_mul(ck.data(), pr.c.data(), k.data());
    crypto_core_ristretto255_scalar_sub(pr.s.data(), r.data(), ck.data());
    return pr;
}

bool verify_proof(const Element& pk, const std::vector<Element>& C, const std::vector<Element>& D,
                  const Proof& proof) {
    if (C.size() != D.size() || C.empty()) return false;
    for (const auto& e : D)
        if (!crypto_core_ristretto255_is_valid_point(e.data())) return false;
    auto seed = composite_seed(pk);
    Element M{}, Z{};
    for (std::size_t i = 0; i < C.size(); ++i) {
        Scalar di = composite_di(seed, i, C[i], D[i]);
        M = add_id(mul(di, C[i]), M);
        Z = add_id(mul(di, D[i]), Z);
    }
    Element t2 = add_id(mul_base(proof.s), mul(proof.c, pk));
    Element t3 = add_id(mul(proof.s, M), mul(proof.c, Z));
    Scalar expected = challenge(pk, M, Z, t2, t3);
    return sodium_memcmp(expected.data(), proof.c.data(), 32) == 0;
}

Bytes from_hex(const std::string& hex) {
    Bytes out(hex.size() / 2);
    std::size_t bin_len = 0;
    if (sodium_hex2bin(out.data(), out.size(), hex.data(), hex.size(), nullptr, &bin_len, nullptr) != 0)
        throw std::invalid_argument("bad hex");
    out.resize(bin_len);
    return out;
}

std::string to_hex(const uint8_t* p, std::size_t n) {
    std::string s(2 * n + 1, '\0');
    sodium_bin2hex(s.data(), s.size(), p, n);
    s.resize(2 * n);
    return s;
}

}  // namespace bcpsi::oprf
