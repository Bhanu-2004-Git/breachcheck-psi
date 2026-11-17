#include "manifest.h"

#include <sodium.h>

#include <cstring>
#include <stdexcept>

namespace bcpsi {

namespace {
struct Writer {
    std::vector<uint8_t> b;
    void u32(uint32_t v) { for (int i = 0; i < 4; ++i) b.push_back(uint8_t(v >> (8 * i))); }
    void u64(uint64_t v) { for (int i = 0; i < 8; ++i) b.push_back(uint8_t(v >> (8 * i))); }
    void raw(const uint8_t* p, std::size_t n) { b.insert(b.end(), p, p + n); }
    void str(const std::string& s) { u32(uint32_t(s.size())); raw(reinterpret_cast<const uint8_t*>(s.data()), s.size()); }
};
struct Reader {
    const std::vector<uint8_t>& b;
    std::size_t off = 0;
    void need(std::size_t n) { if (off + n > b.size()) throw std::runtime_error("manifest truncated"); }
    uint32_t u32() { need(4); uint32_t v = 0; for (int i = 0; i < 4; ++i) v |= uint32_t(b[off++]) << (8 * i); return v; }
    uint64_t u64() { need(8); uint64_t v = 0; for (int i = 0; i < 8; ++i) v |= uint64_t(b[off++]) << (8 * i); return v; }
    void raw(uint8_t* p, std::size_t n) { need(n); std::memcpy(p, b.data() + off, n); off += n; }
    std::string str() { uint32_t n = u32(); if (n > 256) throw std::runtime_error("bad string"); need(n);
        std::string s(b.begin() + off, b.begin() + off + n); off += n; return s; }
};
const char kMagic[] = "BCPSI-manifest-v1";
}  // namespace

std::vector<uint8_t> Manifest::serialize() const {
    Writer w;
    w.str(kMagic);
    w.str(set_name);
    w.u32(N); w.u32(uint32_t(coeff_bits.size()));
    for (int c : coeff_bits) w.u32(uint32_t(c));
    w.u64(t); w.u32(f); w.u32(d); w.u32(alpha); w.u32(window_base); w.u32(flood_bits); w.u32(labeled);
    w.u64(n_max); w.u64(m_max); w.u64(db_version); w.u64(timestamp);
    w.raw(table_seed.data(), table_seed.size());
    w.raw(oprf_pk.data(), oprf_pk.size());
    return w.b;
}

Manifest Manifest::deserialize(const std::vector<uint8_t>& b) {
    Reader r{b};
    if (r.str() != kMagic) throw std::runtime_error("manifest: bad magic");
    Manifest m;
    m.set_name = r.str();
    m.N = r.u32();
    uint32_t nc = r.u32();
    if (nc > 16) throw std::runtime_error("manifest: bad modulus count");
    for (uint32_t i = 0; i < nc; ++i) m.coeff_bits.push_back(int(r.u32()));
    m.t = r.u64(); m.f = r.u32(); m.d = r.u32(); m.alpha = r.u32(); m.window_base = r.u32();
    m.flood_bits = r.u32(); m.labeled = r.u32();
    m.n_max = r.u64(); m.m_max = r.u64(); m.db_version = r.u64(); m.timestamp = r.u64();
    r.raw(m.table_seed.data(), 16);
    r.raw(m.oprf_pk.data(), 32);
    if (r.off != b.size()) throw std::runtime_error("manifest: trailing bytes");
    return m;
}

Manifest Manifest::from_params(const ParamSet& p) {
    Manifest m;
    m.set_name = p.name; m.N = uint32_t(p.N); m.coeff_bits = p.coeff_bits; m.t = p.t;
    m.f = uint32_t(p.f); m.d = uint32_t(p.d); m.alpha = uint32_t(p.alpha);
    m.window_base = uint32_t(p.window_base); m.flood_bits = uint32_t(p.flood_bits);
    m.labeled = p.labeled; m.n_max = p.n_server; m.m_max = p.m_client;
    return m;
}

bool Manifest::matches_pinned(const ParamSet& p, std::string* why) const {
    auto fail = [&](const char* w) { if (why) *why = w; return false; };
    if (N != p.N) return fail("ring degree");
    if (coeff_bits != p.coeff_bits) return fail("coefficient modulus");
    if (t != p.t) return fail("plaintext modulus");
    if (f != p.f || d != p.d) return fail("item layout");
    if (window_base != p.window_base) return fail("window");
    if (m_max != p.m_client) return fail("client set size");
    if (alpha == 0 || alpha > 4096) return fail("alpha out of range");
    if (alpha * uint64_t(d) * p.bins() < n_max) return fail("capacity below n_max");
    return true;
}

SigningKey SigningKey::generate() {
    SigningKey k;
    crypto_sign_keypair(k.pk.data(), k.sk.data());
    return k;
}

SignedManifest sign_manifest(const Manifest& m, const SigningKey& key) {
    SignedManifest sm;
    sm.body = m.serialize();
    crypto_sign_detached(sm.signature.data(), nullptr, sm.body.data(), sm.body.size(), key.sk.data());
    return sm;
}

bool verify_manifest(const SignedManifest& sm, const std::array<uint8_t, 32>& signer_pk, Manifest& out) {
    if (crypto_sign_verify_detached(sm.signature.data(), sm.body.data(), sm.body.size(), signer_pk.data()) != 0)
        return false;
    out = Manifest::deserialize(sm.body);
    return true;
}

}  // namespace bcpsi
