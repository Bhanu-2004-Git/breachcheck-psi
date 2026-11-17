#include "protocol.h"

#include <stdexcept>

namespace bcpsi {

std::size_t size_bytes(const OprfRequest& r) { return r.blinded.size() * 32; }
std::size_t size_bytes(const OprfResponse& r) { return r.evaluated.size() * 32 + 64; }
std::size_t size_bytes(const QueryRequest& r) {
    std::size_t s = r.public_key.size() + r.relin_keys.size();
    for (const auto& c : r.powers) s += c.size();
    return s;
}
std::size_t size_bytes(const QueryResponse& r) { return r.packed.size(); }

seal::SEALContext make_context(const ParamSet& p) {
    seal::EncryptionParameters parms(seal::scheme_type::bfv);
    parms.set_poly_modulus_degree(p.N);
    parms.set_coeff_modulus(seal::CoeffModulus::Create(p.N, p.coeff_bits));
    parms.set_plain_modulus(p.t);
    seal::SEALContext ctx(parms, true, seal::sec_level_type::tc128);
    if (!ctx.parameters_set()) throw std::runtime_error(std::string("SEAL parameters rejected: ") + ctx.parameter_error_message());
    if (!ctx.first_context_data()->qualifiers().using_batching) throw std::runtime_error("batching unavailable");
    return ctx;
}

static int bit_length(uint64_t v) { int b = 0; while (v) { ++b; v >>= 1; } return b; }

std::string pack_ciphertexts(const seal::SEALContext& ctx, const std::vector<seal::Ciphertext>& cts) {
    auto last = ctx.last_context_data();
    const uint64_t q0 = last->parms().coeff_modulus()[0].value();
    const int bits = bit_length(q0);
    const std::size_t N = last->parms().poly_modulus_degree();
    std::string out;
    out.reserve((cts.size() * 2 * N * bits + 7) / 8);
    uint64_t acc = 0;   // little-endian bit stream
    int nacc = 0;
    for (const auto& ct : cts) {
        if (ct.parms_id() != last->parms_id() || ct.size() != 2 || ct.is_ntt_form())
            throw std::runtime_error("pack: ciphertext not at last level / size 2");
        for (std::size_t poly = 0; poly < 2; ++poly) {
            const uint64_t* d = ct.data(poly);
            for (std::size_t i = 0; i < N; ++i) {
                uint64_t v = d[i];
                int rem = bits;
                while (rem > 0) {
                    int take = std::min(rem, 64 - nacc);
                    take = std::min(take, 8);
                    acc |= (v & ((1ull << take) - 1)) << nacc;
                    v >>= take;
                    rem -= take;
                    nacc += take;
                    while (nacc >= 8) { out.push_back(char(acc & 0xFF)); acc >>= 8; nacc -= 8; }
                }
            }
        }
    }
    if (nacc > 0) out.push_back(char(acc & 0xFF));
    return out;
}

std::vector<seal::Ciphertext> unpack_ciphertexts(const seal::SEALContext& ctx, const std::string& blob,
                                                 std::size_t count) {
    auto last = ctx.last_context_data();
    const uint64_t q0 = last->parms().coeff_modulus()[0].value();
    const int bits = bit_length(q0);
    const std::size_t N = last->parms().poly_modulus_degree();
    const std::size_t need = (count * 2 * N * bits + 7) / 8;
    if (blob.size() != need) throw std::runtime_error("unpack: wrong response length");
    std::vector<seal::Ciphertext> out;
    std::size_t bitpos = 0;
    auto read_bits = [&](int nb) {
        uint64_t v = 0;
        for (int k = 0; k < nb;) {
            std::size_t byte = bitpos >> 3;
            int off = int(bitpos & 7);
            int take = std::min(8 - off, nb - k);
            uint64_t chunk = (uint64_t(uint8_t(blob[byte])) >> off) & ((1u << take) - 1);
            v |= chunk << k;
            k += take;
            bitpos += take;
        }
        return v;
    };
    for (std::size_t c = 0; c < count; ++c) {
        seal::Ciphertext ct(ctx, last->parms_id(), 2);
        ct.resize(ctx, last->parms_id(), 2);
        for (std::size_t poly = 0; poly < 2; ++poly) {
            uint64_t* d = ct.data(poly);
            for (std::size_t i = 0; i < N; ++i) {
                uint64_t v = read_bits(bits);
                if (v >= q0) throw std::runtime_error("unpack: coefficient out of range");
                d[i] = v;
            }
        }
        out.push_back(std::move(ct));
    }
    return out;
}

}  // namespace bcpsi
