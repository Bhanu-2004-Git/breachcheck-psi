// RFC 9497 OPRF/VOPRF over ristretto255-SHA512 (libsodium), including the
// batched Chaum-Pedersen DLEQ proof (Part 2: "2HashDH VOPRF", "batched DLEQ").
#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace bcpsi::oprf {

using Bytes = std::vector<uint8_t>;
using Scalar = std::array<uint8_t, 32>;
using Element = std::array<uint8_t, 32>;
using Output = std::array<uint8_t, 64>;
struct Proof { Scalar c, s; };

enum Mode : uint8_t { kOPRF = 0x00, kVOPRF = 0x01 };

void init();  // sodium_init; idempotent

Bytes context_string(Mode mode);
Bytes expand_message_xmd_sha512(const Bytes& msg, const Bytes& dst, std::size_t len);
Element hash_to_group(const Bytes& input, Mode mode);
Scalar hash_to_scalar(const Bytes& input, const Bytes& dst);
Scalar random_scalar();

struct KeyPair { Scalar sk; Element pk; };
KeyPair derive_key_pair(const Bytes& seed, const Bytes& info, Mode mode);
KeyPair generate_key_pair();

// Client
Element blind(const Bytes& input, const Scalar& r, Mode mode);   // throws on identity
Output finalize(const Bytes& input, const Scalar& r, const Element& evaluated);

// Server
Element blind_evaluate(const Scalar& sk, const Element& blinded);  // throws on invalid point
Output evaluate(const Scalar& sk, const Bytes& input, Mode mode);   // direct PRF (offline)

// Batched DLEQ (VOPRF mode): proves k*G = pk and k*C[i] = D[i] for all i.
Proof generate_proof(const Scalar& k, const Element& pk, const std::vector<Element>& C,
                     const std::vector<Element>& D, const Scalar* fixed_r = nullptr);
bool verify_proof(const Element& pk, const std::vector<Element>& C, const std::vector<Element>& D,
                  const Proof& proof);

Bytes from_hex(const std::string& hex);
std::string to_hex(const uint8_t* p, std::size_t n);
template <class T> std::string to_hex(const T& v) { return to_hex(v.data(), v.size()); }

}  // namespace bcpsi::oprf
