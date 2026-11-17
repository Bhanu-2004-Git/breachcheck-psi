// Arithmetic in Z_t for the server's per-slot polynomials (Part 2, Sec. 2.2).
#pragma once
#include <cstdint>
#include <vector>

namespace bcpsi {

class Zt {
public:
    explicit Zt(uint64_t t);
    uint64_t t() const { return t_; }
    uint64_t add(uint64_t a, uint64_t b) const { uint64_t s = a + b; return s >= t_ ? s - t_ : s; }
    uint64_t sub(uint64_t a, uint64_t b) const { return a >= b ? a - b : a + t_ - b; }
    // Barrett reduction; valid for a, b < t < 2^32 (product < 2^64).
    uint64_t mul(uint64_t a, uint64_t b) const {
        uint64_t x = a * b;
        uint64_t q = uint64_t((unsigned __int128)x * barrett_ >> 64);
        uint64_t r = x - q * t_;
        return r >= t_ ? r - t_ : r;
    }
    uint64_t inv(uint64_t a) const { return inv_[a]; }                    // table lookup
    uint64_t pow(uint64_t a, uint64_t e) const;

    // Monic polynomial with the given roots; coefficients low degree first,
    // size roots.size()+1.
    std::vector<uint64_t> roots_poly(const std::vector<uint64_t>& roots) const;
    // Interpolating polynomial through (x_i, y_i), x_i distinct. Size = xs.size()
    // (degree <= size-1). Newton divided differences, then expansion.
    std::vector<uint64_t> interpolate(const std::vector<uint64_t>& xs, const std::vector<uint64_t>& ys) const;
    uint64_t eval(const std::vector<uint64_t>& coeffs, uint64_t x) const;

private:
    uint64_t t_;
    uint64_t barrett_;   // floor(2^64 / t)
    std::vector<uint32_t> inv_;
};

}  // namespace bcpsi
