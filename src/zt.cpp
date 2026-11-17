#include "zt.h"

#include <stdexcept>

namespace bcpsi {

Zt::Zt(uint64_t t) : t_(t), barrett_(0), inv_(t) {
    if (t < 2 || t >= (1ull << 32)) throw std::invalid_argument("Zt: need 2 <= t < 2^32");
    barrett_ = uint64_t(((unsigned __int128)1 << 64) / t);
    // Linear-time inverse table: inv[i] = -(t / i) * inv[t mod i] mod t.
    inv_[0] = 0;
    if (t > 1) inv_[1] = 1;
    for (uint64_t i = 2; i < t; ++i)
        inv_[i] = uint32_t((t - (t / i) * uint64_t(inv_[t % i]) % t) % t);
}

uint64_t Zt::pow(uint64_t a, uint64_t e) const {
    uint64_t r = 1;
    a %= t_;
    while (e) {
        if (e & 1) r = mul(r, a);
        a = mul(a, a);
        e >>= 1;
    }
    return r;
}

std::vector<uint64_t> Zt::roots_poly(const std::vector<uint64_t>& roots) const {
    std::vector<uint64_t> c(roots.size() + 1, 0);
    c[0] = 1;
    std::size_t deg = 0;
    for (uint64_t r : roots) {
        // c(z) <- c(z) * (z - r)
        c[deg + 1] = c[deg];
        for (std::size_t i = deg; i > 0; --i) c[i] = sub(c[i - 1], mul(c[i], r));
        c[0] = sub(0, mul(c[0], r));
        ++deg;
    }
    return c;
}

std::vector<uint64_t> Zt::interpolate(const std::vector<uint64_t>& xs, const std::vector<uint64_t>& ys) const {
    const std::size_t k = xs.size();
    if (ys.size() != k) throw std::invalid_argument("interpolate: size mismatch");
    if (k == 0) return {};
    std::vector<uint64_t> dd(ys);
    for (std::size_t lvl = 1; lvl < k; ++lvl)
        for (std::size_t i = k - 1; i >= lvl; --i) {
            uint64_t den = sub(xs[i], xs[i - lvl]);
            if (den == 0) throw std::invalid_argument("interpolate: repeated x");
            dd[i] = mul(sub(dd[i], dd[i - 1]), inv(den));
        }
    // Horner-style expansion of the Newton form.
    std::vector<uint64_t> c(k, 0);
    c[0] = dd[k - 1];
    std::size_t deg = 0;
    for (std::size_t j = k - 1; j-- > 0;) {
        // c <- c * (z - x_j) + dd[j]
        c[deg + 1] = c[deg];
        for (std::size_t i = deg; i > 0; --i) c[i] = sub(c[i - 1], mul(c[i], xs[j]));
        c[0] = add(sub(0, mul(c[0], xs[j])), dd[j]);
        ++deg;
    }
    return c;
}

uint64_t Zt::eval(const std::vector<uint64_t>& coeffs, uint64_t x) const {
    uint64_t acc = 0;
    for (std::size_t i = coeffs.size(); i-- > 0;) acc = add(mul(acc, x), coeffs[i]);
    return acc;
}

}  // namespace bcpsi
