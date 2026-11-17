#include "params.h"

#include <algorithm>
#include <cmath>
#include <numeric>
#include <sstream>
#include <stdexcept>

namespace bcpsi {

std::size_t ParamSet::window_digits() const {
    std::size_t digits = 0, reach = 1;
    while (reach <= d) {
        reach *= window_base;
        ++digits;
    }
    return digits;
}

int ParamSet::log2_q_total() const { return std::accumulate(coeff_bits.begin(), coeff_bits.end(), 0); }
int ParamSet::log2_q_data() const { return log2_q_total() - coeff_bits.back(); }

static double log_binom_term(double nb, double p, double j) {
    return std::lgamma(nb + 1) - std::lgamma(j + 1) - std::lgamma(nb - j + 1) + j * std::log(p) +
           (nb - j) * std::log1p(-p);
}

double log2_overflow_probability(std::size_t n, std::size_t bins, std::size_t capacity, std::size_t k) {
    const double nb = double(n) * double(k), p = 1.0 / double(bins);
    const double start = double(capacity) + 1;
    if (start > nb) return -1e9;
    // Capacity at or below the mean load: overflow is essentially certain. (The
    // tail sum below starts at `start` and would otherwise miss the bulk.)
    if (start <= nb * p + 1) return std::log2(double(bins));
    double mx = -1e300;
    std::vector<double> terms;
    for (double j = start; j <= nb && j < start + 5000; j += 1) {
        double v = log_binom_term(nb, p, j);
        terms.push_back(v);
        mx = std::max(mx, v);
    }
    double s = 0;
    for (double v : terms) s += std::exp(v - mx);
    return (mx + std::log(s)) / std::log(2.0) + std::log2(double(bins));
}

std::size_t derive_alpha(std::size_t n, std::size_t bins, std::size_t d, std::size_t k, double target) {
    for (std::size_t a = 1; a < 100000; ++a)
        if (log2_overflow_probability(n, bins, a * d, k) <= target) return a;
    throw std::runtime_error("derive_alpha: no feasible alpha");
}

double log2_false_positive(const ParamSet& p) {
    return double(p.f) * std::log2(double(p.d) / double(p.t)) + std::log2(double(p.alpha)) +
           std::log2(double(p.m_client));
}

ParamSet get_paramset(const std::string& name, std::size_t n_override) {
    ParamSet p;
    p.name = name;
    if (name == "T" || name == "S" || name == "M") {
        p.N = 8192;
        p.coeff_bits = {56, 56, 56, 50};      // 218 bits: HE-Standard bound for N=8192
        p.t = 1097729;                        // = 67 * 16384 + 1, prime
        p.n_server = name == "T" ? (1u << 12) : name == "S" ? (1u << 16) : (1u << 20);
        p.flood_bits = 132;                   // calibrated in EVAL (Sec. 4.3 of report)
    } else if (name == "L") {
        p.N = 16384;
        p.coeff_bits = {60, 60, 60, 60, 60};  // 300 bits <= 438 (HE Standard, N=16384)
        p.t = 1146881;                        // = 35 * 32768 + 1, prime
        p.n_server = 1u << 20;
        p.flood_bits = 170;
    } else {
        throw std::invalid_argument("unknown parameter set: " + name);
    }
    if (n_override) p.n_server = n_override;
    // Collision-aware placement (distinct label x-coordinates per slot) needs a
    // second partition to fall back to; with alpha = 1 a single felt collision
    // (prob. ~ 5*load/t per insertion) would abort preprocessing.
    p.alpha = std::max<std::size_t>(2, derive_alpha(p.n_server, p.bins(), p.d));
    return p;
}

std::string describe(const ParamSet& p) {
    std::ostringstream os;
    os << "set=" << p.name << " N=" << p.N << " log2q=" << p.log2_q_total() << " (data "
       << p.log2_q_data() << ") t=" << p.t << " n=" << p.n_server << " m=" << p.m_client
       << " B=" << p.bins() << " d=" << p.d << " alpha=" << p.alpha << " C=" << p.capacity()
       << " window=" << p.window_base << "^" << p.window_digits() << " (" << p.query_ciphertexts()
       << " cts) flood=" << p.flood_bits << " labeled=" << p.labeled;
    return os.str();
}

}  // namespace bcpsi
