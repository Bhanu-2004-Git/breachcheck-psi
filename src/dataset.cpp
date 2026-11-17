#include "dataset.h"

#include <algorithm>
#include <random>
#include <stdexcept>
#include <unordered_set>

#include "hashing.h"

namespace bcpsi {

static std::string random_password(std::mt19937_64& rng) {
    static const char a[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%";
    std::string s(12, ' ');
    for (auto& c : s) c = a[rng() % (sizeof(a) - 1)];
    return s;
}

std::vector<Record> make_server_records(std::size_t n, uint64_t seed) {
    std::mt19937_64 rng(seed);
    std::vector<Record> out(n);
    for (std::size_t i = 0; i < n; ++i) {
        out[i].x = credential_hash("user" + std::to_string(i) + "@example.com", random_password(rng));
        uint64_t breach = rng() & 0xFFFFFFFFull;
        uint64_t days = rng() % 9500;                     // 2000-01-01 .. ~2026
        out[i].label = (breach << 16) | days;
    }
    return out;
}

ClientSet make_client_set(const std::vector<Record>& server, std::size_t m_real, std::size_t k, uint64_t seed) {
    if (k > m_real || k > server.size()) throw std::invalid_argument("make_client_set");
    std::mt19937_64 rng(seed);
    ClientSet cs;
    std::unordered_set<std::size_t> chosen;
    while (chosen.size() < k) chosen.insert(rng() % server.size());
    for (std::size_t idx : chosen) {
        cs.items.push_back(server[idx].x);
        cs.expected_index.push_back(int64_t(idx));
    }
    for (std::size_t j = k; j < m_real; ++j) {
        cs.items.push_back(credential_hash("client" + std::to_string(seed) + "-" + std::to_string(j) + "@example.org",
                                           random_password(rng)));
        cs.expected_index.push_back(-1);
    }
    // Shuffle so members are not at the front.
    std::vector<std::size_t> perm(cs.items.size());
    for (std::size_t i = 0; i < perm.size(); ++i) perm[i] = i;
    std::shuffle(perm.begin(), perm.end(), rng);
    ClientSet out;
    for (std::size_t i : perm) {
        out.items.push_back(cs.items[i]);
        out.expected_index.push_back(cs.expected_index[i]);
    }
    return out;
}

}  // namespace bcpsi
