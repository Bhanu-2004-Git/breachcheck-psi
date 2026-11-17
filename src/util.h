#pragma once
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <thread>
#include <vector>

namespace bcpsi {

class Timer {
public:
    Timer() : t0_(std::chrono::steady_clock::now()) {}
    double ms() const {
        return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0_).count();
    }
    void reset() { t0_ = std::chrono::steady_clock::now(); }
private:
    std::chrono::steady_clock::time_point t0_;
};

// Dynamic-scheduled parallel loop over [0, n). fn(i, thread_id).
template <class F>
void parallel_for(std::size_t n, unsigned threads, F&& fn) {
    threads = std::max(1u, std::min<unsigned>(threads, unsigned(std::max<std::size_t>(n, 1))));
    if (threads == 1) {
        for (std::size_t i = 0; i < n; ++i) fn(i, 0u);
        return;
    }
    std::atomic<std::size_t> next{0};
    std::vector<std::thread> pool;
    for (unsigned t = 0; t < threads; ++t)
        pool.emplace_back([&, t] {
            for (std::size_t i; (i = next.fetch_add(1)) < n;) fn(i, t);
        });
    for (auto& th : pool) th.join();
}

}  // namespace bcpsi
