#include "baseline.h"

#include "util.h"

namespace bcpsi {

static std::string key(const oprf::Bytes& x) { return std::string(x.begin(), x.end()); }

Metrics PlaintextBaseline::build(const std::vector<Record>& records) {
    Timer t;
    table_.reserve(records.size() * 2);
    for (const auto& r : records) table_[key(r.x)] = r.label;
    return {{"base.plain_build_ms", t.ms()}};
}

BaselineResult PlaintextBaseline::query(const std::vector<oprf::Bytes>& items, Metrics& m) const {
    BaselineResult res;
    Timer t;
    // Wire: request = 32-byte hash per item; response = 1 flag byte + 6 label bytes per item.
    for (const auto& x : items) {
        auto it = table_.find(key(x));
        res.found.push_back(it != table_.end());
        res.labels.push_back(it != table_.end() ? it->second : 0);
    }
    m["base.plain_server_ms"] = t.ms();
    m["base.plain_up_bytes"] = double(items.size() * 32);
    m["base.plain_down_bytes"] = double(items.size() * 7);
    return res;
}

static uint32_t prefix_of(const oprf::Bytes& x, int bits) {
    uint32_t v = (uint32_t(x[0]) << 24) | (uint32_t(x[1]) << 16) | (uint32_t(x[2]) << 8) | x[3];
    return v >> (32 - bits);
}

Metrics KAnonBaseline::build(const std::vector<Record>& records) {
    Timer t;
    buckets_.assign(std::size_t(1) << prefix_bits_, {});
    for (const auto& r : records) {
        // suffix = remaining bytes of the 32-byte hash (prefix rounded down to whole bytes)
        std::size_t skip = std::size_t(prefix_bits_) / 8;
        buckets_[prefix_of(r.x, prefix_bits_)].push_back({std::string(r.x.begin() + skip, r.x.end()), r.label});
    }
    return {{"base.kanon_build_ms", t.ms()}};
}

BaselineResult KAnonBaseline::query(const std::vector<oprf::Bytes>& items, Metrics& m) const {
    BaselineResult res;
    Timer t;
    std::size_t down = 0, total_entries = 0;
    const std::size_t skip = std::size_t(prefix_bits_) / 8;
    std::vector<const std::vector<std::pair<std::string, uint64_t>>*> got;
    for (const auto& x : items) {                          // server side
        const auto& b = buckets_[prefix_of(x, prefix_bits_)];
        got.push_back(&b);
        total_entries += b.size();
        down += b.size() * ((32 - skip) + 6);
    }
    m["base.kanon_server_ms"] = t.ms();
    t.reset();
    for (std::size_t i = 0; i < items.size(); ++i) {       // client side
        std::string suf(items[i].begin() + skip, items[i].end());
        int f = 0;
        uint64_t l = 0;
        for (const auto& e : *got[i])
            if (e.first == suf) { f = 1; l = e.second; break; }
        res.found.push_back(f);
        res.labels.push_back(l);
    }
    m["base.kanon_client_ms"] = t.ms();
    m["base.kanon_up_bytes"] = double(items.size() * ((prefix_bits_ + 7) / 8));
    m["base.kanon_down_bytes"] = double(down);
    m["base.kanon_avg_bucket"] = double(total_entries) / double(items.size());
    m["base.kanon_leaked_bits_per_item"] = double(prefix_bits_);
    return res;
}

}  // namespace bcpsi
