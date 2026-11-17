// Benchmark harness. Writes one JSON file per experiment into --outdir.
//
//   bcpsi_bench [--sets S,M,L] [--reps 5] [--threads 1,2] [--members 32]
//               [--outdir results] [--flood-sweep]
//
// For every parameter set: server preprocessing (timed per stage), memory,
// `reps` timed online queries per thread count (each with a fresh client set
// containing `members` planted breached credentials out of 256), one extra
// instrumented run that records the noise budget at every server stage, and
// the two non-private baselines on the same data.
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <thread>

#include "baseline.h"
#include "client.h"
#include "server.h"
#include "util.h"

using namespace bcpsi;

namespace {

std::vector<std::string> split(const std::string& s, char sep = ',') {
    std::vector<std::string> out;
    std::stringstream ss(s);
    for (std::string x; std::getline(ss, x, sep);) if (!x.empty()) out.push_back(x);
    return out;
}

std::string json_metrics(const Metrics& m, int indent) {
    std::ostringstream os;
    os << std::setprecision(10) << "{";
    bool first = true;
    for (const auto& [k, v] : m) {
        os << (first ? "" : ",") << "\n" << std::string(indent + 2, ' ') << "\"" << k << "\": " << v;
        first = false;
    }
    os << "\n" << std::string(indent, ' ') << "}";
    return os.str();
}

std::string cpu_model() {
    std::ifstream f("/proc/cpuinfo");
    for (std::string line; std::getline(f, line);)
        if (line.rfind("model name", 0) == 0) return line.substr(line.find(':') + 2);
    return "unknown";
}

struct Run {
    Metrics m;
};

Metrics run_one(const Server& srv, const std::vector<Record>& recs, const ClientSet& cs, NoiseProbe* probe) {
    Metrics m;
    Client cl(srv.params(), srv.signer_public_key());
    if (!cl.accept_manifest(srv.signed_manifest())) throw std::runtime_error("manifest rejected");
    Timer total;
    auto req = cl.start(cs.items, m);
    auto oresp = srv.oprf(req, m);
    if (!cl.finish_oprf(oresp, m)) throw std::runtime_error("DLEQ rejected");
    auto q = cl.build_query(m);
    if (probe) probe->decryptor = cl.decryptor();
    auto resp = srv.answer(q, m, probe);
    auto res = cl.decode(resp, m);
    m["e2e.compute_ms"] = total.ms();
    cl.erase_secrets();

    std::size_t qcts = 0;
    for (const auto& c : q.powers) qcts += c.size();
    m["size.oprf_up"] = double(size_bytes(req));
    m["size.oprf_down"] = double(size_bytes(oresp));
    m["size.pk"] = double(q.public_key.size());
    m["size.rlk"] = double(q.relin_keys.size());
    m["size.query_cts"] = double(qcts);
    m["size.query_ct_each"] = double(q.powers[0].size());
    m["size.response"] = double(size_bytes(resp));
    m["size.response_ct_each"] = double(size_bytes(resp)) / double(resp.num_ciphertexts);
    m["size.response_cts"] = double(resp.num_ciphertexts);
    m["size.total_up"] = double(size_bytes(req) + size_bytes(q));
    m["size.total_down"] = double(size_bytes(oresp) + size_bytes(resp));

    double tp = 0, fn = 0, fp = 0, lerr = 0;
    for (std::size_t i = 0; i < res.size(); ++i) {
        bool member = cs.expected_index[i] >= 0;
        tp += member && res[i].found;
        fn += member && !res[i].found;
        fp += !member && res[i].found;
        if (member && res[i].found && srv.params().labeled &&
            (!res[i].label_ok || res[i].label != recs[cs.expected_index[i]].label))
            lerr += 1;
    }
    m["ok.tp"] = tp; m["ok.fn"] = fn; m["ok.fp"] = fp; m["ok.label_err"] = lerr;
    m["ok.cuckoo_evictions"] = double(cl.cuckoo_evictions());
    m["cli.total_ms"] = m["cli.oprf_blind_ms"] + m["cli.oprf_verify_ms"] + m["cli.oprf_finalize_ms"] + m["cli.cuckoo_ms"] +
                        m["cli.keygen_ms"] + m["cli.encrypt_ms"] + m["cli.unpack_ms"] + m["cli.decode_ms"];
    m["srv.total_ms"] = m["srv.oprf_eval_ms"] + m["srv.oprf_proof_ms"] + m["srv.total_answer_ms"];
    return m;
}

void bench_set(const std::string& name, std::size_t reps, const std::vector<unsigned>& threads, std::size_t members,
               const std::string& outdir, std::size_t n_override) {
    ParamSet p = get_paramset(name, n_override);
    std::cerr << "== " << describe(p) << "\n";
    unsigned max_threads = *std::max_element(threads.begin(), threads.end());

    Timer t;
    auto recs = make_server_records(p.n_server, 2026);
    double gen_ms = t.ms();
    Server srv(p, max_threads);
    t.reset();
    Metrics pre = srv.preprocess(recs);
    pre["pre.total_ms"] = t.ms();
    pre["pre.dataset_gen_ms"] = gen_ms;
    pre["pre.threads"] = max_threads;
    Metrics mem = srv.memory_usage();
    std::cerr << "   preprocessing " << pre["pre.total_ms"] / 1000 << " s\n";

    std::vector<std::pair<unsigned, Metrics>> runs;
    uint64_t seed = 1;
    for (unsigned th : threads) {
        Server& s = srv;
        s.set_threads(th);
        run_one(s, recs, make_client_set(recs, 256, members, 999), nullptr);   // warm-up
        for (std::size_t r = 0; r < reps; ++r) {
            auto cs = make_client_set(recs, 256, members, seed++);
            auto m = run_one(s, recs, cs, nullptr);
            std::cerr << "   threads=" << th << " rep=" << r << " server " << m["srv.total_ms"] << " ms, client "
                      << m["cli.total_ms"] << " ms, tp=" << m["ok.tp"] << " fp=" << m["ok.fp"] << "\n";
            runs.push_back({th, m});
        }
    }
    // Instrumented (untimed) run for noise budgets.
    NoiseProbe probe;
    srv.set_threads(max_threads);
    auto pm = run_one(srv, recs, make_client_set(recs, 256, members, 4242), &probe);
    probe.budgets["noise.client_min_budget"] = pm["noise.client_min_budget"];

    // Baselines on identical data.
    Metrics base;
    PlaintextBaseline pb;
    auto bm = pb.build(recs);
    base.insert(bm.begin(), bm.end());
    int prefix = 0;
    while ((p.n_server >> prefix) > 256) ++prefix;     // ~256 entries per bucket
    KAnonBaseline kb(prefix);
    bm = kb.build(recs);
    base.insert(bm.begin(), bm.end());
    std::vector<double> plain_ms, kanon_ms, kanon_cli_ms;
    for (std::size_t r = 0; r < std::max<std::size_t>(reps, 5); ++r) {
        auto cs = make_client_set(recs, 256, members, 500 + r);
        Metrics m;
        auto r1 = pb.query(cs.items, m);
        auto r2 = kb.query(cs.items, m);
        plain_ms.push_back(m["base.plain_server_ms"]);
        kanon_ms.push_back(m["base.kanon_server_ms"]);
        kanon_cli_ms.push_back(m["base.kanon_client_ms"]);
        for (const char* k : {"base.plain_up_bytes", "base.plain_down_bytes", "base.kanon_up_bytes", "base.kanon_down_bytes",
                              "base.kanon_avg_bucket", "base.kanon_leaked_bits_per_item"})
            base[k] = m[k];
        std::size_t correct = 0;
        for (std::size_t i = 0; i < cs.items.size(); ++i) correct += (r1.found[i] == (cs.expected_index[i] >= 0)) && (r2.found[i] == r1.found[i]);
        base["base.correct_fraction"] = double(correct) / double(cs.items.size());
    }
    auto med = [](std::vector<double> v) { std::sort(v.begin(), v.end()); return v[v.size() / 2]; };
    base["base.plain_server_ms"] = med(plain_ms);
    base["base.kanon_server_ms"] = med(kanon_ms);
    base["base.kanon_client_ms"] = med(kanon_cli_ms);
    base["base.kanon_prefix_bits"] = prefix;

    std::string tag = name;
    if (n_override) {
        int lg = 0;
        while ((std::size_t(1) << (lg + 1)) <= n_override) ++lg;
        tag += "_n" + std::to_string(lg);
    }
    std::ofstream out(outdir + "/bench_" + tag + ".json");
    out << std::setprecision(10) << "{\n  \"set\": \"" << name << "\",\n  \"describe\": \"" << describe(p) << "\",\n"
        << "  \"cpu\": \"" << cpu_model() << "\",\n  \"hw_threads\": " << std::thread::hardware_concurrency() << ",\n"
        << "  \"params\": {\"N\": " << p.N << ", \"log2q\": " << p.log2_q_total() << ", \"log2q_data\": " << p.log2_q_data()
        << ", \"t\": " << p.t << ", \"n\": " << p.n_server << ", \"m\": " << p.m_client << ", \"B\": " << p.bins()
        << ", \"d\": " << p.d << ", \"alpha\": " << p.alpha << ", \"capacity\": " << p.capacity()
        << ", \"query_cts\": " << p.query_ciphertexts() << ", \"flood_bits\": " << p.flood_bits
        << ", \"log2_overflow\": " << log2_overflow_probability(p.n_server, p.bins(), p.capacity())
        << ", \"log2_fp\": " << log2_false_positive(p) << ", \"members\": " << members << "},\n"
        << "  \"preprocess\": " << json_metrics(pre, 2) << ",\n  \"memory\": " << json_metrics(mem, 2) << ",\n"
        << "  \"noise\": " << json_metrics(probe.budgets, 2) << ",\n  \"baselines\": " << json_metrics(base, 2) << ",\n"
        << "  \"runs\": [";
    for (std::size_t i = 0; i < runs.size(); ++i) {
        Metrics m = runs[i].second;
        m["threads"] = runs[i].first;
        out << (i ? "," : "") << "\n    " << json_metrics(m, 4);
    }
    out << "\n  ]\n}\n";
    std::cerr << "   wrote " << outdir << "/bench_" << tag << ".json\n";
}

// Flooding calibration: final noise budget and correctness as a function of
// the flooding width b, plus the evaluated-noise budget needed to compute the
// statistical circuit-privacy parameter lambda.
void flood_sweep(const std::string& name, const std::vector<int>& bits, const std::string& outdir) {
    ParamSet p = get_paramset(name, 1u << 12);     // ring/moduli of the set, small n
    auto recs = make_server_records(p.n_server, 77);
    Server srv(p, 2);
    srv.preprocess(recs);
    std::ofstream out(outdir + "/flood_" + name + ".json");
    out << "{\n  \"set\": \"" << name << "\", \"N\": " << p.N << ", \"log2q_data\": " << p.log2_q_data()
        << ", \"t\": " << p.t << ",\n  \"points\": [";
    bool first = true;
    for (int b : bits) {
        for (int rep = 0; rep < 3; ++rep) {
            srv.set_flood_bits(b);
            NoiseProbe probe;
            auto m = run_one(srv, recs, make_client_set(recs, 256, 32, 3000 + 10 * b + rep), &probe);
            bool ok = m["ok.fn"] == 0 && m["ok.fp"] == 0 && m["ok.label_err"] == 0 && m["ok.tp"] == 32;
            out << (first ? "" : ",") << "\n    {\"flood_bits\": " << b << ", \"rep\": " << rep
                << ", \"evaluated\": " << probe.budgets["noise.evaluated"] << ", \"flooded\": " << probe.budgets["noise.flooded"]
                << ", \"final\": " << probe.budgets["noise.final"] << ", \"correct\": " << (ok ? "true" : "false") << "}";
            first = false;
            std::cerr << "   flood " << name << " b=" << b << " rep=" << rep << " final=" << probe.budgets["noise.final"]
                      << " correct=" << ok << "\n";
        }
    }
    out << "\n  ]\n}\n";
}

}  // namespace

int main(int argc, char** argv) {
    std::vector<std::string> sets{"S", "M", "L"};
    std::vector<unsigned> threads{1, 2};
    std::size_t reps = 5, members = 32, n_override = 0;
    std::string outdir = "results";
    bool sweep = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&] { if (i + 1 >= argc) throw std::invalid_argument("missing value for " + a); return std::string(argv[++i]); };
        if (a == "--sets") sets = split(next());
        else if (a == "--reps") reps = std::stoul(next());
        else if (a == "--threads") { threads.clear(); for (auto& s : split(next())) threads.push_back(unsigned(std::stoul(s))); }
        else if (a == "--members") members = std::stoul(next());
        else if (a == "--outdir") outdir = next();
        else if (a == "--n") n_override = std::stoul(next());
        else if (a == "--flood-sweep") sweep = true;
        else { std::cerr << "unknown option " << a << "\n"; return 2; }
    }
    oprf::init();
    if (sweep) {
        flood_sweep("M", {0, 60, 90, 110, 120, 132, 140, 145, 150, 155}, outdir);
        flood_sweep("L", {0, 100, 140, 160, 170, 180, 190, 200}, outdir);
    }
    for (const auto& s : sets) bench_set(s, reps, threads, members, outdir, n_override);
    return 0;
}
