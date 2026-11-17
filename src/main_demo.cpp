// End-to-end demo: one client query against a synthetic breach corpus.
//   bcpsi_demo [set=T|S|M|L] [threads] [members]
#include <iostream>

#include "client.h"
#include "server.h"
#include "util.h"

using namespace bcpsi;

int main(int argc, char** argv) {
    std::string set = argc > 1 ? argv[1] : "T";
    unsigned threads = argc > 2 ? unsigned(std::stoul(argv[2])) : 2;
    std::size_t members = argc > 3 ? std::stoul(argv[3]) : 8;
    ParamSet p = get_paramset(set);
    std::cout << describe(p) << "\n";

    auto records = make_server_records(p.n_server, 42);
    Server server(p, threads);
    Timer t;
    server.preprocess(records);
    std::cout << "server preprocessing: " << t.ms() / 1000 << " s\n";

    auto cs = make_client_set(records, 20, members, 7);
    Client client(p, server.signer_public_key());
    std::string why;
    if (!client.accept_manifest(server.signed_manifest(), &why)) { std::cerr << "manifest rejected: " << why << "\n"; return 1; }

    Metrics m;
    t.reset();
    auto req = client.start(cs.items, m);
    auto oresp = server.oprf(req, m);
    if (!client.finish_oprf(oresp, m)) { std::cerr << "DLEQ proof rejected\n"; return 1; }
    auto q = client.build_query(m);
    auto resp = server.answer(q, m);
    auto res = client.decode(resp, m);
    std::cout << "online round trip (no network): " << t.ms() << " ms, up " << (size_bytes(req) + size_bytes(q)) / 1e6
              << " MB, down " << (size_bytes(oresp) + size_bytes(resp)) / 1e6 << " MB\n\n";

    int errors = 0;
    for (std::size_t i = 0; i < res.size(); ++i) {
        bool expect = cs.expected_index[i] >= 0;
        uint64_t want = expect ? records[cs.expected_index[i]].label : 0;
        bool ok = res[i].found == expect && (!expect || (res[i].label_ok && res[i].label == want));
        errors += !ok;
        std::cout << "credential " << i << ": " << (res[i].found ? "BREACHED" : "not found");
        if (res[i].found)
            std::cout << "  breach_id=" << (res[i].label >> 16) << " day=" << (res[i].label & 0xFFFF)
                      << (res[i].label_ok ? "" : " (label check FAILED)");
        std::cout << (ok ? "" : "   <-- MISMATCH") << "\n";
    }
    std::cout << "\nresult: " << (errors ? "FAIL" : "all answers correct") << "\n";
    return errors ? 1 : 0;
}
