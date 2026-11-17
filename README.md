# breachcheck-psi

**Encrypted compromised-credential checking with HE-based unbalanced labeled PSI.**
CYB 599 Graduate Project, Part 3 (Implementation & Evaluation). This is the
implementation of the protocol designed in Part 2.

A client holding up to 256 credentials learns which of them appear in a
server's breach corpus of up to 2^20 records, plus a 48-bit breach label
for each hit. The server learns nothing about the query beyond the
public maximum batch size. Every message has a fixed size, whatever the
client holds or whatever matches.

| Layer | What it does | Built on |
|---|---|---|
| VOPRF | Client items and server records are mapped to `F_k(x)` (RFC 9497, ristretto255-SHA512, batched DLEQ proof). Verified against the RFC test vectors. | libsodium |
| Manifest | Parameters, OPRF public key, table seed and DB version, signed with Ed25519 and pinned by the client | libsodium |
| Hashing | 3-way cuckoo hashing (client) and simple hashing with collision-aware partitions (server), 1638 bins × 5 slots | – |
| Matching | BFV, 8192 or 16384 slots. Client uploads a base-8 window of powers (14 ciphertexts); server evaluates degree-63 root and label polynomials at multiplicative depth 1 | Microsoft SEAL 4.1.2 |
| Server privacy | Random nonzero masks folded into the root polynomial, rerandomization with `Enc_pk(0)`, uniform noise flooding of `c0`, mod-switch to one 56/60-bit prime | SEAL + custom code |

## Quick start (clean machine)

Prerequisites: a C++17 compiler (GCC ≥ 9 or Clang ≥ 10), CMake ≥ 3.16, `make`,
`git`, and network access to GitHub (the build downloads SEAL 4.1.2 and
libsodium). Python 3 with matplotlib is optional and is only used for the figures.

```bash
# Ubuntu / Debian
sudo apt-get install -y build-essential cmake git python3 python3-matplotlib

git clone <REPO_URL> breachcheck-psi
cd breachcheck-psi
./run.sh quick      # build + quick tests + demo + small benchmark   (~3-5 min)
./run.sh full       # build + all tests + full evaluation (S, M, L)  (~15-25 min, ~3 GB RAM)
```

Or with Docker (no host dependencies):

```bash
docker build -t bcpsi .
docker run --rm bcpsi                 # ./run.sh quick
docker run --rm bcpsi ./run.sh full
```

`run.sh` modes: `quick` (default), `full`, `build`, `tests`, `figures`. The
environment variables `JOBS`, `THREADS` (default `1,2`) and `REPS` (default 5)
override the defaults.

## What gets produced

| Path | Content |
|---|---|
| `build/bcpsi_tests` | 19 tests / 4,523 checks: RFC 9497 vectors, DLEQ soundness, polynomial arithmetic, end-to-end runs, false positives over 10,240 non-members, tampered labels, malformed ciphertexts, fixed-shape leakage check, noise budget, mask uniformity |
| `build/bcpsi_demo [T\|S\|M\|L] [threads] [members]` | one end-to-end query with readable output |
| `build/bcpsi_bench` | benchmark harness (see `--help` options in `bench/bench_main.cpp`) |
| `results/bench_{S,M,L}.json` | raw per-run metrics: timings per stage, message sizes, noise budgets, correctness counts, baselines |
| `results/bench_M_n22.json` | scaling point n = 2^22 (`bcpsi_bench --sets M --n 4194304 --reps 3`) |
| `results/flood_{M,L}.json` | flooding-width sweep (noise budget vs. width) |
| `results/*.log` | console logs of tests, demo and benchmark |
| `report/generated/` | figures (PDF/PNG) and LaTeX tables generated from the JSON by `scripts/make_figures.py` |
| `report/report.tex` | evaluation report (compiles with `pdflatex`; uses `report/generated/`) |

## Parameter sets

| Set | n | N | log q (data) | t | bins | α | flood b |
|---|---|---|---|---|---|---|---|
| T (tests) | 2^12 | 8192 | 218 (168) | 1,097,729 | 1638 | 2 | 132 |
| S | 2^16 | 8192 | 218 (168) | 1,097,729 | 1638 | 4 | 132 |
| M (main) | 2^20 | 8192 | 218 (168) | 1,097,729 | 1638 | 37 | 132 |
| L | 2^20 | 16384 | 300 (240) | 1,146,881 | 3276 | 20 | 170 |
| M @ 2^22 (scaling) | 2^22 | 8192 | 218 (168) | 1,097,729 | 1638 | 134 | 132 |

All sets: 100-bit items (5 × 20-bit slots), d = 63, a base-8 window with 2
digits, m = 256, 3 hash functions, 48-bit labels plus 52 redundancy bits. α is
derived so that the bin-overflow probability is at most 2^-40
(`src/params.cpp`). The coefficient moduli are within the HE Standard bounds
for 128-bit security.

## Repository layout

```
src/
  params.*     parameter sets, alpha derivation, overflow / false-positive bounds
  oprf.*       RFC 9497 OPRF/VOPRF (expand_message_xmd, hash-to-group, batched DLEQ)
  hashing.*    item/pad/bin derivation from OPRF outputs, cuckoo hashing, label encoding
  zt.*         Z_t arithmetic (Barrett), root polynomials, Newton interpolation
  manifest.*   signed manifest (Ed25519) and client-side parameter pinning
  server.*     offline preprocessing; online OPRF, power computation, evaluation, flooding
  client.*     blinding, proof verification, query construction, decoding
  protocol.*   SEAL context, wire messages, bit-packing of response ciphertexts
  baseline.*   non-private baselines (plaintext lookup, k-anonymity prefix buckets)
  dataset.*    deterministic synthetic breach corpus and client sets
tests/test_main.cpp    correctness and security-property tests
bench/bench_main.cpp   benchmark harness
scripts/make_figures.py  JSON -> figures + LaTeX tables
run.sh, Dockerfile     reproducible entry points
```

## Security notes and limitations (summary)

* Client privacy holds against a malicious server: blinded group elements plus
  RLWE ciphertexts under a fresh key. Server privacy holds against a malicious
  client through the OPRF (offline guessing needs rate-limited online
  queries), plus statistical circuit privacy from flooding (λ ≥ 40, see the report).
* A malicious server can still return wrong answers or a doctored database.
  Verifiable evaluation is out of scope (Part 1). Rate limiting is modelled
  only by the fixed batch size, and no token system is implemented.
* All runs are in-process over serialized byte strings. Network time is
  modelled, not measured. The data is synthetic.
* `NoiseProbe` (used by tests and benchmarks) hands the client's decryptor to
  the server *only* to measure noise budgets; it is never used on the
  protocol path.

## License

MIT for this repository's code. SEAL (MIT) and libsodium (ISC) are fetched at build time.
