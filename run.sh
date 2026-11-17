#!/usr/bin/env bash
# Reproducible build + test + benchmark driver.
#
#   ./run.sh            same as ./run.sh quick
#   ./run.sh quick      build, quick tests, demo, benchmark set S (~3-5 min incl. build)
#   ./run.sh full       build, all tests, demo, flooding sweep, sets S, M, L
#                       (~15-25 min on 2 cores, needs ~3 GB RAM)
#   ./run.sh build      build only
#   ./run.sh tests      build + full test suite
#   ./run.sh figures    regenerate report/generated/* from results/*.json
#
# Environment overrides: JOBS (parallel build jobs), THREADS (benchmark thread
# counts, default "1,2"), REPS (benchmark repetitions, default 5).
set -euo pipefail
cd "$(dirname "$0")"

MODE="${1:-quick}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"
THREADS="${THREADS:-1,2}"
REPS="${REPS:-5}"
BUILD=build

log() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

check_prereqs() {
  local missing=0
  for tool in cmake make git c++ cc; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing prerequisite: $tool"; missing=1; }
  done
  [ "$missing" -eq 0 ] || { echo "Install: build-essential cmake git (see README)"; exit 1; }
  local v; v=$(cmake --version | head -1 | awk '{print $3}')
  echo "cmake $v, $(c++ --version | head -1)"
}

build() {
  log "Configuring and building (Release). First run downloads SEAL 4.1.2 and libsodium from GitHub."
  check_prereqs
  cmake -S . -B "$BUILD" -DCMAKE_BUILD_TYPE=Release >"$BUILD.configure.log" 2>&1 || { cat "$BUILD.configure.log"; exit 1; }
  cmake --build "$BUILD" -j "$JOBS" 2>&1 | tail -n 3
}

tests() {
  log "Running test suite ($1)"
  mkdir -p results
  if [ "$1" = quick ]; then ./$BUILD/bcpsi_tests --quick | tee results/tests_quick.log
  else ./$BUILD/bcpsi_tests | tee results/tests_full.log; fi
}

demo() {
  log "End-to-end demo (tiny set T)"
  ./$BUILD/bcpsi_demo T 2 8 | tee results/demo.log
}

figures() {
  log "Generating figures and LaTeX tables"
  if command -v python3 >/dev/null 2>&1; then
    python3 scripts/make_figures.py results report/generated || echo "(figure generation failed; JSON results are still in results/)"
  else
    echo "python3 not found; skipping figures (raw JSON is in results/)"
  fi
}

case "$MODE" in
  build)   build ;;
  tests)   build; tests full ;;
  quick)   build; tests quick; demo
           log "Benchmark: set S (reps=2)"
           ./$BUILD/bcpsi_bench --sets S --reps 2 --threads "$THREADS" --outdir results 2>&1 | tee results/bench_quick.log
           figures ;;
  full)    build; tests full; demo
           log "Benchmark: flooding sweep + sets S, M, L (reps=$REPS, threads=$THREADS)"
           ./$BUILD/bcpsi_bench --sets S,M,L --reps "$REPS" --threads "$THREADS" --flood-sweep --outdir results 2>&1 | tee results/bench.log
           figures ;;
  figures) figures ;;
  *) echo "usage: $0 [quick|full|build|tests|figures]"; exit 2 ;;
esac
log "Done. Results in results/, figures/tables in report/generated/"
