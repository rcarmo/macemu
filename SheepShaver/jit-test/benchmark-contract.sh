#!/usr/bin/env bash
# Structural and fail-closed contract for the bounded SheepShaver benchmark.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GLUE="$ROOT/src/kpx_cpu/sheepshaver_glue.cpp"
CPU="$ROOT/src/kpx_cpu/src/cpu/ppc/ppc-cpu.cpp"
JIT="$ROOT/src/kpx_cpu/src/cpu/jit/aarch64/ppc-jit.cpp"
HARNESS="$ROOT/jit-test/benchmark.sh"
DOC="$ROOT/docs/AARCH64_JIT_BENCHMARK.md"

fail() { echo "benchmark contract: FAIL: $*" >&2; exit 1; }
for f in "$GLUE" "$CPU" "$JIT" "$HARNESS" "$DOC"; do
    [[ -f "$f" ]] || fail "missing ${f#$ROOT/}"
done

grep -Fq 'ss-ppc-register-loop-v1' "$GLUE" || fail 'immutable workload id absent'
grep -Fq 'CLOCK_MONOTONIC_RAW' "$GLUE" || fail 'internal monotonic timing absent'
grep -Fq 'observer_enabled_in_timing' "$GLUE" || fail 'timing observer rejection absent'
grep -Fq 'census_binary_required' "$GLUE" || fail 'separate census binary gate absent'
grep -Fq 'ambiguous_engine_or_seed' "$GLUE" || fail 'engine/seed ambiguity gate absent'
grep -Fq 'state_hash != expected_hash' "$GLUE" || fail 'full-state parity gate absent'
grep -Fq 'accounted == architectural' "$GLUE" || fail 'coverage reconciliation gate absent'
grep -Fq 'SSBENCHCOMPILE' "$GLUE" || fail 'compile/cache census absent'
grep -Fq 'ppc_jit_bench_exec.native_retired' "$CPU" || fail 'native retirement census absent'
grep -Fq 'ppc_jit_bench_exec.interpreter_retired' "$CPU" || fail 'fallback retirement census absent'
grep -Fq 'jit_bench_stats.cache_hits++' "$JIT" || fail 'translation-cache hit census absent'
grep -Fq 'jit_bench_stats.generation_current++' "$JIT" || fail 'generation-change census absent'
grep -Fq 'refusing benchmark from dirty source tree' "$HARNESS" || fail 'clean-tree gate absent'
grep -Fq 'flock -n 9' "$HARNESS" || fail 'exclusive lock absent'
grep -Fq 'restore_host' "$HARNESS" || fail 'host-policy restore trap absent'
grep -Fq 'SSBENCHCOVERAGE' "$HARNESS" || fail 'coverage parser absent'
grep -Fq 'application benchmark.' "$DOC" || fail 'scope limitation absent'

echo 'benchmark contract: PASS'
