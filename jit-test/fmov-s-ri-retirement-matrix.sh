#!/bin/bash
# Prove fmov_s_ri's constant roots are serviced before FMOVECR dispatch while
# the shared fmov_s_rr/raw_fmov_s_rr ordinary-single path remains native.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

service="$(CASE=selector_0_pi bun jit-test/fpp-fmovecr-fallback-matrix.ts)"
grep -Fxq 'FPP_FMOVECR_FALLBACK_MATRIX service_pass=1 strict_pass=0 fail=0 total=1' <<<"$service"
strict="$(CASE=pi_fp7_max_destination bun jit-test/fpp-fmovecr-fallback-matrix.ts)"
grep -Fxq 'FPP_FMOVECR_FALLBACK_MATRIX service_pass=0 strict_pass=1 fail=0 total=1' <<<"$strict"
live="$(CASE=single_aind_a0 bun jit-test/fpp-fmove-memory-basic-matrix.ts)"
grep -Fxq 'FPP_FMOVE_MEMORY_BASIC_MATRIX pass=1 fail=0 total=1' <<<"$live"

printf 'FMOV_S_RI_RETIREMENT_FOCUSED service=1 strict=1 live_single=1 fail=0 total=3\n'
