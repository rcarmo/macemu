#!/bin/bash
# Attribute FMOVECR zero/one to the configured exact-MPFR service boundary and
# prove strict full-JIT rejects the family before retired native wrappers run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

service=0
strict=0
for case_name in selector_15_zero selector_50_ten_pow_0; do
    output="$(CASE="$case_name" bun jit-test/fpp-fmovecr-fallback-matrix.ts)"
    grep -Fxq 'FPP_FMOVECR_FALLBACK_MATRIX service_pass=1 strict_pass=0 fail=0 total=1' <<<"$output"
    service=$((service + 1))
done
output="$(CASE=pi_fp7_max_destination bun jit-test/fpp-fmovecr-fallback-matrix.ts)"
grep -Fxq 'FPP_FMOVECR_FALLBACK_MATRIX service_pass=0 strict_pass=1 fail=0 total=1' <<<"$output"
strict=$((strict + 1))

printf 'FMOV_ZERO_ONE_RETIREMENT_FOCUSED service=%d strict=%d fail=0 total=%d\n' \
    "$service" "$strict" "$((service + strict))"
test "$service" -eq 2
test "$strict" -eq 1
