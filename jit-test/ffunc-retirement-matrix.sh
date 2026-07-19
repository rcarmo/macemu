#!/bin/bash
# Prove that all four retained ffunc_rr compatibility roots use MPFR service
# and are rejected before native execution under strict full-JIT policy.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

service=0
strict=0
for case_name in \
    fsin_direct_double_nearest \
    fetox_direct_double_nearest \
    flog2_direct_double_nearest; do
    output="$(CASE="$case_name" bun jit-test/fpp-native-transcendental-service-matrix.ts)"
    grep -Fxq 'FPP_NATIVE_TRANS_MATRIX service_pass=1 strict_pass=0 fail=0 total=1' <<<"$output"
    service=$((service + 1))
done
for case_name in fsin_fp7_strict fetox_fp7_strict flog2_fp7_strict; do
    output="$(CASE="$case_name" bun jit-test/fpp-native-transcendental-service-matrix.ts)"
    grep -Fxq 'FPP_NATIVE_TRANS_MATRIX service_pass=0 strict_pass=1 fail=0 total=1' <<<"$output"
    strict=$((strict + 1))
done

output="$(CASE=fcos_extended_source_double_nearest bun jit-test/fpp-cosh-acos-cos-service-matrix.ts)"
grep -Fxq 'FPP_COSH_ACOS_COS_MATRIX service_pass=1 strict_pass=0 fail=0 total=1' <<<"$output"
service=$((service + 1))
output="$(CASE=fcos_fp7_strict bun jit-test/fpp-cosh-acos-cos-service-matrix.ts)"
grep -Fxq 'FPP_COSH_ACOS_COS_MATRIX service_pass=0 strict_pass=1 fail=0 total=1' <<<"$output"
strict=$((strict + 1))

printf 'FFUNC_RETIREMENT_FOCUSED service=%d strict=%d fail=0 total=%d\n' \
    "$service" "$strict" "$((service + strict))"
test "$service" -eq 4
test "$strict" -eq 4
