#!/bin/bash
# Prove the retained fpowx_rr -> raw_fpowx_rr host-pow chain is dominated by
# FTWOTOX exact MPFR service before operand acquisition.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

service=0
strict=0
for case_name in \
  ftwotox_direct_single_nearest \
  ftwotox_direct_double_nearest \
  ftwotox_positive_infinity \
  ftwotox_negative_infinity \
  ftwotox_quiet_nan_payload \
  ftwotox_finite_single_overflow \
  ftwotox_finite_single_underflow \
  ftwotox_fp7_self_alias; do
  output=$(CASE="$case_name" bun jit-test/fpp-native-transcendental-service-matrix.ts)
  grep -q '^FPP_NATIVE_TRANS_MATRIX service_pass=1 strict_pass=0 fail=0 total=1$' <<<"$output"
  service=$((service + 1))
done
output=$(CASE=ftwotox_fp7_strict bun jit-test/fpp-native-transcendental-service-matrix.ts)
grep -q '^FPP_NATIVE_TRANS_MATRIX service_pass=0 strict_pass=1 fail=0 total=1$' <<<"$output"
strict=1
printf 'FPOWX_RETIREMENT service=%d strict=%d fail=0 total=%d\n' "$service" "$strict" "$((service + strict))"
test "$service" -eq 8
test "$strict" -eq 1
