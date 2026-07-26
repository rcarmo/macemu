#!/bin/bash
# Configured-service and strict-attribution control for retired
# fp_from_double_mr -> raw_fp_from_double_mr compatibility chain.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

output=$(bun jit-test/fpp-fmove-double-destination-matrix.ts)
printf '%s\n' "$output"
grep -q '^FPP_DOUBLE_DEST_MATRIX service_pass=28 strict_pass=3 fail=0 total=31$' <<<"$output"
printf 'FP_FROM_DOUBLE_MR_RETIREMENT service=28 strict=3 fail=0 total=31\n'
