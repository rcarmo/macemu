#!/bin/bash
# Configured-service and strict-attribution evidence for retired
# fmov_to_d_rrr -> raw_fmov_to_d_rrr native double-destination chain.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

output=$(bun jit-test/fpp-fmove-double-destination-matrix.ts)
printf '%s\n' "$output"
grep -q '^FPP_DOUBLE_DEST_MATRIX service_pass=28 strict_pass=3 fail=0 total=31$' <<<"$output"
printf 'FMOV_TO_D_RRR_RETIREMENT service=28 strict=3 fail=0 total=31\n'
