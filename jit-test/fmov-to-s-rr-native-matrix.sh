#!/bin/bash
# Exact-native lifecycle evidence for fmov_to_s_rr -> raw_fmov_to_s_rr.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

semantic=$(bun jit-test/fpp-fmove-single-destination-matrix.ts)
printf '%s\n' "$semantic"
grep -q '^FPP_SINGLE_DEST_MATRIX pass=21 fail=0 total=21$' <<<"$semantic"

basic=$(GROUP=single bun jit-test/fpp-fmove-destination-basic-matrix.ts)
printf '%s\n' "$basic"
grep -q '^FPP_FMOVE_DEST_BASIC_MATRIX pass=5 fail=0 total=5$' <<<"$basic"

extended=$(GROUP=single bun jit-test/fpp-fmove-destination-extended-ea-matrix.ts)
printf '%s\n' "$extended"
grep -q '^FPP_FMOVE_DEST_EXTENDED_EA_MATRIX pass=4 fail=0 total=4$' <<<"$extended"

printf 'FMOV_TO_S_RR_NATIVE_MATRIX semantic=21 basic=5 extended=4 fail=0 total=30\n'
