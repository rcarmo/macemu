#!/bin/bash
# Configured-service controls for the retired legacy binary64-shadow
# extended-memory conversion chains.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

extended=$(bun jit-test/fpp-fmove-extended-fallback-matrix.ts)
printf '%s\n' "$extended"
grep -q '^FPP_FMOVE_EXTENDED_FALLBACK_MATRIX service_pass=8 strict_pass=4 fail=0 total=12$' <<<"$extended"

static=$(bun jit-test/fpp-fmovem-static-service-matrix.ts)
printf '%s\n' "$static"
grep -q '^FPP_FMOVEM_STATIC_MATRIX service_pass=10 strict_pass=3 fail=0 total=13$' <<<"$static"

dynamic=$(bun jit-test/fpp-fmovem-dynamic-service-matrix.ts)
printf '%s\n' "$dynamic"
grep -q '^FPP_FMOVEM_DYNAMIC_MATRIX service_pass=12 strict_pass=3 fail=0 total=15$' <<<"$dynamic"

printf 'FP_EXTENDED_MEMORY_RETIREMENT service=30 strict=10 fail=0 total=40\n'
