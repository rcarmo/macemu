#!/bin/bash
# Compile and execute the reachable AArch64 FMOV_dd/raw_fmov_rr bit-copy contract.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
case "$(uname -m)" in
    aarch64|arm64) ;;
    *) echo "FMOV_EMITTER_FAIL native AArch64 host required" >&2; exit 1 ;;
esac

work="$(mktemp -d /tmp/b2-fmov-emitter-XXXXXX)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror \
    "$SCRIPT_DIR/emitter-fmov-conformance.cpp" \
    -o "$work/emitter-fmov-conformance"
"$work/emitter-fmov-conformance"
