#!/bin/bash
# Compile and execute the generic AArch64 CMP encoder conformance matrix.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
case "$(uname -m)" in
    aarch64|arm64) ;;
    *) echo "COMPARE_EMITTER_FAIL native AArch64 host required" >&2; exit 1 ;;
esac

work="$(mktemp -d /tmp/b2-cmp-emitter-XXXXXX)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror \
    "$SCRIPT_DIR/emitter-compare-conformance.cpp" \
    -o "$work/emitter-compare-conformance"
"$work/emitter-compare-conformance"
