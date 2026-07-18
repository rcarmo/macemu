#!/bin/bash
# Compile and execute the reachable AArch64 FCMP_dd/FCMP_d0 encoder contract.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
case "$(uname -m)" in
    aarch64|arm64) ;;
    *) echo "FCMP_EMITTER_FAIL native AArch64 host required" >&2; exit 1 ;;
esac

work="$(mktemp -d /tmp/b2-fcmp-emitter-XXXXXX)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror \
    "$SCRIPT_DIR/emitter-fcmp-conformance.cpp" \
    -o "$work/emitter-fcmp-conformance"
"$work/emitter-fcmp-conformance"
