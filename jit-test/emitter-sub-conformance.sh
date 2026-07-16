#!/bin/bash
# Compile and execute the reachable generic AArch64 SUB/SUBS encoder conformance matrix.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
case "$(uname -m)" in
    aarch64|arm64) ;;
    *) echo "SUB_EMITTER_FAIL native AArch64 host required" >&2; exit 1 ;;
esac

work="$(mktemp -d /tmp/b2-sub-emitter-XXXXXX)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror \
    "$SCRIPT_DIR/emitter-sub-conformance.cpp" \
    -o "$work/emitter-sub-conformance"
"$work/emitter-sub-conformance"
