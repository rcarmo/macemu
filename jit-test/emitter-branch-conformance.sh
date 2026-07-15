#!/bin/bash
# Compile and execute the generic AArch64 branch-encoder conformance matrix.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
case "$(uname -m)" in
    aarch64|arm64) ;;
    *) echo "BRANCH_EMITTER_FAIL native AArch64 host required" >&2; exit 1 ;;
esac

work="$(mktemp -d /tmp/b2-branch-emitter-XXXXXX)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT

"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror \
    -fsanitize=undefined -fno-sanitize-recover=all \
    "$SCRIPT_DIR/emitter-branch-conformance.cpp" \
    -o "$work/emitter-branch-conformance"
"$work/emitter-branch-conformance"
