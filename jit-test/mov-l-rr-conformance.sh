#!/bin/bash
# Compile and execute the raw full-width AArch64 register-copy boundary.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
case "$(uname -m)" in
    aarch64|arm64) ;;
    *) echo "MOV_L_RR_FAIL native AArch64 host required" >&2; exit 1 ;;
esac
work="$(mktemp -d /tmp/b2-mov-l-rr-XXXXXX)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT
"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror \
    "$SCRIPT_DIR/mov-l-rr-conformance.cpp" -o "$work/mov-l-rr-conformance"
"$work/mov-l-rr-conformance"
