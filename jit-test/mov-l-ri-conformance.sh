#!/bin/bash
# Compile and execute mov_l_ri's 32-bit raw materialisation and 64-bit PC_P control.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
case "$(uname -m)" in
    aarch64|arm64) ;;
    *) echo "MOV_L_RI_FAIL native AArch64 host required" >&2; exit 1 ;;
esac
work="$(mktemp -d /tmp/b2-mov-l-ri-XXXXXX)"
cleanup() { rm -rf "$work"; }
trap cleanup EXIT
"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror \
    "$SCRIPT_DIR/mov-l-ri-conformance.cpp" -o "$work/mov-l-ri-conformance"
"$work/mov-l-ri-conformance"
