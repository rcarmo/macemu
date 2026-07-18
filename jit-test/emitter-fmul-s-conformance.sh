#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
case "$(uname -m)" in aarch64|arm64) ;; *) echo "FMUL_EMITTER_FAIL native AArch64 host required" >&2; exit 1;; esac
work="$(mktemp -d /tmp/b2-fmul-s-emitter-XXXXXX)"; trap 'rm -rf "$work"' EXIT
"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror "$SCRIPT_DIR/emitter-fmul-s-conformance.cpp" -o "$work/probe"
"$work/probe"
