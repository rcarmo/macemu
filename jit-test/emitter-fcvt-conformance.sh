#!/bin/bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
case "$(uname -m)" in aarch64|arm64) ;; *) echo "FCVT_EMITTER_FAIL native AArch64 host required" >&2; exit 1;; esac
work="$(mktemp -d /tmp/b2-fcvt-emitter-XXXXXX)"; trap 'rm -rf "$work"' EXIT
"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror "$SCRIPT_DIR/emitter-fcvt-conformance.cpp" -o "$work/probe"
"$work/probe"
