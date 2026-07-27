#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
case "$(uname -m)" in aarch64|arm64) ;; *) echo "transform emitter conformance requires AArch64" >&2; exit 1;; esac
TMP="$(mktemp -d /tmp/b2-emitter-transform-XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
c++ -std=c++17 -O2 -Wall -Wextra -Werror "$ROOT/jit-test/emitter-transform-conformance.cpp" -o "$TMP/probe"
"$TMP/probe"
