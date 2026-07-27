#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
case "$(uname -m)" in aarch64|arm64) ;; *) echo "logical-immediate emitter conformance requires AArch64" >&2; exit 1;; esac
TMP="$(mktemp -d /tmp/b2-emitter-logimm-XXXXXX)"
trap 'rm -rf "$TMP"' EXIT
c++ -std=c++17 -O2 -Wall -Wextra -Werror "$ROOT/jit-test/emitter-logical-immediate-conformance.cpp" -o "$TMP/probe"
"$TMP/probe"
