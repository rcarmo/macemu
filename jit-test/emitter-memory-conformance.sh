#!/usr/bin/env bash
set -euo pipefail
if [[ "$(uname -m)" != "aarch64" && "$(uname -m)" != "arm64" ]]; then
  echo "MEMORY_EMITTER_FAIL native AArch64 host required" >&2
  exit 1
fi
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d /tmp/b2-emitter-memory.XXXXXX)
trap 'rm -rf "$tmp"' EXIT
"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror \
  "$root/jit-test/emitter-memory-conformance.cpp" -o "$tmp/emitter-memory-conformance"
"$tmp/emitter-memory-conformance"
