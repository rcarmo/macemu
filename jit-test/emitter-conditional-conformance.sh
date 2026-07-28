#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -m)" != "aarch64" && "$(uname -m)" != "arm64" ]]; then
  echo "CONDITIONAL_EMITTER_FAIL native AArch64 host required" >&2
  exit 1
fi

root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d /tmp/b2-emitter-conditional.XXXXXX)
trap 'rm -rf "$tmp"' EXIT

"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror \
  "$root/jit-test/emitter-conditional-conformance.cpp" \
  -o "$tmp/emitter-conditional-conformance"
"$tmp/emitter-conditional-conformance"
