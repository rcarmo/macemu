#!/bin/bash
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
case "$(uname -m)" in aarch64|arm64);; *) exit 1;; esac
W="$(mktemp -d /tmp/b2-emitter-word-XXXXXX)"; trap 'rm -rf "$W"' EXIT
"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror "$D/emitter-word-conformance.cpp" -o "$W/probe"
"$W/probe"
