#!/bin/bash
# Extract the production raw condition-only branch boundary and execute its
# complete integer/FP truth table with canonical and inverted incoming carry.
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$D/.." && pwd)"
case "$(uname -m)" in
    aarch64|arm64) ;;
    *) echo "RAW_JCC_OPONLY_FAIL native AArch64 host required" >&2; exit 1 ;;
esac
W="$(mktemp -d /tmp/b2-raw-jcc-oponly-XXXXXX)"
trap 'rm -rf "$W"' EXIT
SOURCE="$ROOT/BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.cpp"
awk '
  /^#define FIX_INVERTED_CARRY/ { capture="macro" }
  /^STATIC_INLINE void compemu_raw_jcc_l_oponly\(int cc\)/ { capture="body" }
  capture { print }
  capture == "macro" && /^  }$/ { capture="" }
  capture == "body" && /^}$/ { capture="" }
' "$SOURCE" >"$W/raw-jcc-oponly.inc"
grep -q '^#define FIX_INVERTED_CARRY' "$W/raw-jcc-oponly.inc"
grep -q '^STATIC_INLINE void compemu_raw_jcc_l_oponly(int cc)' "$W/raw-jcc-oponly.inc"
test "$(grep -c '^#define FIX_INVERTED_CARRY' "$W/raw-jcc-oponly.inc")" -eq 1
test "$(grep -c '^STATIC_INLINE void compemu_raw_jcc_l_oponly' "$W/raw-jcc-oponly.inc")" -eq 1
test "$(grep -c 'case NATIVE_CC_F_' "$W/raw-jcc-oponly.inc")" -eq 16
cp "$D/raw-jcc-oponly-conformance.cpp" "$W/probe.cpp"
"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror \
    -I"$ROOT/BasiliskII/src/uae_cpu_2026/compiler" "$W/probe.cpp" -o "$W/probe"
"$W/probe"
