#!/bin/bash
# Extract the production spcflags/do-nothing raw boundary and execute both
# branch outcomes at the imm12/register retired-cycle lowering boundary.
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$D/.." && pwd)"
case "$(uname -m)" in
    aarch64|arm64) ;;
    *) echo "RAW_MAYBE_DO_NOTHING_FAIL native AArch64 host required" >&2; exit 1 ;;
esac
W="$(mktemp -d /tmp/b2-raw-maybe-do-nothing-XXXXXX)"
trap 'rm -rf "$W"' EXIT
SOURCE="$ROOT/BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.cpp"
awk '
  /^STATIC_INLINE void LOAD_U32\(int r, uae_u32 val\)/ { capture="load32" }
  /^STATIC_INLINE void LOAD_U64\(int r, uae_u64 val\)/ { capture="load64" }
  /^STATIC_INLINE void compemu_raw_maybe_do_nothing\(IM32 cycles\)/ { capture="body" }
  capture { print }
  capture == "load32" && /^}$/ { capture="" }
  capture == "load64" && /^}$/ { capture="" }
  capture == "body" && /^}$/ { capture="" }
' "$SOURCE" >"$W/raw-maybe-do-nothing.inc"
grep -q '^STATIC_INLINE void LOAD_U32(int r, uae_u32 val)' "$W/raw-maybe-do-nothing.inc"
grep -q '^STATIC_INLINE void LOAD_U64(int r, uae_u64 val)' "$W/raw-maybe-do-nothing.inc"
grep -q '^STATIC_INLINE void compemu_raw_maybe_do_nothing(IM32 cycles)' "$W/raw-maybe-do-nothing.inc"
test "$(grep -c '^STATIC_INLINE void LOAD_U32' "$W/raw-maybe-do-nothing.inc")" -eq 1
test "$(grep -c '^STATIC_INLINE void LOAD_U64' "$W/raw-maybe-do-nothing.inc")" -eq 1
test "$(grep -c '^STATIC_INLINE void compemu_raw_maybe_do_nothing' "$W/raw-maybe-do-nothing.inc")" -eq 1
cp "$D/raw-maybe-do-nothing-conformance.cpp" "$W/probe.cpp"
"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror \
    -I"$ROOT/BasiliskII/src/uae_cpu_2026/compiler" "$W/probe.cpp" -o "$W/probe"
"$W/probe"
