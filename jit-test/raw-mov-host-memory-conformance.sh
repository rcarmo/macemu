#!/bin/bash
# Extract the production raw integer host-memory move boundaries and execute
# pointer-width, direct-regstruct, and absolute-address paths natively.
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$D/.." && pwd)"
case "$(uname -m)" in
    aarch64|arm64) ;;
    *) echo "RAW_MOV_HOST_MEMORY_FAIL native AArch64 host required" >&2; exit 1 ;;
esac
W="$(mktemp -d /tmp/b2-raw-mov-host-memory-XXXXXX)"
trap 'rm -rf "$W"' EXIT
SOURCE="$ROOT/BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.cpp"
awk '
  /^STATIC_INLINE void LOAD_U32\(int r, uae_u32 val\)/ { capture="helper32" }
  /^STATIC_INLINE void LOAD_U64\(int r, uae_u64 val\)/ { capture="helper64" }
  /^LOWFUNC\(NONE,WRITE,2,compemu_raw_mov_l_mi,/ { capture="body" }
  /^LOWFUNC\(NONE,WRITE,2,compemu_raw_mov_l_mr,/ { capture="body" }
  /^LOWFUNC\(NONE,READ,2,compemu_raw_mov_l_rm,/ { capture="body" }
  capture { print }
  capture == "helper32" && /^}$/ { capture="" }
  capture == "helper64" && /^}$/ { capture="" }
  capture == "body" && /^LENDFUNC\(NONE,WRITE,2,compemu_raw_mov_l_mi,/ { capture="" }
  capture == "body" && /^LENDFUNC\(NONE,WRITE,2,compemu_raw_mov_l_mr,/ { capture="" }
  capture == "body" && /^LENDFUNC\(NONE,READ,2,compemu_raw_mov_l_rm,/ { capture="" }
' "$SOURCE" >"$W/raw-mov-host-memory.inc"
for name in compemu_raw_mov_l_mi compemu_raw_mov_l_mr compemu_raw_mov_l_rm; do
  grep -q "^LOWFUNC(.*,$name," "$W/raw-mov-host-memory.inc"
done
test "$(grep -c '^STATIC_INLINE void LOAD_U32' "$W/raw-mov-host-memory.inc")" -eq 1
test "$(grep -c '^STATIC_INLINE void LOAD_U64' "$W/raw-mov-host-memory.inc")" -eq 1
test "$(grep -c '^LOWFUNC' "$W/raw-mov-host-memory.inc")" -eq 3
test "$(grep -c '^LENDFUNC' "$W/raw-mov-host-memory.inc")" -eq 3
cp "$D/raw-mov-host-memory-conformance.cpp" "$W/probe.cpp"
"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror \
    -I"$ROOT/BasiliskII/src/uae_cpu_2026/compiler" "$W/probe.cpp" -o "$W/probe"
"$W/probe"
