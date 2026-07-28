#!/bin/bash
# Extract the production fixed-register JIT prologue boundary and execute it
# natively against 64-bit register-structure and NATMEM_OFFSET values.
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$D/.." && pwd)"
case "$(uname -m)" in
    aarch64|arm64) ;;
    *) echo "RAW_INIT_REGSTRUCT_FAIL native AArch64 host required" >&2; exit 1 ;;
esac
W="$(mktemp -d /tmp/b2-raw-init-regstruct-XXXXXX)"
trap 'rm -rf "$W"' EXIT
SOURCE="$ROOT/BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.cpp"
awk '
  /^STATIC_INLINE void LOAD_U64\(int r, uae_u64 val\)/ { capture="helper" }
  /^LOWFUNC\(NONE,NONE,1,compemu_raw_init_r_regstruct,/ { capture="body" }
  capture { print }
  capture == "helper" && /^}/ { capture="" }
  capture == "body" && /^LENDFUNC\(NONE,NONE,1,compemu_raw_init_r_regstruct,/ { capture="" }
' "$SOURCE" >"$W/raw-init-regstruct.inc"
grep -q '^STATIC_INLINE void LOAD_U64(int r, uae_u64 val)' "$W/raw-init-regstruct.inc"
grep -q '^LOWFUNC(NONE,NONE,1,compemu_raw_init_r_regstruct,' "$W/raw-init-regstruct.inc"
grep -q '^LENDFUNC(NONE,NONE,1,compemu_raw_init_r_regstruct,' "$W/raw-init-regstruct.inc"
test "$(grep -c '^STATIC_INLINE void LOAD_U64' "$W/raw-init-regstruct.inc")" -eq 1
test "$(grep -c '^LOWFUNC' "$W/raw-init-regstruct.inc")" -eq 1
test "$(grep -c '^LENDFUNC' "$W/raw-init-regstruct.inc")" -eq 1
cp "$D/raw-init-regstruct-conformance.cpp" "$W/probe.cpp"
"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror \
    -I"$ROOT/BasiliskII/src/uae_cpu_2026/compiler" "$W/probe.cpp" -o "$W/probe"
"$W/probe"
