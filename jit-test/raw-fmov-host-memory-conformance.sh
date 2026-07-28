#!/bin/bash
# Compile the production raw host-memory FPU spill/reload bodies against the
# production AArch64 encoder, then execute both address branches natively.
set -euo pipefail
D="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$D/.." && pwd)"
case "$(uname -m)" in
    aarch64|arm64) ;;
    *) echo "RAW_FMOV_HOST_MEMORY_FAIL native AArch64 host required" >&2; exit 1 ;;
esac
W="$(mktemp -d /tmp/b2-raw-fmov-host-memory-XXXXXX)"
trap 'rm -rf "$W"' EXIT
SOURCE="$ROOT/BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.cpp"
awk '
  /^STATIC_INLINE void LOAD_U64\(int r, uae_u64 val\)/ { capture="helper" }
  /^LOWFUNC\(NONE,WRITE,2,compemu_raw_fmov_mr_drop,/ { capture="body" }
  /^LOWFUNC\(NONE,READ,2,compemu_raw_fmov_rm,/ { capture="body" }
  capture { print }
  capture == "helper" && /^}/ { capture="" }
  capture == "body" && /^LENDFUNC\(NONE,WRITE,2,compemu_raw_fmov_mr_drop,/ { capture="" }
  capture == "body" && /^LENDFUNC\(NONE,READ,2,compemu_raw_fmov_rm,/ { capture="" }
' "$SOURCE" >"$W/raw-fmov-host-memory.inc"
grep -q '^STATIC_INLINE void LOAD_U64(int r, uae_u64 val)' "$W/raw-fmov-host-memory.inc"
grep -q '^LOWFUNC(NONE,WRITE,2,compemu_raw_fmov_mr_drop,' "$W/raw-fmov-host-memory.inc"
grep -q '^LOWFUNC(NONE,READ,2,compemu_raw_fmov_rm,' "$W/raw-fmov-host-memory.inc"
test "$(grep -c '^LOWFUNC' "$W/raw-fmov-host-memory.inc")" -eq 2
test "$(grep -c '^LENDFUNC' "$W/raw-fmov-host-memory.inc")" -eq 2
test "$(grep -Ec '^LOWFUNC\(NONE,(WRITE,2,compemu_raw_fmov_mr_drop|READ,2,compemu_raw_fmov_rm),' "$W/raw-fmov-host-memory.inc")" -eq 2
test "$(grep -Ec '^LENDFUNC\(NONE,(WRITE,2,compemu_raw_fmov_mr_drop|READ,2,compemu_raw_fmov_rm),' "$W/raw-fmov-host-memory.inc")" -eq 2
cp "$D/raw-fmov-host-memory-conformance.cpp" "$W/probe.cpp"
"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror \
    -I"$ROOT/BasiliskII/src/uae_cpu_2026/compiler" "$W/probe.cpp" -o "$W/probe"
"$W/probe"
