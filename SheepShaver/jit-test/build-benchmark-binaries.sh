#!/usr/bin/env bash
# Build separate timing and census SheepShaver binaries from the same source tree.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UNIX_DIR="$ROOT/src/Unix"
cd "$UNIX_DIR"
[[ -f Makefile && -f config.h ]] || {
    echo 'configure SheepShaver/src/Unix before building benchmark binaries' >&2
    exit 2
}

# Build the production/timing binary normally. It contains no SS_JIT_BENCH_CENSUS
# observer increments in its compiled code.
make -j"$(nproc)" SheepShaver
cp -f SheepShaver SheepShaver-bench-timing

# Recompile only the three census-aware translation units under a separate name,
# then relink from the same object set without disturbing production objects.
CXX=${CXX:-g++}
COMMON=(-I../kpx_cpu/include -I../kpx_cpu/src -DUSE_AARCH64_JIT
        -I../kpx_cpu/src/cpu/jit/aarch64 -DUSE_JIT -I../include -I.
        -I../CrossPlatform -I../slirp -DHAVE_CONFIG_H -D_REENTRANT
        '-DDATADIR="/usr/share/SheepShaver"' -g -O2 -I/usr/include/SDL2
        -DSS_JIT_BENCH_CENSUS)
"$CXX" "${COMMON[@]}" -c ../kpx_cpu/src/cpu/jit/aarch64/ppc-jit.cpp -o obj/ppc-jit-census.o
"$CXX" "${COMMON[@]}" -c ../kpx_cpu/src/cpu/ppc/ppc-cpu.cpp -o obj/ppc-cpu-census.o
"$CXX" "${COMMON[@]}" -c ../kpx_cpu/sheepshaver_glue.cpp -o obj/sheepshaver_glue-census.o

link_line=$(make -n -B SheepShaver | grep -E '^g\+\+ -o SheepShaver ' | tail -1)
[[ -n "$link_line" ]] || { echo 'could not extract Makefile link line' >&2; exit 2; }
link_line=${link_line/obj\/ppc-jit.o/obj\/ppc-jit-census.o}
link_line=${link_line/obj\/ppc-cpu.o/obj\/ppc-cpu-census.o}
link_line=${link_line/obj\/sheepshaver_glue.o/obj\/sheepshaver_glue-census.o}
link_line=${link_line/g++ -o SheepShaver /"$CXX" -o SheepShaver-bench-census }
eval "$link_line"

sha256sum SheepShaver-bench-timing SheepShaver-bench-census
