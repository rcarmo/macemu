# SheepShaver AArch64 JIT zero-fallback desktop gate — 2026-07-04

## Verdict

**GREEN / bounded gate MET** for the canonical SheepShaver OldWorld HD200MB desktop/VNC workload.

Current default AArch64 JIT reaches and holds the canonical Mac OS VNC desktop with no measured interpreter fallback over a 900s run.

This is a bounded runtime validation. It does **not** claim arbitrary application coverage, benchmark speedup, CPU/RAM improvement, or heavy AltiVec/PPC64 workload coverage.

## Source

```text
repo=/workspace/projects/macemu
HEAD=5ac684b5
origin=5ac684b5
commit=5ac684b5 SheepShaver JIT: add terminal fail probe
```

The gate relies on the current default product path: `SS_JIT_REENTRANT_DIRECT` is unset. Do not interpret this result as a measurement of the diagnostic opt-out path (`SS_JIT_REENTRANT_DIRECT=0`).

## Runtime artifact

```text
/workspace/reports/sheepshaver/validation/20260704T100557Z-jit-default-zero-fallback-vnc
```

Important files in that artifact:

```text
filtered-summary.txt
last-ratio.txt
marker-counts.txt
ratio-parsed.txt
vnc/screen-600s.png
vnc/screen-900s.png
```

Raw full stderr was intentionally not retained/attached as a useful report artifact; use the filtered summary and marker counts.

## Configuration

```text
SS_USE_JIT=1
SS_JIT_REENTRANT_DIRECT unset
SS_JIT_RATIO=1
SS_JIT_HIST=1
SS_JIT_SKIP_HIST=1
SS_JIT_SKIP_LOG=1
SS_JIT_FAILPROBE=1
SDL_AUDIODRIVER=dummy
SDL_VIDEODRIVER=x11
GDK_BACKEND=x11

ROM=/workspace/assets/sheepshaver/ppc-roms/PowerMac-9500-OldWorld.rom
Disk=scratch copy of /workspace/fixtures/basilisk/images/HD200MB
VNC=127.0.0.1:5999
```

Prefs used the canonical desktop settings:

```text
ramsize 134217728
screen win/640/480
displaycolordepth 8
nosound true
nocdrom true
nogui true
ignoreillegal true
ignoresegv true
vncserver true
vncport 5999
cpuclock 500
```

## Build and harness gate

```text
SheepShaver/src/Unix make -j4: PASS
SheepShaver/jit-test/run.sh: PASS
pass=303 fail=0 total=303 score=100
```

## Desktop hold

```text
900s target reached
alive_before_kill=1
VNC captures: 120s, 300s, 600s, 900s all succeeded
600s and 900s screenshots visibly show Finder desktop/menu bar/icons
```

Image statistics from the artifact:

```text
screen-120s.png size=640x480 mean=161.46,161.42,161.77 stddev=80.12,80.12,80.29
screen-300s.png size=640x480 mean=161.46,161.42,161.77 stddev=80.12,80.12,80.29
screen-600s.png size=640x480 mean=130.60,130.58,130.55 stddev=41.53,41.52,41.54
screen-900s.png size=640x480 mean=130.60,130.58,130.55 stddev=41.53,41.52,41.54
```

## Final ratio

```text
PPC-JIT-A64-RATIO: native_dispatch=4363032000 exec_normal_blocks=0 native_dispatch_pct=100.000000 native_insns_known=19108887569 exec_normal_insns=0 native_known_insn_pct=100.000000 skip_jit=0 gate3=0
```

Parsed counters:

```text
native_dispatch=4363032000
exec_normal_blocks=0
native_dispatch_pct=100.000000
native_insns_known=19108887569
exec_normal_insns=0
native_known_insn_pct=100.000000
skip_jit=0
gate3=0
```

## Forbidden marker counts

```text
JIT_FALLBACK=0
PPC_JIT_A64_SKIP=0
PPC_JIT_A64_FAILPROBE=0
PPC_JIT_A64_CUM=0
GATE3_or_handing=0
crash_markers=0
hist_nonzero_blocks=0
```

The live wrapper mistakenly copied zero-valued histogram status lines into `forbidden.log`; exact marker grep is represented above. Non-zero histogram blocks were zero.

## Interpretation

This confirms that the earlier 2026-06-24 “desktop interpreter-dominant” histogram is stale for current `master`. That histogram was valid for the pre-fix path, but current default execution includes the later fixes for interpreter-chain retry, FPSCR/FP helper coverage, slow-path store byte order, and default-on reentrant direct-JIT.

For the canonical idle desktop/VNC workload, the no-interpreter-fallback gate is met. At the time, application coverage was proposed as the next broader-confidence gate; the subsequent attempt did not meet its evidence threshold (`AARCH64_JIT_APP_COVERAGE_ATTEMPT_20260704.md`). A later, separately authorised bounded register-loop benchmark measured performance without making any application-coverage claim (`AARCH64_JIT_BENCHMARK_RESULT_20260802.md`).

## Safe wording

Use this bounded wording:

```text
SheepShaver AArch64 JIT current default path reaches and holds the canonical OldWorld HD200MB VNC desktop with no measured interpreter fallback: exec_normal_blocks=0, exec_normal_insns=0, skip_jit=0, gate3=0, no JIT_FALLBACK/FAILPROBE/CUM/crash markers, and no non-zero exec-normal histogram blocks over a 900s full desktop hold.
```

Do not append speedup, CPU/RAM, or broad app-coverage claims without separate benchmark/application gates.
