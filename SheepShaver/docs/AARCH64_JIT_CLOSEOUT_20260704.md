# SheepShaver AArch64 JIT close-out — 2026-07-04

## Verdict

**DONE / PARKED** for the canonical SheepShaver OldWorld HD200MB desktop/VNC completion gate.

Rui's close-out direction is to stop SheepShaver JIT active work here. Do not pursue broader application-launch coverage, performance measurements, CPU/RAM comparisons, or further optimisation unless Rui explicitly opens a follow-up.

## Completion commits

```text
174d740d SheepShaver docs: record zero-fallback desktop gate
04897075 SheepShaver docs: record app coverage attempt
```

`174d740d` is the MET gate: current default AArch64 JIT reaches and holds the canonical Mac OS desktop/VNC workload with measured zero interpreter fallback.

`04897075` records the app-coverage caveat: application-launch attempts kept the JIT counters green, but the retained VNC automation evidence was not sufficient to claim a real app-workload gate. App coverage is therefore explicitly **not claimed**.

## Canonical no-fallback artifact

Strict validation artifact:

```text
/workspace/reports/sheepshaver/validation/20260704T100557Z-jit-default-zero-fallback-vnc
```

Linked evidence in that artifact:

```text
filtered-summary.txt
last-ratio.txt
marker-counts.txt
ratio-parsed.txt
vnc/screen-600s.png
vnc/screen-900s.png
```

Recorded validation summary:

```text
workload: canonical OldWorld HD200MB desktop/VNC
SS_USE_JIT=1
SS_JIT_REENTRANT_DIRECT unset
make: PASS
jit-test: 303/303 fail=0 score=100
hold: 900s target reached; emulator alive before kill
VNC: 600s and 900s screenshots show Finder desktop/menu bar/icons
```

Final no-fallback counters:

```text
native_dispatch_pct=100.000000
native_known_insn_pct=100.000000
exec_normal_blocks=0
exec_normal_insns=0
skip_jit=0
gate3=0
JIT_FALLBACK=0
PPC_JIT_A64_SKIP=0
PPC_JIT_A64_FAILPROBE=0
PPC_JIT_A64_CUM=0
GATE3_or_handing=0
crash_markers=0
hist_nonzero_blocks=0
```

## Scope boundary

Claim only this:

```text
SheepShaver AArch64 JIT current default path reaches and holds the canonical OldWorld HD200MB VNC desktop with no measured interpreter fallback over the retained 900s validation run.
```

Do **not** claim:

- arbitrary application coverage;
- Speedometer or other benchmark speedup;
- lower CPU/RAM usage;
- heavy AltiVec/PPC64 workload coverage;
- broader Mac OS app-launch correctness.

## Park state

SheepShaver JIT bring-up is closed on the canonical completion gate and should stand down from the active rotation. Shared CPU/run slot goes back to BasiliskII/Previous unless Rui reopens SheepShaver with a new explicit scope.
