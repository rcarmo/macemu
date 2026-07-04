# SheepShaver AArch64 JIT app-coverage attempt — 2026-07-04

## Verdict

**Canonical desktop/VNC zero-fallback gate remains complete. App-coverage gate is not claimed.**

Two app-coverage attempts kept the JIT ratio counters green, but the VNC automation evidence was not strong enough to declare a real application-workload gate met. Treat this as a harness-limited confidence attempt, not a new milestone.

No JIT/source change was made for these attempts.

## Baseline already locked

The canonical idle desktop/VNC gate is recorded separately in:

```text
SheepShaver/docs/AARCH64_JIT_ZERO_FALLBACK_GATE_20260704.md
commit 174d740d SheepShaver docs: record zero-fallback desktop gate
```

That gate is still the valid milestone:

```text
canonical OldWorld HD200MB VNC desktop
SS_USE_JIT=1
SS_JIT_REENTRANT_DIRECT unset
exec_normal_blocks=0
exec_normal_insns=0
skip_jit=0
gate3=0
VNC desktop screenshots at 600s/900s
```

## App attempt 1

Artifact:

```text
/workspace/reports/sheepshaver/validation/20260704T110619Z-jit-default-app-coverage-vnc
```

Config:

```text
HEAD=174d740d
SS_USE_JIT=1
SS_JIT_REENTRANT_DIRECT unset
SS_JIT_RATIO=1
SS_JIT_HIST=1
SS_JIT_SKIP_HIST=1
SS_JIT_SKIP_LOG=1
SS_JIT_FAILPROBE=1
apps intended: Calculator, Note Pad via Apple menu
```

Final retained ratio:

```text
PPC-JIT-A64-RATIO: native_dispatch=2001380000 exec_normal_blocks=0 native_dispatch_pct=100.000000 native_insns_known=8773215631 exec_normal_insns=0 native_known_insn_pct=100.000000 skip_jit=0 gate3=0
```

Retained driver/capture evidence:

```text
2026-07-04T11:09:22.515Z connected 640x480
2026-07-04T11:09:22.602Z desktop_wait=true
2026-07-04T11:09:23.667Z launch Calculator via Apple menu
capture_180s=ok ... screen-180s.png
```

Limitation: the 180s screenshot showed the boot-time “About Mac OS” document/static menu image rather than a confirmed launched Calculator/Note Pad window. The wrapper did not retain post-launch screenshots or a final filtered summary. The green ratio is useful, but this is not sufficient application-coverage proof.

## App attempt 2

Artifact:

```text
/workspace/reports/sheepshaver/validation/20260704T120447Z-jit-default-app-coverage-vnc2
```

Config:

```text
HEAD=174d740d
SS_USE_JIT=1
SS_JIT_REENTRANT_DIRECT unset
SS_JIT_RATIO=1
SS_JIT_HIST=1
SS_JIT_SKIP_HIST=1
SS_JIT_SKIP_LOG=1
SS_JIT_FAILPROBE=1
apps intended: Calculator, Note Pad via real Apple menu after closing About document
duration_target=420s
```

Final retained ratio:

```text
PPC-JIT-A64-RATIO: native_dispatch=1708636000 exec_normal_blocks=0 native_dispatch_pct=100.000000 native_insns_known=7492183578 exec_normal_insns=0 native_known_insn_pct=100.000000 skip_jit=0 gate3=0
```

Limitation: no post-launch VNC screenshots or app-driver completion log were retained. The counter stream again stayed green, but the application workload itself was not proven visually.

## Honest interpretation

The JIT signal in both attempts is encouraging:

```text
exec_normal_blocks=0
exec_normal_insns=0
native_dispatch_pct=100.000000
native_known_insn_pct=100.000000
skip_jit=0
gate3=0
```

However, because the VNC automation did not retain a confirmed real-app screenshot/window, the app-coverage gate is **not** declared met. The only declared milestone remains the canonical desktop/VNC no-interpreter-fallback gate.

## Recommended next step

Hold for Rui direction. If broader app confidence is requested later, rerun a smaller app gate when the shared slot is free:

1. Boot to desktop under the same zero-fallback env.
2. Close the boot-time About document.
3. Launch exactly one easy-to-confirm app, preferably Calculator from the Apple menu.
4. Immediately capture a screenshot proving the app window is visible.
5. Hold 120–300s and require:

```text
exec_normal_blocks=0
exec_normal_insns=0
skip_jit=0
gate3=0
PPC-JIT-A64-FAILPROBE=0
PPC-JIT-A64-CUM=0
crash_markers=0
```

If VNC scripting remains unreliable, do not spend more time on it unless Rui explicitly asks. The canonical desktop/VNC gate is already met and recorded.
