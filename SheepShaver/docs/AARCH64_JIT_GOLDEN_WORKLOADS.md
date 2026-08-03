# SheepShaver AArch64 JIT — Golden Workloads

## Purpose

This document defines the canonical workloads that validate the SheepShaver PPC JIT.

A JIT change is not good because it moves the frontier.
A JIT change is good if it improves or preserves these workloads.

---

## Workload 1: Interpreter parity (opcode equivalence harness)

**What it tests**: Exact semantic parity between interpreter and JIT for every implemented opcode.

**How to run**:
```bash
cd /workspace/projects/macemu/SheepShaver
SS_USE_JIT=1 make test-opcodes
# or directly: bash jit-test/run.sh
```

**Pass condition**:
- The 298 ordered vectors run once in interpreter mode (`SS_USE_JIT=0`) and once in production-JIT mode (`SS_USE_JIT=1`); the two `REGDUMP`s must be identical
- Five focused regressions additionally compare interpreter mode with the single-block `SS_TEST_JIT=1` direct-JIT path
- Production-JIT is the real dispatch-loop proof for branch/loop re-dispatch; the direct path stops at the first branch terminator
- `METRIC pass=303 fail=0 total=303 score=100`

**Important**: until 2026-06-22 the main loop ran each vector twice in the default
(JIT) mode and compared the two runs — a JIT-vs-JIT *determinism* check that passed any
deterministically-wrong codegen. Converting it to interp-vs-production-JIT *equivalence*
immediately surfaced four masked codegen bugs (nand always returned 0xFFFFFFFF; addme/
subfme double-counted carry; divw diverged on architecturally-undefined inputs), now
fixed. Always run this (the real equivalence form) before and after any opcode handler
or codegen change.

**Status**: ✅ 303/303 interpreter-vs-JIT equivalence cases at the accepted 2026-08-02 gate: 298 ordered interpreter-vs-production-JIT vectors plus five focused interpreter-vs-direct-JIT regressions. Coverage includes RA-width, string/multiple, SPR/FPSCR/FPU, PPC64 and AltiVec delegation, FP edge cases, lane-order/control-mask cases, CR6 dotted-vector behaviour, signed `addis`/`lis`, `bcctr` CTR-decrement behaviour, and the focused `srawi`/overflow/memory regressions. `jit-test/run.sh` is the authoritative inventory.

---

## Workload 2: Boot to desktop (interpreter)

**What it tests**: Full Mac OS 7.5 boot through ROM init, extension loading, Finder launch.
Validates: EMUL_OP handling, interrupt dispatch, block boundaries, memory model.

**How to run**:
```bash
cd /workspace/projects/macemu/SheepShaver
make run-tmux TMUX_SESSION=ss-boot-interp PREFS_DIR=/tmp/ss-boot-interp VNC_PORT=5999
# Wait ~12s, connect VNC, verify desktop visible
```

**Pass condition**: Mac OS desktop visible via VNC. No SIGSEGV.

**Status**: ✅ Stable. Must not regress when any JIT dispatch path is changed.

---

## Workload 3: Boot to desktop (JIT)

**What it tests**: Same as Workload 2 but with SS_USE_JIT=1.
Additionally validates: JIT dispatch loop, PPCR_PC after JIT call, spcflag handling, block cache.

**How to run**:
```bash
cd /workspace/projects/macemu/SheepShaver
make run-jit-tmux TMUX_SESSION=ss-boot-jit PREFS_DIR=/tmp/ss-boot-jit VNC_PORT=5999
# Wait ~12s, connect VNC, verify desktop visible
```

**Pass condition**: Mac OS desktop visible via VNC. No SIGSEGV. Crash log clean.

**Status**: ✅ Under strict JIT (`SS_USE_JIT=1`) the emulator boots through ROM init, extension
loading and Finder launch to a **holding desktop** (Finder menu bar + Apple menu navigable) with
GATE3=0 (no bad-selector dispatch) and no crash markers. An earlier gated run after the then-current
299-vector fix batch captured VNC screenshots at 125/140/155s and held alive; its historical
compile/lookup counters reported `blocks=100000 complete=89360`, `hit=519213 miss=10640`, and one
8 MB code-cache flush. Do not interpret those compile/lookup counters as the later exact retired-instruction
coverage schema. The canonical retained 900-second gate subsequently measured zero interpreter fallback
for the bounded desktop/VNC workload (`AARCH64_JIT_ZERO_FALLBACK_GATE_20260704.md`). Residual: a
cosmetic QuickDraw text-blit divergence (“black blocks” behind dialog text) remains under investigation;
it does not affect boot stability or desktop hold. The later bounded register-loop benchmark is documented
separately and does not quantify this boot/desktop workload; see `AARCH64_JIT_BENCHMARK_RESULT_20260802.md`.

---

## Workload 4: ROM harness

**What it tests**: Broad PPC opcode coverage via random ROM code execution.
Validates: arithmetic, branches, memory ops, FPU basics across wide input range.

**How to run**:
```bash
cd /workspace/projects/macemu/SheepShaver
make test-rom
```

**Pass condition**: No SIGSEGV. Score >= 95%.

**Status**: ✅ Maintained.

---

## Workload 5: VNC interaction smoke

**What it tests**: VNC connection, mouse/keyboard event delivery to Mac OS.
Validates: threading, ADB injection, SDL event drain, VNC framebuffer update.

**How to run**:
```bash
cd /workspace/projects/macemu/SheepShaver
make run-tmux
# Connect VNC, click desktop icons, type text

# Shared CI/story validation from the repository root:
cd /workspace/projects/macemu
qa/tests/vnc/run.js \
  --emulator sheepshaver \
  --features qa/tests/vnc/stories \
  --artifacts /tmp/sheepshaver-vnc-noop
```

**Pass condition**: Clicks and keystrokes reach Mac OS. No crash on input events. Shared VNC stories produce structured artifacts and can be converted to PDF reports.

**Status**: ✅ Stable after VNC threading fix (commit a0f4cc7c). The shared runner defaults to `noop`; a real backend should reuse the same `qa/tests/vnc/lib/vnc-driver.js` contract.

---

## Workload 6: Speedometer 4.02 (PPC-native)

**What it tests**: Full PPC-native benchmark workload. Validates JIT correctness and performance
across CPU-intensive code paths (arithmetic, FPU, string, graphics primitives).

**How to run**:
```bash
cd /workspace/projects/macemu/SheepShaver
make run-tmux PREFS_DIR=/tmp/ss-bench
# Connect VNC
# Navigate Benchmark.hda → Speedometer 4.02
# Run benchmark, read scores
```

**Pass condition**: Completes all benchmark categories without crash. Reports valid scores.

**JIT maturity ladder** (per JIT-APPROACH-RESET):
- Interpreter score: historical baseline
- JIT with containment gates: correctness first; no full-system speedup is inferred from coverage
- JIT with block cache/chaining: hot-block reuse and direct chaining are implemented, but performance remains workload-dependent
- Register allocation is broadened to memory-touching blocks (~72% of compiled blocks) through per-access barriers, and `icbi` cache-flush thrash was reduced (~3600 → ~54 flushes/boot)
- The reviewed bounded `ss-ppc-register-loop-v1` result is warm steady-state and dispatch-heavy: direct JIT took 1.888748037× interpreter time. It is not a Speedometer or application result.

**Status**: ⚠️ Block cache/chaining is implemented and the JIT holds the Finder desktop. Historical MacBench/Speedometer scores are not a current repeatable gate, and the 2026-08-02 microbenchmark must not be substituted for an in-guest application benchmark.

---

## Workload 7: Application compatibility smoke (Prince of Persia)

**What it tests**: 68K application compatibility via Mac OS 68K-in-PPC emulator in ROM.
Validates: EMUL_OP dispatch, resource manager, 68K→PPC context switches.

**How to run**:
```bash
cd /workspace/projects/macemu/SheepShaver
make run-tmux PREFS_DIR=/tmp/ss-bench
# Connect VNC, launch Prince of Persia from Benchmark.hda
```

**Pass condition**: Game starts, intro screen renders without crash.

**Status**: ⚠️ Crashes during `PatchNativeResourceManager` when loading game resources.
Root cause: GetNamedResource/Get1NamedResource native hooks use invalid tvec for this ROM/OS path.
Fix: those two hooks disabled (commit fbb716a0). Residual crash is in Mac ROM/68K emulator path.

---

## Shared QA/reporting layer

SheepShaver should reuse the repository-level VNC/Gherkin tooling rather than growing a separate story tree:

- Shared stories: `qa/tests/vnc/stories/`
- SheepShaver profile: `qa/tests/vnc/profiles/sheepshaver.json`
- Deterministic screenshot assertions: `qa/tests/vnc/tools/screenshot-read.js`
- PDF report generator: `qa/tests/vnc/tools/generate-pdf-report.mjs`

The same user stories should cover desktop reachability, app/control-panel launch, typing, network panel inspection, desktop soak, screenshot assertions, diagnostics, and report generation. SheepShaver-specific launch details belong in the profile, Makefile targets, or a matrix wrapper, not in duplicated Gherkin stories.

---

## Maturity ladder

A change is mature when all workloads below it are green:

```
L0  Interpreter-only boot                  (Workload 2 green)
L1  JIT dispatch enabled, complete-block gate present  (Workload 3 progresses)
L2  Block cache/chaining added                         (hot-loop + boot-progress workloads green)
L3  Lazy CR0/register allocation revalidated           (all harnesses green + boot proof) — ACHIEVED:
    lazy CR0 active (callee-saved x19), RA broadened to memory-touching blocks via per-access
    barrier; harness 303/303 + strict-JIT desktop holds
L4  Complete-block policy revisited only with proof     (all fallback/barrier semantics audited)
```

Do not report performance numbers until the workload's maturity level is declared.

---

## Known blockers

| Workload | Blocker |
|----------|---------|
| 3 (JIT boot) | Desktop holds under strict JIT; residual cosmetic QuickDraw text-blit divergence only |
| 6 (Speedometer) | No current repeatable in-guest score gate; the bounded register-loop result is not a substitute |
| 7 (PoP) | PatchNativeResourceManager crash in ROM path |
