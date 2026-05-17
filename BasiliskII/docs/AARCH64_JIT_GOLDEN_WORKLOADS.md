# AArch64 JIT Golden Workloads

## Purpose

This document defines the canonical workloads that validate the BasiliskII AArch64 JIT.

A JIT change is not good because it moves the current frontier.
A JIT change is good if it improves or preserves these workloads.

---

## Workload 1: Interpreter parity in JIT-enabled build

**What it tests**:

- shared helper/interpreter semantics do not change merely because JIT support is compiled in
- build-with-JIT but run-without-native stays aligned with the clean interpreter model

**Why it matters**:

This repository has already seen build-time JIT enablement change shared semantics indirectly.
That is a contract violation even before native codegen is involved.

**Pass condition**:

- no semantic drift between clean interpreter behavior and JIT-enabled interpreter behavior on agreed test surfaces

**Status**:

Must remain mandatory.

---

## Workload 2: Opcode equivalence harness

**What it tests**:

- exact semantic parity for targeted instruction classes
- register/state/flag equivalence between interpreter and JIT execution

**How to run**:

```bash
cd /workspace/projects/macemu
./jit-test/run.sh
```

**Pass condition**:

- all enabled vectors pass
- no new mismatch appears in previously green vectors
- no JIT-only crash in harness mode

**Notes**:

This is the canonical proof for local instruction semantics.
It is not sufficient on its own for whole-runtime correctness.

---

## Workload 3: ROM harness

**What it tests**:

- broad control-flow and instruction-surface correctness
- whether compiled execution can survive real ROM code without depending on UI/hardware side effects

**How to run**:

```bash
cd /workspace/projects/macemu
./jit-test/rom-harness.sh
# or, through the QA matrix wrapper:
BasiliskII/qa/scripts/run-matrix.sh --case optlev2-rom-smoke --timeout 30
```

**Pass condition**:

- no crash
- stable or improved ROM coverage
- no regression in previously stable block classes

**Notes**:

ROM coverage is an important trend signal, but not by itself proof of safe desktop/runtime behavior.

---

## Workload 4: Boot-to-desktop workload

**What it tests**:

- block transitions
- interrupt/timer cadence
- PC ownership across block boundaries
- memory model
- stateful OS startup behavior

**Pass condition**:

- Mac OS boots to desktop on the canonical boot disk image
- VNC/Xvfb display is reachable when the desktop QA profile is used
- no crash
- no permanent wrong-state hang introduced by the JIT change
- screenshots are captured for boot progress and desktop reached milestones

**Notes**:

This is the most important whole-system workload.
If a change regresses this workload, it must be treated as a runtime-contract regression even if the opcode harness improves.

---

## Workload 5: Graphics corruption workload

**What it tests**:

- memory writes into real framebuffer paths
- flag correctness in stateful routines
- interpreter/JIT parity in rendering-sensitive code

**Current canonical example class**:

- titlebar/menu-chrome corruption class already investigated in this repo

**Pass condition**:

- watched pixels match the clean interpreter/no-JIT reference
- no extra overwrite appears in the real VRAM path
- screenshots remain visually identical or acceptably equivalent

**Notes**:

This workload exists because rendering corruption is often a downstream symptom of deeper state/flag bugs.

---

## Workload 6: Allocator / low-memory state workload

**What it tests**:

- stateful boot/allocator/list-management routines
- pointer-family correctness in guest state
- low-memory and metadata mutation discipline

**Current canonical example class**:

- allocator/free-list divergence work already identified in repository notes

**Pass condition**:

- no wrong-family pointer drift in the known low-memory state paths
- no guest heap/allocator metadata corruption introduced by compiled execution

**Notes**:

This is the canonical probe for “almost correct but still poisonous” JIT behavior.

---

## Workload 7: Shared VNC user-story QA

**What it tests**:

- Finder desktop reachability through the same user-visible stories used by SheepShaver
- mouse/keyboard scripting contract
- application/control-panel launch
- desktop soak responsiveness
- failure diagnostics and artifact collection

**How to run**:

```bash
cd /workspace/projects/macemu
qa/tests/vnc/run.js \
  --emulator basiliskii \
  --features qa/tests/vnc/stories \
  --artifacts BasiliskII/qa/artifacts/reports/vnc-noop
```

The default driver is `noop`, which is useful for CI story/report validation. Real desktop validation requires a future non-noop VNC backend behind `qa/tests/vnc/lib/vnc-driver.js`.

**Pass condition**:

- Story runner succeeds for the BasiliskII profile.
- With a real backend, screenshot assertions confirm a non-blank display, expected dimensions, and committed OCR/template anchors where available.
- Failures classify emulator bugs separately from missing guest assets, host permissions, or automation gaps.

---

## Workload 8: Hardware/network/audio QA

**What it tests**:

- safe user-mode networking (`ether slirp` first)
- SDL dummy and real audio paths
- disk image write persistence
- PRAM/time behavior
- display mode changes
- optional CD-ROM/extfs/clipboard paths when assets and permissions allow

**Pass condition**:

- Each attempted device class has a report entry with prefs, logs, screenshots where relevant, and a clear PASS/FAIL/BLOCKED result.
- Privileged host network changes are not required for the default matrix.
- Missing guest tools/assets are documented as such rather than treated as emulator regressions.

---

## Workload 9: Performance benchmark

**What it tests**:

- real delivered speedup on a stable contract state

**Examples**:

- Speedometer / graphics benchmark style workloads
- dispatch/compile counters only after correctness workloads are green

**Pass condition**:

- benchmark runs to completion
- performance is reported together with maturity level

**Rule**:

Do not use unstable frontier builds as the basis for architectural performance conclusions.

---

## Maturity ladder

A change is mature only when it preserves all lower levels.

```text
L0  Clean interpreter baseline stable
L1  JIT-enabled interpreter parity stable
L2  Opcode equivalence harness stable
L3  ROM harness stable
L4  Desktop boot stable
L5  Graphics + allocator/low-memory workloads stable
L6  Shared VNC stories + deterministic screenshot assertions stable
L7  Hardware/network/audio evidence collected for the target profile
L8  Performance benchmark meaningful
```

### Interpretation

- Moving from L2 to L3 is not enough if L4 regresses
- L8 numbers are only meaningful when L0–L7 are green

---

## Change acceptance rules

Every significant BasiliskII JIT change should state which workloads were checked.

### Minimum required by change type

#### Local opcode semantic change
- Workload 2
- relevant subset of Workload 3

#### Boundary / block-exit / chaining change
- Workloads 2, 3, 4
- and usually 5 or 6 if prior evidence touched those areas

#### Flag/liveness change
- Workloads 2, 3, 5, 6

#### Fault/restart/recovery change
- Workloads 3, 4, 6

#### Performance-motivated change
- all correctness, VNC, and hardware evidence workloads first, then Workload 9

---

## Current missing discipline

The repository already has the right ingredients, but they are still too dispersed across:

- bring-up notes
- audit notes
- memory notes
- ad hoc frontier experiments

This file exists to make the validation loop explicit.

---

## Recommended current canonical set for BasiliskII

Until refined further, the working canonical set should be:

1. `jit-test/run.sh` opcode equivalence harness
2. `jit-test/rom-harness.sh` or `BasiliskII/qa/scripts/run-matrix.sh --case optlev2-rom-smoke`
3. `BasiliskII/qa/scripts/run-matrix.sh --case optlev2-desktop-vnc --dry-run` for prefs/manifest generation, then the real desktop run once the VNC backend is wired in
4. `qa/tests/vnc/run.js --emulator basiliskii --features qa/tests/vnc/stories --artifacts BasiliskII/qa/artifacts/reports/vnc-noop` for shared story validation
5. screenshot assertions with `qa/tests/vnc/tools/screenshot-read.js` for dimensions/non-blank/OCR/template checks
6. PDF reporting with `qa/tests/vnc/tools/generate-pdf-report.mjs`
7. one canonical graphics-corruption repro preset
8. one canonical low-memory/allocator-sensitive repro preset
9. one canonical performance benchmark preset

The exact real-VNC launch profile and committed UI templates should be frozen after the first captured desktop run.

---

## Bottom line

The BasiliskII JIT is ready to stop being judged only by frontier movement.
From now on, it should be judged by whether it preserves the golden workloads in the maturity ladder above.
