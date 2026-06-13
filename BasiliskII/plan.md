# BasiliskII AArch64 JIT — next-phase plan

## Goal

Evolve the current BasiliskII ARM64 JIT from a contract-first basic-block engine into a safer, faster chained/trace-capable JIT with:

- stronger block hashing and chain bookkeeping
- explicit validated vs direct chain policy
- trace/region-style compilation on top of canonical blocks
- better register allocation within hot paths
- broader lazy-flags use with explicit ownership rules

This plan is intentionally **harness-first**.
The opcode harness and ROM/test harnesses are the primary acceptance gates for every phase.

---

## Current baseline

What we already have:

- block cache keyed by `cache_tags`
- same-hash collision chains via `next_same_cl`
- dependency-tracked jump patching via `dep[]` / `deplist`
- validated vs direct handler split via:
  - `handler`
  - `direct_handler`
  - `handler_to_use`
  - `direct_handler_to_use`
- a real, if still conservative, block-local register allocator
- partial lazy-flags infrastructure:
  - `live.flags_in_flags`
  - `live.flags_on_stack`
  - `live.flags_are_important`
  - `needed_flags`
- opcode equivalence harness at **301/301 pass**
- strict ROM/steady-state harness green as of 2026-06-13: `DC[64460000] pc=00156f94`, zero fallback/SEGV/verifier/bad-PC markers

What is still missing:

- a fully normalized chain handoff contract
- explicit hot-edge profiling for trace formation
- region/trace objects above the current block layer
- allocator policy aimed at hot-path reuse rather than just local correctness
- consumer-driven lazy flags across larger native windows

---

## Non-negotiable rules

1. **No ROM patches, stub regions, or RAM presets to mask JIT bugs.**
2. **The basic-block JIT remains the semantic authority.**
3. **Trace/region work sits on top of canonical blocks, not instead of them.**
4. **Lazy flags are legal only while ownership is unambiguous.**
5. **Any boundary that can reach helpers, interpreter code, exceptions, or do_nothing paths must see coherent architectural state.**
6. **Every tranche must use the opcode and test harnesses heavily before it is considered real progress.**

---

## Validation contract

## Required harnesses

### 1. Opcode equivalence harness — mandatory on every JIT tranche

Run:

```bash
cd /workspace/projects/macemu
./jit-test/run.sh
```

Required result:

- `pass=301`
- `fail=0`
- `score=100`

This is the primary proof for:

- opcode semantics
- flag semantics
- register/state equivalence
- local JIT correctness

### 2. ROM/test harness — mandatory on every chaining/boundary/trace tranche

Run:

```bash
cd /workspace/projects/macemu
./jit-test/rom-harness.sh
```

This is the primary proof for:

- real block transitions
- chain handoff behavior
- timer/interrupt/block-exit behavior
- robustness beyond isolated opcode vectors

### 3. Golden workload escalation

Before promoting any phase from experiment to default direction, also check the documented BasiliskII golden workloads:

- opcode harness
- ROM harness
- boot/runtime workload(s)
- graphics / allocator-sensitive workloads when the phase touches liveness or lazy flags

---

## Phase order

## Phase 0 — state-safe chaining foundations

### Goal

Finish making block chaining safe enough that future performance work sits on top of explicit architectural boundaries instead of hopeful state leakage.

### Scope

- full PC-triple coherence at all dispatcher/do_nothing/helper boundaries
- explicit chain-side PC ownership on hot handoff paths
- keep `flush(1)` as the authoritative full architectural barrier
- keep helper barriers exact and conservative

### Current status

**Complete for the strict-clean full-JIT baseline.** Keep this phase as a regression contract for future performance work.

This tranche has already started with:

- helper barriers rebuilding the full PC triple
- selective block-entry NZCV restore
- dispatcher/do_nothing side exits materializing a full PC triple
- initial hot-chain full-PC materialization experiment in ARM64 endblock paths

### Acceptance

- opcode harness: required green
- ROM harness: required on every step in this phase
- no new PC-corruption regressions or fallback-contract regressions

---

## Phase 1 — stronger block-cache / edge-profile layer

### Goal

Build the profiling and bookkeeping needed for a trace/region tier without weakening the current block engine.

### Planned work

- add explicit hot-edge profiling for successor pairs
- record stable successor frequency per block edge
- distinguish:
  - lookup hash/cache state
  - dependency patch state
  - profiling state
- add region-candidate metadata to blockinfo or adjacent structures
- keep invalidation semantics simple and block-based

### Current status

**In progress.**

The ARM64 BasiliskII block layer now has a real Phase-1 profiling substrate:

- per-block `edge_exec_count[2]`
- per-block `edge_target_pc[2]`
- stable-edge thresholds (`B2_JIT_STABLE_EDGE_MIN_EXEC`, `B2_JIT_STABLE_EDGE_MIN_PCT`)
- dominant/stable edge classification
- env-gated hot-edge snapshots via `B2_JIT_TRACE_EDGES=1`

The validation loop also got stronger:

- the opcode harness now forces rebuild of key JIT glue objects so clean runs do not silently use stale code
- `B2_TEST_NAMES=...` allows focused opcode-subset loops while preserving the normal metrics contract
- Xvfb startup in `jit-test/run.sh` now ensures display `:99` actually exists instead of assuming any Xvfb process is sufficient

This is still intentionally conservative: it gives us real runtime edge data and a reliable harness loop without changing invalidation semantics or enabling broad trace formation yet.

### Acceptance

- opcode harness: green on every change
- ROM harness: green/no-regression trend required
- no invalidation or checksum regressions

---

## Phase 2 — validated direct chaining policy

### Goal

Turn current ad hoc direct chaining into an explicit policy layer that can later feed trace formation.

### Planned work

- retain validated/non-direct entry as the default safety net
- allow direct chain promotion only for edges that meet explicit criteria
- require edge-state proof before promotion:
  - PC contract satisfied
  - flags contract satisfied
  - no helper boundary ambiguity
  - no unresolved exception ownership seam
- add downgrade path when an edge becomes unstable

### Current status

**Started, still experimental.**

An opt-in ARM64 direct-chain experiment is now wired to the Phase-1 edge summaries:

- `B2_JIT_ENABLE_STABLE_DIRECT_EDGES=1`
- stable-edge summaries are carried across recompiles
- constant-successor chain patching can prefer the target block's real direct handler for source edges that were previously observed to be stable
- dependency patching preserves source-edge direct preference when the target block is rebuilt or invalidated

This is deliberately narrow:

- default behavior stays contract-first / validated-first
- only explicit, stable, profiled edges are eligible
- broad promotion policy is still deferred until ROM/runtime evidence improves

### Acceptance

- opcode harness: green
- ROM harness: mandatory
- desktop/runtime workloads before any broader direct-chain promotion

---

## Phase 3 — trace / region-lite tier

### Goal

Add a first region JIT tier in the form of single-entry hot traces with guarded side exits.

### Why this shape

Do **not** jump straight to arbitrary multi-entry CFG regions.
The first useful form here is:

- single hot entry
- linearized hot successors
- multiple side exits back to canonical block handlers
- region invalidates if any constituent block invalidates

### Planned work

- introduce a `regioninfo`/trace object
- build hot traces from stable profiled edges
- side exits return to canonical block handlers
- keep region invalidation simple: any member invalidation kills the region
- preserve the block JIT as the fallback authority

### Acceptance

- opcode harness: green
- ROM harness: mandatory
- desktop/runtime workload(s): required before enabling outside experiments

---

## Phase 4 — better register allocation in hot paths

### Goal

Upgrade from the current local allocator toward a policy that actually reduces reload/store traffic inside hot chains/traces.

### Planned work

- collect better live-range information
- improve spill decisions around barriers and exits
- rematerialize cheap constants instead of always spilling
- preserve hot guest registers within a trace interior
- keep region exits conservative until their contract is proven

### Important constraint

Allocator improvements must not hide state across boundaries that still assume architectural entry.
Trace interiors may stay virtual; trace exits must still be explicit.

### Acceptance

- opcode harness: mandatory
- ROM harness: mandatory
- graphics/allocator-sensitive workloads when spill/liveness behavior changes materially

---

## Phase 5 — broader lazy-flags ownership

### Goal

Expand lazy flags from today’s conservative model into a stronger consumer-driven model.

### Planned work

- keep flags virtual across larger native windows when ownership is private
- materialize only for explicit consumers:
  - helpers
  - interpreter fallback
  - exception paths
  - uncertain exits
  - region side exits whose consumers require architectural flags
- reduce redundant restore/store behavior where `needed_flags` proves no consumer

### Important constraint

This phase happens **after** chaining/region boundaries are explicit enough that lazy flags do not cross unclear ownership seams.

### Acceptance

- opcode harness: mandatory
- ROM harness: mandatory
- graphics + allocator-sensitive workloads: required before promotion

---

## First implementation tranche to pursue now

1. finish Phase 0 chain-handoff normalization
2. keep using the opcode harness on every code change
3. run the ROM harness on every chaining/boundary change
4. only after Phase 0 stabilizes, start adding edge profiling metadata for Phase 1

That means the immediate work stays focused on:

- PC/state ownership on hot chain paths
- boundary-safe direct chaining
- using the harnesses as the real arbiter of progress

---

## What not to do yet

Do **not** jump straight to:

- arbitrary multi-entry regions
- hidden virtual state across uncertain exits
- aggressive lazy flags before boundary ownership is explicit
- allocator changes that assume region semantics before those semantics exist

---

## Success criteria

Short-term success:

- maintain `301/301` opcode harness
- improve ROM harness behavior without masking bugs
- finish Phase 0 with a clearly documented chain contract

Medium-term success:

- stable hot-edge profiling
- trace/region-lite tier with safe side exits
- measurable reduction in dispatch overhead

Long-term success:

- region-aware allocator improvements
- broader lazy flags with explicit ownership
- meaningful whole-system speedup on golden workloads without contract regressions
