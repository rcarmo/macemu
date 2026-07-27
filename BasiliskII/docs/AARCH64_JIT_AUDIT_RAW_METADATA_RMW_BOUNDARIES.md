# AArch64 JIT raw metadata RMW boundary audit

Date: 2026-07-27

Base: `59d1c22d` (`master`, published checksum-boundary ownership repair)

## Scope

This tranche audits the mechanically selected `compemu_raw_dec_m` together with
its source-coherent metadata-RMW companion `compemu_raw_inc_m`. These are not
68K opcode decrement/increment handlers:

- `dec_m` updates a JIT block's signed hotness/profiling countdown;
- `inc_m` updates per-edge execution counters while native control flow is being
  profiled.

`compemu_raw_inc_opcount` uses a register-structure indexed table and remains a
separate boundary.

## Boundary contracts

Both primitives materialise a full 64-bit host pointer, perform a 32-bit load,
wrap in the 32-bit domain, and store exactly one 32-bit result.

`compemu_raw_dec_m` must execute `SUBS Wtmp,Wtmp,#1`: its signed N flag is
consumed immediately by the already audited `compemu_raw_maybe_recompile`
`BGE`/tail branch. The compiler sequence is fixed as canonical-PC publication,
decrement, then signed recompile test. Boundary values therefore behave as:

- `1 -> 0`: continue (`N=0`);
- `0 -> 0xffffffff`: recompile (`N=1`);
- `0x80000000 -> 0x7fffffff`: recompile because signed overflow yields
  `N != V`; this value is outside the bounded non-negative production domain.

`compemu_raw_inc_m` deliberately uses non-flag-setting `ADD Wtmp,Wtmp,#1`.
Edge accounting is inserted after a guest branch outcome is decided and must
not replace the live NZCV state used by surrounding native control flow.

## Runtime proof

`jit-test/raw-metadata-rmw-boundary-matrix.sh` runs a bounded RAM loop:

```text
MOVEQ #127,D0; SUBQ.L #1,D0; BNE.S self
```

An env-gated test control combines two existing policies only for a fresh test
block: native L2 generation plus a bounded positive first-generation count.
The emitted production paths are unchanged. On count expiry, the real
`dec_m -> compemu_raw_maybe_recompile -> recompile_block` path rebuilds the
block. Before edge state is reset, test-only summary counters record the actual
`inc_m`-maintained edge total and committed stable-edge mask.

Accepted limits pass exactly:

```text
count=1:  recompile_block=1 metadata_rebuild=1 metadata_edges=1  metadata_summary=02
count=64: recompile_block=1 metadata_rebuild=1 metadata_edges=64 metadata_summary=02
```

Both produce terminal `D0=0`. Invalid counts `0` and `65` abort with the exact
`B2_TEST_METADATA_RMW_COUNT must be 1..64` diagnostic. The test control and
summary fields are dormant when the environment variables are absent.

## Structural acceptance

The structural gate locks:

- pointer/load/arithmetic/store ordering for both bodies;
- 32-bit `SUBS` and flag-neutral 32-bit `ADD` selection;
- countdown decrement before signed recompile testing;
- bounded test control and exact runtime summary fields;
- count-limit acceptance/rejection rows;
- exact closure promotion of both raw boundaries.

## Acceptance results

The accepted clean-source epoch passes:

- metadata RMW boundary matrix: **2/2 runtime + 2/2 fail-closed limits**;
- complete emitter/boundary phase: pass, `validation_complete=1`, `infra_fail=0`;
- complete active-risky corpus: **904/904**, zero equivalence or infrastructure failures;
- allocator pressure: **33/33**;
- clean full build: pass;
- complete structural audit: pass;
- repeated inventory/source hashes: byte-identical;
- source hygiene: `git diff --check` pass;
- independent bounded review: **APPROVE**.

Clean-epoch hashes before publication:

```text
37dfc019905a6e3c6a377201066fc7262ce475ba7caf85b0e2b4efda620550aa  BasiliskII/src/Unix/compemu.cpp
c87630b87ebcf9080021f5378f50b1375c71c73ba16c71e2898a7fb2e9a4cfe6  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.csv
3a06a204985d09d917a248249a29d2faba4ed06706d5ba6a71f6afd86eb821ab  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.md
```

## Closure effect

Deterministic regeneration moves exactly `compemu_raw_dec_m` and
`compemu_raw_inc_m` from `unreviewed` to `audited`. After this tranche,
**70 emitter APIs and 14 raw boundaries remain unreviewed**. Whole-engine
closure is not claimed.

## Reproduction

```sh
./jit-test/raw-metadata-rmw-boundary-matrix.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
