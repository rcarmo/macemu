# AArch64 JIT raw deferred-exception boundary audit

Date: 2026-07-28

Base: `edc9c034` (`master`, published raw FPU host-memory closure)

## Scope

This tranche audits only the mechanically selected
`compemu_raw_handle_except`. The downstream `popall_execute_exception` unwind,
FPU-shadow synchronisation, and `execute_exception()` semantic service were
already covered by the CHK, CHK2, division, and TRAPV lifecycle audits. This
report proves the raw conditional handoff itself rather than inheriting those
higher-level results.

## Boundary contract

At the sole per-instruction caller, `may_raise_exception` is reset before each
opcode and set only by a deferred-exception producer. After the opcode:

1. load the 32-bit `regs.jit_exception` request from `R_REGSTRUCT`;
2. branch over the terminal when the request is zero, without changing it or
   invoking the exception service;
3. when nonzero, materialise the exact compile-time `retired_cycles` argument
   in `W0`; and
4. branch through a range-checked/patched `B` to
   `popall_execute_exception`; and
5. preserve the `W0` cycle argument across the compiled-in
   `jit_fpu_sync_from_shadow()` AAPCS64 call before tail-entering
   `execute_exception()`.

The raw body deliberately clobbers host NZCV for its zero test. Architectural
CCR publication and tagged request semantics belong to the accepted producer
and `execute_exception()` contracts. The body does not clear the request;
`execute_exception()` owns consumption and clearing.

## Runtime proof

`jit-test/raw-handle-except-boundary-matrix.sh` reuses two existing strict
exact-native CHK.W vectors through the main harness:

| Case | Request | Raw checks | Taken exits | Cycles argument | Terminal proof |
|---|---:|---:|---:|---:|---|
| `chk_w_in_range` | zero | 1 | 0 | 0 | normal sentinel, unchanged stack/SR |
| `chk_w_negative_trap_n` | tagged vector 6 | 1 | 1 | 1024 | exact format-2 frame PCs, stacked SR/N, vector handler |

Four counters are active only when `B2_TEST_DISPATCH_SUMMARY` is enabled:
checks before `CBZ`, taken exits after `CBZ`, the exact cycle value copied to
`W0`, and the value actually received at `execute_exception()` after FPU shadow
synchronisation and unwind. Both cases require every neighbouring checksum,
metadata, normal, nostats, recompile, and execute-normal-cycles counter to
remain zero. The taken row requires sent and received values to equal 1024; the
fall-through row requires both to remain zero.

## Structural acceptance

The structural gate pins the 32-bit request load, counter positions, CBZ
fall-through, exact `W0` cycle materialisation, patched exception target,
balanced `X0` stack preservation around FPU shadow sync, C-entry received-cycle
observation, sole caller, per-opcode `may_raise_exception` reset and post-op
checkpoint, bounded main-runner integration, both strict-native fingerprints,
terminal states, and one-row closure promotion.

## Acceptance results

Final acceptance:

- direct two-case matrix: **2/2**;
- handle-except checks: **2** total, exactly one per native case;
- taken exception exits: **1**;
- sent cycle argument: **1024**;
- received cycle argument: **1024**, proving `X0` survives the compiled
  `jit_fpu_sync_from_shadow()` call;
- complete emitter/boundary phase: pass;
- complete active-risky corpus: **904/904**;
- allocator pressure: **33/33**;
- clean full build: pass, including a forced rebuild of
  `obj/compemu_support.o` and relink;
- complete structural audit: pass;
- deterministic 998-row closure regeneration: exactly one row promoted,
  leaving **70 emitter APIs** and **8 raw boundaries** unreviewed;
- repeated hashes: inventory CSV
  `abab404df8c6124770ab9915e9f07098047e29b6ea0669569bec60b063862467`,
  Markdown
  `c20c80c72d45b0e2f5c897740a1859b9957f10d558b65b916d72f873a1816786`,
  and generated `compemu.cpp`
  `37dfc019905a6e3c6a377201066fc7262ce475ba7caf85b0e2b4efda620550aa`;
- source hygiene: pass;
- independent bounded review: initial reject because inventory promotion did
  not itself reject the report's pending marker and the final evidence was not
  recorded here. Inventory generation now rejects pending accepted reports,
  the structural gate requires this exact final evidence; final re-review: **approve**.

## Closure effect

Deterministic regeneration must move exactly `compemu_raw_handle_except` from
`unreviewed` to `audited`. Whole-engine closure is not claimed.

## Reproduction

```sh
./jit-test/raw-handle-except-boundary-matrix.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
