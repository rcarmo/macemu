# AArch64 JIT raw floating-condition publication boundary audit

Date: 2026-07-28

Base: `1ae3470c` (`master`, published raw integer host-memory moves)

## Scope

This tranche audits only the mechanically selected final raw row,
`raw_fflags_into_flags`. It adds no production code and no duplicate native
oracle. The one-instruction body composes the already-audited `FCMP_d0`
primitive with the already-audited `fflags_into_flags` MIDFUNC and its two
configured FScc/FBcc consumers.

## Exact boundary contract

The production body is exactly:

```cpp
STATIC_INLINE void raw_fflags_into_flags(int r)
{
    FCMP_d0(r);
}
```

It compares the lazy `FP_RESULT` carrier with `+0.0` and publishes the IEEE
relation in physical NZCV:

- less: `N` (`1000`);
- equal, including `-0.0`: `Z|C` (`0110`);
- greater: `C` (`0010`);
- unordered: `C|V` (`0011`).

The boundary preserves the FP operand and general registers. `FCMP_d0` already
has accepted exact-word and native semantics for all 32 FP source fields,
relation classes, FPCR/FPSR preservation, and signalling-NaN IOC behaviour in
`AARCH64_JIT_AUDIT_FCMP_EMITTERS.md`.

## Composition and ownership

There is one direct configured caller, `fflags_into_flags_internal()`:

1. `f_readreg(FP_RESULT)` acquires the fixed-home lazy carrier read-only;
2. `raw_fflags_into_flags(r)` emits the single compare;
3. `f_unlock(r)` releases the read association; and
4. `live_flags()` publishes the temporary predicate for its immediate consumer.

The MIDFUNC wrapper first calls `clobber_flags()`. Both configured compiler
roots, `comp_fscc_opp()` and `comp_fbcc_opp()`, call
`preserve_flags_before_nzcv_clobber()` before materialisation. FScc consumes and
then discards the temporary NZCV; FBcc consumes it at the block edge and resets
carry-polarity metadata when returning to architectural integer CCR ownership.
No caller treats floating C as inverted integer carry.

## Existing exact-native evidence

`jit-test/fflags-into-flags-native-matrix.ts` already executes this exact raw
body transitively through the real configured compiler roots:

- FScc positive, zero, negative, and unordered classifications;
- FBcc FTST/FCMP producers, ordered/unordered predicates, and word/long edges;
- exact predicate result and FPSR relation;
- unchanged integer `SR=0x271f`;
- second-pass native attribution, strict no-fallback, and isolated CoW media.

Accepted result: **8/8 exact-native**. This composes with the accepted generic
FCMP evidence of **1,056 exact words** and **72 native vectors**. A separate
wrapper harness would execute the same single `FCMP_d0` instruction and add no
independent semantic coverage.

## Structural acceptance

The gate pins:

- an exact one-statement raw body and one source definition;
- the sole direct caller and read/compare/unlock/live ordering;
- exactly two configured preprocessed roots, FScc and FBcc;
- CCR preservation before floating NZCV publication;
- post-consumption state/carry-polarity cleanup;
- the existing eight-case strict-native matrix;
- independent continued audit of `FCMP_d0` and `fflags_into_flags`; and
- exactly one closure-row promotion.

## Acceptance results

Final acceptance:

- raw body: exactly **1** `FCMP_d0` statement;
- direct configured caller: **1**;
- configured FScc/FBcc roots: **2**;
- focused strict-native composition: **8/8**;
- inherited generic FCMP evidence: **1,056 exact words**, **72 native vectors**;
- complete emitter/boundary phase: pass, including
  `emitter_fmsub_exact_words=1048576`;
- complete active-risky corpus: **904/904**;
- allocator pressure: **33/33**;
- clean full AArch64 build: pass;
- complete structural audit: pass;
- deterministic 998-row regeneration: exactly one row promoted; raw-boundary
  unreviewed count becomes **0**, with **70 emitter APIs** remaining;
- published `1ae3470c` predecessor CSV SHA-256:
  `ecb65b0ae5e2aa2326406f5cb47e06a414625f2ed61936aec04db862f844617d`;
- repeated current hashes: inventory CSV
  `7dee9ce2603c44f959ac1e59020106eaa640c1bc5aaf2a7fc3ca979d798fed44`,
  Markdown
  `e72f4ff1283c1cfcdd5d620e9d3c54106a7ff56d0ba8e70cf02c1ab6421f7324`,
  and generated `compemu.cpp`
  `37dfc019905a6e3c6a377201066fc7262ce475ba7caf85b0e2b4efda620550aa`;
- production and generated source: unchanged;
- source hygiene: pass;
- independent bounded review: **APPROVE** for the exact one-statement body,
  sole caller ordering, two configured FScc/FBcc roots, CCR/carry-metadata
  ownership, reuse of the accepted primitive/composition native evidence,
  cumulative predecessor hashes, and exact one-row raw-boundary exhaustion.

## Closure effect

Deterministic regeneration must move only `raw_fflags_into_flags` from
`unreviewed` to `audited`. Raw boundaries then have zero unreviewed rows; 70
emitter APIs remain. Whole-engine closure is not claimed.

## Reproduction

```sh
bun jit-test/fflags-into-flags-native-matrix.ts
bun jit-test/closure-inventory.ts
bun jit-test/structural-audit.ts
./jit-test/run.sh --phases emitters --build-mode skip
git diff --check
```
