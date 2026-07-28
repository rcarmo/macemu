# AArch64 JIT raw condition-only branch boundary audit

Date: 2026-07-28

Base: `d98e1bd4` (`master`, published fixed-register prologue audit)

## Scope

This tranche audits only the mechanically selected
`compemu_raw_jcc_l_oponly`. Its caller patches the final emitted branch to a
runtime target. The boundary itself owns condition lowering and optional carry
normalisation, but no target address or block-state side effect.

Generic `B_i`, `CC_B_i`, and condition wrapper encoders plus
`write_jmp_target()` remain covered by their independent accepted branch-emitter
audit.

## Condition contract

The boundary accepts two disjoint domains:

- native integer condition IDs 0..14, including custom M68K unsigned HI/LS;
- floating pseudo-condition IDs 16..31, covering false/equal, ordered
  comparisons, ordered/unordered, unordered unions, not-equal, and true.

Before lowering either domain, `FIX_INVERTED_CARRY` canonicalises an inverted
host carry representation with MRS/EOR/MSR and clears the compiler-state marker.
Integer HI is `!C && !Z`; LS is `C || Z`, matching M68K borrow polarity rather
than raw AArch64 HI/LS. FP predicates use FCMP's four NZCV classes and explicitly
include or exclude unordered (V) as required.

Each lowering emits one to three branch words. The last word is always the
caller-patched taken branch; preceding words only route around or into it.

## Native proof

`jit-test/raw-jcc-oponly-conformance.sh` exact-extracts the production
`FIX_INVERTED_CARRY` macro and complete raw function. Its native AArch64 probe
patches only the final branch, then evaluates:

- all 15 integer condition IDs over all 16 NZCV combinations;
- all 16 FP pseudo-condition IDs over Greater, Equal, Less, and Unordered FCMP
  flag classes;
- both canonical and deliberately inverted incoming carry for every case.

The matrix therefore contains **608 native outcomes**: 480 integer and 128 FP,
including 304 carry-normalisation cases. Every case also requires final NZCV to
match the canonical architectural flags. Exact per-condition 1/2/3-word body
shapes and the additional three-word carry prefix fail closed.

## Structural acceptance

The structural gate pins all 16 FP switch cases, integer default, HI/LS
compositions, carry-normalisation sequence/state publication, exact extraction,
truth-table/cardinality source, configured reference count, the two live
AArch64 caller classes (mid-block side exit and final edge), bounded main-runner
integration, one-row closure promotion, and continued independent generic
branch-emitter status.

## Acceptance results

Final acceptance:

- exact-extracted native truth table: **608/608** outcomes;
- integer matrix: **480/480**;
- floating-point matrix: **128/128**;
- inverted-carry normalisation: **304/304** with canonical final NZCV;
- condition IDs: **31** (15 integer and 16 floating pseudo-conditions);
- configured whole-root references: **5** (function spelling pair, two live
  AArch64 callers, and configured root accounting);
- complete emitter/boundary phase: pass;
- complete structural audit: pass;
- deterministic 998-row closure regeneration: exactly one row promoted,
  proved by reconstructing the published predecessor CSV and matching SHA-256
  `6dc4188cb85f9faf44e75d51c7ea477ef898e2f304fa903c8abe08e3e5b88452`;
- all **21** generic branch-emitter rows backed by
  `AARCH64_JIT_AUDIT_BRANCH_EMITTERS.md` remain independently audited;
- closure leaves **70 emitter APIs** and **5 raw boundaries** unreviewed;
- repeated hashes: inventory CSV
  `f3a79573a57e2d6664910b445dbfb779a56c401684e62b878154971e858999f5`,
  Markdown
  `3f4774cd5e1102cf8173f109e62ac540fda881627cdbe336c4d5040264309240`,
  and unchanged generated `compemu.cpp`
  `37dfc019905a6e3c6a377201066fc7262ce475ba7caf85b0e2b4efda620550aa`;
- production and generated source: unchanged from `d98e1bd4`;
- source hygiene: pass;
- independent bounded review: initial reject because the exact one-row delta
  was not mechanically pinned and branch independence sampled only six APIs;
  corrected with full-CSV predecessor reconstruction/hash and all 21
  report-backed branch rows; final re-review: **approve**.

## Closure effect

Deterministic regeneration must move exactly `compemu_raw_jcc_l_oponly` from
**unreviewed** to **audited**. Whole-engine closure is not claimed.

## Reproduction

```sh
./jit-test/raw-jcc-oponly-conformance.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
