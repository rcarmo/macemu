# AArch64 JIT raw checksum boundary audit

Date: 2026-07-27

September follow-up: the retained matrix now has **4 cases**, compares the full
interpreter REGDUMP/sentinel, and includes an instruction-group permutation
that previously ran stale native code. The secondary checksum is bytewise and
order-sensitive; invalid spans return explicit failure separately from valid
zero source. See [implementation review](AARCH64_JIT_IMPLEMENTATION_REVIEW_20260906.md).
The three-case results below are the historical boundary acceptance.

Base: `251f4fc1` (`master`, published scalar-transform emitter closure)

## Scope

This tranche audits only the mechanically selected raw boundary
`compemu_raw_check_checksum`. It deliberately does not promote the structurally
related `compemu_raw_execute_normal`, `compemu_raw_execute_normal_cycles`, or
`compemu_raw_exec_nostats`; those remain unreviewed until independently
exercised.

## Boundary contract

The generated per-block `direct_pcc` trampoline must:

1. materialise `&bi->pc_p` into `REG_WORK1`;
2. dereference the saved host PC;
3. branch through a range-checked/patched AArch64 `B` to
   `popall_check_checksum_setpc`;
4. publish canonical `regs.pc_p`, `regs.pc_oldp`, and `regs.pc` through the
   already audited `compemu_raw_set_pc_from_reg` dependency;
5. restore the preserved JIT-entry register frame; and
6. tail-branch to `check_checksum` without changing LR ownership.

The stub itself is NZCV-neutral. The complete terminal boundary does not promise
guest-NZCV preservation across optional FPU synchronisation/C dispatch because
it does not return to arithmetic native continuation.

## Reachability and checksum semantics

`prepare_block()` emits one `direct_pcc` stub for every block. Lazy validation
sets inbound direct dependencies to that address and marks the block
`BI_NEED_CHECK`. `check_checksum()` then:

- reactivates unchanged source and its dependencies (`BI_ACTIVE`);
- invalidates changed source and falls back for recompilation;
- treats a zero checksum as valid when checksum-span metadata exists.

Inventory count is three configured references (definition/end marker plus the
configured caller representation used by the census).

## Direct runtime proof

`jit-test/raw-checksum-boundary-matrix.sh` uses the normal opcode harness to
compile a RAM block, then an env-gated test control selects its already emitted
`direct_pcc` before replay. Instrumentation increments only on entry to the
`popall_check_checksum_setpc` label, separately from the C helper counter.

Three cases pass:

```text
unforced:  direct_checksum=0
unchanged: direct_checksum=1 check_checksum=1 good=1 bad=0
changed:   direct_checksum=1 check_checksum=1 good=0 bad=1
```

The unforced control proves ordinary dispatcher entry does not accidentally
cross the raw-stub counter. Both forced cases require exactly one direct entry
and one checksum-helper call, with mutually exclusive good/bad counters, and
produce a clean `REGDUMP`. The selected block must own its cache line; the hook
fails closed otherwise, and keeps the cache tag coherent with
`handler_to_use=direct_pcc`. The unchanged stream proves direct entry, PC
publication, checksum validation, and reactivation. The changed stream proves
stale native code is rejected. Test controls and summary output are inactive
unless `B2_TEST_FORCE_DIRECT_CHECKSUM` / `B2_TEST_DISPATCH_SUMMARY` are
explicitly set.

## Structural acceptance

The structural gate locks body instruction ordering, target label, configured
count, PC-publication/unwind/tail-branch order, test-only gate conditions,
direct/helper/good/bad counters, bounded runner integration, and the continued
unreviewed status of the three sibling raw boundaries.

## Acceptance results

The accepted clean-source epoch passes:

- direct checksum boundary matrix: **3/3** (unforced negative control +
  unchanged good + changed bad);
- complete emitter/boundary phase: all 34 bounded suites pass;
- complete active-risky corpus: **904/904**, zero equivalence or infrastructure failures;
- allocator pressure: **33/33**;
- clean full build: pass;
- complete structural audit: pass;
- repeated inventory/source hashes: byte-identical;
- source hygiene: `git diff --check` pass;
- independent bounded review: initial approval was superseded by a sibling
  ownership-invariant rejection; follow-up repairs add cache-line ownership,
  coherent handler policy, an unforced negative control, and exact census-column
  checking. Final independent and original-rejector re-reviews: **APPROVE**.

Clean-epoch hashes before publication:

```text
37dfc019905a6e3c6a377201066fc7262ce475ba7caf85b0e2b4efda620550aa  BasiliskII/src/Unix/compemu.cpp
82d8655a2cd0efd8a50f931a8a0289c4c2de55e669cb2420919f81215921f246  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.csv
7623eb0dd593deff34938ddae103a0e7a9086c1748157baf73fd23eae009cb87  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.md
```

## Closure effect

Deterministic regeneration moves exactly `compemu_raw_check_checksum` from
`unreviewed` to `audited`. After this tranche, **70 emitter APIs and 16 raw
boundaries remain unreviewed**. Whole-engine closure is not claimed.

## Reproduction

```sh
./jit-test/raw-checksum-boundary-matrix.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
