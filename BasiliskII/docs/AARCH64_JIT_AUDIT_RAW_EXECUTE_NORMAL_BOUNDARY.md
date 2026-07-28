# AArch64 JIT raw execute_normal boundary audit

Date: 2026-07-27

Base: `507711ef` (`master`, published raw exec_nostats closure)

## Scope

This tranche audits only the mechanically selected
`compemu_raw_execute_normal`. The adjacent
`compemu_raw_execute_normal_cycles` remains unreviewed because its countdown
subtraction/store is a distinct runtime contract. `compemu_raw_handle_except`
also remains unreviewed.

## Boundary contract

Each block's `direct_pen` first-entry stub must:

1. materialise the address of that block's `pc_p` field;
2. load the canonical host PC from the field into `REG_WORK1`;
3. branch through a range-checked/patched AArch64 `B` to
   `popall_execute_normal_setpc`;
4. publish canonical `regs.pc_p`, `regs.pc_oldp`, and `regs.pc` through the
   audited `compemu_raw_set_pc_from_reg` dependency;
5. restore the preserved JIT-entry register frame; and
6. tail-branch to `execute_normal` without changing LR ownership.

The shared `popall_execute_normal` label deliberately allows cache and other
lifecycle paths to enter after PC publication. The direct-entry counter is
therefore structurally pinned before that label.

## Lifecycle and runtime proof

`jit-test/raw-execute-normal-boundary-matrix.sh` first traces and compiles a
short RAM stream. Before its replay, the test-only hook requires an active
block that owns its cache line and has a prepared `direct_pen`. It then calls
the production `block_need_recompile()` transition, which sets
`BI_NEED_RECOMP`, disables stale direct chaining, and repatches dependencies.
Only after that transition does the hook temporarily select the owned
cache-line's `direct_pen`; it does not alter the cache owner or bypass block
handler/dependency state.

The direct stub publishes PC and enters `execute_normal`. Its
`check_for_cache_miss()` sees the same owner, and `compile_block()` accepts the
`BI_NEED_RECOMP` state and rebuilds the block through the ordinary lifecycle.

The exact accepted summary is:

```text
direct_execute_normal=1 exec_normal=2 exec_nostats=0 recompile_block=0
```

The two C entries are the initial trace and the one direct-stub replay. The
separate direct-label count proves that exactly one of them passed through
`compemu_raw_execute_normal`; zero `exec_nostats` excludes the neighbouring
optlevel-0 handoff, and zero `recompile_block` excludes the countdown expiry
entry. The final register dump requires `D0=2`.

The lifecycle hook is inactive unless
`B2_TEST_FORCE_DIRECT_EXECUTE_NORMAL` is explicitly enabled. The direct-side
counter and summary emission are independently inactive unless
`B2_TEST_DISPATCH_SUMMARY` is enabled; the acceptance matrix enables both.

## Structural acceptance

The structural gate locks the pointer dereference, branch target, direct-side
counter placement, canonical PC/unwind/tail order, owned-line and active-block
preconditions, production `block_need_recompile()` transition before the
cache-line override, replay oracle, bounded runner integration, and continued
unreviewed status of `compemu_raw_execute_normal_cycles`.

## Acceptance results

Accepted evidence before the final clean epoch:

- direct execute_normal matrix: **1/1**, with exact
  `direct_execute_normal=1`, `exec_normal=2`, `exec_nostats=0`, and
  `recompile_block=0`;
- complete emitter/boundary phase: pass, including all four dispatcher
  matrices together;
- complete active-risky corpus: **904/904**;
- allocator pressure: **33/33**;
- clean full build: pass;
- complete structural audit: pass;
- deterministic 998-row closure regeneration: exactly one row promoted,
  leaving **70 emitter APIs** and **12 raw boundaries** unreviewed;
- repeated hashes: inventory CSV
  `7ffebf544cdad8cfc698ce7da23b80bcf159213ef1c38b4a0590d8700bb0bf43`,
  Markdown
  `cce398dc10485fe05fc84508d485ebb58afcb6c6fc94aa0e5c2ba204b3090977`,
  and generated `compemu.cpp`
  `37dfc019905a6e3c6a377201066fc7262ce475ba7caf85b0e2b4efda620550aa`;
- source hygiene: pass;
- independent bounded review: initial evidence-only rejects repaired; final
  code, runtime, report, and deterministic epoch are complete.

## Closure effect

Deterministic regeneration must move exactly `compemu_raw_execute_normal` from
`unreviewed` to `audited`. Whole-engine closure is not claimed.

## Reproduction

```sh
./jit-test/raw-execute-normal-boundary-matrix.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
