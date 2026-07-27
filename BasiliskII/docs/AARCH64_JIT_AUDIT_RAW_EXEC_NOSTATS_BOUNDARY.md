# AArch64 JIT raw exec_nostats boundary audit

Date: 2026-07-27

Base: `2e5a2bfc` (`master`, published metadata-RMW raw closure)

## Scope

This tranche audits only the mechanically selected
`compemu_raw_exec_nostats`. The structurally adjacent
`compemu_raw_execute_normal`, `compemu_raw_execute_normal_cycles`, and
`compemu_raw_handle_except` remain unreviewed until their distinct cache,
cycle-countdown, and exception contracts receive direct evidence.

## Boundary contract

The optlevel-0 terminal must:

1. materialise the immediate canonical host PC into `REG_WORK1`;
2. branch through a range-checked/patched AArch64 `B` to
   `popall_exec_nostats_setpc`;
3. publish canonical `regs.pc_p`, `regs.pc_oldp`, and `regs.pc` through the
   audited `compemu_raw_set_pc_from_reg` dependency;
4. restore the preserved JIT-entry register frame; and
5. tail-branch to `exec_nostats` without changing LR ownership.

The boundary is terminal: it does not promise guest-NZCV preservation across
the optional FPU synchronisation and C interpreter entry.

## Runtime proof

`jit-test/raw-exec-nostats-boundary-matrix.sh` compiles a short RAM stream with
optlevel 0 forced, then replays it through the generated block stub. A counter
emitted only at `popall_exec_nostats_setpc` is distinct from the existing C
`exec_nostats` counter.

The exact accepted summary after two requested replays is:

```text
direct_exec_nostats=2 exec_nostats=2 exec_normal=1
```

The two direct-label/C-entry events make cardinality observable rather than
conflating the boundary with an unrelated once-per-run event. The final
register dump requires `D0=2`, proving each replay entered at the published
start PC, interpreted the complete stream, and returned normally.
The direct-label instrumentation is emitted only when the existing
`B2_TEST_DISPATCH_SUMMARY` gate is active.

## Structural acceptance

The structural gate locks the raw body instruction ordering, patch target,
set-PC/unwind/tail-branch order, distinct direct and C counters, exact replay
oracle, bounded runner integration, and continued unreviewed status of
`execute_normal` and `execute_normal_cycles`.

## Acceptance results

Final acceptance:

- direct exec_nostats matrix: **1/1**, with exact repeated entry counts
  `direct_exec_nostats=2`, `exec_nostats=2`, and `exec_normal=1`;
- complete emitter/boundary phase: pass;
- complete active-risky corpus: **904/904**;
- allocator pressure: **33/33**;
- clean full build: pass;
- complete structural audit: pass, including a direct-side ordering assertion
  that keeps the counter before the shared `popall_exec_nostats` label;
- deterministic closure inventory: **998 rows**, with **13 raw boundaries** and
  **70 emitter APIs** remaining unreviewed;
- source hygiene: pass;
- independent bounded review: approve; sibling review approve after the
  direct-side ordering assertion requested here.

## Closure effect

Deterministic regeneration must move exactly `compemu_raw_exec_nostats` from
`unreviewed` to `audited`. Whole-engine closure is not claimed.

## Reproduction

```sh
./jit-test/raw-exec-nostats-boundary-matrix.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
