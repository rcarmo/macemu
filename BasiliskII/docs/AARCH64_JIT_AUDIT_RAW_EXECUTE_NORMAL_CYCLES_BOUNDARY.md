# AArch64 JIT raw execute_normal_cycles boundary audit

Date: 2026-07-28

Base: `66d85e5b` (`master`, published raw execute_normal closure)

## Scope

This tranche audits only the mechanically selected
`compemu_raw_execute_normal_cycles`. The downstream
`popall_execute_normal_setpc` PC-publication/unwind/tail boundary is already
audited independently. `compemu_raw_handle_except` remains unreviewed because
its exception-request and cycle contract is distinct.

## Boundary contract

The interpreter-barrier handoff must:

1. load the signed 32-bit global countdown;
2. subtract every retired scaled cycle, using the AArch64 imm12 lowering for
   `0..4095` or a materialised 32-bit register otherwise;
3. store the 32-bit result before loading the runtime PC pointer;
4. load the canonical host PC from the supplied memory field; and
5. branch through a range-checked/patched `B` to the already accepted
   `popall_execute_normal_setpc` boundary.

The subtraction intentionally wraps in 32-bit two's-complement arithmetic. A
negative result does not branch to `do_nothing` here: this handoff always enters
`execute_normal`; the outer dispatcher owns later tick servicing/reset policy.

## Runtime proof

`jit-test/raw-execute-normal-cycles-boundary-matrix.sh` uses the production
restored-`sr` interpreter barrier in an L2 RAM block. The fallback opcode runs,
then the compiled block emits this exact raw terminal. A replay-only seed hook
sets a known positive countdown and clears the gated observation fields before
dispatch. Instrumentation inside the raw body records its own input/output and
entry count; it is inactive unless `B2_TEST_DISPATCH_SUMMARY` is enabled.

Two cases cover both lowering branches:

| Case | Native ops before barrier | Seed | Retired cycles | Exact result |
|---|---:|---:|---:|---:|
| imm12 | 0 | 1000 | 1024 | `0xffffffe8` / 4294967272 |
| register | 4 NOPs | 10000 | 5120 | 4880 |

Both require exactly one raw entry, two total `execute_normal` entries (initial
trace plus replay), zero `exec_nostats`, zero `recompile_block`, canonical
`D0=0x2700`, and terminal `D1=2`.

## Structural acceptance

The structural gate pins both subtraction branches, 32-bit load/store width,
store-before-PC ordering, the patched downstream label, bounded seed parsing,
production restored-`sr` route, exact before/after values, summary cardinality,
and bounded main-runner integration.

## Acceptance results

Final acceptance:

- direct two-case matrix: **2/2**;
- corrective execute-normal route matrix: **2/2**, including the unforced
  `direct_execute_normal=0` control requested by sibling review;
- all five dispatcher matrices together: pass;
- complete emitter/boundary phase: pass;
- complete active-risky corpus: **904/904**;
- allocator pressure: **33/33**;
- clean full build: pass;
- complete structural audit: pass;
- deterministic 998-row closure regeneration: exactly one row promoted,
  leaving **70 emitter APIs** and **11 raw boundaries** unreviewed;
- repeated hashes: inventory CSV
  `12925b8411e6e31b4605fc5c8de0a4ad8095b369c5c45169b7891437b5b728c6`,
  Markdown
  `b0c815671329f10872ca03b3b73723ba728fe1016194d827ba8a40ab3cd93b0b`,
  and generated `compemu.cpp`
  `37dfc019905a6e3c6a377201066fc7262ce475ba7caf85b0e2b4efda620550aa`;
- source hygiene: pass;
- independent bounded review: approve for arithmetic width/wrap, both lowering
  branches, instrumentation register safety, seed timing, gate strength, and
  closure scope;
- sibling review of the preceding execute-normal row: approve after the
  stronger paired unforced/forced control was added here.

## Closure effect

Deterministic regeneration must move exactly
`compemu_raw_execute_normal_cycles` from `unreviewed` to `audited`.
Whole-engine closure is not claimed.

## Reproduction

```sh
./jit-test/raw-execute-normal-cycles-boundary-matrix.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
