# AArch64 JIT BLR emitter audit

Date: 2026-07-27

Base: `a6d51ba0` (`master`, published remaining logical emitter closure)

## Scope

This tranche audits the one remaining reachable indirect call encoder:

- `BLR_x`.

Its five configured-source references comprise three reachable generic
helper-call boundaries and two definition-only extended-FP host-library bodies.
The latter remain configured-unreachable because their opcode roots use exact
MPFR services. This report covers the encoder and call/link contract; it does
not reclassify any already audited or unreachable raw boundary. `BL_i` remains
configured-unreachable.

## Configured-source and raw census

| API | Configured-source references | Raw source sites | Reachable boundaries | Definition-only boundaries |
|---|---:|---:|---:|---:|
| `BLR_x` | 5 | 5 | 3 | 2 |

Structural acceptance locks all five source sites, but does not describe the two
definition-only FP sites as reachable callers.

## Encoding and semantic contracts

- encode the architectural `BLR Xn` word for every five-bit register field;
- branch to the address held in `Xn`;
- write the address of the instruction after `BLR` to `X30`;
- return correctly when the callee executes `RET`;
- preserve NZCV;
- retain the accepted helper ABI: LR is stacked around host calls, and generic
  helper targets use allocator-reserved `X18` rather than an argument register.

All 32 register fields are checked against an independently constructed word.
Native execution uses caller-saved `X9`, `X16`, `X17`, and production-reserved
`X18`; callee-saved registers are deliberately excluded from the harness target
set unless explicitly saved. Every case also loads a distinct register with a
safe decoy callee, so an encoder hard-wired to `X16` or another tested register
cannot pass by sharing the intended target address.

## Direct native conformance

`jit-test/emitter-blr-conformance.cpp` includes the production header and emits
RW-then-RX caller/callee pairs. Each native case passes a target through the
selected register, executes `BLR`, records `X30` only in the intended callee, returns through
the generated link, and records NZCV after return. The decoy callee records zero
instead, turning incorrect target-register selection into a deterministic
failure rather than a crash.

```text
METRIC emitter_blr_api=1
METRIC emitter_blr_exact_words=32
METRIC emitter_blr_native_vectors=4
METRIC emitter_blr_target_decoys=4
METRIC emitter_blr_link_semantics=1
METRIC emitter_blr_preserves_nzcv=1
```

The complete emitter phase passes with this suite installed after remaining
logical conformance and before the previously accepted semantic-family gates.

## Structural acceptance

`jit-test/structural-audit.ts` fails closed on:

- loss or alteration of the `BLR_x` definition;
- configured-source or raw-site drift from five references, or drift from the
  three-reachable/two-definition-only boundary split;
- loss of LR stack save/restore within any of the five individual bodies;
- loss of the reserved-X18 generic helper target contract;
- loss of exhaustive 32-register encoding, four native target vectors and
  distinct safe decoys, exact link capture, or NZCV preservation;
- omission of the bounded suite from the complete emitter phase.

## Acceptance results

The accepted clean-source epoch passes:

- direct BLR conformance: **32/32 exact register fields + 4/4 native vectors**;
- complete emitter phase: all 31 bounded suites pass;
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
883b379768871c48d182157290293d853d08bcd9da0ed1b618eb8de8554d2af6  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.csv
96a8b9271fe5bb50ffdd9212b4a3a2c103f827073770b5c60e76da6b54692c54  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.md
```

## Closure effect

Deterministic regeneration moves exactly `BLR_x` from `unreviewed` to
`audited`. After this tranche, **99 emitter APIs and 17 raw boundaries remain
unreviewed**. Whole-engine closure is not claimed.

## Reproduction

```sh
./jit-test/emitter-blr-conformance.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
