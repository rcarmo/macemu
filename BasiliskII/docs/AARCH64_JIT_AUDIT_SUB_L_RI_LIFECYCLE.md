# AArch64 JIT `sub_l_ri` lifecycle audit

Date: 2026-07-27

Base: `d2560825` (`master`, published MOVE-to-CCR lifecycle repair)

## Scope

This tranche audits the last unreviewed AArch64 MIDFUNC row:

- `midfunc,sub_l_ri`

It covers the configured generator, FPU compiler, register-allocator, and
emitter lifecycle for immediate subtraction from a 32-bit guest value. It does
not claim whole-engine closure; emitter APIs and raw/runtime boundaries remain
for later mechanically selected tranches.

## Configured caller census

The preprocessed configured graph has **156** references:

| Caller class | Calls | State represented |
|---|---:|---|
| generated branch displacement normalisation | 122 | signed byte/word/long branch offsets before host-PC conversion |
| generated guest-SP decrement | 24 | 68K stack movement |
| generated private MOVEM cursor | 4 | word/long predecrement transfer cursor |
| configured FPU guest-address cursor | 6 | static FMOVEM predecrement address movement |
| **Total** | **156** | |

The 150 generated calls decompose exactly by destination spelling as
`src=90`, `offs=32`, `SP_REG=24`, and `movem_dsta=4`. The six FPU calls are all
`sub_l_ri(ad, 4)`. No configured caller supplies `PC_P`, a host pointer, or a
pointer-capable private scratch value.

## Repaired type contract

The prior implementation inferred arithmetic width from mutable numeric state:

- `PC_P`, or a constant numerically above `0xffffffff`, selected `SUB_xxi`;
- other values selected `SUB_wwi`;
- the dynamic branch nevertheless tested `isconst(d)` after the constant early
  return, making its numeric-width arm unreachable.

That heuristic originated before typed host-pointer arithmetic was available
and no longer represented a configured caller. It also made a value range act
as a type tag, contrary to the audited guest/host pointer boundary.

`sub_l_ri(d,i)` now has one explicit contract:

- `d` is modulo-2^32 guest state;
- `i == 0` is a no-op preserving constant/materialised state;
- constant state folds as `uae_u32(value - i)`;
- dynamic state is acquired with `rmw(d)`, emitted with `SUB_wwi`, and unlocked;
- `PC_P` or a constant above `0xffffffff` fails closed with `jit_abort`;
- pointer-width clients must use typed `arm_ADD_ptr_ri(d, -i)` instead.

This removes one dead `SUB_xxi` source caller. The already-audited generic SUB
emitter report and structural census are updated from six to five `SUB_xxi`
spellings; its encoding and 70-vector native conformance remain unchanged.

## Exact-native and lifecycle evidence

`jit-test/sub-l-ri-conformance.cpp` includes the production ARM64 emitter,
checks exact `SUB_wwi(9,9,1)` encoding `0x51000529`, maps emitted instructions
RW then RX, clears the instruction cache, and executes six modulo-32 vectors:
zero, one, two, `0xffffffff`, `0x80000000`, and a value with nonzero upper
32 bits. The upper half is deliberately discarded by W-width arithmetic.

`jit-test/sub-l-ri-lifecycle-matrix.sh` then binds the primitive to all
configured caller classes:

- four strict-native branch controls: byte, word, and long forward BRA plus a
  negative word BNE displacement;
- one A7 LINK.W predecrement/stack control;
- word and long MOVEM predecrement base-alias controls;
- one configured FPU static-predecrement service-dominance control.

Result:

```text
SUB_L_RI_LIFECYCLE conformance=6 branches=4 stack=1 movem=2 fpu_service=1 fail=0 total=14
```

The FPU control is intentionally a configured service-dominance proof rather
than strict execution of the retained native tail: exact MPFR service owns the
operation before that tail in the configured AArch64 graph.

## Structural acceptance

`jit-test/structural-audit.ts` fails closed on:

- loss of the guest-only signature, zero-immediate path, constant truncation,
  dynamic `SUB_wwi`, allocator unlock, or pointer-state abort;
- reintroduction of numeric pointer inference or `SUB_xxi` in `sub_l_ri`;
- any change to the 150 generated destination classes or six FPU callers;
- inventory reference drift from 156;
- loss of the exact-native probe or any lifecycle control;
- drift in the generic SUB emitter caller and immediate-argument censuses.

## Acceptance results

The accepted clean-source epoch passes:

- focused lifecycle: **14/14**;
- generic SUB/SUBS emitter replay: **70/70**;
- complete active-risky corpus: **904/904**, zero equivalence or infrastructure failures;
- allocator pressure: **33/33**;
- clean full build: pass;
- complete structural audit: pass;
- repeated generator/inventory hashes: byte-identical;
- source hygiene: `git diff --check` pass;
- independent bounded review: **APPROVE**.

Clean-epoch hashes before publication:

```text
37dfc019905a6e3c6a377201066fc7262ce475ba7caf85b0e2b4efda620550aa  BasiliskII/src/Unix/compemu.cpp
4a603d76c31ea8c86c942e5f9421f3b592851d7e83516b33c8c424e4c205a9ca  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.csv
03feced39b65f8d4b2094ddf3703d4b51329b0d7569cba1c03131e4766a21762  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.md
```

## Closure effect

Deterministic inventory regeneration moves exactly:

```text
midfunc,sub_l_ri: unreviewed -> audited
```

No row is added or removed, no reference count changes, and the next selected
row is the first remaining emitter API. Whole-engine closure remains pending.

## Reproduction

```sh
./jit-test/sub-l-ri-conformance.sh
./jit-test/sub-l-ri-lifecycle-matrix.sh
./jit-test/emitter-sub-conformance.sh
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
