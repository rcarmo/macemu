# AArch64 JIT remaining logical emitter audit

Date: 2026-07-27

Base: `4c28bb0c` (`master`, published unsigned bitfield emitter closure)

## Scope

This tranche audits seven remaining reachable runtime logical encoders:

- `BIC_www`;
- `ORR_www`, `ORR_wwwLSRi`;
- `ORR_xxx`, `ORR_xxxLSLi`;
- `TST_ww`, `TST_xx`.

It intentionally excludes compile-time logical-immediate builders `immEncode`,
`immOP_AND`, and `immOP_ORR`; those compose the remaining flag-bit helpers and
belong to the flags batch. Configured-unreachable `BIC_xxx`, `ORR_wwwLSLi`, and
`ORR_xxxLSRi` remain untouched.

## Configured and raw census

| API | Configured references | Raw calls |
|---|---:|---:|
| `BIC_www` | 4 | 4 |
| `ORR_www` | 40 | 40 |
| `ORR_wwwLSRi` | 16 | 16 |
| `ORR_xxx` | 5 | 21 |
| `ORR_xxxLSLi` | 7 | 7 |
| `TST_ww` | 136 | 152 |
| `TST_xx` | 4 | 10 |
| **Total** | **212** | **250** |

The extra X ORR and W/X TST raw calls reside in retained compatibility or
configured-unreachable bodies. Structural acceptance locks both per-API lists.

## Encoding and semantic contracts

- `BIC_www`: `Wd = Wn & ~Wm`, W truncation, NZCV preserved;
- `ORR_www` / `ORR_xxx`: sized register OR, NZCV preserved;
- `ORR_wwwLSRi`: W rhs logical-right shift by imm5 then OR;
- `ORR_xxxLSLi`: X rhs left shift by imm6 then OR;
- `TST_ww` / `TST_xx`: sized AND to WZR/XZR, publish N/Z and clear C/V.

Result forms allow destination/lhs and destination/rhs aliases. Immediate shift
fields mask to five or six bits. TST has no architectural result.

Fourteen assembler anchors cover ordinary and register-31 encodings for all
seven APIs, including maximum shifts 31 and 63.

## Direct native conformance

`jit-test/emitter-logical-conformance.cpp` includes the production header and
executes RW-then-RX short sequences with an independent sized logical oracle.
Coverage includes zero/all-ones, sign-bit, disjoint/overlapping masks, W
truncation, shifts 0/1/16/31 and 0/1/32/63, and destination aliases.

BIC/ORR cases start with hostile NZCV and must preserve it exactly. TST W/X
cases independently require sized N/Z and C=V=0.

```text
METRIC emitter_logical_apis=7
METRIC emitter_logical_anchor_words=14
METRIC emitter_logical_native_vectors=104
METRIC emitter_logical_alias_vectors=57
METRIC emitter_logical_flag_vectors=16
```

The complete emitter phase passes with this suite installed after exhaustive
bitfield conformance and before prior semantic-family gates.

## Structural acceptance

`jit-test/structural-audit.ts` fails closed on:

- loss of any seven definitions;
- configured per-API census drift from 212 references;
- raw per-API drift from 250 calls;
- loss of the 14 assembler anchors, 104 native vectors, 57 aliases, or 16 TST
  flag cases;
- loss of BIC/ORR NZCV preservation or TST sized N/Z and C/V-clear checks;
- omission of the bounded suite from the complete emitter phase;
- accidental promotion of immediate-builder or unreachable shift forms.

## Acceptance results

The accepted clean-source epoch passes:

- direct logical conformance: **14 anchors + 104 native vectors**;
- complete emitter phase: all 30 bounded suites pass;
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
92555957881bb0fcc6d631b8a8bc0b20a3bcb8127ba909106030c14980392cbd  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.csv
7349f51f72511d22b649d4630729c5dd04d0ab8dad6994d3c96768bcd514c7eb  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.md
```

## Closure effect

Deterministic regeneration moves exactly the seven listed APIs from
`unreviewed` to `audited`. After this tranche, **100 emitter APIs and 17 raw
boundaries remain unreviewed**. Whole-engine closure is not claimed.

## Reproduction

```sh
./jit-test/emitter-logical-conformance.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
