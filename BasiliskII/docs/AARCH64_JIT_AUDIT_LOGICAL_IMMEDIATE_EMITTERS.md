# AArch64 JIT logical-immediate builder and mutator audit

Date: 2026-07-27

Base: `1520e90b` (`master`, published BLR emitter closure)

## Scope

This source-coherent tranche audits the ten remaining reachable builders and
mutators sharing AArch64 logical-immediate field algebra:

- `immEncode`, `immOP_AND`, and `immOP_ORR`;
- `CLEAR_xxZflag`, `CLEAR_xxCflag`, and `CLEAR_xxVflag`;
- `SET_xxZflag` and `SET_xxVflag`;
- `CLEAR_xxbit` and `SET_xxbit`.

`CLEAR_NZCV` and `SET_xxCflag` have no configured roots and remain unreachable.
Already audited `immOP_EOR`, `EOR_xxCflag`, and `EOR_xxbit` are not reopened.

## Configured and raw census

| API | Configured references | Retained raw source sites/compositions |
|---|---:|---:|
| `immEncode` | 23 | 24 header compositions including its definition |
| `immOP_AND` | 7 | 8 header tokens including its definition |
| `immOP_ORR` | 5 | 6 header tokens including its definition |
| `CLEAR_xxZflag` | 7 | 7 C++ call sites |
| `CLEAR_xxCflag` | 5 | 5 C++ call sites |
| `CLEAR_xxVflag` | 2 | 2 C++ call sites |
| `SET_xxZflag` | 8 | 12 C++ call sites |
| `SET_xxVflag` | 11 | 11 C++ call sites |
| `CLEAR_xxbit` | 5 | 5 C++ call sites |
| `SET_xxbit` | 10 | 11 C++ call sites |
| **Total inventory references** | **83** | — |

The configured/raw differences are retained compatibility or configured-
unreachable bodies. Structural acceptance locks both inventories without
promoting their enclosing boundaries.

## Encoding and semantic contracts

`immEncode(N, immr, imms)` must place `N` in bit 22, `immr` in bits 21:16,
and `imms` in bits 15:10. `immOP_AND` and `immOP_ORR` must equal the 64-bit
logical-immediate bases `0x92000000` and `0xb2000000`.

The fixed helpers clear or set one saved-NZCV data bit:

- Z: bit 30;
- C: bit 29;
- V: bit 28.

The generic helpers clear or set one bit in the complete domain 0..63. All
callable helpers are X-width data operations, support destination/source alias,
preserve every non-target bit, and leave architectural PSTATE NZCV unchanged.
Register field 31 is encoder-only evidence; native semantics stay in the AAPCS
caller-saved/production register domain.

## Direct conformance

`jit-test/emitter-logical-immediate-conformance.cpp` includes the production
header and proves:

- all 8,192 `(N,immr,imms)` field triples independently;
- both independent opcode-base constants;
- all 128 bit-position words for `CLEAR_xxbit` and `SET_xxbit`, four field-31
  boundary words, and 15 fixed-helper assembler anchors/field controls;
- clear/set native semantics for all 64 bits with zero and all-ones inputs;
- aliases, distinct destinations, caller literals 7/29/31, and bit 63;
- fixed Z/C/V clear/set semantics and hostile-NZCV preservation.

```text
METRIC emitter_logimm_apis=10
METRIC emitter_logimm_encode_checks=8192
METRIC emitter_logimm_base_constants=2
METRIC emitter_logimm_exact_words=147
METRIC emitter_logimm_exhaustive_native=256
METRIC emitter_logimm_alias_vectors=266
METRIC emitter_logimm_distinct_vectors=15
METRIC emitter_logimm_flag_vectors=7
METRIC emitter_logimm_native_vectors=288
```

## Structural acceptance

`jit-test/structural-audit.ts` fails closed on definitions, configured counts,
retained raw sites/compositions, exhaustive field/bit domains, exact words,
vector counts, alias/distinct semantics, NZCV preservation, unreachable
neighbours, and complete-emitter integration.

## Acceptance results

The accepted clean-source epoch passes:

- direct logical-immediate conformance: **8,192 field checks + 147 exact words + 288 native vectors**;
- complete emitter phase: all 32 bounded suites pass;
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
96949fa36594a3d21bca674480e1c540727abbd3c85d7336b2fefb44f1993bc5  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.csv
d40c0041366ceb9aeabbb515a93f3a11f503203d3dcd89e537ade546c3457d3e  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.md
```

## Closure effect

Deterministic regeneration moves exactly the ten listed APIs from `unreviewed`
to `audited`. `CLEAR_NZCV` and `SET_xxCflag` remain unreachable. After this
tranche, **89 emitter APIs and 17 raw boundaries remain unreviewed**. Whole-engine
closure is not claimed.

## Reproduction

```sh
./jit-test/emitter-logical-immediate-conformance.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
