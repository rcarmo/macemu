# AArch64 JIT scalar transform emitter audit

Date: 2026-07-27

Base: `404acf3f` (`master`, published logical-immediate emitter closure)

## Scope

This tranche audits the 19 reachable scalar count/reverse/extend encoders:

- generic signed fields `SBFM_wwii`, `SBFM_xxii`;
- signed aliases `SXTB_ww`, `SXTB_xx`, `SXTH_ww`, `SXTH_xx`, `SXTW_xw`;
- generic unsigned fields `UBFM_wwii`, `UBFM_xxii`;
- unsigned aliases `UXTB_ww`, `UXTB_xx`, `UXTH_ww`, `UXTH_xx`;
- `REV_ww`, `REV_xx`, `REV16_ww`, `REV16_xx`, `REV32_xx`;
- `CLS_ww`.

Adjacent `CLZ_ww`, `EXTR_wwwi`, and `EXTR_xxxi` have no configured roots and
remain unreachable. SIMD lane operation `REV64_dd` is a separate API.

## Census

The 19 inventory rows contain **63 configured references**. Retained C++ call
sites differ for compatibility/unreachable bodies: `REV_ww` has 8 raw sites
versus 4 configured, `REV16_ww` 7 versus 5, and `SXTH_ww` 4 versus 3. Generic
SBFM/UBFM inventory references are macro compositions; structural acceptance
locks their header token counts at 3/4/3/3. Every API is locked individually.

## Contracts

SBFM/UBFM pack W/X `immr` and `imms` fields and implement both extraction
(`imms>=immr`) and wrap/insert aliases (`imms<immr`). Signed forms replicate
the selected result sign bit; unsigned forms zero-fill. W results zero-extend.

The nine aliases sign- or zero-extend byte, word, or W values at their declared
W/X result width. Reverse forms permute bytes within 16-, 32-, or 64-bit lanes.
`CLS_ww` counts leading bits equal to bit 31, excluding the sign bit. Every form
supports destination/source aliasing and preserves NZCV.

## Direct conformance

`jit-test/emitter-transform-conformance.cpp` exhaustively enumerates every
`(immr,imms)` pair for signed/unsigned W/X fields: **10,240 exact encodings and
10,240 native executions**. An independent oracle handles extraction, wrapping,
sign replication, truncation, and zero extension.

Thirty assembler-anchored words cover all nine aliases and six transforms at
ordinary and maximum register fields. A further 45 native vectors cover zero,
mixed, and all-ones inputs, W/X width, negative and positive extension, every
reverse lane geometry, CLS extremes/mixed runs, aliases, and hostile NZCV.

```text
METRIC emitter_transform_apis=19
METRIC emitter_transform_field_encodings=10240
METRIC emitter_transform_anchor_words=30
METRIC emitter_transform_field_native=10240
METRIC emitter_transform_alias_native=27
METRIC emitter_transform_operation_native=18
METRIC emitter_transform_native_vectors=10285
METRIC emitter_transform_preserves_nzcv=1
```

## Structural acceptance

The structural gate fails closed on all definitions, configured and raw/header
censuses, exhaustive domains, exact words, native totals, W/X semantics, alias
and NZCV checks, complete-emitter integration, or changed reachability of
`CLZ_ww`/`EXTR_*`.

## Acceptance results

The accepted clean-source epoch passes:

- direct scalar-transform conformance: **10,240 exhaustive field encodings + 30 anchors + 10,285 native vectors**;
- complete emitter phase: all 33 bounded suites pass;
- complete active-risky corpus: **904/904**, zero equivalence or infrastructure failures;
- allocator pressure: **33/33**;
- clean full build: pass;
- complete structural audit: pass;
- repeated inventory/source hashes: byte-identical;
- source hygiene: `git diff --check` pass;
- independent bounded review: **APPROVE**.

One earlier broad attempt is explicitly rejected as infrastructure evidence: a
sibling session killed all host Xvfb processes, causing the fixed `:99` display
to disappear after 65 vectors and yielding only missing-REGDUMP failures. The
sibling confirmed the unqualified `pkill`; after display cleanup was restricted
and `:99` was supervised, the complete 904-vector run passed and the server
remained alive.

Clean-epoch hashes before publication:

```text
37dfc019905a6e3c6a377201066fc7262ce475ba7caf85b0e2b4efda620550aa  BasiliskII/src/Unix/compemu.cpp
7d53c03496fd11bb7e60305486258d849e676c599d2dba7ac8c3a1fab286b5f9  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.csv
5105394f28c8567e332796d97dac09b2aef64ad36792a544191dfc24ea9edd64  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.md
```

## Closure effect

Deterministic regeneration moves exactly the 19 listed APIs from `unreviewed`
to `audited`. After this tranche, **70 emitter APIs and 17 raw boundaries remain
unreviewed**. Whole-engine closure is not claimed.

## Reproduction

```sh
./jit-test/emitter-transform-conformance.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
