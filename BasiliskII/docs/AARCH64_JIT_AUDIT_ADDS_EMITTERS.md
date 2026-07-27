# AArch64 JIT ADD-with-flags emitter audit

Date: 2026-07-27

Base: `45928702` (`master`, published ADCS/SBCS carry-emitter closure)

## Scope

This tranche audits the three reachable W-width flag-setting ADD encoders:

- `emitter_api,ADDS_wwi`
- `emitter_api,ADDS_www`
- `emitter_api,ADDS_wwwLSLi`

The corresponding X-width forms remain configured-unreachable:

- `ADDS_xxi`
- `ADDS_xxx`
- `ADDS_xxxLSLi`

No production repair is required.

## Configured caller census

All seven configured calls are in `compemu_midfunc_arm64_2.cpp`:

| API | References | Configured role |
|---|---:|---|
| `ADDS_wwi` | 1 | long ADD immediate, guarded to `0..0xfff` |
| `ADDS_www` | 2 | long ADD materialised immediate and dynamic register |
| `ADDS_wwwLSLi` | 4 | byte/word immediate and dynamic register lane normalisation |

The shifted-register arguments are exactly `24,24,16,16`: byte paths shift the
second operand into bits 31:24; word paths shift it into bits 31:16. Results
and NZCV are therefore computed at the architectural byte/word sign position,
then the narrowed result is extracted into the guest destination lane.

Every parent marks `flags_carry_inverted=false` and duplicates physical C to
68K X after the ADDS emission. The complete ADD lifecycle audit remains the
higher-level proof for source ownership, destination aliases, memory EA and
writeback, narrow extraction, X publication, and guest flags.

## Encoding contract

```text
ADDS Wd,Wn,#imm12          0011000100 imm12 Wn Wd
ADDS Wd,Wn,Wm              00101011000 Wm 000000 Wn Wd
ADDS Wd,Wn,Wm,LSL #shift   00101011000 Wm shift5 Wn Wd
```

Fields are W-width and publish N/Z/C/V. Immediate values are masked to 12 bits;
shift values are masked to five bits. Architectural register 31 remains valid
with SP semantics in the immediate form and WZR semantics in register forms.

Seven independent exact words cover ordinary, maximum immediate/register, and
maximum shifted fields:

```text
ADDS w9,w10,#0                 31000149
ADDS w9,w10,#4095              313ffd49
ADDS wzr,wsp,#4095             313fffff
ADDS w9,w10,w11                2b0b0149
ADDS wzr,wzr,wzr               2b1f03ff
ADDS w9,w10,w11,LSL #31        2b0b7d49
ADDS wzr,wzr,wzr,LSL #31       2b1f7fff
```

## Direct native conformance

`jit-test/emitter-adds-conformance.cpp` includes the production header and
executes short sequences from RW-then-RX mappings after an instruction-cache
flush. Its result/NZCV oracle is independent of the encoder expressions.

Coverage:

- 12 immediate cases, including 0, 1, `0xfff`, carry, signed overflow, zero,
  negative results, and W truncation;
- 12 register cases across all NZCV outcomes;
- 15 shifted-register cases at shifts 0, 1, 16, 24, and 31;
- destination-distinct, destination/lhs alias, and destination/rhs alias forms;
- hostile initial NZCV to prove all flags are overwritten.

Result:

```text
METRIC emitter_adds_apis=3
METRIC emitter_adds_exact_words=7
METRIC emitter_adds_immediate_vectors=12
METRIC emitter_adds_register_vectors=12
METRIC emitter_adds_shift_vectors=15
METRIC emitter_adds_alias_vectors=24
METRIC emitter_adds_native_vectors=39
```

The complete emitter phase passes with this suite inserted after the carry
encoders and before previously accepted semantic families.

## Structural acceptance

`jit-test/structural-audit.ts` fails closed on:

- any encoding-field change;
- caller/reference drift from `1 + 2 + 4`;
- immediate loss of the `0..0xfff` guard;
- register caller-class drift from `REG_WORK2` and `s`;
- shifted caller drift from `24,24,16,16`;
- loss of carry-normalisation/X-publication ownership;
- loss of exact words, independent result/NZCV oracle, imm/shift boundaries,
  or destination aliases;
- omission of the bounded suite from the complete emitter phase.

## Acceptance results

The accepted clean-source epoch passes:

- direct ADDS conformance: **7 exact words + 39 native result/NZCV vectors**;
- complete emitter phase: all 26 bounded suites pass;
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
e61bfd80b99f2428e74dd0f417d31dfc042ca1cadd3f9dafe5f7a99cc699d68b  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.csv
f290f2e43ae9ce4d7f335216da6c003264f283aa3fec684e71815190671e76fc  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.md
```

## Closure effect

Deterministic regeneration moves exactly:

```text
emitter_api,ADDS_wwi: unreviewed -> audited
emitter_api,ADDS_www: unreviewed -> audited
emitter_api,ADDS_wwwLSLi: unreviewed -> audited
```

No X-width form changes classification. After this tranche, **121 emitter APIs
and 17 raw boundaries remain unreviewed**. Whole-engine closure is not claimed.

## Reproduction

```sh
./jit-test/emitter-adds-conformance.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
