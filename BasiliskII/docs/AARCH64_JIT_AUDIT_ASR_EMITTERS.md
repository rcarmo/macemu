# AArch64 JIT ASR emitter audit

Date: 2026-07-27

Base: `ffa7f05c` (`master`, published ANDS emitter closure)

## Scope

This tranche audits the three reachable no-flags arithmetic-right-shift
encoders selected by `ASR_wwi`:

- `emitter_api,ASR_wwi`
- `emitter_api,ASR_xxi`
- `emitter_api,ASR_xxx`

The W register-count encoder `ASR_www` remains configured-unreachable. Guest
68K N/Z/V/C/X semantics, count-zero X ownership, six-bit count routing, and
result narrowing remain governed by the accepted shift-family lifecycle; these
raw encoders must preserve NZCV.

## Configured and raw census

Configured inventory references are:

```text
ASR_wwi  7
ASR_xxi  2
ASR_xxx  9
```

Direct raw production calls are:

```text
ASR_wwi  8
ASR_xxi  1
ASR_xxx  9
```

The extra raw W-immediate call is in unreachable `arm_ADD_ldiv8`. Conversely,
the configured preprocessing policy records two X-immediate references for its
live definition/root graph although there is one direct call. Both totals are
18; structural acceptance locks the differing compositions independently.

Live parents use:

- W immediate for sign-extended byte/word shifts, long no-flags shifts, and
  fixed-count memory ASR;
- X immediate for flag-live long ASR after `SXTW`, including architectural
  count 32;
- X register count after masking the guest count to six bits, which is required
  for 68K counts 32..63 and avoids W-register modulo-32 behaviour.

## Encoding contract

```text
ASR Wd,Wn,#imm5  SBFM Wd,Wn,imm5,31
ASR Xd,Xn,#imm6  SBFM Xd,Xn,imm6,63
ASRV Xd,Xn,Xm    data-processing two-source opcode 001010
```

Immediate fields mask to five or six bits. Variable X shifts use the low six
bits of the register count, as required by AArch64 and by the parent 68K shift
mapping. All forms leave NZCV untouched.

Eight exact controls cover zero/max immediate fields, max registers, and the X
register form:

```text
ASR w9,w10,#0       13007d49
ASR w9,w10,#31      131f7d49
ASR wzr,wzr,#31     131f7fff
ASR x9,x10,#0       9340fd49
ASR x9,x10,#63      937ffd49
ASR xzr,xzr,#63     937fffff
ASR x9,x10,x11      9acb2949
ASR xzr,xzr,xzr     9adf2bff
```

## Direct native conformance

`jit-test/emitter-asr-conformance.cpp` includes the production header and
executes short sequences from RW-then-RX pages after instruction-cache flush.
It computes signed fill with an independent width-bounded oracle.

Coverage:

- 12 W-immediate vectors, including counts 0, 1, 15, 30, 31, 32, and 63;
- 12 X-immediate vectors, including 0, 1, 32, 62, 63, 64, and 127;
- 48 X-register vectors: six signed/unsigned boundary values crossed with
  counts 0, 1, 31, 32, 63, 64, 65, and 127;
- W truncation, sign fill, positive/negative saturation, and count masking;
- destination-distinct, lhs-alias, and rhs-alias forms;
- hostile initial NZCV, which must be preserved exactly.

Result:

```text
METRIC emitter_asr_apis=3
METRIC emitter_asr_exact_words=8
METRIC emitter_asr_w_immediate_vectors=12
METRIC emitter_asr_x_immediate_vectors=12
METRIC emitter_asr_x_register_vectors=48
METRIC emitter_asr_alias_vectors=44
METRIC emitter_asr_native_vectors=72
METRIC emitter_asr_preserves_nzcv=1
```

The complete emitter phase passes with this gate installed after ANDS and
before previously accepted semantic-family suites.

## Structural acceptance

`jit-test/structural-audit.ts` fails closed on:

- any immediate/register encoding-field change;
- configured inventory drift from `7 + 2 + 9`;
- raw call drift from `8 + 1 + 9`;
- loss of byte/word 31 saturation, long 32 saturation, six-bit mask, X
  register-count routing, or long result narrowing;
- loss of exact words, independent signed oracle, count edges, aliases, or
  NZCV preservation;
- omission of the bounded suite from the complete emitter phase;
- unexpected reachability of `ASR_www` or `arm_ADD_ldiv8`.

## Acceptance results

The accepted clean-source epoch passes:

- direct ASR conformance: **8 exact words + 72 native signed-shift vectors**;
- complete emitter phase: all 28 bounded suites pass;
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
727f6482d0018616977c212b16f0422e0e3ce3ff3af2388856f847c9ce075f5d  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.csv
93a645a8635107bd2bfaeb2fcccf8b59ef76fe256ce7291d25fa82542b8f2506  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.md
```

## Closure effect

Deterministic regeneration moves exactly:

```text
emitter_api,ASR_wwi: unreviewed -> audited
emitter_api,ASR_xxi: unreviewed -> audited
emitter_api,ASR_xxx: unreviewed -> audited
```

`ASR_www` remains unreachable. After this tranche, **115 emitter APIs and 17
raw boundaries remain unreviewed**. Whole-engine closure is not claimed.

## Reproduction

```sh
./jit-test/emitter-asr-conformance.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
