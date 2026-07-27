# AArch64 JIT `_W` word-emission audit

Date: 2026-07-27

Base: `826ca31e` (`master`, published final MIDFUNC closure)

## Scope

This tranche audits the mechanically selected emitter API:

- `emitter_api,_W`

`_W` is not an instruction-semantic family. It is the common sink used by the
AArch64 header encoders to pass one final instruction word to `emit_long`.
Semantic field, width, flags, alias, and range contracts remain attached to
each encoder API and are not promoted merely because their shared sink is
closed.

The production contract spans:

- `_W(c)` in `codegen_arm64.h`;
- `emit_long(uae_u32)` and `skip_long()` in `compemu_support_arm.cpp`;
- target ordering and four-byte advancement;
- existing instruction-cache publication at compilation/patch boundaries.

`emit_long` is implementation evidence rather than a separately inventoried
raw boundary.

## Configured census

The closure inventory records **269 configured references** for `_W`. The
source header contains **268 `_W(` tokens**: one definition plus 267 direct
macro-body uses. The configured inventory count includes the definition and
configured references under its preprocessing/token policy; the structural
gate locks both independently so a new encoder cannot silently bypass review.

There are two direct production `emit_long` calls outside `_W` on the AArch64
path. One is `_W` itself; the other writes a data/relative-address payload in
`compemu_raw_mov_l_mi`. That non-instruction payload is deliberately outside
this emitter-API promotion and remains governed by its parent primitive.

## Word and target contract

`_W(c)` must:

- evaluate `c` exactly once;
- cast the result to `uae_u32` before passing it to the emission layer;
- emit exactly one word and add no hidden alignment, cache, or patch action.

The cast is part of correctness: encoder expressions contain signed and
64-bit intermediates, but every AArch64 instruction is exactly 32 bits.
Unsigned and signed wider inputs therefore truncate to their low 32 bits
without host-width sign extension.

Production `emit_long(uae_u32 x)` must:

1. store `x` at the current `target` as one `uae_u32`;
2. call `skip_long()`;
3. advance the target by exactly four bytes through `skip_n_bytes(4)`.

This preserves source order and one-word cardinality. Capacity, executable
publication, and branch patching remain owned by their established outer
compilation boundaries; `_W` must not duplicate those responsibilities.

## Direct conformance

`jit-test/emitter-word-conformance.cpp` includes the production encoder header
with an observing `emit_long` and proves:

- ordinary `uae_u32` passage;
- truncation of `0x1122334455667788` to `0x55667788`;
- truncation of signed `-1` to `0xffffffff`;
- exactly one evaluation of a side-effecting expression;
- three-word sequence order and cardinality;
- exact representative words from branch, arithmetic, logical, load/store,
  FP, and return classes;
- direct native execution of a three-word raw sequence emitted through `_W`.

The six representative words are:

```text
B +1                 14000001
ADD w0,w0,#1         11000400
EOR w0,w0,w1         4a010000
LDR w2,[x3,#16]      b9401062
FMOV d4,d5           1e6040a4
RET                   d65f03c0
```

Result:

```text
METRIC emitter_word_direct_vectors=5
METRIC emitter_word_representative_words=6
METRIC emitter_word_native_vectors=1
METRIC emitter_word_single_evaluation=1
METRIC emitter_word_truncation32=1
```

The script is the first explicit gate in the complete emitter phase. All 23
previously accepted emitter suites pass behind it, proving that inserting the
common-sink gate does not disturb their semantic acceptance.

## Structural acceptance

`jit-test/structural-audit.ts` fails closed on:

- any change to the exact unsigned `_W` definition;
- drift from 268 header tokens or 269 configured inventory references;
- loss of the production `uae_u32` store, `skip_long()`, or four-byte advance;
- loss of truncation, single-evaluation, order/cardinality, representative-word,
  or native-execution witnesses;
- omission of the bounded conformance script from `jit-test/run.sh`.

## Acceptance results

The accepted clean-source epoch passes:

- direct sink conformance: **5 primitive vectors + 6 representative words +
  1 native sequence**;
- complete emitter phase: all 24 bounded suites pass;
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
754e01b9caba5725f6aa65461679c412d2877eb41491cd5e220614087a06aa8e  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.csv
ac9b46a2bd7b51272a7f2e6d7a12192ae5d3b4fe576481a174d3c550e444b9c2  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.md
```

## Closure effect

Deterministic regeneration moves exactly:

```text
emitter_api,_W: unreviewed -> audited
```

No semantic encoder or raw boundary is promoted by association. After this
tranche, **126 emitter APIs and 17 raw boundaries remain unreviewed**.
Whole-engine closure is not claimed.

## Reproduction

```sh
./jit-test/emitter-word-conformance.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
