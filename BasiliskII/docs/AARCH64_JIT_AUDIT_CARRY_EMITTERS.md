# AArch64 JIT carry-arithmetic emitter audit

Date: 2026-07-27

Base: `f9329cf6` (`master`, published `_W` emission-sink closure)

## Scope

This tranche audits the two reachable flag-setting carry encoders selected by
`ADCS_www`:

- `emitter_api,ADCS_www`
- `emitter_api,SBCS_www`

The surrounding non-flag, X-width, and negate-with-carry definitions remain
configured-unreachable and are not promoted by association:

- `ADC_www`, `ADC_xxx`, `ADCS_xxx`;
- `SBC_www`, `SBC_xxx`, `SBCS_xxx`;
- `NGC_ww`, `NGC_xx`, `NGCS_ww`, `NGCS_xx`.

`NGC_ww` and `NGCS_ww` have raw spellings only inside unreachable NEGX
MIDFUNC bodies. The other listed forms have no configured caller.

## Caller census and reachability

Each accepted encoder has:

- **three configured callers** in `compemu_midfunc_arm64_2.cpp`;
- **three raw compatibility duplicates** in
  `compemu_legacy_arm64_compat.cpp`;
- **six direct raw source spellings** total;
- inventory reference count **3**.

Configured `ADCS_www` callers are flag-live ADDX byte, word, and long paths.
Configured `SBCS_www` callers are flag-live SUBX byte, word, and long paths.
The compatibility functions mirror those same width classes but are not
additional configured roots under the closure inventory's preprocessed graph.

## Encoding contract

Both instructions are W-width add/subtract-with-carry forms and set NZCV:

```text
ADCS Wd,Wn,Wm  sf=0 op=0 S=1 fixed=11010000 shift=0
SBCS Wd,Wn,Wm  sf=0 op=1 S=1 fixed=11010000 shift=0
```

The encoder fields are:

- destination `Wd`: bits 4:0;
- lhs `Wn`: bits 9:5;
- rhs `Wm`: bits 20:16;
- all fields accept architectural register 31 (WZR semantics).

Exact controls:

```text
ADCS w9,w10,w11       3a0b0149
ADCS wzr,wzr,wzr      3a1f03ff
SBCS w9,w10,w11       7a0b0149
SBCS wzr,wzr,wzr      7a1f03ff
```

`aarch64-linux-gnu-objdump` independently decodes the fourth architectural
alias as `NGCS wzr,wzr`, which is the expected SBCS encoding with `Wn=WZR`.

## Carry and borrow semantics

The emitters operate on physical AArch64 PSTATE.C:

- ADCS computes `Wn + Wm + C`, publishes carry-out in C, and sets N/Z/V;
- SBCS computes `Wn - Wm - !C`, publishes **no-borrow** in C, and sets N/Z/V.

Translation to 68K X/C and borrow polarity belongs to the accepted ADDX/SUBX
lifecycle, not these raw encoders:

- ADDX restores X as physical carry before ADCS and copies carry-out to X;
- SUBX restores inverted X/no-borrow before SBCS, then inverts physical C for
  architectural 68K borrow and copies it to X;
- byte/word ADDX uses all-ones lower padding so carry reaches the guest lane;
- narrow ADDX/SUBX reconstruct Z from the truncated result and apply sticky Z
  without disturbing N/C/V or carry polarity.

The direct encoder probe checks architectural physical-C semantics. The
existing 48-vector strict ADDX/SUBX matrix proves the surrounding guest flag
mapping for all widths, aliases, X inputs, carry/borrow, overflow, and sticky Z.

## Direct native conformance

`jit-test/emitter-carry-conformance.cpp` includes the production header and
maps each short sequence RW then RX before direct AArch64 execution.

It uses 12 boundary/overflow operand pairs, both incoming C values, and rotates
through destination-distinct, destination/lhs alias, and destination/rhs alias
forms. For each combination it independently computes and checks the 32-bit
result plus all N/Z/C/V bits under hostile initial flags.

Result:

```text
METRIC emitter_carry_apis=2
METRIC emitter_carry_exact_words=4
METRIC emitter_adcs_native_vectors=24
METRIC emitter_sbcs_native_vectors=24
METRIC emitter_carry_alias_vectors=48
METRIC emitter_carry_native_vectors=48
```

The complete emitter phase passes with this gate inserted after the foundational
`_W` sink and before the existing semantic-family suites.

## Structural acceptance

`jit-test/structural-audit.ts` fails closed on:

- any encoding-field change;
- raw call drift from six per API;
- configured call drift from three per API;
- inventory reference drift from three per API;
- loss of byte/word/long configured caller classes;
- loss of exact words, independent ADCS/SBCS result/NZCV or alias matrices;
- omission of the bounded script from the complete emitter phase;
- loss of the accepted ADDX/SUBX narrow-padding, borrow-polarity, and sticky-Z
  integration contracts.

## Acceptance results

The accepted clean-source epoch passes:

- direct carry conformance: **4 exact words + 48 result/NZCV/alias vectors**;
- complete emitter phase: all 25 bounded suites pass;
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
fda4f1fc4169d02ac890c42a422b5823aca2165c52b728a635a700e8db35c0fa  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.csv
fe40544ff2ced6e988ba695abdaf55fec9be49ba41a9d8d736320f18784ae416  BasiliskII/docs/AARCH64_JIT_CLOSURE_INVENTORY.md
```

## Closure effect

Deterministic regeneration moves exactly:

```text
emitter_api,ADCS_www: unreviewed -> audited
emitter_api,SBCS_www: unreviewed -> audited
```

No unreachable carry form changes classification. After this tranche,
**124 emitter APIs and 17 raw boundaries remain unreviewed**. Whole-engine
closure is not claimed.

## Reproduction

```sh
./jit-test/emitter-carry-conformance.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
