# AArch64 generic EOR emitter audit

Date: 2026-07-16
Branch: `jit-audit-next`
Base: `c6acda3f4d1f144b72e1bc4afe393cb6d603a2d5`

## Scope

The deterministic closure inventory selects `EOR_www` after the complete M68K
EOR lifecycle. The complete reachable generic EOR encoder surface is:

- `EOR_www`;
- `EOR_wwwLSLi`;
- `EOR_xxCflag`;
- `EOR_xxbit`; and
- the shared immediate base `immOP_EOR` composed by the final two helpers.

`EOR_xxx` and `EOR_xxxLSLi` remain source-unreachable and are not promoted.
The generic EOR emitter audit is separate from M68K EOR semantics and from the
already accepted `EORSR` lifecycle.

No production encoder correction was required. This tranche adds direct
production-header conformance, fail-closed caller contracts, deterministic
closure classification, and documentation.

## Encoding contract

`EOR_www` and `EOR_wwwLSLi` emit AArch64 32-bit shifted-register EOR with
`S=0`. The unshifted form fixes LSL zero; the shifted form masks its immediate
to the architectural five-bit W range. W writes zero-extend into the host X
register.

`immOP_EOR` is exactly `0xd2000000`, the 64-bit logical-immediate EOR base.
`EOR_xxCflag` composes it with `immCflag`, toggling bit 29 of a saved NZCV word.
`EOR_xxbit` composes the same base with a one-bit logical immediate for bit
0-63. Neither helper writes PSTATE directly and all four callable encoders keep
NZCV unchanged.

The production-header probe checks 13 independent GNU-assembler-confirmed
words:

```text
EOR w9,  w10, w11             4a0b0149
EOR w30, w29, w28             4a1c03be
EOR wzr, wzr, wzr             4a1f03ff
EOR w9,  w10, w11, LSL #7     4a0b1d49
EOR w30, w29, w28, LSL #31    4a1c7fbe
EOR wzr, wzr, wzr, LSL #0     4a1f03ff  (input shift 32 masks to zero)
EOR x9,  x10, #0x20000000     d2630149
EOR x30, x29, #0x20000000     d26303be
EOR sp,  xzr, #0x20000000     d26303ff
EOR x9,  x10, #0x1            d2400149
EOR x12, x13, #0x20000000     d26301ac
EOR x30, x29, #0x8000000000000000 d24103be
EOR sp,  xzr, #0x8000000000000000 d24103ff
```

The field-31 logical-immediate rows are raw encoder evidence: register field 31
names SP as the destination and XZR as the source. Production callers are
bounded to allocator registers R0-R17 and fixed work registers R2-R5; native
semantic vectors stay within that domain.

## Native semantic matrix

`jit-test/emitter-eor-conformance.cpp` executes the emitted words directly on
the AArch64 host. Its 22 native vectors comprise 18 result vectors and four
explicit unchanged-NZCV vectors. They cover:

- W zero extension and X 64-bit preservation;
- ordinary production-domain register fields, with separate exact-word checks
  for high and maximum fields;
- destination/source-N, destination/source-M, and all-equal aliases;
- LSL counts 1, 5, 7, 31, and masked 32;
- C-bit set/clear and preservation of every other bit;
- generic single-bit toggles at bits 0, 5, 29, and 63;
- distinct and in-place immediate destinations; and
- unchanged NZCV for every callable API.

The probe also checks the non-emitting `immOP_EOR` base independently. It builds
with `-Wall -Wextra -Werror`, maps code RW then RX, flushes the instruction
cache, and fails closed on any word, result, flag, or vector-count mismatch.

## Caller census and domain

The configured closure scan observes 53 reachable references:

```text
EOR_www        24
EOR_wwwLSLi     1
EOR_xxCflag    21
EOR_xxbit       5
immOP_EOR       2
```

The stronger raw-source census covers 64 compositions across active and
conditionally compiled production implementations:

```text
EOR_www        25
EOR_wwwLSLi     1
EOR_xxCflag    31
EOR_xxbit       5
immOP_EOR       2
```

Every raw call shape is locked structurally. `EOR_www` has eight exact operand
shapes totalling 25 calls. `EOR_wwwLSLi` has one fixed `LSL #1` caller.
`EOR_xxCflag` has 31 in-place calls across allocator or R2-R5 work registers.
`EOR_xxbit` has four width-masked dynamic compositions (`s & 0x7` or
`s & 0x1f`) and one literal bit-zero X toggle. `immOP_EOR` appears only in its
own definition and the two audited final helper compositions.

The structural gate fails if a caller count, operand shape, shift/bit bound,
register-domain definition, helper composition, exact word, native vector, or
harness integration changes. `EOR_xxx` and `EOR_xxxLSLi` remain unreachable.

## Acceptance gates

```sh
bash jit-test/emitter-eor-conformance.sh
B2_TEST_NAMES=eor_core_b_reg_zero_native bash jit-test/run.sh
bash jit-test/run.sh
bash jit-test/regalloc-pressure.sh
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
bash -n jit-test/run.sh jit-test/regalloc-pressure.sh \
  jit-test/emitter-eor-conformance.sh
make -C BasiliskII/src/Unix clean
make -C BasiliskII/src/Unix -j12
git diff --check
```

Final evidence:

```text
METRIC emitter_eor_apis=5
METRIC emitter_eor_exact_words=13
METRIC emitter_eor_base_constants=1
METRIC emitter_eor_native_result_vectors=18
METRIC emitter_eor_native_flag_vectors=4
METRIC emitter_eor_native_vectors=22
focused: pass=1 fail=0 infra_fail=0 score=100
active-risky: pass=725 fail=0 infra_fail=0 score=100
allocator pressure: 22/22 PASS, 0 FAIL
closure inventory: 997 rows; emitter_api=42 audited, 91 unreachable,
                   161 unreviewed
```

The clean AArch64 `uae_cpu_2026`/`USE_JIT_FPU` build succeeds. `compemu.cpp`,
`compstbl.cpp`, and `comptbl.h` retain hashes
`3476e73b1d78da29814d529c8493909bf00f85e7928a0e0afa0cb3e3a8f459b5`,
`45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`, and
`67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`
across the clean build and explicit regeneration. Two closure generations are
byte-identical; final CSV and Markdown hashes are
`4fd10774e886e3e868b8bbbe7178475159c1e0633f7c9040268d4c856cb3d972` and
`7f293f2980d10b08489c2a1a9e8171d3e09ab34823b6b337a92af8384bb2f2bd`.

Only these five directly proved entries are promoted. At this tranche's
acceptance, the next mechanically selected family was the complete reachable
M68K OR lifecycle; it is now accepted by
`AARCH64_JIT_AUDIT_OR_LIFECYCLE.md`. Whole-engine closure is not claimed.
