# AArch64 JIT FPP divide batch

## Scope

This bounded `i_FPP` batch covers ordinary `FDIV` (`0x20`) and forced-result
`FSDIV`/`FDDIV` (`0x60`/`0x64`). It does not cover `FMOD`, `FREM`, `FSCALE`,
`FSGLDIV`, add/multiply/subtract families, control operations, or the complete
`i_FPP` lifecycle.

## Authoritative semantics

The implementation and fixed matrix follow the *MC68881/MC68882 User's Manual*
and standalone MPFR 4.2.2 calculations:

- both architectural operands retain their full extended significand and
  exponent range before division;
- ordinary FDIV rounds the completed result at FPCR precision and rounding
  direction;
- FSDIV/FDDIV force 24/53-bit result precision and matching exponent range,
  while still acquiring both operands as extended values;
- finite non-zero divided by zero reports DZ; zero divided by zero and infinity
  divided by infinity report OPERR; a NaN operand suppresses those generated
  arithmetic exceptions;
- a signalling NaN is quieted and reports SNAN; normal NaN selection then
  applies, so when both operands are NaNs the destination/dividend payload and
  sign take precedence; and
- finite forced overflow/underflow publishes OVFL/UNFL plus INEX2 and the
  corresponding accrued state.

The local FDIV section refers to the manual's common NaN rules. Section 4.5.4
states that an untrapped SNaN is converted to a nonsignalling NaN and processing
continues under the nonsignalling rule; if both operands are then NaNs, the
destination operand is returned.

No downloaded manual or reference artefact is retained.

## Defects found and repaired

Ordinary FDIV previously acquired the source at FPCR single/double precision
and evaluated through that narrowed value. It now joins the direct-result path:
the source remains extended, division targets FPCR width directly, and result
range/flags are published once.

FSDIV/FDDIV already acquired the source at full width and divided directly at
24/53 bits, but MPFR's default NaN metadata discarded architectural payload,
sign, and signalling ownership. A shared binary-NaN selector now considers both
operands: it records and quiets either SNaN, then applies destination precedence
whenever both operands are NaNs. The selected quieted payload/sign is applied to
both metadata and MPFR state. Destination SNaNs explicitly contribute SNAN status.

Forced division also lacked explicit exponent-range classification when MPFR
returned infinity or zero at the target boundary. Finite operands producing
forced infinity now report OVFL+INEX2; finite operands producing forced zero
report UNFL+INEX2.

A harness-only replay seed was required to prove destination SNaN and FP7 state
without routing through the separately unreviewed native FMOVEM lifecycle.
`B2_TEST_REPLAY_FP0_EXT` through `B2_TEST_REPLAY_FP7_EXT` restore exactly three
extended words, decode under the extended MPFR range, restore the selected FPCR
format, and clear the corresponding binary64 dirty-shadow ownership bit. This
is test-state restoration only; ordinary emulator execution is unchanged.

## Focused runtime evidence

`bun jit-test/fpp-divide-service-matrix.ts` passes:

```text
FPP_DIVIDE_MATRIX service_pass=37 strict_pass=3 fail=0 total=40
```

The fixed matrix covers:

- ordinary extended `1/3` and a low-significand-bit reciprocal discriminator;
- FPCR single/double result precision and directed rounding;
- forced single/double precision under multiple rounding modes;
- signed divide-by-zero, zero/zero, infinity/infinity, zero/infinity;
- forced finite overflow and underflow;
- destination/source qNaN suppression, both SNaN/qNaN operand orders after
  quieting, equal-qNaN and equal-SNaN destination precedence, payload and sign;
- FP7 self-alias plus non-idempotent FP7 destination replay reseeding;
- postincrement and predecrement source EA effects;
- accrued FPSR and integer CCR preservation; and
- three exact strict full-JIT rejections.

Every service case enters a compiled block natively at PC `0x1008` and executes
FDIV/FSDIV/FDDIV through the configured MPFR fallback. FPSR is snapshotted into
D0 before the following extended store clears current exception status; final
FPSR verifies condition codes and accrued exceptions separately.

## Integrated acceptance epoch

One integrated runtime epoch passed all six phases in 2,318 seconds:

- this batch's **37 service + 3 strict** focused matrix;
- complete structural and standalone strict full-JIT negative gates;
- the authoritative active-risky list: **1,259/1,259**, with zero semantic or
  infrastructure failures; and
- complete allocator-pressure replay: **31/31**, with zero failures.

A clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build produced the expected
AArch64 ELF. Pre-clean, post-clean, and two explicit generator runs were
byte-identical and left no generated diff:

```text
compemu.cpp   55fb6af9005d0077f91b3168707c67106824a5c43fa27c3deaf5bfeaabeee260
compstbl.cpp  45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b
comptbl.h     67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1
```

## Structural contracts

The structural audit requires the three-selector AArch64 service exit before
operand acquisition; ordinary direct-result membership; forced-width direct
arithmetic and range classification; explicit binary NaN selection and sign
publication; register-indexed replay seeding with extended-range decode and
dirty-shadow release; exact matrix membership; native-entry proof; and strict
rejection.

Independent bounded review initially rejected forced NaN sign publication and
FP7 replay evidence. Both were repaired: the selected sign is applied to the
MPFR result, replay supports FP0-FP7, and non-idempotent FP7 destination vectors
prove reseeding. Re-review approved the bounded tranche.

## Closure decision

No closure row is promoted. `generator,i_FPP` remains **unreviewed** pending all
selector groups. This service evidence does not classify reachable generic raw
FPU emitters.
