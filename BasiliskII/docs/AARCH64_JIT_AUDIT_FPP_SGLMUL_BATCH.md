# AArch64 JIT FPP FSGLMUL batch

## Scope

This bounded checkpoint covers `FSGLMUL` (`0x27`) only. Control operations and
complete `i_FPP` closure remain separate.

## Semantics and repairs

FSGLMUL accepts arbitrary-precision factors but rounds the product significand
to single precision while retaining the extended exponent range. It must not
pre-round either factor, double-round an extended intermediate, or report
single-format range merely because the exponent lies outside IEEE single.

AArch64 now enters semantic service before operand acquisition. Both factors
remain extended, while MPFR multiplies directly into a 24-bit result under
extended exponent limits. FPCR direction applies but FPCR precision does not.
The shared publication boundary applies binary NaN ownership, signed results,
zero-times-infinity OPERR, and exact FPSR state.

## Focused evidence

`bun jit-test/fpp-sglmul-service-matrix.ts` passes:

```text
FPP_SGLMUL_MATRIX service_pass=22 strict_pass=1 fail=0 total=23
```

The matrix covers:

- independent one-sided destination/source factor-retention witnesses;
- an exact midpoint witness whose direct 24-bit product rounds upward while an
  extended-first product ties down to 1.0;
- nearest, plus and negative round-minus results independent of FPCR precision;
- exact extended exponent results outside IEEE single range without false
  overflow/underflow;
- signed zero/infinity and both zero-times-infinity operand orders;
- qNaN/SNaN metadata, quieting, and destination precedence;
- FP7 alias/reseed, postincrement/predecrement EA effects, accrued FPSR,
  integer CCR preservation, exact native entry and strict rejection; and
- exact fallback opcode attribution at PC `0x1008`.

The complete two-pass service profile is also pinned: one initial
`f239@0x1000` destination load followed by two identical source/FSGLMUL,
FPSR-capture, and store triples. Absolute-long source uses PCs
`0x1008/0x1010/0x1014`; register, postincrement, and predecrement forms use
`0x1008/0x100c/0x1010` with their exact `f200`/`f218`/`f220` source opcode.
This replaces the stale six-boundary exception for the signalling-destination
case; clean runtime records the same seven non-duplicative boundaries.

## Structural and review decision

The structural audit pins the pre-acquisition service guard, operation 39
membership in the direct-single/extended-exponent result contract, exact
midpoint and one-sided records, specials/NaNs, aliases/EA, fallback attribution,
strict rejection, and 22+1 accounting.

Independent review accepted the implementation but required the explicit
midpoint/double-round witness. It was independently derived, added, and passed
before final approval.

No closure row is promoted to **audited**. `generator,i_FPP` remains
**unreviewed** pending all selector groups.

A later combined multiply-root audit established that this selector and the
FMUL/FSMUL/FDMUL block are the only configured `fmul_rr` roots, and both service
before operand acquisition. With no MIDFUNC caller, `fmul_rr`,
`raw_fmul_rr`, and binary64 `FMUL_ddd` are therefore **unreachable**. This
matrix remains the 22+1 runtime-fidelity proof for the FSGLMUL root. The
separate `FMUL_sss` forced-single emitter remains reachable and audited.
