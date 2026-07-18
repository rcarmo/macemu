# AArch64 JIT FPP FMOD batch

## Scope

This bounded `i_FPP` batch covers `FMOD` (`0x21`) only. `FREM`, `FSCALE`,
`FSGLDIV`, other binary arithmetic, control operations, and the complete
`i_FPP` lifecycle remain separate.

## Authoritative semantics

The fixed oracle follows the *MC68881/MC68882 User's Manual*, first edition,
section 4-61 through 4-63, and standalone integer/MPFR calculations:

- both operands are converted to extended precision before arithmetic;
- the result is `destination - source*N`, where `N` is the destination/source
  quotient rounded toward zero;
- the quotient byte receives the quotient sign (operand-sign XOR) and unsigned
  low seven magnitude bits;
- destination zero returns the same signed zero, and source infinity returns
  the destination; the result still undergoes normal FPCR result rounding;
- source zero or destination infinity returns NaN and reports OPERR;
- an untrapped SNaN is quieted and reports SNAN, then common destination
  precedence applies if both operands are NaNs; and
- ordinary post-processing sets condition codes, exception status, and accrued
  state while replacing the prior quotient byte on a defined FMOD.

No downloaded manual or reference artefact is retained.

## Defects found and repaired

The compiler previously lowered FMOD through `frem_rr`, which implements IEEE
remainder rather than truncating modulo and did not publish a Motorola quotient
byte. FMOD now uses exact semantic service on every host and exits before
operand acquisition. The `7 mod 4` discriminator returns `+3` with quotient 1;
IEEE remainder would return `-1` with quotient 2.

The MPFR service path previously acquired its source at FPCR single/double
precision, so low extended bits and exponent range could be lost before modulo.
FMOD now joins the extended-source/post-rounded-result contract: arithmetic is
performed with architectural extended operands, then the completed remainder is
rounded and range-checked once at FPCR precision.

The existing exact `mpfr_rem1` helper already computes truncating quotient low
bits without materialising an arbitrarily large quotient. Its special-value
boundary is now completed:

- binary NaN payload/sign selection uses the common quiet-then-destination rule;
- destination-zero/source-infinity results publish quotient sign even when the
  magnitude is zero; and
- invalid source-zero/destination-infinity and NaN paths preserve the prior
  quotient while publishing operation status.

## Focused runtime evidence

`bun jit-test/fpp-fmod-service-matrix.ts` passes:

```text
FPP_FMOD_MATRIX service_pass=31 strict_pass=1 fail=0 total=32
```

The fixed matrix covers:

- positive and negative operand combinations, quotient sign, low-seven wrap,
  and the explicit `7 mod 4` FMOD-versus-FREM discriminator;
- independent destination/source extended-low-bit witnesses;
- FPCR single/double result rounding in all relevant directions;
- finite single overflow and underflow after post-rounding;
- signed-zero and source-infinity result rules with zero quotient magnitude;
- source-zero and destination-infinity OPERR with prior quotient preservation;
- qNaN and SNaN payload/sign/quieting with destination precedence;
- FP7 self-alias and non-idempotent destination reseeding;
- postincrement/predecrement EA effects;
- quotient replacement with accrued-exception preservation; and
- exact strict full-JIT rejection.

Every service case enters a compiled block natively at PC `0x1008` and executes
FMOD through configured semantic service. FPSR is snapshotted into D0 before the
following extended store clears operation-local exception status.

The complete two-pass service profile is pinned as the initial destination load
at `f239@0x1000`, followed by two identical source/FMOD, FPSR-capture, and store
triples. Absolute-long source uses `f239@0x1008`, `f200@0x1010`, and
`f239@0x1014`; register, postincrement, and predecrement forms use their exact
`f200`/`f218`/`f220` source opcode at `0x1008`, then `f200@0x100c` and
`f239@0x1010`. This replaces a stale six-fallback exception for the
signalling-destination case; clean runtime records seven non-duplicative
boundaries with PCs derived from each source form's encoded length.

## Integrated acceptance epoch

One integrated runtime epoch passed all six phases in 2,333 seconds:

- this batch's **31 service + 1 strict** focused matrix;
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

The structural audit requires an unconditional FMOD service exit before operand
acquisition on every host and forbids `get_fp_value`, `frem_rr`, and native FPSR
publication in the compiler case. It pins extended-source membership, exact
`mpfr_rem1` quotient publication, quotient sign for zero-magnitude specials,
common binary NaN ownership, all 31 matrix cases, native-entry proof, exact
two-pass opcode/PC profiles, and strict rejection.

Independent review initially rejected a residual non-AArch64 `frem_rr` path and
a false-positive `2 mod 1.5` discriminator. Both were repaired: no host may
compile FMOD natively, and `7 mod 4` now distinguishes truncating FMOD from
nearest-even FREM. Re-review approved the bounded tranche.

## Closure decision

No closure row was promoted at this guest-service checkpoint.
`generator,i_FPP` remained **unreviewed** pending all selector groups.

A later paired lower-chain audit combines FMOD with FREM because both retained
wrappers share the same native divide/fused-subtract ownership. `fmod_rr` and
`frem1_rr` have no configured callers; `raw_fmod_rr` and `raw_frem1_rr` are
definition-only with exact `FDIV_ddd` -> `FRINTZ_dd`/`FRINTA_dd` ->
`FMSUB_dddd` order. The two raw wrappers, all three retained `FDIV_ddd` sites,
both `FMSUB_dddd` sites, both retained `FRINTZ_dd` sites, and sole-site
`FRINTA_dd` are therefore **unreachable**. `FRINTI_dd` remains the sole live
member of the direct rounding cluster, audited/reachable at two sites. The
repaired 31+1 FMOD and 33+1 FREM matrices own configured runtime fidelity;
direct divide/fused-subtract/round audits remain historical encoding and
host-semantic evidence. `generator,i_FPP` remains **unreviewed**.
