# AArch64 JIT FPP unary decomposition batch

## Scope

This bounded `i_FPP` acceptance batch covers four adjacent ordinary MPFR
selectors:

- `FINT` (`0x01`) and `FINTRZ` (`0x03`), which decompose a value into an
  integral floating-point result;
- `FGETEXP` (`0x1e`) and `FGETMAN` (`0x1f`), which decompose a value into its
  unbiased binary exponent and signed mantissa.

All four are configured AArch64 service boundaries. FINT is unconditional,
FINTRZ's legacy native path exists only under inactive `USE_X86_FPUCW`, and
FGETEXP/FGETMAN unconditionally fail compilation after their disable checks.
Other arithmetic, transcendental, remainder/scale, FMOVEM/control operations,
and the complete `i_FPP` lifecycle remain separate.

## Authoritative semantics

The fixed oracle follows the *MC68881/MC68882 User's Manual*, first edition,
sections 2.2.2 and the individual FINT, FINTRZ, FGETEXP, and FGETMAN
descriptions:

- every operation first converts its source to extended precision;
- FINT rounds to an integer using the FPCR rounding direction;
- FINTRZ always rounds to an integer toward zero;
- FGETEXP returns the unbiased exponent as an extended floating-point integer;
- FGETMAN returns signed zero unchanged, otherwise a signed mantissa in
  `[1.0, 2.0)`;
- after an exact internal operation, an FP-register result is rounded to the
  FPCR precision and exponent range;
- infinity gives a NaN, sets OPERR, and accrues IOP for FGETEXP/FGETMAN;
- signalling NaNs are quieted with SNAN status, while quiet NaN payload and
  sign are retained.

The manual was used as development reference only; its downloaded PDF/text was
removed after these contracts were transcribed.

## Defects found and repaired

### Source precision versus result precision

The ordinary MPFR path allocated its sole source/result temporary at FPCR
single or double precision before operand acquisition. That pre-rounded the
architectural operand before any of these four operations.

The four selectors now acquire their source with a 64-bit MPFR significand and
extended exponent range. On successful operation, the exact extended result is
then converted to a separate FPCR-precision temporary, range-checked, and
stored in FPn. The configured exponent format is restored on both acquisition
failure and success.

This distinction is observable in both directions:

- `FINT(0.5 + 2^-64)` under FPCR single must produce one, because the source is
  extended before integral rounding;
- a large exact integral value with a low bit below single precision must lose
  that result bit and raise INEX2 after FINT/FINTRZ, because destination
  post-processing still obeys FPCR precision;
- FGETMAN must preserve a low extended source bit through decomposition but
  round that bit at single/double result precision.

### Extended-denormal exponent import

`set_from_extended()` treated an encoded zero exponent as unbiased `-16383`.
As with single and double subnormals, the effective exponent is the encoded
value one before bias removal. The smallest extended denormal therefore loaded
one power of two too small and FGETEXP returned `-16446` instead of `-16445`.
The importer now applies the missing zero-exponent adjustment.

### Infinity-derived NaN status and sign

MPFR's `mpfr_set_nan()` raises its own invalid flag. FGETEXP/FGETMAN already
set the architectural OPERR bit, so leaving the MPFR NaN flag live caused the
wrong SNAN status to appear. Both helpers now clear that MPFR implementation
flag. Both decomposition helpers restore the infinity source sign on the resulting
MPFR NaN and synchronize the separate architectural `nan_sign` metadata. That
metadata is consumed by later operations and JIT shadow export, so matching an
immediate extended-memory serialization alone is insufficient.

The focused probes snapshot FPSR into D0 immediately after the operation. The
following `FMOVE.X FP7,(A0)` correctly clears the current exception byte while
retaining accrued exceptions, so final REGDUMP FPSR alone is not accepted as
proof of operation-local OPERR/SNAN state.

## Focused runtime evidence

`bun jit-test/fpp-integral-rounding-fallback-matrix.ts` passes:

```text
FPP_INTEGRAL_ROUNDING_MATRIX service_pass=55 strict_pass=2 fail=0 total=57
```

It covers all four FINT rounding directions, FINTRZ independence from FPCR
rounding direction, input/result precision discriminators, signed zero and
infinity, qNaN/sNaN, FP7 self-alias, accrued FPSR, exact integer/inexact
publication, and strict full-JIT rejection.

`bun jit-test/fpp-decomposition-fallback-matrix.ts` passes:

```text
FPP_DECOMPOSITION_MATRIX service_pass=38 strict_pass=2 fail=0 total=40
```

It covers signed zero, positive/negative normal values, exact power/fraction
exponents, minimum normal, maximum finite, minimum denormal, infinity OPERR,
qNaN/sNaN payload/sign, FPCR single/double post-rounding, FP7 self-alias,
operation-local FPSR snapshots, accrued status, exact 80-bit guarded output,
negative-infinity NaN metadata consumed by a successor FNEG, and strict
full-JIT rejection.

Both matrices use direct extended-memory source encodings so no preceding
ordinary FMOVE can alter the operand. A direct operation has three serviced
boundaries in the replay sequence after the FPSR snapshot was added; a
load-plus-register-alias sequence has four.

## Shared acceptance epoch

After the NaN-metadata repair, one clean-binary acceptance batch passed all
eight selected phases in 2,439 seconds:

- structural audit and standalone strict full-JIT negative contracts;
- adjacent serviced-family replay: FABS/FNEG **31+6 strict** and FSQRT
  **54+3 strict**;
- this batch's FINT/FINTRZ **55+2 strict** and FGETEXP/FGETMAN **38+2
  strict** matrices;
- complete active-risky replay: **1,259/1,259**, with zero semantic or
  infrastructure failures;
- complete allocator-pressure replay: **31/31**, with zero failures.

A clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build produced the expected
AArch64 ELF. Pre-clean, post-clean, and two explicit generator runs were
byte-identical and left no generated diff:

```text
compemu.cpp   55fb6af9005d0077f91b3168707c67106824a5c43fa27c3deaf5bfeaabeee260
compstbl.cpp  45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b
comptbl.h     67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1
```

Shell syntax, Bun parse checks, `git diff --check`, unknown-case cleanup probes,
and independent bounded review also pass. Interrupted development artefacts
were removed; no persistent test tree or downloaded reference copy remains.

## Structural contracts

The structural audit requires:

- the configured AArch64 service boundaries for all four selectors;
- the exact four-selector extended-source predicate;
- source precision/format expansion before `get_fp_value()`;
- configured format restoration on acquisition failure;
- separate result rounding and range checking at FPCR precision;
- FINT FPCR-directed rounding and FINTRZ forced toward-zero rounding;
- extended-denormal exponent adjustment;
- FGETEXP/FGETMAN infinity OPERR without a spurious MPFR NaN flag;
- both helpers' infinity-derived MPFR NaN sign and architectural `nan_sign`
  metadata retention;
- fail-closed maintained matrix totals of 55+2 and 38+2.

## Closure decision

No closure row is promoted to **audited**. `generator,i_FPP` remains
**unreviewed** pending all remaining selector groups. The already classified
unreachable `midfunc,frndint_rr` and `midfunc,frndintz_rr` rows remain
unchanged.

A later configured-root audit established that `raw_frndint_rr` and
`raw_frndintz_rr` are definition-only beneath those unreachable MIDFUNCs. They
are therefore **unreachable**, guarded by exact parent/body, inactive
`USE_X86_FPUCW`, definition-only reference, and future-caller checks. The
closure initially stopped at the raw wrappers: `FRINTI_dd` remained reachable
through integer-destination rounding, and `FRINTZ_dd` remained reachable through
modulus truncation, with exact 2/2 retained-site counts.

A later paired FMOD/FREM lower-chain audit retired definition-only
`raw_fmod_rr`/`raw_frem1_rr`; both `FRINTZ_dd` sites and sole-site `FRINTA_dd`
are now **unreachable**. Their direct audit remains historical evidence, while
`FRINTI_dd` stays audited/reachable at two sites.

This was raw-boundary retirement at landing time, not native acceptance.
The accepted 55+2 FINT/FINTRZ matrix remains configured guest runtime evidence;
the FGETEXP/FGETMAN decomposition paths and their separate raw/MIDFUNC residue
are unchanged.
