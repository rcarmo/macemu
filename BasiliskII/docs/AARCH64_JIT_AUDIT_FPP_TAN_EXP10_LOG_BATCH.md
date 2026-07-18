# AArch64 JIT FPP tangent/exp10/log batch

## Scope

This bounded `i_FPP` batch covers four ordinary MPFR selectors with configured
AArch64 pre-operand service boundaries: `FTAN` (`0x0f`), `FTENTOX` (`0x12`),
`FLOGN` (`0x14`), and `FLOG10` (`0x15`). Native `FSIN`, `FETOX`, `FTWOTOX`,
and `FLOG2`, plus remaining arithmetic/control groups and the complete `i_FPP`
lifecycle, remain separate.

## Authoritative semantics

The fixed oracle follows the *MC68881/MC68882 User's Manual*, first edition,
individual instruction and exception tables:

- every source is converted to extended precision before evaluation;
- the completed result obeys FPCR precision, exponent range, and rounding;
- `FTAN` preserves signed zero; either infinity returns NaN plus OPERR;
- `FTENTOX(+infinity)` returns positive infinity and
  `FTENTOX(-infinity)` returns positive zero;
- `FLOGN` and `FLOG10` return negative infinity plus DZ for either signed zero,
  positive infinity for positive infinity, and NaN plus OPERR for negative
  finite or infinite inputs; and
- signalling NaNs are quieted with SNAN status while quiet NaN payload/sign
  metadata is retained.

The manual was downloaded from the public Bitsavers Motorola archive only
while extracting these rules and then deleted.

## Defect found and repaired

The four selectors joined the shared extended-source/direct-result contract.
The old ordinary MPFR path allocated its source at FPCR single/double precision,
pre-rounding architectural input. It now loads under 64-bit extended
precision/range, restores the selected FPCR format, and evaluates directly into
a separate target-width MPFR result. This removes source narrowing without
introducing transcendental double rounding and preserves separate NaN metadata.

Independent MPFR searches produced source-sensitive witnesses at both 24- and
53-bit result precision. Representative FPCR-single nearest results are:

```text
FTAN    4002:b0333c59a280eb2c -> c004:ec2eb70000000000
FTENTOX 3ffe:e1ff06630812f2b6 -> 4001:f450470000000000
FLOGN   4000:88c1802d52cd3d8d -> 3ffe:c2626b0000000000
FLOG10  4000:97166b22d6c2bbfd -> 3ffd:bf00400000000000
```

Each differs from evaluating a source first rounded to single precision.

## Focused runtime evidence

`bun jit-test/fpp-tan-exp10-log-fallback-matrix.ts` passes:

```text
FPP_TAN_EXP10_LOG_MATRIX service_pass=45 strict_pass=4 fail=0 total=49
```

The fixed matrix covers all four single rounding directions and one
source-sensitive double result per selector; signed zero; infinity/domain
rules; qNaN/sNaN payload, sign, and operation-local status; extended-to-single
and finite exponential underflow; exact guarded 80-bit output; FP7 self-alias;
accrued FPSR and integer CCR preservation; and strict rejection before native
execution.

FPSR is snapshotted into D0 before the following extended store clears current
exception status. Final FPSR alone is therefore not used as evidence for DZ,
OPERR, SNAN, UNFL, or INEX2.

## Shared acceptance epoch

One clean-binary batch passed all six selected phases in 2,374 seconds:

- structural and standalone strict full-JIT negative gates;
- adjacent inverse-function **38+3 strict** replay;
- this batch's **45+4 strict** focused matrix;
- complete active-risky replay: **1,259/1,259**, zero semantic or
  infrastructure failures; and
- complete allocator-pressure replay: **31/31**, zero failures.

A clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build produced the expected
AArch64 ELF. Pre-clean, post-clean, and two explicit generator runs were
byte-identical and left no generated diff:

```text
compemu.cpp   55fb6af9005d0077f91b3168707c67106824a5c43fa27c3deaf5bfeaabeee260
compstbl.cpp  45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b
comptbl.h     67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1
```

Shell syntax, Bun parsing, `git diff --check`, deterministic 998-row closure
regeneration, standalone MPFR oracle generation, and independent review also
pass. Temporary reference/oracle/log files were removed.

## Structural contracts

The structural audit requires all four configured service exits; exact
membership in the extended-source/direct-result selector set; direct
target-width `tan`, base-10 power, natural-log, and base-10-log evaluation;
FTAN infinity OPERR and logarithm zero/negative domain handling; shared NaN
metadata/range publication; and the fail-closed 45+4 matrix.

## Closure decision

No closure row is promoted. `generator,i_FPP` remains **unreviewed** pending
all selector groups. This semantic-service evidence does not classify the
still-reachable generic raw FPU emitters.
