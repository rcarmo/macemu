# AArch64 JIT FPP cosh/acos/cos batch

## Scope

This bounded `i_FPP` batch covers `FCOSH` (`0x19`), `FACOS` (`0x1c`), and
`FCOS` (`0x1d`). FCOSH and FACOS already had configured MPFR exits but shared
the ordinary source-narrowing defect; FCOS still used AArch64 binary64/native
libm lowering. Binary arithmetic, remainder/scale, `FSINCOS`, control
operations, and the complete `i_FPP` lifecycle remain separate.

## Authoritative semantics

The fixed oracle follows the *MC68881/MC68882 User's Manual*, first edition,
and standalone MPFR 4.2.2 calculations independent of emulator output:

- every source is converted to extended precision before evaluation;
- the completed result obeys FPCR precision, exponent range, and rounding;
- FCOSH is even, maps both signed zeroes to positive one, and maps both
  infinities to positive infinity;
- FACOS accepts the closed interval `[-1,+1]`, maps `+1` to positive zero,
  `-1` to pi, either signed zero to pi/2, and out-of-domain values to NaN plus
  OPERR;
- FCOS is even, maps both signed zeroes to positive one, and maps either
  infinity to NaN plus OPERR; and
- signalling NaNs are quieted with SNAN status while quiet NaN payload/sign
  metadata is retained.

No downloaded manual or reference artefact is retained.

## Defects found and repaired

The ordinary MPFR path allocated FCOSH/FACOS sources at FPCR single/double
precision before acquisition. Both now join the extended-source/direct-result
contract: load the architectural value under the 64-bit extended significand
and exponent range, restore FPCR format, then evaluate directly into a separate
target-width result.

FCOS acquired through the AArch64 binary64 shadow and called host `cos`, losing
extended significand/exponent state, FPCR result semantics, and exact Motorola
FPSR publication. It now exits before operand acquisition and uses MPFR service.

Standalone MPFR produced source-sensitive 80-bit witnesses at both target
widths. Representative FPCR-single nearest results are:

```text
FACOS 3ffe:ffffffffffffffff -> 3fdf:b504f30000000000
FCOS  4031:b6a11497bd5f9551 -> bffe:9115a50000000000
```

The FACOS source is the nearest extended value below one and rounds to exactly
one in binary64, collapsing the correct small positive result to zero. The FCOS
witness exercises large-argument range
reduction whose result depends on low extended source bits.

## Focused runtime evidence

`bun jit-test/fpp-cosh-acos-cos-service-matrix.ts` passes:

```text
FPP_COSH_ACOS_COS_MATRIX service_pass=36 strict_pass=3 fail=0 total=39
```

The matrix covers all four single rounding directions and one double witness
per selector; signed zero; infinity/domain rules; qNaN/sNaN payload, sign, and
operation-local status; FCOSH finite single overflow; exact guarded 80-bit
output; FP7 self-alias; accrued FPSR and integer CCR preservation; compiled
block entry plus exact `f239` fallback at PC `0x1000`; and strict rejection.

FPSR is snapshotted into D0 before the following extended store clears current
exception status. Final FPSR alone is not accepted as evidence for OPERR,
SNAN, OVFL, or INEX2.

## Shared acceptance epoch

One shared runtime epoch passed all six phases in 1,753 seconds:

- this batch's **36 service + 3 strict** focused matrix;
- adjacent FSIN/FETOX/FTWOTOX/FLOG2 **49+4 strict** replay;
- complete structural and standalone strict full-JIT negative gates;
- the authoritative active-risky list: **904/904**, with zero semantic or
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

Shell syntax, Bun parsing, `git diff --check`, deterministic 998-row closure
regeneration, standalone MPFR oracle generation, and independent bounded review
also pass. Review tightened the FACOS discriminator to the exact nearest
extended value below one and made the structural service proof fail closed:
FCOSH/FACOS case blocks may not acquire operands, while FCOS must exit inside
its AArch64 guard before acquisition. Temporary oracle and acceptance files
were removed.

## Structural contracts

The structural audit requires all three configured service exits; FCOS's
AArch64-only exit before operand acquisition; exact membership in the shared
direct-result set; direct target-width `cosh`, `acos`, and `cos`; FACOS domain
and FCOS infinity handling; shared NaN metadata/range publication; and the
fail-closed 36+3 matrix.

## Closure decision

No closure row is promoted. `generator,i_FPP` remains **unreviewed** pending
all selector groups. This service evidence does not classify reachable generic
raw FPU emitters.
