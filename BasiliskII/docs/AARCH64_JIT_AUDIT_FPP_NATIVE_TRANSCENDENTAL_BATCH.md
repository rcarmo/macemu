# AArch64 JIT FPP native-transcendental batch

## Scope

This bounded `i_FPP` batch covers the four ordinary selectors that still used
AArch64 binary64-native transcendental lowering: `FSIN` (`0x0e`), `FETOX`
(`0x10`), `FTWOTOX` (`0x11`), and `FLOG2` (`0x16`). Adjacent serviced
selectors, `FCOS`, `FACOS`, `FCOSH`, binary arithmetic, `FSINCOS`, control
operations, and the complete `i_FPP` lifecycle remain separate.

## Authoritative semantics

The fixed oracle follows the *MC68881/MC68882 User's Manual*, first edition,
and standalone MPFR 4.2.2 calculations which do not consume emulator output:

- each architectural source is converted to extended precision before the
  operation;
- the completed result obeys FPCR precision, exponent range, and rounding;
- `FSIN` preserves signed zero and returns NaN plus OPERR for either infinity;
- `FETOX` and `FTWOTOX` return positive zero for negative infinity and positive
  infinity for positive infinity;
- `FLOG2` returns negative infinity plus DZ for either signed zero, positive
  infinity for positive infinity, and NaN plus OPERR for negative values; and
- signalling NaNs are quieted with SNAN status while quiet NaN payload/sign
  metadata is retained.

The manual was used only as a public reference; no downloaded copy is retained.

## Defects found and repaired

The old compiler routes acquired an architectural source through the AArch64
binary64 shadow and called host `sin`, `exp`, `pow`, or `log2`. That loses the
low eleven bits and most of the exponent range of a Motorola extended value,
ignores FPCR single/double target semantics, and cannot publish exact Motorola
FPSR status. All four selectors now exit before operand acquisition and use the
existing MPFR semantic service.

The MPFR implementation now joins these selectors to the shared
extended-source/direct-result contract: load under the 64-bit extended
significand and exponent range, restore the selected FPCR format, then evaluate
directly into a distinct target-width result. Direct evaluation avoids both
source narrowing and transcendental double rounding. `FTWOTOX` uses MPFR's
base-two exponential directly rather than a generic integer-power call.

Standalone MPFR produced fixed 80-bit inputs and directed target-width outputs.
Two source-sensitive FPCR-single witnesses are:

```text
FSIN  4007:ab6c19190b221197 -> bffd:cc84b20000000000
FETOX 4003:b3f2897065067d03 -> 401f:aefe3d0000000000
```

Both differ from evaluating a binary64-narrowed source. Range evidence is
stronger than ordinary rounding alone: `FLOG2` of the minimum extended
subnormal returns the exact finite value `-16445` (`c00d:807a...`); the old
binary64 route first collapsed that source to zero and could only produce
negative infinity with spurious DZ.

## Focused runtime evidence

`bun jit-test/fpp-native-transcendental-service-matrix.ts` passes:

```text
FPP_NATIVE_TRANS_MATRIX service_pass=49 strict_pass=4 fail=0 total=53
```

The fixed matrix covers all four single rounding directions and one double
result per selector; signed zero; infinity/domain rules; qNaN/sNaN payload,
sign, and operation-local status; finite single overflow and underflow;
minimum-extended source fidelity; exact guarded 80-bit output; FP7 self-alias;
accrued FPSR and integer CCR preservation; and strict rejection before native
execution.

FPSR is snapshotted into D0 before the following extended store clears current
exception status. Final FPSR alone is not used as evidence for DZ, OPERR, SNAN,
OVFL, UNFL, or INEX2.

## Shared acceptance epoch

One clean-binary batch passed all selected runtime phases:

- this batch's **49 service + 4 strict** focused matrix;
- adjacent FTAN/FTENTOX/FLOGN/FLOG10 **45+4 strict** replay;
- complete structural and standalone strict full-JIT negative gates;
- the authoritative active-risky list: **904/904**, with zero semantic or
  infrastructure failures; and
- complete allocator-pressure replay: **31/31**, with zero failures.

The earlier 1,259 label in neighbouring tranche reports combined unlike
focused/runtime counts; `jit-test/active-risky-tests.txt` has contained exactly
904 entries since `c4c1d99a`. This report records each evidence class separately
rather than carrying that inflated active-corpus label forward.

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
also pass. The reviewer identified and then approved strengthened fail-closed
evidence: service cases require both compiled-block entry and exact `f239`
fallback at PC `0x1000`; strict companions reject fallback as full-JIT
execution; and the structural gate proves every AArch64 service exit precedes
operand acquisition. Temporary oracle, review, and acceptance files were
removed.

## Structural contracts

The structural audit requires all four AArch64-only service exits before source
acquisition; exact membership in the direct-result selector set; direct
target-width `sin`, `exp`, `exp2`, and `log2` evaluation; FSIN infinity OPERR
and FLOG2 zero/negative domain handling; shared NaN metadata/range publication;
and the fail-closed 49+4 matrix.

## Closure decision

No closure row is promoted. `generator,i_FPP` remains **unreviewed** pending
all selector groups. This service evidence does not classify reachable generic
raw FPU emitters.
