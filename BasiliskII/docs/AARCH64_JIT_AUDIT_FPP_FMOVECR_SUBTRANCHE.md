# AArch64 JIT FPP FMOVECR subtranche

## Scope

This bounded `i_FPP` subtranche covers the complete FMOVECR selector family:
all 22 architecturally defined constant-ROM selectors, selected undefined
selectors, FPCR rounding/precision, destination register fields, exact 80-bit
values, and FPSR publication.

On AArch64 FMOVECR is now one exact MPFR service boundary. FMOVEM/control moves,
explicit-precision arithmetic, ordinary arithmetic, and the complete `i_FPP`
lifecycle remain separate.

## Defect found and repaired

The native selector dispatch mixed incompatible precision strategies:

- π, log10(2), log2(e), and ln(2) were binary32 literals;
- e, log10(e), ln(10), and powers were binary64 or host constants;
- powers beyond binary64 range reached the approximate extended helper and
  could fall back while smaller selectors remained native;
- FPCR-selected 24-/53-/64-bit rounding and INEX publication were inconsistent.

A direct comparison reproduced π as
`4000:c90fdb0000000000` natively rather than the architectural extended value
`4000:c90fdaa22168c235`. Selector 63 already fell back, confirming that one
family had mixed execution policies.

The AArch64 FMOVECR gate now fails before selector dispatch. Every defined and
undefined selector executes through the MPFR constant ROM, preserving one
precision/rounding/exception contract.

## Runtime evidence

`bun jit-test/fpp-fmovecr-fallback-matrix.ts` runs 36 service cases:

- all defined selectors: 0, 11-15, and 48-63;
- π, log constants, e, zero, one, and powers `10^1` through `10^4096`;
- π under all four FPCR rounding modes at single and double precision;
- six representative undefined selectors spanning 1 through 127, following
  the current MPFR zero policy;
- guarded exact 80-bit memory output, FPSR, unchanged A0/SR, and visible
  FMOVECR fallback.

Three strict cases cover π, `10^4096`, and undefined selector 127 with FP7
maximum destination fields. They require strict opcode fallback, no native
entry, and no SIGSEGV.

Accepted result:

```text
FPP_FMOVECR_FALLBACK_MATRIX service_pass=36 strict_pass=3 fail=0 total=39
```

Composition evidence:

```text
FPP_EXPLICIT_MOVE_FALLBACK_MATRIX service_pass=13 strict_pass=2 fail=0 total=15
FPP_FMOVE_EXTENDED_FALLBACK_MATRIX service_pass=8 strict_pass=4 fail=0 total=12
FPP_FMOVE_PACKED_FALLBACK_MATRIX service_pass=9 strict_pass=4 fail=0 total=13
active-risky: pass=904 fail=0 infra_fail=0 score=100
allocator pressure (isolated): pass=31 fail=0
```

## Structural contracts

- The AArch64 FMOVECR service gate must issue `FAIL(1)` and return before
  `switch (extra & 0x7f)`.
- The matrix must retain fixed 80-bit oracles for every defined selector, rather
  than recomputing constants with the implementation under test.
- π must cover all four rounding modes at single and double precision with
  exact INEX accrued state.
- Undefined-selector policy and FP7 strict boundaries must remain explicit.

## Closure decision

The original FMOVECR checkpoint promoted no closure row. `generator,i_FPP`
remains **unreviewed** pending the other FPP subfamilies.

A later configured-root audit resolved the constant-helper graph beneath the
AArch64 service gate. `fmov_l_ri` has no configured root, and its constant-10
and constant-100 children are already unreachable. Their definition-only raw
wrappers `raw_fmov_d_ri_10` and `raw_fmov_d_ri_100` are therefore
**unreachable**, guarded by the exact two-level dispatch, distinct lower bodies,
`LOWFUNC`/`LENDFUNC`-only references, and future-caller checks.

This is a two-row raw-boundary retirement, not native acceptance. The accepted
**36+3** FMOVECR matrix remains configured guest runtime evidence. Shared
`FMOV_di` and `SCVTF_dw` emitters remain audited and reachable with exact 5/6
configured sites. The zero/one MIDFUNC and raw wrappers remain reachable and
unreviewed; they are deliberately outside this checkpoint.
