# AArch64 generic FCVTAS_wd emitter audit

Date: 2026-07-18
Branch: `jit-audit-next`
Base: `6a06d7bd`

## Scope

This checkpoint audits only the reachable scalar-double to signed-W conversion
emitter API `FCVTAS_wd(Wd,Dn)`.

Its sole configured caller is `fmov_to_int_emit()`, where `FRINTI_dd` first
rounds according to guest FPCR and `FCVTAS_wd` then converts that integral
temporary. The surrounding byte/word/long saturation, Motorola exception
publication, and guest destination lifecycle remain owned by the accepted
45-case ordinary-FMOVE destination audit. Adjacent `FCVT_ds`, `FCVT_sd`,
`FCVTAS_xd`, `FCVTZS_xd`, FRINT, MIDFUNC, raw, and `i_FPP` rows are not promoted.

## Direct generic contract

`jit-test/emitter-fcvtas-conformance.cpp` directly compiles against
`codegen_arm64.h` and proves:

- all **1,024** Wd × Dn encodings, including W31 and D31;
- **256** native conversions across 16 value classes, four register routes,
  and all four FPCR rounding modes;
- nearest-away ties (`±0.5`, `±1.5`) and non-half fractions;
- exact zero, signed bounds, positive/negative overflow and infinity;
- quiet/signalling NaN;
- signed saturation on finite overflow/infinity and zero for NaN;
- IXC for finite fractional conversion and IOC for invalid conversion;
- source, NZCV, FPCR, and seeded FPSR preservation/augmentation;
- W30 link-register ownership, W0 result-pointer collision, W31 discard, and
  callee-saved D8/D15 routes.

The four FPCR-mode cross-product proves FCVTAS itself is nearest-away and does
not consume FPCR rounding direction. This is distinct from the production
caller's preceding `FRINTI`, which owns guest-directed rounding.

The executable fixture saves LR and its result pointer before testing writable
W fields. An external AArch64 assembly wrapper seeds D8-D15 plus FPCR/FPSR,
invokes the generated function, snapshots exact post-return state, and restores
the harness process originals. Code memory transitions RW→RX and receives an
instruction-cache flush before execution.

Accepted result:

```text
METRIC emitter_fcvtas_exact_words=1024
METRIC emitter_fcvtas_native_vectors=256
METRIC emitter_fcvtas_fpcr_vectors=256
METRIC emitter_fcvtas_discard_vectors=64
```

## Composition evidence

`GROUP=integer bun jit-test/fpp-fmove-destination-basic-matrix.ts` is the
mechanically selected guest-level composition contract with **36/36**
exact-native byte/word/long cases. It proves FRINTI→FCVTAS composition, all guest
FPCR directions, saturation, upper-lane preservation, OPERR/INEX and accrued
IOP/INEX publication, NaN sign, maximum guest fields, writable EA ordering,
integer CCR, and exact destination bytes. Single conversion remains adjacent;
the four ordinary double-store cases now belong to their accepted semantic
service matrix rather than this strict-native subset.

## Closure decision

`emitter_api,FCVTAS_wd` is promoted to **audited**.

No adjacent conversion emitter, MIDFUNC, raw boundary, or generator row is
promoted. `generator,i_FPP` remains **unreviewed**.
