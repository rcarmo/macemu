# AArch64 generic FCVT precision-conversion emitter audit

Date: 2026-07-18
Branch: `jit-audit-next`
Base: `bfa2bbeb`

## Scope

This checkpoint audits the complete reachable bidirectional scalar
binary32/binary64 conversion pair:

- `FCVT_sd(Sd,Dn)`: binary64 to binary32;
- `FCVT_ds(Dd,Sn)`: binary32 to binary64.

It does not promote compound raw/MIDFUNC callers, which additionally own
memory, arithmetic, or Motorola exception publication, and does not promote
`generator,i_FPP`.

## Configured source sites

Configured AArch64 source contains six `FCVT_ds` and seven `FCVT_sd` sites.
They cover:

- signed-single register import and the configured AArch64 single-memory
  route (`readlong` → `fmov_s_rr` → `raw_fmov_s_rr` → `FCVT_ds`);
- ordinary single destination conversion with isolated host FPSR sampling;
- forced-single divide and multiply, each narrowing two operands and widening
  its result;
- cut-to-single and single-result publication paths that narrow then widen;
- the retained single-precision remainder/composition helper.

The exact 6/7 source-site counts and authoritative spellings are structural.
The configured single-memory call chain is also pinned through its generator,
MIDFUNC, raw boundary, and conversion order. A new source site does not inherit
this audit silently. The alternative retained `fmovs_rm`/`raw_fmovs_rm` memory
primitive remains a separate unreviewed compound boundary.

## Direct generic evidence

`jit-test/emitter-fcvt-conformance.cpp` directly includes
`codegen_arm64.h`, emits into RW memory, changes it to RX, flushes the
instruction cache, and executes on the AArch64 host.

Encoding coverage exhausts all register fields:

- **1,024** `FCVT_sd` words;
- **1,024** `FCVT_ds` words.

Native coverage comprises **144 narrowing + 112 widening vectors**:

- all four raw AArch64 FPCR rounding modes;
- exact normal and signed zero;
- inexact normal conversion;
- positive/negative halfway-to-minimum-subnormal under directed rounding;
- positive/negative overflow result selection;
- minimum binary32 subnormal and low-significand widening;
- signed infinity;
- quiet/signalling NaN payload mapping and quieting;
- exact IXC/UFC/OFC/IOC behavior while preserving seeded FPSR state;
- source and NZCV preservation for distinct fields;
- D0/S1, D31/S30, callee-saved D8/S15, and **64 in-place aliases**.

Widening is exact and FPCR-independent. Narrowing obeys raw AArch64 FPCR mode
order (nearest, plus, minus, zero); this is deliberately distinct from guest
68k mode mapping performed by the runtime.

The generated callable saves LR, its result pointer, and D8-D15. An external
AArch64 wrapper seeds D8-D15 plus FPCR/FPSR, calls the generated function,
snapshots post-return state, verifies it in C++, then restores the harness
process's originals.

Accepted result:

```text
METRIC emitter_fcvt_exact_words=2048
METRIC emitter_fcvt_narrow_vectors=144
METRIC emitter_fcvt_widen_vectors=112
METRIC emitter_fcvt_alias_fields=64
```

## Composition evidence

The accepted guest matrices remain independent composition controls:

- `fpp-fmove-single-destination-matrix.ts`: **21/21** binary64→binary32,
  including all guest FPCR modes, range/subnormal boundaries, NaN payloads,
  exact Motorola FPSR publication, Dn and memory destinations;
- `GROUP=single fpp-fmove-source-matrix.ts`: **8/8** mechanically decoded
  binary32 Dn/immediate import routes, including D7→FP7, signed zero,
  infinity, and NaN while preserving integer CCR;
- `GROUP=single fpp-fmove-memory-basic-matrix.ts`: **3/3** mechanically
  decoded binary32 `(An)`, `(An)+`, and `-(An)` imports, including exact EA
  mutation and strict native replay.

Both selectors decode the architectural three-bit format field rather than
naming cases, and structural acceptance pins their selectors and totals.

## Closure decision

The directly evidenced rows are promoted:

- `emitter_api,FCVT_sd` → **audited**;
- `emitter_api,FCVT_ds` → **audited**.

No compound raw boundary, MIDFUNC, arithmetic family, memory path, or generator
row is promoted. `generator,i_FPP` remains **unreviewed**.
