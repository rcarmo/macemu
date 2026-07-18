# AArch64 FMOV primitive-cluster audit

Date: 2026-07-18
Branch: `jit-audit-next`
Base: `c459deea`

## Scope

This checkpoint audits the complete reachable binary64 register-copy primitive
stack:

- emitter API `FMOV_dd`;
- raw boundary `raw_fmov_rr`;
- MIDFUNC `fmov_rr`.

It does **not** classify generator `i_FPP`, conversion emitters, memory
loads/stores, arithmetic operations, or architectural ordinary register FMOVE.
The latter was retired to MPFR service in the preceding checkpoint because an
architectural FP register contains 80-bit state that cannot be represented by
this binary64 primitive.

## Runtime contract

`FMOV_dd(Dd,Dn)` must encode one AArch64 scalar double-register FMOV and copy
all 64 bits without classification, conversion, rounding, exception delivery,
or mutation of NZCV, FPCR, or FPSR. This includes:

- positive and negative zero;
- minimum subnormal and maximum finite values;
- positive and negative infinity;
- signalling- and quiet-NaN payloads;
- arbitrary non-floating bit patterns;
- every source and destination field from D0 through D31;
- self aliases, which remain exact no-ops.

`raw_fmov_rr` must remain a one-instruction wrapper around that emitter.
`fmov_rr` may elide a virtual self move. For distinct virtual registers it must
acquire the source before publishing the destination, emit the raw bit copy,
mark the destination dirty through `f_writereg`, preserve the source, and leave
no lock ownership behind.

## Allocator model

This floating allocator is deliberately fixed-home rather than
pressure-allocated:

- architectural FP0-FP7 map to D8-D15;
- `FP_RESULT` maps to D6;
- the reachable scratch `FS1` maps to D7;
- `f_unlock()` is empty because floating homes do not participate in the
  integer allocator's lock/eviction competition.

The homes used by every configured `fmov_rr` caller are pairwise distinct.
Consequently an artificial “all floating registers live” pressure test would
not exercise a production mechanism. The accepted ownership evidence instead
pins the fixed-home mapping, source-before-destination order, self-alias return,
raw emission order, dirty publication, and empty unlock contract.

## Reachable caller roles

The configured reachability graph retains 21 references to `fmov_rr`. The raw
FPP compiler contains seven authoritative call spellings; after AArch64 branch
selection and macro/root expansion they reduce to these roles:

1. `MAKE_FPSR`: runtime-live publication of a binary64 native result into
   `FP_RESULT` for later FPU condition classification;
2. `put_fp_value`: a retained but unreachable register-destination branch; its
   only caller selects class 3, which necessarily has `extra & 0x4000` set;
3. the residual ordinary-FMOVE body: runtime-live only for non-extended imports;
   register-source FMOVE exits to MPFR before acquisition, while extended
   memory sources are rejected before EA mutation;
4. the non-AArch64 FCMP copy: inactive in the configured AArch64 branch, which
   uses `fcompare_result_rr`;
5. FTST publication: the direct `FP_RESULT <- src` path is runtime-live; the
   retained `FS1` bridge is unreachable because successful `get_fp_value()`
   returns FP0-FP7 or `FS1`, never `FP_RESULT`.

No runtime-live configured call uses `fmov_rr` as an architectural 80-bit copy.
Dead-but-compiled spellings remain in the structural census so a future
reachability change cannot silently broaden this audited contract. The direct
raw boundary has three configured references and consists solely of
`FMOV_dd(d,s)`.

## Exact native evidence

`jit-test/emitter-fmov-conformance.cpp` is compiled and run natively on the
AArch64 host through `jit-test/emitter-fmov-conformance.sh`. It executes from a
RW-to-RX page and reports:

```text
METRIC emitter_fmov_exact_words=1024
METRIC emitter_fmov_native_vectors=10240
METRIC emitter_fmov_self_alias_vectors=320
METRIC emitter_fmov_bit_classes=10
```

The 1,024 exact words exhaust the 32×32 source/destination encoding field. The
10,240 native vectors cross that field with ten bit classes. The fixture saves
and restores AAPCS64 D8-D15 and the caller's FPCR/FPSR, seeds controlled NZCV,
FPCR, and FPSR before the tested instruction, and checks exact destination
bits, source preservation, and all three unchanged states afterward.

The mandatory structural gate additionally fails closed if:

- `raw_fmov_rr` contains anything other than `FMOV_dd(d, s)`;
- the MIDFUNC loses self-alias elision, source-before-destination acquisition,
  the raw copy, or dirty publication;
- fixed floating homes or the empty `f_unlock` contract change;
- the seven authoritative caller spellings or configured reference count
  change;
- the native probe, bounded launcher, or mandatory harness invocation is
  removed.

## Closure classification

The directly evidenced rows are promoted:

- `emitter_api,FMOV_dd` → **audited**;
- `raw_boundary,raw_fmov_rr` → **audited**;
- `midfunc,fmov_rr` → **audited**.

`generator,i_FPP` remains **unreviewed**. This checkpoint changes no production
implementation and makes no claim about adjacent FPU encoders or the remaining
FPP composition surface.
