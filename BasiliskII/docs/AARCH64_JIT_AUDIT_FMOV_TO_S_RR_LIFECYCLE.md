# AArch64 JIT binary32 destination lifecycle

Date: 2026-07-26
Base: `5c31d5ee`

## Scope

This mechanically selected checkpoint closes the live conversion unit:

- `midfunc,fmov_to_s_rr`;
- `raw_boundary,raw_fmov_to_s_rr`.

It converts the native binary64 FP shadow to an IEEE binary32 payload for
ordinary FMOVE single destinations. It is distinct from the already accepted
source-side `fmov_s_rr` / `raw_fmov_s_rr` widening path and from separately
audited generic `FCVT_sd` and `FMOV_ws` emitters.

## Configured roots and ownership

`put_fp_value()` contains exactly two configured roots:

1. direct Dn destination (`reg`);
2. writable-memory conversion through integer scratch `S2`, followed by the
   normal guarded guest-memory store.

The MIDFUNC acquires the FP source with `f_readreg`, acquires the full 32-bit
integer destination with `writereg`, emits the raw conversion, releases the
integer destination, then releases the FP source. Integer and FP allocator banks
cannot alias. Dn receives all 32 payload bits; the memory path routes those bits
through the accepted EA/writeback and special-memory boundary.

## Conversion and status contract

`raw_fmov_to_s_rr`:

- preserves guest NZCV;
- saves and clears host FPSR around one `FCVT S,D` conversion;
- copies the exact binary32 payload into the integer destination;
- captures and restores host FPSR;
- replaces guest exception status with SNAN/OVFL/UNFL/INEX2 derived from host
  IOC/OFC/UFC/IXC;
- accumulates IOP/OVFL/UNFL/INEX with underflow requiring inexact and overflow
  implying inexact; and
- restores guest NZCV.

The accepted MPFR/native boundary preserves NaN sign and payload in both
directions. FPCR remains active during conversion and is not modified.

## Exact-native evidence

`jit-test/fmov-to-s-rr-native-matrix.sh` composes maintained matrices and
requires **30** strict exact-native cases:

```text
FPP_SINGLE_DEST_MATRIX pass=21 fail=0 total=21
FPP_FMOVE_DEST_BASIC_MATRIX pass=5 fail=0 total=5
FPP_FMOVE_DEST_EXTENDED_EA_MATRIX pass=4 fail=0 total=4
FMOV_TO_S_RR_NATIVE_MATRIX semantic=21 basic=5 extended=4 fail=0 total=30
```

The semantic 21 cover signed zero/infinity, exact normal/subnormal limits,
normal inexact conversion, all four FPCR rounding directions, positive and
negative overflow selection, exact/tiny underflow, positive/negative quiet-NaN
payloads, FPSR replacement/accrual, Dn and `(An)`, `SR=0x271f`, second-pass
native attribution, strict no-fallback, and CoW isolation.

The grouped basic/extended routes add postincrement, predecrement, d16,
brief-indexed, absolute-short, and absolute-long destinations with exact
writeback/preservation, guarded bytes, and strict native execution.

## Closure decision

Exactly two rows move from **unreviewed** to **audited**. MIDFUNC totals become
285 audited / 125 unreachable / 12 unreviewed; raw-boundary totals become 36
audited / 22 unreachable / 25 unreviewed. No production or generated source
and no generic-emitter classification changes. The 998-row inventory next
selects `fmovs_rm`.

## Acceptance

- focused strict exact-native lifecycle matrix: **30/30**;
- structural audit: pass for two configured roots, allocator ordering, raw
  state/status contracts, grouped selectors, and exact wrapper totals;
- deterministic closure regeneration: pass twice with stable artifacts:
  - CSV: `1a1ac8510b69c6496125b682a06d2543aa3ccbe0775bf29932ce5a525bd9df09`;
  - Markdown: `16ca7fbcfaf1f017e617362565d35a8c23900998d823c75d106d181c2cbbd66a`;
- independent bounded review: **APPROVE** for exact roots, allocator lifetime,
  guest NZCV and host FPSR/FPCR ownership, Motorola exception mapping,
  substantive 21+5+4 coverage, additive selectors, and exact two-row scope;
- executable/generated source is unchanged from `5c31d5ee`; its clean AArch64
  build and generated hashes remain current;
- shell syntax and `git diff --check`: pass.
