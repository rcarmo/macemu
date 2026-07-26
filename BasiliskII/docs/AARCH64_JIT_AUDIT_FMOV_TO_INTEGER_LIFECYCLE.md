# AArch64 JIT FMOVE FP-to-signed-integer destination lifecycle

Date: 2026-07-26
Base: `17d503ca`

## Scope

This mechanically anchored lower-layer checkpoint closes the shared configured
byte, word, and long FP-to-signed-integer destination lifecycle:

- `fmov_to_b_rr` -> `raw_fmov_to_b_rr`;
- `fmov_to_w_rr` -> `raw_fmov_to_w_rr`;
- `fmov_to_l_rr` -> `raw_fmov_to_l_rr`.

The selected `fmov_to_b_rr` row is the highest-risk unreviewed family in the
source-derived inventory. Word and long are included because all three wrappers
delegate to the same `fmov_to_int_emit()` classifier and differ only in width
and destination-lane ownership. Splitting them would leave one implementation
contract partially classified. Binary32 `fmov_to_s_rr`, double stores, generic
conversion emitters, and `generator,i_FPP` remain separate.

## Configured roots and ownership

Each MIDFUNC has exactly two configured `put_fp_value()` roots:

1. direct Dn destination (`reg`);
2. writable-memory conversion through integer scratch `S2` before the normal
   guest-memory store.

All wrappers acquire the native FP source before the integer destination, emit
while both are live, then release the integer destination before the FP source.
Long uses a full `writereg()`. Byte and word use `INIT_WREG_b/w`: architectural
Dn destinations are read-modify-write so their upper 24/16 bits survive, while
scratch destinations are write-only. Integer and FP values remain in separate
allocator banks.

## Shared conversion contract

`raw_fmov_to_l_rr`, `raw_fmov_to_w_rr`, and `raw_fmov_to_b_rr` delegate to
`fmov_to_int_emit()` with widths 32, 16, and 8 respectively. The shared emitter:

- rounds with `FRINTI` under the active guest FPCR mode before conversion;
- converts the rounded value with `FCVTAS`;
- saturates finite overflow, infinity, and NaN according to source sign;
- clamps byte/word candidates to signed width and inserts only the low lane;
- distinguishes exact, representable-inexact, and invalid/range cases;
- replaces FPSR exception status with INEX2 or OPERR as required;
- accumulates INEX or IOP while preserving CCB and quotient;
- preserves guest integer NZCV around all private classification branches.

The direct generic `FCVTAS_wd`, `SCVTF_dw`, and FRINT emitters retain their
independent encoder audits; this lifecycle checkpoint promotes no emitter API.

## Exact-native evidence

`jit-test/fmov-to-int-native-matrix.sh` composes maintained strict matrices and
requires **54/54** exact-native cases:

```text
FPP_FMOVE_DEST_BASIC_MATRIX pass=36 fail=0 total=36
FPP_FMOVE_DEST_EXTENDED_EA_MATRIX pass=18 fail=0 total=18
FMOV_TO_INT_NATIVE_MATRIX pass=54 fail=0 total=54
```

The 36 basic cases cover:

- byte/word/long Dn and memory destinations;
- exact signed limits and one-unit overflow in both directions;
- all four FPCR rounding modes;
- positive/negative finite overflow, fractional overflow, infinity, and NaN;
- OPERR/INEX2 replacement and accrued IOP/INEX accumulation;
- Dn upper-lane preservation, FP7/D7 maximum fields, `(An)`, `(An)+`, `-(An)`,
  and byte A7 geometry;
- exact destination bytes/registers, writeback, `SR=0x271f`, second-pass native
  entry, and strict no-fallback execution.

The 18 extended-EA cases cover byte/word/long d16, scaled indexed, absolute
short/long, maximum index/register fields, full pre/postindexed forms, guarded
stores, and the all-integer-registers-live allocator-pressure route.

## Closure decision

The authoritative inventory promotes exactly six rows to **audited**:

- `midfunc,fmov_to_b_rr`, `midfunc,fmov_to_w_rr`, `midfunc,fmov_to_l_rr`;
- `raw_boundary,raw_fmov_to_b_rr`, `raw_boundary,raw_fmov_to_w_rr`,
  `raw_boundary,raw_fmov_to_l_rr`.

No production conversion code changes are required: the shared implementation
was repaired by the accepted ordinary-FMOVE destination tranche and this audit
closes its lower-layer reachability and ownership contracts. The deterministic
inventory remains **998 rows** and changes exactly these six statuses:

- MIDFUNC totals become 284 audited / 124 unreachable / 14 unreviewed;
- raw-boundary totals become 35 audited / 21 unreachable / 27 unreviewed;
- generator, emitter-API, and runtime-boundary totals are unchanged.

`fmov_to_s_rr`, `fmov_to_d_rrr`, `generator,i_FPP`, and adjacent emitter/raw
families remain unreviewed. The next mechanically selected family is
`fmov_to_d_rrr`.

## Acceptance

- focused strict exact-native lifecycle matrix: **54/54** after a clean build;
- structural audit: pass, including exactly six configured roots, three
  width-specific MIDFUNCs, three shared raw boundaries, allocator release
  ordering, exception/NZCV composition, grouped matrix selection, and wrapper
  totals;
- clean host-native AArch64 build with `USE_JIT_FPU`: pass;
- generated source is byte-stable across two serial regenerations:
  - `compemu.cpp`: `90b3064253b7d2894cd9ecaed738687ba6b2ff7aec5ec75586afa212db7dd1ee`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
- closure artifacts are byte-stable across two serial regenerations:
  - CSV: `48b82040eb1db281e6142e685245bdd30fdd51887211e1423d47fd0f5c034b3a`;
  - Markdown: `f16e0f1b2d57bef284b2163d7c1ecfa61bdd7070ff1c3e92c7a009a165924f16`;
- independent bounded review: **APPROVE** for exact six-row scope, configured
  roots, MIDFUNC/raw ownership, rounding/status semantics, substantive runtime
  coverage, structural strength, and absence of unrelated reclassification;
- shell syntax and `git diff --check`: pass.

The executable source is unchanged from base `17d503ca`; the accepted full
active-risky, allocator-pressure, strict-policy, and Finder-retirement baselines
therefore remain carried integration evidence rather than rerun claims for this
evidence-only lower-layer checkpoint.
