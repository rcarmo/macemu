# AArch64 JIT binary32 source-conversion lifecycle

Date: 2026-07-19
Branch: `jit-audit-next`
Base: `e56852de`

## Scope

This checkpoint audits the live `fmov_s_rr` MIDFUNC and its lower boundary
`raw_fmov_s_rr`. Together they reinterpret a 32-bit integer source as IEEE
binary32 and widen it to the JIT's binary64 floating shadow.

There are exactly two configured production call sites, both in
`get_fp_value(size=1)`:

- direct Dn single-precision sources; and
- fetched single-precision sources, covering guest memory and immediate data.

The four historical FMOVECR constant spellings use the separately retired
`fmov_s_ri` wrapper below the exact-MPFR service return and do not enlarge this
runtime scope.

## Conversion and ownership contract

`fmov_s_rr` acquires the integer source with `readreg`, acquires its floating
destination with `f_writereg`, calls `raw_fmov_s_rr`, then releases destination
and source ownership in that order. The raw boundary performs exactly:

1. `FMOV Sscratch,Wsource`, which transfers the low 32 source bits without a
   numeric integer conversion; and
2. `FCVT Ddestination,Sscratch`, which widens binary32 to binary64.

Both generic emitters already have exhaustive independent encoding/native-state
acceptance. This checkpoint closes their compound MIDFUNC/raw use, including
signed zero, infinities, NaNs, fractions, and maximum register fields.

Ordinary FPP callers target FS1. The floating allocator assigns FS1 fixed D7,
marks its allocator state dirty, and intentionally excludes it from the
architectural dirty mask because `FS1=9` is beyond `FP_RESULT=8`. The ordinary
FMOVE then copies the converted value to the selected architectural FP register
and `FP_RESULT`; central opcode-boundary cleanup retires FS1 through
`freescratch() -> f_forget_about(FS1)`. Fixed floating homes (D7 for FS1,
D8-D15 for FP0-FP7, D6 for FP_RESULT) cannot alias integer allocator homes.

The conversion instructions do not modify integer NZCV, and every focused case
requires unchanged `SR=0x271f`. Guest-memory routes preserve or commit their
architectural address-register state before conversion under the already
accepted ordinary-FMOVE EA contracts.

## Configured-root and structural proof

The closure and structural checks fail closed unless:

- raw FPP source has exactly two configured `fmov_s_rr` calls;
- one is the Dn size-1 route and one follows `readlong` in the fetched size-1
  route;
- the MIDFUNC retains read -> floating write -> raw conversion -> destination
  release -> source release ordering;
- the raw boundary retains `FMOV_sw` -> `FCVT_ds` ordering;
- FS1 retains its fixed D7 home, allocator-dirty/non-architectural dirty-mask
  distinction, and central opcode-boundary retirement;
- ordinary FMOVE retains destination and `FP_RESULT` publication after source
  acquisition; and
- retired `fmov_s_ri` remains outside the reachable graph while the shared raw
  boundary remains live only through `fmov_s_rr`.

## Runtime evidence

`bash jit-test/fmov-s-rr-native-matrix.sh` runs 18 existing strict exact-native
single-source cases:

- eight Dn/immediate cases covering negative zero, positive/negative infinity,
  positive/negative NaN, a finite fraction, and D7/FP7 maximum fields;
- `(A0)`, `(A0)+`, and `-(A0)`;
- `d16(A0)`, brief indexed A0, absolute short, absolute long, forward/backward
  `d16(PC)`, and brief indexed PC.

Every underlying case requires exact binary64 shadow bits, FPSR, unchanged
`SR=0x271f`, strict second-pass native entry with no fallback, preserved or
correctly updated source/address registers, restored memory fixtures, and
isolated CoW/HOME cleanup.

Expected focused result:

```text
FMOV_S_RR_NATIVE_MATRIX pass=18 fail=0 total=18
```

The complete accepted source matrices remain broader evidence: source **29/29**,
basic memory **18/18**, and extended EA **39/39**.

## Closure decision

The following rows become **audited**:

- `midfunc,fmov_s_rr`;
- `raw_boundary,raw_fmov_s_rr`.

`midfunc,fmov_s_ri` remains unreachable. No generic emitter API row changes and
no production or generated source changes. Whole-engine closure is not claimed.

## Acceptance

- focused strict exact-native single-source matrix: **18/18**;
- structural audit: pass for the two configured roots, fetched-load ordering,
  MIDFUNC ownership, raw bit-transfer/widening order, fixed FP homes, FS1
  allocator-dirty/architectural-dirty-mask boundary, destination/FP_RESULT
  publication, central cleanup, and exact wrapper inventory;
- deterministic inventory: **998 rows**, exactly `fmov_s_rr` and
  `raw_fmov_s_rr` unreviewed -> audited with unchanged reference counts;
  MIDFUNC totals become 281 audited / 124 unreachable / 17 unreviewed, raw
  totals become 32 audited / 21 unreachable / 30 unreviewed, and total
  unreviewed becomes **174**;
- `AARCH64_JIT_CLOSURE_INVENTORY.csv`:
  `7665a9a21a26f6876daebec0f977cbfdf47a5d5336272f54b495c3d44cf81b70`;
- `AARCH64_JIT_CLOSURE_INVENTORY.md`:
  `245f215404ad7d851848f38bc062c1cb6d6491c2b842d38a2ecf261e7e3d7d6f`;
- independent bounded review confirmed every technical contract and found no
  semantic counterexample. Its initial verdict was **BLOCK** solely because
  the acceptance record had not yet been populated while the generated
  inventory already showed audited rows; after the record was completed,
  follow-up review returned **APPROVE** for the report, roots, ownership,
  conversion, scratch lifecycle, publication, runtime matrix, and exact closure
  delta;
- executable source is unchanged from canonical `e56852de`. The carried
  integration baseline remains active corpus **904/904**, allocator pressure
  **33/33**, strict policy pass, clean AArch64 `USE_JIT_FPU` build, and stable
  generated sources;
- accepted unchanged artifacts:
  - `compemu.cpp`: `90b3064253b7d2894cd9ecaed738687ba6b2ff7aec5ec75586afa212db7dd1ee`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
  - AArch64 `BasiliskII`: `23d3ffce585ad7fd8512e7565ad7258a5a380a2c08e651afbc8dcdd06f3dfe5b`.

Shell/Bun syntax, source hygiene, `git diff --check`, deterministic regeneration,
and scoped CoW/HOME cleanup pass. Acceptance logs are removed after publication.
