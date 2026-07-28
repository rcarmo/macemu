# AArch64 JIT raw FPU host-memory boundary audit

Date: 2026-07-28

Base: `752fdc06` (`master`, published raw execute-normal-cycles closure)

## Scope

This source-coherent batch audits only the paired fixed-home FPU allocator
boundaries:

- `compemu_raw_fmov_mr_drop`: spill one binary64 host FP register to its owned
  host-memory slot; and
- `compemu_raw_fmov_rm`: reload one binary64 host FP register from its owned
  host-memory slot.

The already accepted `fmov_rm -> raw_fmov_d_rm` guest-FMOVE composition remains
separate. Generic `LDR_dXi`, `STR_dXi`, and immediate-materialisation emitter
APIs are not promoted by this audit.

## Boundary contract

Both raw bodies select one of two addressing forms at emit time:

1. an eight-byte-aligned address in `[&regs, &regs + 32760)` emits one unsigned
   immediate binary64 `LDR/STR Dn,[X28,#offset]`; or
2. every other host address is materialised in `X2`, then accessed as a
   binary64 lane at offset zero.

The upper direct boundary is offset 32752. Offset 32760, misaligned addresses,
and unrelated host allocations must take the absolute-pointer branch. Neither
path may alter NZCV or reinterpret the 64 payload bits; signed zero, infinities,
subnormals, and NaN class/payload/sign are ordinary bits here.

## Allocator contract

`f_tomem_drop()` is the sole configured store caller. It emits a spill only for
a `DIRTY` virtual FP value and publishes `INMEM` only after the raw store.
`f_evict()` then clears the fixed host-register association.

`f_alloc_reg(r, 0)` is the sole configured load caller. For an `INMEM` value it
emits the raw reload, publishes `CLEAN`, and records the fixed mapping:
architectural FP0-FP7 to D8-D15, `FP_RESULT` to D6, and `FS1` to D7. A
write-only allocation (`willclobber`) does not reload and becomes `DIRTY`.

## Direct native proof

`jit-test/raw-fmov-host-memory-conformance.sh` extracts both exact production
`LOWFUNC...LENDFUNC` bodies and their production `LOAD_U64` pointer-materialiser
from `codegen_arm64.cpp`, compiles them against the production AArch64 encoder
header and a synthetic regstruct, then executes the generated code natively.
This avoids copying the implementations into the test and avoids conflating
this host-memory seam with guest FPU decoding.

The matrix requires:

- 128 exact direct words: load/store, offsets 0 and 32752, all D0-D31 fields;
- 30 absolute-pointer shapes: load/store, unrelated/misaligned/upper-boundary
  addresses, representative D0/D7/D8/D15/D31 fields;
- 60 native stores and 60 native loads, including unrelated, offset-32760, and
  misaligned (`&regs + 1`) fallback execution;
- direct and absolute-pointer execution;
- caller-saved and callee-saved FP register groups; and
- ten payload classes including positive/negative zero, minimum subnormal,
  maximum finite, infinities, signalling/quiet signed NaNs, and arbitrary bit
  patterns, with exact NZCV preservation.

## Structural acceptance

The structural gate pins both range/alignment predicates, direct and fallback
instructions, pointer materialisation ordering, explicit unrelated/misaligned/
offset-32760 runtime witnesses, sole-caller counts, spill and reload state
publication ordering, exact raw-body/helper source extraction, matrix cardinality,
main-runner integration, two-row closure promotion, and continued unreviewed
status for generic `LDR_dXi`/`STR_dXi`.

## Acceptance results

Final acceptance:

- source-extracted direct matrix: **128/128 exact direct words**;
- fallback-shape matrix: **30/30**;
- native host-memory matrix: **120/120** (60 stores and 60 loads), including
  direct, unrelated-pointer, upper-boundary, and misaligned paths;
- complete emitter/boundary phase: pass;
- complete active-risky corpus: **904/904**;
- allocator pressure: **33/33**;
- clean full build: pass;
- complete structural audit: pass;
- deterministic 998-row closure regeneration: exactly two rows promoted,
  leaving **70 emitter APIs** and **9 raw boundaries** unreviewed;
- repeated hashes: inventory CSV
  `9dc985e20749ca87f0681c43d07554f4856ac2a6fd9992833ac113a4156f5d94`,
  Markdown
  `0410d73ebd811a070b29c701cefd75c6ecf42940bf3b8eb97dfae93e748c6d00`,
  and generated `compemu.cpp`
  `37dfc019905a6e3c6a377201066fc7262ce475ba7caf85b0e2b4efda620550aa`;
- source hygiene: pass;
- independent bounded review: initial reject for a shape-only misaligned case,
  insufficiently explicit fallback witnesses, and locally replicated
  `LOAD_U64`; all three were corrected by native misaligned execution,
  structural witness pins, and exact helper extraction; final re-review:
  **approve**.

## Closure effect

Deterministic regeneration must move exactly `compemu_raw_fmov_mr_drop` and
`compemu_raw_fmov_rm` from `unreviewed` to `audited`. Whole-engine closure is
not claimed.

## Reproduction

```sh
./jit-test/raw-fmov-host-memory-conformance.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
