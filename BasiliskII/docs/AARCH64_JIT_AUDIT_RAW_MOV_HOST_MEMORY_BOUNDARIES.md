# AArch64 JIT raw integer host-memory move boundary audit

Date: 2026-07-28

Base: `24237365` (`master`, published raw specialty-exit closure)

## Scope

This source-coherent tranche audits the mechanically selected
`compemu_raw_mov_l_mi` together with its paired register-store and load
boundaries, `compemu_raw_mov_l_mr` and `compemu_raw_mov_l_rm`. All three share
one address classifier and width contract. `raw_fflags_into_flags` remains a
separate FPU/NZCV boundary.

## Boundary contract

Each helper classifies the supplied host address into exactly one path:

1. `regs.pc_p` or `regs.pc_oldp`: preserve the complete 64-bit host pointer
   with X-register load/store;
2. a 4-byte-aligned address at unsigned offset `0..16380` from fixed
   `R_REGSTRUCT`: use one 32-bit W load/store; or
3. every other address, including misaligned and unrelated host storage:
   materialise its full 64-bit absolute address, then use a 32-bit W load/store.

Immediate stores truncate to the architectural low 32 bits except for the two
pointer fields. Register stores and loads obey the same width selection. All
paths preserve host NZCV.

## Defect and repair

The absolute register-store fallback originally always materialised its address
in `REG_WORK1`. A valid call with payload source `REG_WORK1` therefore replaced
the payload before `STR_wXi`. The exact-native external-address/x2 cell
reproduced this collision.

The repaired body selects `REG_WORK2` as address scratch when `s == REG_WORK1`,
and `REG_WORK1` otherwise. Both are reserved raw work registers; no allocator
state changes. Direct regstruct and pointer paths remain unchanged.

## Exact-native proof

`jit-test/raw-mov-host-memory-conformance.sh` extracts the production
`LOAD_U32`, `LOAD_U64`, and all three raw bodies. Its native AArch64 matrix
covers:

- both pointer fields;
- aligned offsets 16 and 16380;
- misaligned offset 17 and a separately mapped external page;
- values `0`, `0xffffffff`, `0x0000000100000001`,
  `0x123456789abcdef0`, and `0xffff000080000001`;
- register-store sources x1 (`REG_PAR2`), x2 (`REG_WORK1`, the repaired
  collision), and x6 (ordinary caller-saved register);
- alternating hostile `0x5`/`0xb` NZCV patterns; and
- 18 separately checked emission shapes and terminal width classes.

Current direct result:

- boundaries: **3**;
- exact emission shapes: **18/18**;
- immediate-store executions: **30/30**;
- register-store executions: **90/90**;
- load executions: **30/30**;
- pointer-field cells: **10/10**;
- direct 32-bit cells: **10/10**;
- absolute-address cells: **10/10**;
- NZCV preservation: **150/150**.

## Reachability

The deterministic configured inventory records 9, 17, and 26 whole-root
references for `mi`, `mr`, and `rm`. Active callers cover allocator reload and
writeback, flag/X publication, diagnostic snapshots, specialty checks,
countdown/interrupt state, and dynamic runtime-PC publication. Structural
acceptance pins those exact configured counts, every address arm, pointer
fields, width selection, scratch-alias repair, source extraction, native
matrix, and three-row closure promotion.

## Acceptance results

Final acceptance:

- exact emission shapes: **18/18**;
- native payload executions: **150/150**;
- immediate stores: **30/30**;
- register stores: **90/90**, including x2/`REG_WORK1` absolute fallback;
- loads: **30/30**;
- pointer/direct32/absolute classes: **10/10** each;
- hostile NZCV preservation: **150/150**;
- configured preprocessed caller counts: **6/14/24** for `mi`/`mr`/`rm`;
- configured whole-root inventory references: **9/17/26**;
- complete emitter/boundary phase: pass, including
  `emitter_fmsub_exact_words=1048576`;
- complete active-risky corpus: **904/904**;
- allocator pressure: **33/33**;
- clean full AArch64 build: pass;
- complete structural audit: pass;
- deterministic 998-row regeneration: exactly three rows promoted, leaving
  **70 emitter APIs** and **1 raw boundary** unreviewed;
- published `24237365` predecessor CSV SHA-256:
  `ccad95c24f1975dbfb0e7c2bc5de24fc6d331bbb19f8815da6a59d41fe885091`;
- repeated current hashes: inventory CSV
  `ecb65b0ae5e2aa2326406f5cb47e06a414625f2ed61936aec04db862f844617d`,
  Markdown
  `c1d31def556c6586d83e185f3b4d51f634f0a18d3410e78ae891d0e83586bb3f`,
  and generated `compemu.cpp`
  `37dfc019905a6e3c6a377201066fc7262ce475ba7caf85b0e2b4efda620550aa`;
- source hygiene: pass;
- independent bounded review: initial reject concerned candidate-report
  promotion, raw-source rather than configured caller census, and predecessor
  chronology. Structural now rejects candidate text, counts the configured
  preprocessed support source, and pins the exact published `24237365` CSV;
  the FPU host-memory tranche is confirmed earlier at `edc9c034`. The first re-review confirmed all three corrections plus runtime/oracle correctness but
  rejected the remaining literal pending marker. That marker is now removed;
  final re-review: **approve**.

## Closure effect

Deterministic regeneration must move exactly `compemu_raw_mov_l_mi`,
`compemu_raw_mov_l_mr`, and `compemu_raw_mov_l_rm` from `unreviewed` to
`audited`, leaving 70 emitter APIs and one raw boundary unreviewed.
Whole-engine closure is not claimed.

## Reproduction

```sh
./jit-test/raw-mov-host-memory-conformance.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
./jit-test/regalloc-pressure.sh
git diff --check
```
