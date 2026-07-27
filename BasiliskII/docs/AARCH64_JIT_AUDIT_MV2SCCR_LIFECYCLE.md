# AArch64 JIT `MV2SCCR` lifecycle audit

Date: 2026-07-27  
Base: `55d4256e`

## Scope

This checkpoint audits the single reachable MIDFUNC row
`midfunc,jff_MV2SCCR` and repairs the complete AArch64 MOVE-to-CCR source
lifecycle that feeds it.

The inventory generator row `i_MV2SR` remains **serviced** because its word/full
SR forms enter the ordered privileged semantic service. The byte-coded
MOVE-to-CCR forms remain native and call `jff_MV2SCCR`; that size-dependent
split is intentional.

## Configured topology

Generated source has exactly 24 calls:

- eleven legal MOVE-to-CCR source forms in the flag-live compiler table;
- the same eleven forms in the nominal no-flags table;
- one RTR stacked-CCR call in each table.

The eleven MOVE-to-CCR forms are Dn, `(An)`, postincrement, predecrement, d16,
indexed, absolute short/long, PC d16/indexed, and immediate. Address-register
direct is illegal.

## Defect found and repaired

`table68k` labels MOVE-to-CCR as the byte-sized `MV2SR.B` semantic form because
only the low CCR byte is installed. The architectural **source access is still
a word**, as the interpreter's `gencpu.c` explicitly enforces.

AArch64 `gencomp.c` incorrectly passed `curi->size` to `genamode`, causing:

- byte reads rather than word reads;
- `(An)+` / `-(An)` updates by one rather than two;
- wrong byte selection from big-endian memory;
- byte rather than word alignment/fault/special-memory geometry;
- a byte immediate fetch instead of the encoded word.

The repair maps only the byte-coded MOVE-to-CCR source acquisition to
`sz_word`, then passes the fetched value to `jff_MV2SCCR`, which consumes the
low five CCR bits. Regeneration changes exactly the 20 non-register generated
handlers (ten source forms in each table): nine memory forms use `readword`,
postincrement/predecrement use ±2, and immediate consumes a word. Dn remains a
register source.

## Flag mapper contract

`jff_MV2SCCR` locks the source before allocating `FLAGX`, then maps:

- source bit 4 → `FLAGX` bit 0;
- bit 3 → AArch64 N (NZCV bit 31);
- bit 2 → Z (bit 30);
- bit 0 → C (bit 29);
- bit 1 → V (bit 28).

It writes NZCV once, clears `flags_carry_inverted`, and unlocks X then source.
Bits 31:5 are ignored. The MIDFUNC owns no memory access or PC transition;
source EA/fault/writeback belongs to generated acquisition, while RTR owns its
stack/PC lifecycle.

## Exact-native evidence

`jit-test/mv2sccr-native-matrix.ts` runs 44 strict interpreter/JIT pairs with
forced RAM L2 and exact `NATEXEC pc=00001000` attribution:

- all 32 low-five-bit XNZVC combinations from D0, with nonzero ignored upper
  bits and exact D0 preservation;
- all ten legal non-register source forms, including nonzero ignored high word
  bits, postincrement/predecrement word stride, PC-relative addressing, and
  immediate word acquisition;
- one forced-special-memory word source;
- the accepted RTR stacked CCR/dynamic-PC control.

Result after the repair:

```text
MV2SCCR_NATIVE_MATRIX pass=44 fail=0 total=44
```

The pre-repair matrix passed the 32 register combinations and immediate but
failed all memory-source geometry, deterministically reproducing the defect.

## Closure decision

`midfunc,jff_MV2SCCR` moves from **unreviewed** to **audited**. The coarse
`i_MV2SR` generator classification, memory primitives, FLAGX allocator state,
NZCV emitter APIs, RTR generator, and full-SR service remain independently
classified. Whole-engine closure is not claimed.

## Acceptance

- strict exact-native matrix: **44/44**;
- configured calls: **24**;
- generated word-memory handlers: **18** (nine per table);
- exhaustive XNZVC combinations: **32**;
- special-memory word control: **1**;
- reproduced pre-fix failure: register/immediate cases passed while all memory
  sources used wrong byte selection/update geometry;
- complete active-risky corpus: **904/904**, no semantic/infrastructure failure;
- allocator-pressure regression: **33/33**;
- clean full build and post-clean focused matrix: pass;
- deterministic generator output:
  `37dfc019905a6e3c6a377201066fc7262ce475ba7caf85b0e2b4efda620550aa`;
- exact one-row closure delta; deterministic inventory hashes:
  - CSV: `a94a691b2b83a744479cce08d76486d420cefcd695ace81618b071d9a70b2790`;
  - Markdown: `968fccebdbc4dfb4fa95e21dc6d066bf245640d6f33c9402d14ee209e0cef403`;
- authoritative source hashes:
  - `gencomp.c`: `2522d65121b8f28fb9198602f3598075524429603c078d6c97ae52da61c4e5c1`;
  - mapper source: `527afb9c0f8a2c79f35e5d5a7c9f2a509dd51585221d8db1bd42ddc981e65e4c`;
- independent bounded review: **APPROVE** for word-source architecture,
  generated geometry, XNZVC mapping, exhaustive matrix, and selective closure;
- structural audit and `git diff --check`: pass.
