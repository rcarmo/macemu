# AArch64 JIT EXT lifecycle audit

Date: 2026-07-16

## Scope

This report closes the reachable integer `i_EXT` generator lifecycle across the
three configured 68020+ forms:

- `EXT.W Dn`: sign-extend byte to word while preserving Dn[31:16];
- `EXT.L Dn`: sign-extend word to long;
- `EXTB.L Dn`: sign-extend byte directly to long.

It covers negative, zero, and positive results; maximum Dn fields; chained
byte-to-word-to-long widening; fixed logical flags; exact native entry; all
three no-flags-table routes; and allocator ownership. EXT has no live namesake
MIDFUNC: the configured implementation is emitted directly by `gencomp.c`.

## Generator contract

The generator always fetches the full 32-bit Dn source, then selects a widening
route from the decoded size class:

- EXT.W allocates a private scratch and sign-extends Dn[7:0] into it; the final
  word write replaces only Dn[15:0], preserving the upper word;
- EXT.L sign-extends Dn[15:0] in place to 32 bits;
- EXTB.L sign-extends Dn[7:0] in place to 32 bits.

The widened result is then passed through logical flag publication at the result
width and stored at word or long width. The architectural flag contract is X
preserved, N/Z from the widened result, and V=C=0.

Configured generation contains six handlers: three forms in the flag-live table
and the same three in the no-flags table. The flag-live routes test the widened
word/long before publishing flags. The no-flags routes perform only widening and
writeback.

## Exact-native runtime matrix

The focused matrix contains 16 exact-native vectors:

- negative, zero, positive, and maximum-Dn cases for EXT.W;
- negative, zero, positive, and maximum-Dn cases for EXT.L;
- negative, zero, positive, and maximum-Dn cases for EXTB.L;
- a chained EXT.W + EXT.L negative widening case;
- one no-flags-table case per form, with a later MOVEQ determining observed SR.

Every case starts directly at the audited EXT opcode and uses two-pass exact
native replay. Exact Dn and SR assertions prove upper-lane preservation, full
32-bit replacement, sign extension, and XNZVC semantics.

Focused result: **16/16**, zero semantic or infrastructure failures, score 100.

## Allocator pressure

EXT.W D0 allocates a private widened-word scratch while D0 remains the source.
The pressure witness forces the scratch toward D0's live host mapping. The
allocator rejects that collision (`skip=1`), produces D0=$A5A5FF80, and replays
SR=$2718 exactly at native entry.

## Structural result

The fail-closed structural audit locks:

- one live generator case and all three widening routes;
- word-versus-long writeback and flag-test widths;
- six generated handlers split 3/3 across compiler tables;
- exact widening/test/write route counts and no flags in no-flags handlers;
- all 16 encodings, expected Dn/SR states, initial states, exact-native replay,
  risky tags, active-corpus entries, and pressure witness.

## Acceptance evidence

- focused exact-native matrix: **16/16**, zero semantic or infrastructure
  failures, score 100;
- complete active-risky replay: **904/904**, zero semantic or infrastructure
  failures, score 100;
- complete allocator-pressure replay: **31/31**, including the EXT.W scratch/
  source witness with `skip=1` and exact Dn/SR native replay;
- strict full-JIT negative gate passes, including the expected allocation abort;
- clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build produces an AArch64 ELF;
- generated output is byte-reproducible before clean, after clean, and after two
  explicit regenerations:
  - `compemu.cpp`: `55fb6af9005d0077f91b3168707c67106824a5c43fa27c3deaf5bfeaabeee260`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
- deterministic 997-row closure inventory promotes exactly generator `i_EXT`:
  - generator `audited=57`, `serviced=44`, `unreviewed=29`;
  - MIDFUNC remains `audited=262`, `unreachable=118`, `unreviewed=42`;
  - emitter API remains `audited=49`, `unreachable=91`, `unreviewed=154`;
  - raw boundary remains `audited=24`, `unreviewed=58`;
  - CSV: `8d28a495a772cd8e2b5306dba0e5cb811064298cf9bedb28981bbde29976b19f`;
  - Markdown: `e4fbc769bda876e22e3db01b2ef8a4173871790c234f103ae8de4f279db259e1`;
- shell syntax, structural audit, deterministic closure regeneration, source
  hygiene, and diff hygiene are clean.

The inventory next selects `FBcc`. Whole-engine closure is not claimed.
