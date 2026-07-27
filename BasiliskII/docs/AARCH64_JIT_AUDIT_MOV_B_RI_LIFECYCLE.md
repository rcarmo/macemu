# AArch64 JIT `mov_b_ri` lifecycle audit

Date: 2026-07-27
Base: `40ca55cb`

## Scope

This checkpoint audits `midfunc,mov_b_ri`. It is a byte-lane constant writer,
not a full-register MOV-immediate and not a generic encoder API.

Configured generated source contains exactly eleven calls. Every call is
`mov_b_ri(dst,0)` in flag-live `MOVE.B <ea>,Dn` lowering, one for each readable
source class: Dn, `(An)`, postincrement, predecrement, displacement, indexed,
absolute short/long, PC-relative displacement/indexed, and immediate. The zero
stages a destination lane before `or_b(dst,src)` publishes the MOVE result and
flags when source and destination differ.

## Ownership and value contract

For architectural Dn/An vregs (`d < 16`), byte writes must preserve bits 31:8:

- if the destination is constant, `set_const` merges the masked low byte into
  the retained upper 24 bits and returns;
- otherwise `rmw(d)` materialises and locks the current full register,
  `MOV_wi(REG_WORK1,s&0xff)` bounds the immediate, and
  `BFI_wwii(d,REG_WORK1,0,8)` replaces only the low lane before unlock.

For private/scratch vregs (`d >= 16`), no architectural upper lane exists;
`set_const(d,s&0xff)` establishes an exact clean byte value. AArch64 `set_const`
keeps all non-`PC_P` constants bounded to 32 bits. This branch is retained and
structurally checked but **dormant in the configured caller set**: every live
call passes architectural `dst` (`D0..D7`).

`mov_b_ri` emits no flag operation. In every configured composition,
`start_needflags`, `or_b`, `live_flags`, and `end_needflags` own NZVC; MOVE
preserves X. The primitive has no memory or fault boundary.

## Runtime evidence

`jit-test/mov-b-ri-lifecycle-matrix.sh` requires:

```text
MOV_B_RI_LIFECYCLE focused=2 source_ea=12 pressure=1 fail=0 total=15
```

The two focused strict-native vectors force both architectural-destination
states:

- `move_b_preserve_flags`: D0 remains a compiler constant after `MOVE.L #imm`
  and takes the constant-merge branch;
- `move_core_b_reg_negative_native`: block-entry D0 is materialised and takes
  the `rmw+BFI` branch, preserving `A5A50000` while replacing the low byte.

Twelve strict-native MOVE.B cases cover register/immediate, all maintained
source and destination memory classes, special memory, A7 byte stride, negative
and zero flags, upper-lane preservation, and aliases. The forced
`move_b_mem_source_dst_collision` pressure cell proves source ownership survives
destination RMW allocation.

## Closure decision

`midfunc,mov_b_ri` moves from **unreviewed** to **audited**. `BFI_wwii`,
`MOV_wi`, allocator primitives, and the complete MOVE lifecycle retain their
independent classifications. No production or generated source changes.
Whole-engine closure is not claimed.

## Acceptance

- focused/runtime/pressure control: **2 + 12 + 1 / 15**;
- structural audit: pass for exact caller/zero-immediate census, all eleven
  readable source classes, constant and materialised branches, lane masking,
  flag separation, strict replay, and pressure witness;
- deterministic closure regeneration: 998 rows with an exact one-row delta:
  - CSV: `c871134bee9d297187c668bf40066c2b2c6fda9597a08db5cbe4dca10b32f9e7`;
  - Markdown: `759da342613465e109c726a60ea3baf38de876e409bafd0017aa62d97abf3a45`;
- independent bounded review: **APPROVE** for the exact eleven zero-staging
  architectural-Dn calls, honest dormant scratch branch, lane/mask/flag
  semantics, 15-case evidence, and exact one-row promotion;
- executable/generated source unchanged from `40ca55cb`;
- shell syntax and `git diff --check`: pass.
