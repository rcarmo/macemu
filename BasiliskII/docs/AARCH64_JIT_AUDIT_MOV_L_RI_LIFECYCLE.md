# AArch64 JIT `mov_l_ri` and raw materialisation audit

Date: 2026-07-27  
Base: `bcc25a1e`

## Scope

This checkpoint audits two coupled rows:

- `midfunc,mov_l_ri`, the central constant-state entry; and
- `raw_boundary,compemu_raw_mov_l_ri`, its reachable 32-bit materialiser.

The MIDFUNC has 2,396 configured references. This is not treated as 2,396
independent opcode semantics: `mov_l_ri` emits no instruction immediately and
owns no flags or memory. Its contract is to classify a virtual-register value
as constant, preserving the distinction between 32-bit M68K values and the
64-bit host pointer carried only by `PC_P`.

## Configured caller census

Generated `compemu.cpp` contains 2,379 calls in exactly fifteen destination
classes:

| destination | calls | destination | calls |
|---|---:|---|---:|
| `src` | 710 | `srca` | 560 |
| `dsta` | 372 | `dst` | 209 |
| `pctmp` | 160 | `PC_P` | 90 |
| `cnt` | 48 | `extra` | 42 |
| `chk2_size` | 42 | `offs` | 38 |
| `zero` | 36 | `one` | 36 |
| `ret` | 20 | `pack_enc` | 8 |
| `movep_enc` | 8 |  |  |

The remaining configured references come from support and FPU compiler roots.
They cover indexed-EA constants, integer FP inputs, and compiler temporaries.
No value magnitude is used as type information.

## Width and ownership contract

`mov_l_ri(d,s)` delegates to `set_const(d,s)`. `set_const` first disassociates
the old virtual-register state and then:

- truncates every destination except `PC_P` to `uae_u32`;
- retains the full `uintptr` value for `PC_P`;
- records `ISCONST` without changing NZCV, X, memory, or guest PC.

When a constant later needs a host register, `alloc_reg_hinted` preserves that
same split:

- `PC_P` uses `LOAD_U64`;
- every other constant uses `compemu_raw_mov_l_ri`, whose complete body is
  `LOAD_U32(d,s)`.

Thus guest values are materialised through W-register writes, which clear the
upper native half, while the PC host pointer is never sent through the raw
32-bit boundary.

## Raw-boundary census

The closure inventory records eight references after configured reachability:
LOWFUNC/LENDFUNC, five genuinely live support callers, and one retained comment
token adjacent to allocator materialisation. The comment is not executable
coverage and is pinned separately so the numeric inventory count cannot be
misread as six callers.

The five live caller sites/classes are:

1. non-`PC_P` allocator constant materialisation after `set_const` truncation;
2. `uae_u32 arg1` for runtime semantic helpers;
3. optional `uae_u32 arg2` for the same helper ABI;
4. `next_m68k_pc`, explicitly `uae_u32`;
5. fallback table index, explicitly cast to `uae_u32`.

Raw source also has two call spellings below unreachable `fmov_l_ri` and
`fmov_s_ri`. Neither is a configured live caller and neither is used to justify
this row.

There is no reachable host-pointer caller. Helper targets use `LOAD_U64` through
`compemu_raw_call`, and PC publication uses explicit 32/64 typed primitives.

## Exact evidence

`jit-test/mov-l-ri-conformance.sh` compiles and executes the production
LOAD_U32/LOAD_U64 macro composition on AArch64. It verifies twelve exact words
and seven native results:

- six 32-bit patterns: zero, one, two-halfword positive, MOVN high-ones,
  all-ones, and bit-31-set;
- one four-halfword 64-bit pointer control.

The native results prove zero extension for guest values and full-width
preservation for the pointer control.

`jit-test/mov-l-ri-lifecycle-matrix.sh` adds:

- two strict-native focused chains: `move_b_preserve_flags` for guest constant
  propagation/materialisation and `indexed_full_neg_base` for constant `PC_P`
  materialisation plus high-bit guest EA arithmetic;
- ten accepted strict-native MOVE.L controls spanning dynamic and immediate
  values, zero/negative, memory sources/destinations, PC-relative input,
  aliases, and memory-to-memory update.

Result:

```text
MOV_L_RI_LIFECYCLE conformance=7 focused=2 move_l=10 fail=0 total=19
```

## Closure decision

`midfunc,mov_l_ri` and `raw_boundary,compemu_raw_mov_l_ri` move from
**unreviewed** to **audited**. `LOAD_U32`, `LOAD_U64`, MOV-wide emitter APIs,
allocator policy, MOVE lifecycle, helper semantics, and PC ownership retain
their independent classifications. No production or generated source changes.
Whole-engine closure is not claimed.

## Acceptance

- exact/native conformance: **12 words, 7 vectors**;
- strict runtime controls: **2 + 10 / 12**;
- lifecycle total: **19/19**;
- structural audit: exact 2,396 inventory references, 2,379 generated calls,
  fifteen destination classes, guest/pointer split, eight raw references, five
  live support callers, one retained comment token, and two unreachable raw
  source spellings;
- deterministic closure regeneration: 998 rows with an exact two-row delta:
  - CSV: `9ef7bc75aadda951d292144c6eaa78de8c60239896eb6b8291f1313eb0e7b9eb`;
  - Markdown: `16fe0c0b88d38fec404a4531120f11c96c8c0aa4829126215b416d814bf4a8da`;
- independent bounded review: initial **REJECT** exposed the false sixth live FP
  caller; after separating five live callers, one comment token, and two dead
  FP-parent spellings, re-review returned **APPROVE**;
- executable/generated source remains byte-identical to `bcc25a1e`:
  - generated `compemu.cpp`: `90b3064253b7d2894cd9ecaed738687ba6b2ff7aec5ec75586afa212db7dd1ee`;
  - `gencomp.c`: `7ff6be9dc85916f77e31e2b426460c23d7aaf449c1be1800a21ebb40a21a741a`;
  - MIDFUNC source: `495296a9400c5c54bd21e928217a9228534afb720f38b9af96222274f5652ae2`;
  - raw source: `ca7997484b3c0a40d25b90f4ae48e538b4978e01816e014e75ac63399906bc24`;
- shell syntax, C++ warnings-as-errors, structural audit, and `git diff --check`: pass.
