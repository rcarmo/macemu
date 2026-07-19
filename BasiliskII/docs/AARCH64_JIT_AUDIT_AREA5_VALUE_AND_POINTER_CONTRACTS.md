# AArch64 JIT Audit — Area 5: Value Width and Pointer Contracts

## Scope

This audit covers generic integer MIDFUNC arithmetic, host-pointer construction,
partial-width ownership, indexed effective-address generation, and diagnostic
work accidentally emitted on production hot paths.

Primary files:

- `compiler/compemu_midfunc_arm64.cpp`
- `compiler/compemu_midfunc_arm.cpp`
- `compiler/compemu_midfunc_arm.h`
- `compiler/compemu_support_arm.cpp`
- `compiler/compemu_legacy_arm64_compat.cpp`
- `compiler/codegen_arm64.cpp`
- `compiler/gencomp.c`
- `compiler/gencomp_arm.c`

Validation target: Orange Pi 6 Plus, CIX P1 AArch64 SoC, 12 CPU cores,
16 GB-class RAM, Debian Trixie, Bun-based regression harness, GCC/G++ AArch64
build, and BasiliskII's 64 MB full-JIT Finder workload.

## Width contract

The backend carries two different value classes through integer virtual
registers:

1. M68K integer and effective-address values, whose arithmetic is modulo
   2^32 and whose upper native-register half must be zero after a W-register
   write.
2. Native host pointers, which use the full `uintptr` width and must survive
   constant folding, register allocation, spills, and pointer increments.

The operation that crosses those classes must state the conversion explicitly:
a signed M68K displacement is sign-extended from 32 bits exactly once and added
to a native host base. Numeric magnitude is not type information.

The resulting MIDFUNC contracts are:

- `arm_ADD_l_ri`: ordinary modulo-2^32 guest arithmetic;
- `arm_ADD_l_ri_hostptr`: signed guest displacement plus native host base;
- `arm_ADD_ptr_ri`: pointer-width immediate increment.

## Confirmed defect

`arm_ADD_l_ri` previously selected guest or pointer arithmetic from values:

- `i > 0xffffffff` was treated as evidence that `i` was a host pointer;
- immediates within the current low host mapping were also classified as
  pointers;
- constants already exceeding 32 bits were kept pointer-width.

That inference conflated two reachable call families:

- Bcc/DBcc generation adds `(uintptr)comp_pc_p` to a signed guest branch
  displacement and genuinely constructs a host PC;
- `calc_disp_ea_020()` adds signed base and outer displacements to a guest
  effective address and must remain modulo 2^32.

A negative 68020 indexed-EA displacement arrives through the old `IMPTR`
parameter as a large unsigned value. The old MIDFUNC therefore emitted
pointer-width `ADD Xd, Xbase, Wd, SXTW`, leaving sign-extended upper bits for a
guest address with bit 31 set. Scratch virtual registers deliberately preserve
64-bit values. Current direct-memory helpers defend themselves with UXTW, but
the generic value contract had become consumer-dependent: every later X-width
move, spill, or address use had to remember that a nominal guest value might
carry pointer-shaped upper bits.

## Structural fix

- Removed `arm64_low32_hostptr_imm()` and every value-range pointer heuristic.
- Made `arm_ADD_l_ri` unconditionally use W-register arithmetic and 32-bit
  constant folding.
- Added an explicit signed-W-plus-host-base operation for Bcc/DBcc target
  construction.
- Added a separate X-register pointer increment for pointer-valued scratch
  registers and `PC_P`.
- Updated both generators, generated `compemu.cpp`, `sync_m68k_pc()`, and the
  legacy ARM64 compatibility boundary to call the appropriate typed operation.
- Kept the contracts distinct on ARM32 as well, even though guest values and
  host pointers have the same physical width there.

## Production diagnostic removal

`compemu_raw_endblock_pc_inreg()` incremented a global
`jit_endblock_inreg_count` on every dynamic-PC block exit. The value had no
reader and was not gated by a diagnostic option. The emitted load/add/store and
the global were removed. Structural audit now rejects the symbol.

## Reachability decisions

- `lea_l_brr_indexed()` is reached only from `calc_disp_ea_020()` in the current
  ARM generator. Its reachable destination/index alias is handled; generated
  callers keep the destination scratch distinct from the base. No speculative
  alias rewrite was made.
- `fmov_d_rrr()` and `fmov_to_d_rrr()` have declarations and MIDFUNC/raw
  definitions but no generated or support-layer callers. Their suspicious raw
  ownership details were dead and were not changed by this Area 5 checkpoint.
  A later configured-root audit promoted only the definition-only
  `raw_fmov_d_rrr` row to **unreachable**, with exact body/future-caller guards;
  `fmov_to_d_rrr` and its separate raw boundary remain outside that decision.
- The `rtarea_bank` ROM guard is under the UAE build branch. BasiliskII's active
  branch uses `ROMBaseHost..ROMBaseHost+ROMSize`; no current-build change was
  justified.

## Regression gates

`jit-test/structural-audit.ts` now requires:

- all three explicit arithmetic contracts;
- SXTW only at the guest-displacement-to-host-pointer conversion;
- W-register-only generic guest addition;
- typed Bcc/DBcc generator and generated-source calls;
- absence of numeric host-range inference;
- absence of the endblock diagnostic counter.

`indexed_full_neg_base` first executes BSR.B/RTS to cover constant
register-sourced pointer-width `PC_P` addition, then executes a 68020
full-format indexed load with a negative word base displacement and a
sign-bit-set guest EA. It is a permanent interpreter/JIT equivalence vector and
is part of the active risky gate.

## Verification at landing

- clean AArch64 build: pass;
- structural audit: all metrics `1`;
- focused indexed-EA vector: `1/1`;
- full opcode equivalence: `330/330`, `fail=0`, `infra_fail=0`, `score=100`;
- allocator-pressure cell: pass, `natexec=126`, interpreter/JIT dumps equal;
- generated `compemu.cpp`: stable at SHA-256
  `84f195108c5b6bbc6984fd527130ad60f9133e56b7c82f1ddb21b4942e322d2b`;
- frozen-clock full JIT: interactive Finder reached; guest input displayed the
  improper-shutdown dialog and Return revealed the populated desktop;
- frozen-clock patch removed and production timer rebuilt before commit.

## `arm_ADD_l` closure supplement — 2026-07-19

A later source-derived inventory correctly kept the register-sourced wrapper
`arm_ADD_l` unreviewed because the original report named only its three typed
immediate callees. Configured-root reconciliation now closes that one row.

The wrapper has exactly two configured ownership classes:

- `calc_disp_ea_020()` calls `arm_ADD_l(target, base)` when a full-format
  indexed guest EA includes its base. This must use modulo-2^32 W arithmetic;
- the ARM64 compatibility `add_l()` wrapper calls `arm_ADD_l(PC_P, src)` only
  for six generated BSR providers (byte/word/long in both compiler tables).
  This must add a signed 32-bit displacement to the full host PC pointer.

Ordinary generated `add_l(dst,src)` arithmetic does not reach `arm_ADD_l`; it
routes through the independently audited `jff_/jnf_ADD_l` lifecycle. The source
contract keeps constant `PC_P` through `arm_ADD_ptr_ri`, dynamic `PC_P` through
`ADD Xd,Xd,Ws,SXTW`, constant guest destinations through `arm_ADD_l_ri`, and
dynamic guest destinations through `ADD Wd,Wd,Ws`.

`jit-test/arm-add-l-native-matrix.ts` adds seven strict exact-native cases:

- all three constant BSR displacement providers;
- dynamic full-index guest EA addition with long and sign-extended word index;
- guest modulo-2^32 wrap; and
- a forced full-index base/target allocation collision.

Every case uses forced RAM L2, two-pass replay, exact `NATEXEC` attribution,
strict no-fallback checks, complete interpreter/JIT dump equality, and CoW disk
isolation. Result: `ARM_ADD_L_NATIVE_MATRIX pass=7 fail=0 total=7`.

This supplement promotes only MIDFUNC `arm_ADD_l`. No generic ADD emitter,
ordinary ADD lifecycle row, allocator helper, or neighbouring value MIDFUNC is
promoted.

Acceptance evidence:

- focused matrix: **7/7 exact-native**;
- structural audit and Bun/shell/source hygiene: pass;
- deterministic inventory: **998 rows**, exactly `arm_ADD_l`
  unreviewed→audited; MIDFUNC totals become 276 audited / 119 unreachable / 27
  unreviewed; all other layers are unchanged;
- closure CSV: `962856ecf2fcced7d54436feaa3dd0c979da17716fbfa3e2db21694929ae6dff`;
- closure Markdown: `3d7e9667b73a1a2ec2774bfb099e4804f419b00d1fb140dcc810321cd5b50abd`;
- independent bounded review: **APPROVE** after anchoring the Area 5 closure
  regex so `arm_ADD_l_ri8` and `arm_ADD_ldiv8` remain unreachable;
- unchanged executable baseline from immediately preceding canonical commit
  `696a9e46`: active corpus **904/904**, allocator pressure **33/33**, strict
  policy pass, clean AArch64 build, and stable generated sources.

## Contributor rule

Do not infer whether a virtual-register value is a guest integer or a host
pointer from its numeric range. Use an operation whose name and implementation
state the width transition explicitly.
