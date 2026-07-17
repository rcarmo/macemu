# ARM64 JIT Opcode Status — 64-bit Pointer Safety

## Summary

This is the historical **64-bit pointer-safety** matrix, not a whole-engine
semantic closure verdict. A row marked safe here means only that the reviewed
`get_n_addr()` pointer-truncation pattern is absent or repaired. The independent,
source-derived structural classifications are in
`AARCH64_JIT_CLOSURE_INVENTORY.md`; entries still marked `unreviewed` there are
not promoted by this table.

The ARM64 JIT register allocator is 32-bit. When `get_n_addr()` / `jnf_MEM_GETADR_OFF()`
produces a 64-bit host pointer and caches it in a virtual register, the allocator may
evict it as 32 bits, **truncating the pointer**. Any subsequent memory access through
the truncated pointer writes to the wrong address.

**Fixed pattern**: replace `get_n_addr` + `mov_l_rR`/`mov_l_Rr` (unsafe cached pointer)
with `readlong`/`writelong`/`readword`/`writeword` (reconstructs pointer each time).

## Opcode Family Status

| Family | Instructions | Handlers | Status | Risk | Notes |
|--------|-------------|----------|--------|------|-------|
| 0x0 | ORI/ANDI/SUBI/ADDI/EORI/CMPI/BTST/BCHG/BCLR/BSET | 232 | ✅ Safe | None | No get_n_addr usage |
| 0x1 | MOVE.B | 88 | ✅ Safe | None | No get_n_addr usage |
| 0x2 | MOVE.L/MOVEA.L | 108 | ✅ Safe | None | No get_n_addr usage |
| 0x3 | MOVE.W/MOVEA.W | 108 | ✅ Safe | None | No get_n_addr usage |
| 0x4 | CLR/NEG/NBCD/NOT/MOVEM/LEA/PEA/JSR/JMP/RTS/LINK/UNLK/SWAP/EXT/TST/CHK | 197 | ✅ Pointer-safe | None | 9 handlers use safe readlong/writelong; MOVEM lifecycle and NBCD semantics are separately audited; other structural rows remain governed by the closure inventory |
| 0x5 | ADDQ/SUBQ/Scc/DBcc | 178 | ✅ Safe | None | No get_n_addr usage |
| 0x6 | Bcc/BSR/BRA | 42 | ✅ Safe | None | No get_n_addr usage |
| 0x7 | MOVEQ/EMUL_OP | 1 | ✅ Safe | None | No get_n_addr usage |
| 0x8 | OR/DIV/SBCD | 54 | ✅ Audited | None | Complete OR flag/no-flags/immediate/readable-and-writable-EA lifecycle; DIVS/DIVL zero/overflow and patched joins; SBCD exact correction, X/C/sticky-Z, A7 predecrement; no get_n_addr usage |
| 0x9 | SUB/SUBA/SUBX | 86 | ✅ Safe | None | No get_n_addr usage |
| 0xA | A-line traps | — | ✅ Interpreter | None | A-line handled by runtime helper |
| 0xB | CMP/CMPA/CMPM/EOR | 86 | ✅ Audited | None | CMP/CMPA/CMPM, complete EOR flag/no-flags/immediate/writable-EA lifecycles, and the reachable generic EOR emitter surface are separately audited; no get_n_addr usage |
| 0xC | AND/MUL/ABCD/EXG | 79 | ✅ Audited | None | AND complete flags/no-flags/immediate/EA lifecycle plus shared logical pre-write EA ownership; MULL explicit result ownership, full-product flags, aliases, and allocator lifetime; ABCD exact correction, X/C/sticky-Z, A7 predecrement; no get_n_addr usage |
| 0xD | ADD/ADDA/ADDX | 86 | ✅ Pointer-safe | None | No get_n_addr usage; `ADD` lifecycle is separately audited, while `ADDA`/`ADDX` remain governed by the closure inventory |
| 0xE | ASL/ASR/LSL/LSR/ROL/ROR/ROXL/ROXR | 36 | ✅ Audited | None | Register-count and fixed-memory flag/count/alias/X ownership complete; no get_n_addr usage |
| 0xF | MOVE16/FPU/cpSAVE/cpRESTORE | 27 | ✅ Safe | None | No get_n_addr usage |

## Fixes Applied

| Opcode | Instruction | Fix | Commit |
|--------|------------|-----|--------|
| 0x48d0-0x48f9 | MOVEM.L reg→mem (all EA modes) | writelong without mid_bswap | `0a98ff57` |
| 0x48e0 | MOVEM.L reg→-(An) predecrement | sub_l_ri + writelong | `0a98ff57` |
| 0x4cd0-0x4cfb | MOVEM.L mem→reg (all EA modes) | readlong + add_l_ri | `0a98ff57` |
| 0x4cd8 | MOVEM.L (An)+→reg postincrement | readlong + add_l_ri | `0a98ff57` |
| 0xf620 | MOVE16 (Ax)+,(Ay)+ | readlong + writelong_clobber | `c3ddf684` |
| 0xf600/f608 | MOVE16 other variants | readlong + writelong_clobber | `c3ddf684` |

## Remaining Barriers

| Barrier | Opcode | Reason | Removable? |
|---------|--------|--------|------------|
| EMUL_OP | 0x71xx | C-side state change via EmulOp() handler | No — architectural |

## Remaining Containment

| Range | Purpose | Removable? |
|-------|---------|------------|
| 0x04000000-0x0400ffff | Low ROM: $dd0 I/O, timer, early boot | Maybe — needs per-instruction analysis |
| 0x040b0000-0x040bffff | NuBus slot init: reads 0x50Fxxxxx hardware | No — unmapped hardware registers |

## Other Known Fixes (not 64-bit truncation)

| Fix | Commit | Description |
|-----|--------|-------------|
| Repair/audit native FPP ordinary-FMOVE extended destination EAs | current structural audit | Proves d16/indexed An and absolute short/long stores through 26 strict exact-native guarded-write vectors, including brief/full direct and indirect forms, maximum fields, and all integer registers live; rejects d16 PC, indexed PC, and immediate destinations through a 3-case fail-closed matrix; bounded no-promotion subtranche, so `i_FPP` remains unreviewed; see `AARCH64_JIT_AUDIT_FPP_FMOVE_DESTINATION_EXTENDED_EA_SUBTRANCHE.md` |
| Repair/audit native FPP ordinary-FMOVE IEEE-single destinations | current structural audit | Maps isolated AArch64 FCVT status to exact 68k SNAN/OVFL/UNFL/INEX2 and accrued fields, preserves guest NZCV/host FPSR plus MPFR NaN payload/sign, and proves all FPCR modes with normal/subnormal/range/special cases through 21 strict exact-native vectors; bounded no-promotion subtranche, so `i_FPP` remains unreviewed; see `AARCH64_JIT_AUDIT_FPP_FMOVE_SINGLE_DESTINATION_SUBTRANCHE.md` |
| Repair/audit native FPP ordinary-FMOVE basic destinations | current structural audit | Replaces invalid pointer-as-vreg destination conversion, implements MPFR-compatible byte/word/long rounding/saturation and FPSR OPERR/INEX publication, maps all four FPCR modes, preserves signed NaN across the MPFR/native boundary, and proves Dn plus `(An)`/postincrement/predecrement stores through 45 strict exact-native vectors; bounded no-promotion subtranche, so `i_FPP` remains unreviewed; see `AARCH64_JIT_AUDIT_FPP_FMOVE_DESTINATION_BASIC_SUBTRANCHE.md` |
| Repair/audit native FPP ordinary-FMOVE extended source EAs | current structural audit | Adds the missing PC-indexed compiler route and proves d16/indexed An, absolute short/long, d16/indexed PC, brief/full indexed and indirect forms through 39 strict exact-native value/FPSR vectors; bounded subtranche only, so `i_FPP` remains unreviewed; see `AARCH64_JIT_AUDIT_FPP_FMOVE_EXTENDED_EA_SUBTRANCHE.md` |
| Audit native FPP ordinary-FMOVE basic-memory sources | current structural audit | Proves `(An)`, `(An)+`, and `-(An)` across byte/word/long/single/double values, exact writeback, A7 byte geometry, and maximum A7/FP7 fields through 18 strict exact-native vectors; no implementation change or closure promotion, so `i_FPP` remains unreviewed; see `AARCH64_JIT_AUDIT_FPP_FMOVE_MEMORY_BASIC_SUBTRANCHE.md` |
| Repair native FPP ordinary-FMOVE sources | current structural audit | Replaces the invalid AArch64 `temp_fp` pointer-as-vreg compatibility route with typed byte/word/long/single conversions; proves immediate double and all FP0-FP7 copy/self-alias routes through 43 strict exact-native value/FPSR vectors; bounded subtranche only, so `i_FPP` remains unreviewed; see `AARCH64_JIT_AUDIT_FPP_FMOVE_SOURCE_SUBTRANCHE.md` |
| Repair native FPP FCMP/FTST condition results | current structural audit | Direct FCMP relation classification replaces subtraction, preserves equal signed-zero/infinity CCB distinctions and integer CCR, and passes 176 FCMP plus 128 FTST strict exact-native vectors with exact FPSR; bounded subtranche only, so `i_FPP` remains unreviewed; see `AARCH64_JIT_AUDIT_FPP_COMPARE_FTST_SUBTRANCHE.md` |
| Complete native FBcc generator lifecycle | current structural audit | All 16 FP predicates over positive/zero/negative/signed-NaN classes, word/long signed displacements, exact taken/not-taken successors, full integer CCR preservation, MPFR/native FPSR boundary synchronisation, and 160 strict exact-native vectors; see `AARCH64_JIT_AUDIT_FBCC_LIFECYCLE.md` |
| Complete EXT generator lifecycle | current structural audit | Six generated handlers split 3/3 across compiler tables, EXT.W byte-to-word upper-lane preservation, EXT.L word-to-long, EXTB.L byte-to-long, fixed logical flags, 16 exact-native vectors, and one scratch/source allocator witness; see `AARCH64_JIT_AUDIT_EXT_LIFECYCLE.md` |
| Complete EXG generator lifecycle | current structural audit | Six generated handlers split 3/3 across compiler tables, all Dn/Dn, An/An, and Dn/An forms, exact simultaneous exchange, self aliases, maximum fields, roundtrips, 12 exact-native vectors, and one temporary/source allocator witness; see `AARCH64_JIT_AUDIT_EXG_LIFECYCLE.md` |
| Complete CLR generator lifecycle | current structural audit | 48 generated handlers split 24/24 across compiler tables, byte/word/long Dn and all writable memory forms, exact upper-lane and fixed-flag semantics, store-before-flags ordering, 15 exact-native vectors, and one EA/zero allocator witness; six namesake MIDFUNCs remain unreachable; see `AARCH64_JIT_AUDIT_CLR_LIFECYCLE.md` |
| Complete Bcc generator lifecycle | current structural audit | 90 generated handlers split 45/45 across compiler tables, all fourteen conditional pairs plus BRA, byte/word/long signed target arithmetic, 34 exact-native vectors, two condition-translation boundaries, and exact CCR preservation; raw branch lowering remains separately unreviewed; see `AARCH64_JIT_AUDIT_BCC_LIFECYCLE.md` |
| Complete ADDA lifecycle and repaired source/writeback ownership | current structural audit | Four reachable no-flags MIDFUNC routes, 52 generated handlers, exact word sign-extension and long-width semantics, 27 exact-native plus two constant-fold vectors, and two allocator witnesses that reproduced both postincrement/source and destination/source collisions; see `AARCH64_JIT_AUDIT_ADDA_LIFECYCLE.md` |
| Generic SUB/SUBS emitter width/field/alias/NZCV contracts | current structural audit | Seven reachable AArch64 encoder APIs, 11 exact words, 70 direct native vectors, and 115 fail-closed raw caller checks; see `AARCH64_JIT_AUDIT_SUB_EMITTERS.md` |
| Complete SUB lifecycle and repaired destination-EA ownership | current structural audit | Twelve reachable SUB MIDFUNC routes, 208 generated handlers, nine readable and seven writable EA classes, 126 balanced writable-EA pins, 37 exact-native vectors, and the exact-native FLAGX/pre-write-EA collision which reproduced and verifies the repair; see `AARCH64_JIT_AUDIT_SUB_LIFECYCLE.md` |
| Complete OR lifecycle and source/destination EA ownership | current structural audit | Twelve reachable OR MIDFUNC routes, 156 generated handlers, nine readable and seven writable EA classes, 84 balanced writable-EA pins, 37 exact-native vectors, and two focused allocator collisions; see `AARCH64_JIT_AUDIT_OR_LIFECYCLE.md` |
| Generic EOR emitter encoding/bit/no-flags contracts | current structural audit | Four reachable callable AArch64 encoders plus `immOP_EOR`, 13 exact words, 22 direct native vectors, and 64 fail-closed raw source compositions; see `AARCH64_JIT_AUDIT_EOR_EMITTERS.md` |
| Complete EOR lifecycle and writable-EA ownership | current structural audit | Twelve reachable EOR MIDFUNC routes, 96 generated handlers, 84 balanced EOR memory-EA pins, 28 exact-native vectors, and two focused allocator collisions; see `AARCH64_JIT_AUDIT_EOR_LIFECYCLE.md` |
| Generic AND emitter width/field/no-flags contracts | current structural audit | Three reachable AArch64 encoder APIs, 9 exact words, 27 direct native vectors, and 83 fail-closed raw caller checks; see `AARCH64_JIT_AUDIT_AND_EMITTERS.md` |
| AND and shared logical pre-write EA lifecycle | current structural audit | Twelve reachable AND MIDFUNC routes, 84 AND and 252 shared OR/AND/EOR generated memory-EA pins, 34 complete AND vectors, two adjacent OR/EOR regressions, and two focused allocator collisions; see `AARCH64_JIT_AUDIT_AND_LIFECYCLE.md` |
| Generic ADD emitter width/field/no-flags contracts | current structural audit | Seven reachable AArch64 encoder APIs, 12 exact words, 46 direct native vectors, and 72 fail-closed raw caller checks; see `AARCH64_JIT_AUDIT_ADD_EMITTERS.md` |
| ADD pre-write EA and arithmetic lifecycle | current structural audit | Six shared MIDFUNC operand routes plus 126 generated memory-EA pins through ordered storage; 34 exact-native vectors and two focused allocator collisions; see `AARCH64_JIT_AUDIT_ADD_LIFECYCLE.md` |
| MOVEM cursor/base/extension lifecycle | current structural audit | Private load/store cursors, delayed update-mode publication, 68020+ base-in-mask predecrement semantics, exact PC-relative replay, special-memory service, and forced cursor/base allocator pressure; see `AARCH64_JIT_AUDIT_MOVEM_LIFECYCLE.md` |
| Long-multiply result/flag/allocator lifecycle | `4bb12cca` | Explicit Dl/Dh/source ownership, full-product N/Z/V, high-before-low alias ordering, and generator value locking under a forced S1-to-Dl collision; see `AARCH64_JIT_AUDIT_MULL_LIFECYCLE.md` |
| Fixed-memory shifts and ROX ownership | `01a04904` | `jff`/`jnf` memory-shift lifecycle, branchless C/V, and one RMW X binding under forced allocator pressure; see `AARCH64_JIT_AUDIT_MEMORY_SHIFTS_ROX.md` |
| Division zero/overflow lifecycle | `47ed4dea` | Signed 32/32 overflow, conditional result preservation, signed-overflow Z, aliases, and all 28 DIVL joins; see `AARCH64_JIT_AUDIT_DIVISION_LIFECYCLE.md` |
| BCD arithmetic/flag/A7 family | `1aeb577e` | `ABCD`/`SBCD`/`NBCD` share exact 68040 correction and X/C/sticky-Z handling; ordered byte predecrement uses `areg_byteinc[]`; see `AARCH64_JIT_AUDIT_BCD.md` |
| A-line trap L2 helper | `adc83002` | Runtime helper for A-line exception control flow |
| 64-bit PC_P truncation | `91f2e0f8` | add_l/sub_l_ri routes through arm_ADD_l for PC_P |
| Endblock pc_p store | `80afe33d` | Unconditional regs.pc_p store on hot chain |
| Spcflags mid-block PC | `c59cf7fe` | Full PC triple in spcflags cold path |
| Cross-block flag loss | `ffb1b731` | flush(save_regs=1) forces flags_are_important |
| tick_inhibit removal | `872ddd69` | Don't inhibit ticks during block tracing |
| Mid-block tick injection | `1f43f27f` | cpu_do_check_ticks every 64 compiled instructions |
| NuBus video probe patch | `ee27ef35` | ROM patch: jmp (a6) at 0xb27c |
| NuBus slot probe patch | `016d85ac` | ROM patch: beq→bra at 0xba0b0 |
