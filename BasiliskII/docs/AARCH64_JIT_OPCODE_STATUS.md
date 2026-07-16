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
| 0x8 | OR/DIV/SBCD | 54 | ✅ Audited | None | DIVS/DIVL zero/overflow and patched joins; SBCD exact correction, X/C/sticky-Z, A7 predecrement; no get_n_addr usage |
| 0x9 | SUB/SUBA/SUBX | 86 | ✅ Safe | None | No get_n_addr usage |
| 0xA | A-line traps | — | ✅ Interpreter | None | A-line handled by runtime helper |
| 0xB | CMP/CMPA/CMPM/EOR | 86 | ✅ Safe | None | No get_n_addr usage |
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
