# SheepShaver AArch64 JIT — Project Plan

## Goal

Bring SheepShaver's PPC emulation to full native performance on AArch64,
starting with an optimized interpreter and progressing to a direct-codegen JIT.

## Current Status (May 2026)

**Mac OS boots to "Welcome to Mac OS" splash screen with JIT active (`SS_USE_JIT=1`). The interpreter boots to desktop and remains the exact fallback path for incomplete/barrier blocks.**

| Metric | Value |
|--------|-------|
| Opcode test harness | **209/209** pass (score=100) |
| ROM harness (10K blocks) | **1800/1825** pass (98.6%) on PowerMac 9500 OldWorld ROM |
| Unique opcodes inlined | **285+** PPC opcodes as native ARM64 |
| Block completion policy | Only `jblk.complete` blocks execute natively; fallback-only/incomplete blocks are interpreted |
| Lazy CR0 | ✅ Active again with x19 pending-result copy; materialized at consumers/exits |
| Register allocation | ✅ Conservative: active only for straight-line, non-faultable blocks |
| JIT benchmark (addi+bdnz 100M) | **~737 MIPS** (intra-block CBNZ tight loop, Orange Pi 6 Plus) |
| Interpreter benchmark | 167 MIPS |
| FPU | ✅ double + single + fused multiply-add + FPSCR rounding modes |
| AltiVec (NEON) | ✅ 140 opcodes via AArch64 NEON intrinsics |
| XER carry/overflow | ✅ byte-level LDRB/STRB (struct-aware, not packed uint32) |
| VNC input | ✅ keyboard + mouse via direct ADB injection |
| Boot tested | Mac OS 7.5 to "Welcome to Mac OS" splash (JIT), desktop (interpreter) |

### Screenshots

| Stage | Screenshot |
|-------|-----------|
| ROM boot (no disk) | ![](doc/aarch64-boot-nodisk.png) |
| Mac OS boot (interpreter) | ![](doc/aarch64-macos-boot.png) |
| JIT-enabled boot | ![](doc/aarch64-jit-macos-welcome.png) |

### ROM Harness

A standalone headless tool (`rom-harness/`) loads the Mac ROM, scans for PPC
basic blocks, JIT-compiles each, and compares outputs against a built-in
reference interpreter. No display, no hardware, no SheepShaver runtime needed.

The ROM harness found and helped fix **13 JIT bugs** including the critical
XER struct layout mismatch (XER is `{uint8 so,ov,ca,byte_count}`, not a
packed uint32), CSET encoding error, 7 missing carry-flag writes, andi. CR0
omission, bc not-taken epilogue, BO field decode, and FPSCR rounding mode NOPs.

Subsequent audits (May 2026) found and fixed further JIT bugs:
- `rld*` sub-opcode SH[5] mis-decode for sh≥32 (rldicl/rldicr/rldic/rldimi mapped to wrong variant)
- `rld*` mask code was dead (inside wrong `if` branch; sub 0/1/2 received no mask)
- `rldcl`/`rldcr` emitted ROR instead of ROL
- `rldimi` not implemented (fell to interpreter)
- `bcl` LR never updated (`emit_save_lr_if_link` was defined but never called)
- 9 Rc=1 CR0 updates missing: rlwinm./rlwimi./cntlzw./extsh./extsb./mullw./mulhw./mulhwu./divw.
- `ppc-execute.cpp`: duplicate VXISI mask in `record_fpscr`; incorrect `(uint32)d` cast in multiply
- AArch64 PPC64 temp-register/EA clobbers in `mulld`/`mulhdu`/`mulhd`/`divdu`/`divd`, `stdx`/`stdux`/`stdcx.`, `std`/`stdu`, and `lq`
- `bclrl` old-LR target ordering and full `bclr` BO CTR/condition semantics (`bdnzlr`-style forms)
- Fallback-only/barrier opcodes (`sc`, `tw`, `twi`/`tdi`, `lswx`/`stswx`, unknown SPR) now delegate to the interpreter instead of compiling as NOP/self-return blocks
- Opcode-test cleanup fixed: `mmap()`-allocated test RAM is released with `munmap()`

## Architecture

### Interpreter path (always available)
```
PPC instruction → ppc-decode.cpp → ppc-execute.cpp (Duff's device dispatch)
                                    ↓
                            direct memory access via host pointers
```

### JIT path (AArch64, USE_AARCH64_JIT)
```
PPC instruction → ppc-cpu.cpp execute loop
                    ↓
              ppc-jit.cpp (compile basic block to ARM64)
                    ↓
              ppc-codegen-aarch64.h (ARM64 instruction encoding)
                    ↓
              jit-cache (RWX mmap, icache flush)
                    ↓
              native execution: void block(powerpc_registers *regs)
                    ↓
              fall back to interpreter for incomplete blocks
```

### Code layout
```
src/kpx_cpu/src/cpu/jit/aarch64/
  ppc-jit.h          — JIT public interface
  ppc-jit.cpp        — PPC → ARM64 compiler (scalar, FPU, PPC64, and AltiVec/NEON handlers)
  ppc-jit-glue.hpp   — integration with ppc-cpu.cpp execute loop
  ppc-codegen-aarch64.h      — ARM64 instruction encoding helpers
  jit-target-cache.hpp       — AArch64 icache flush + RWX mapping
  dyngen-target-exec.h       — PPC → ARM64 register mapping constants
```

### Register convention for generated code
```
x20 = pointer to powerpc_registers struct (callee-saved)
x0-x3 = scratch / temporaries
d0-d2 = FP scratch (for FPU ops)
GPR[n] accessed via LDR/STR Wt, [x20, #n*4]
FPR[n] accessed via LDR/STR Dt, [x20, #256+n*8]
CR/FPSCR/LR/CTR/PC and byte-addressed XER fields at known offsets from x20
```

## Opcode Coverage

### Integer ALU (11)
`addi`/`li`, `addis`/`lis`, `addic`, `addic.`, `mulli`,
`add(.)`/`subf(.)`/`neg(.)`, `mullw`, `divw`

### Logical (6)
`ori`, `oris`, `xori`, `xoris`, `andi.`, `andis.`

### Shift/Rotate (6)
`slw`, `srw`, `sraw`, `srawi`, `rlwinm`, `rlwimi`

### Compare (4)
`cmpwi`, `cmplwi`, `cmpw`, `cmplw` — all with CR field update

### Record forms
`add.`, `subf.`, `and.`, `or.`, `xor.`, `neg.` — CR0 update via CSEL

### Branch (7)
`b`, `bl`, `bdnz` (with intra-block backward chaining),
`beq`/`bne`/`blt`/`bgt`/`ble`/`bge`/`bhi`/`bls`...,
`blr`, `bctr`/`bctrl`, `isync`

### Load/Store integer (13)
`lwz`/`lwzu`/`lwzx`, `stw`/`stwu`/`stwx`,
`lbz`/`stb`, `lhz`/`lha`/`sth`, `lmw`/`stmw`

### Load/Store FP (4)
`lfs` (single→double), `lfd` (double), `stfs` (double→single), `stfd` (double)

### FP arithmetic double (12)
`fmr`, `fneg`, `fabs`, `fnabs`, `fadd`, `fsub`, `fmul`, `fdiv`,
`fmadd`, `fmsub`, `fnmadd`, `fnmsub`, `fcmpu`

### FP arithmetic single (4)
`fadds`, `fsubs`, `fmuls`, `fdivs` (compute double, round to single)

### Utility (9)
`cntlzw`, `extsh`, `extsb`, `srawi`,
`mfspr`/`mtspr` (LR, CTR), `mfcr`, `mtcrf`, NOP

## Completed Phases

### Phase 1: Interpreter baseline ✅
- Interpreter achieves 167 MIPS with Duff's device + block cache
- Test harness with **209** PPC opcode vectors (score=100)

### Phase 2: JIT scaffolding ✅
- Direct codegen compiler: `ppc-jit.cpp`
- ARM64 instruction encoding: `ppc-codegen-aarch64.h`
- Code cache: 4MB RWX mmap with icache flush
- Integration into `ppc-cpu.cpp` execute loop

### Phase 3: Integer opcode handlers ✅
- All integer ALU, logical, shift/rotate, compare, branch
- Load/store word/byte/halfword with byte-swap
- SPR access, CR move; intra-block bdnz loop chaining; record forms (CR0)

### Phase 4: FPU ✅
- Double-precision: fadd/fsub/fmul/fdiv + fused multiply-add
- FP move/negate/abs; FP compare → CR field
- Single-precision round-to-single via FCVT; FP load/store with byte-swap

### Phase 4b: Hash + chaining block cache ✅
- 8192 buckets, 16384 pool entries
- PC → compiled code lookup; invalidate-by-PC; full flush on icbi

### Phase 4c: Lazy CR0 flags ✅ re-enabled conservatively
- Rc=1 results are copied to x19 (`RCR0`, callee-saved) and CR0 is materialized at CR consumers or block exits
- This fixes the earlier boot-regression risk where the pending result lived in scratch state
- Targeted Rc=1 1B-loop timing improved from a warmed immediate-CR0 baseline of ~2.84s to ~2.39–2.63s

### Phase 4d: Register allocation ✅ re-enabled conservatively
- x21–x28 register-cache scaffolding is active only for straight-line, non-faultable blocks
- Blocks with conditional branches or guest-memory accesses keep direct struct LDR/STR until per-label/per-fault RA state is implemented
- LRU/dirty-flush code is active under that gate

## Remaining Work

### Phase 5: Region JIT / optimization hardening
- [x] Block-to-block chaining (compile-time `chain_code` plus runtime back-patching)
- [x] Revalidate and re-enable lazy CR0 with targeted harness/regression proof
- [x] Revalidate and re-enable register allocation for straight-line non-faultable blocks
- [ ] Broaden register allocation to branch/faultable blocks only after per-label/per-fault RA state exists
- [ ] Profile-guided hot-block prioritization
- [ ] Raise 512-instruction block limit if needed

### Not yet implemented (rare opcodes)
- ~~CR logical ops~~ ✅ Implemented: crand, cror, crxor, crnor, crandc, creqv, crorc, crnand
- ~~mcrf~~ ✅ Implemented
- ~~`bcl` LR update~~ ✅ Fixed: `emit_save_lr_if_link` now called in all simple BO-field cases
- ~~`rldimi`~~ ✅ Implemented: BIC+ORR mask-insert with compile-time mask (`de8b850a`)
- ~~Rc=1 CR0 for rlwinm./rlwimi./cntlzw./extsh./extsb./mullw./mulhw./mulhwu./divw.~~ ✅ Fixed (`10e8f719`)
- ~~`rld*` sub-opcode decode (SH[5] mis-decode for sh≥32)~~ ✅ Fixed (`77004daa`)
- Complex `bc` variants (decrement CTR + test condition combo with `lk=1`) — still falls to interpreter
- `sc` (system call) — interpreter fallback by design
- `tw`/`twi`/`tdi` (trap) — interpreter fallback by design
- Unknown `mfspr`/`mtspr` — interpreter fallback by design

## Test Harness

```bash
# Run opcode equivalence tests (interpreter determinism) — 209/209 pass
./jit-test/run.sh

# Run Rc=1 record-form + rld* regression tests (JIT vs interpreter)
./jit-test/ss-record-regression.sh src/Unix/SheepShaver

# Run with JIT native execution
SS_TEST_HEX="38600064 388000c8 7CA32214" SS_TEST_DUMP=1 SS_TEST_JIT=1 ./SheepShaver

# Boot Mac OS with JIT
vm.mmap_min_addr=0  # required for low memory globals
USE_AARCH64_JIT=1   # compile flag
```

## Build

```bash
cd src/Unix
./autogen.sh
./configure --enable-sdl-video --enable-sdl-audio
make -j12
# For JIT: rebuild ppc-cpu.cpp with -DUSE_AARCH64_JIT and link ppc-jit.o
```

## Constraints

- No dyngen — direct ARM64 emission only
- No ROM patches to work around JIT bugs
- Test-driven: opcode harness validates each handler
- Interpreter always available as fallback for uncompiled blocks

## Interpreter Delegation and NOP/Hint Justification

The JIT must not compile uncertain semantics as harmless NOPs. Current policy:

- Architecturally invisible hints may compile as NOPs.
- Barrier-worthy, privileged, trap, runtime-helper, or unknown CPU-specific operations return `false` from `compile_one()` so the interpreter owns exact semantics.
- Incomplete compile probes are not executed because `ppc-cpu.cpp` still requires `jblk.complete`.

### Safe NOP / hint classes

| Instruction class | Why native NOP is acceptable |
|---|---|
| `DCBF`, `DCBST`, `DCBT`, `DCBTST`, `DCBA`, `DCBI`, `ICBI` | No emulated PPC cache hierarchy; generated ARM64 code performs its own host icache flushes. |
| `SYNC`, `EIEIO` | Single-threaded emulator path is sequentially consistent for guest-visible state. |
| `DSS`, `DST`, `DSTST` | Data-stream/prefetch hints only. |
| `ECIWX`, `ECOWX` | External-control I/O is not used by the supported Power Mac workloads. |

### Exact interpreter fallback classes

| Instruction class | Current handling |
|---|---|
| `SC` | `compile_one()` returns `false`; interpreter raises/handles the system-call path. |
| `TW`, `TWI`, `TDI` | `compile_one()` returns `false`; interpreter evaluates trap conditions. |
| `LSWX`, `STSWX` | `compile_one()` returns `false`; runtime byte count comes from XER and remains interpreter-owned. |
| Unknown `MFSPR`/`MTSPR` | `compile_one()` returns `false`; interpreter owns privileged/CPU-specific semantics. |
| Unknown/secondary AltiVec forms | `compile_one()` returns `false`; no silent compiled NOP masking. |
| EMUL_OP / helper-style runtime operations | No inline codegen; interpreter provides the semantic barrier. |

### Implemented non-NOP classes

| Instruction class | Status |
|---|---|
| FPSCR bit manipulation (`MTFSFI`, `MTFSB0`, `MTFSB1`, `MTFSF`) | Implemented with FPSCR updates and ARM64 FPCR rounding sync. |
| Immediate string ops (`LSWI`, `STSWI`) | Implemented with byte count and register wrapping. |
| AltiVec/VMX | Broad NEON-backed implementation; unknown forms fall back rather than silently no-op. |

### Summary

The remaining native NOPs are limited to hints/cache/stream/external-control operations that
are not guest-observable in the supported emulator configuration. Anything that can alter
architectural control flow, raise exceptions, or depend on privileged state should fall back.
