# MacEmu AArch64 JIT — Status

## SheepShaver PPC JIT (2026-05-13)

**Build:** ✅
**Interpreter:** ✅ Boots Mac OS to desktop (VNC port 5999, ~324 MIPS on Orange Pi 6 Plus)
**JIT boot:** ✅ Boots to "Welcome to Mac OS" splash screen with JIT active
**JIT harness:** ✅ 209/209 opcode vectors pass (score=100)
**ROM harness:** ✅ 1800/1825 ROM blocks pass (98.6%) on 10K-block scan
**Tight-loop benchmark:** ✅ ~737 MIPS (addi+bdnz 100M, intra-block CBNZ, Orange Pi 6 Plus)

### JIT Boot Status

With JIT active, SheepShaver boots Mac OS to the Welcome splash screen.
Phases 1–3 complete; Phase 4 (block chaining) complete:
1. **Phase 1:** Hash + chaining block cache (8192 buckets)
2. **Phase 2:** Lazy CR0 flags
3. **Phase 3:** Register allocation (x21–x28)
4. **Phase 4a:** Fast JIT dispatch inner loop (`a8afdf92`)
5. **Phase 4b:** Compile-time block chaining — `chain_code` entry points (`4bcd9336`)
6. **Phase 4c:** Runtime back-patching — chain site pool, `patch_chain_sites` on insert (`e1f11657`)
7. **Phase 4d:** `rld*` correctness — rldicl/rldicr/rldic masks; rldcl/rldcr ROL; sub-opcode SH[5] decode (`8ad71eed`, `77004daa`)
8. **Phase 4e:** Rc=1 CR0 audit — rlwinm./rlwimi./cntlzw./extsh./extsb./mullw./mulhw./mulhwu./divw. all fixed (`10e8f719`)
9. **Phase 4f:** `rld*` sub-decode fix, dead mask code fix, `rldimi` implemented (`77004daa`, `de8b850a`)

MacBench results (after Phase 3): CPU 835, FPU 1027.
Tight-loop benchmark (after Phase 4b): ~737 MIPS (intra-block CBNZ).

### ROM Harness

Standalone headless tool: `SheepShaver/rom-harness/`

Loads the Mac ROM, scans for PPC basic blocks, JIT-compiles each,
compares against a built-in reference interpreter. No display, no
hardware, no SheepShaver runtime dependencies.

**Score: 1800/1825 (98.6%)** on PowerMac 9500 OldWorld ROM (10K-block scan).

Remaining 25 failures: CR field interactions in multi-instruction blocks
and complex branch BO patterns (CTR+condition combo).

### Recent bug fixes (2026-05)

- **`bcl` LR update silent no-op** (`16802900`): `emit_save_lr_if_link()` was defined but never
  called — all three simple BO-field cases in the `bc` handler ignored `lk=1`. Critical case:
  `bcl 20,31,+4` (PPC idiom for materialising PC into LR) never updated LR.
- **Signal handler register dump** (`69821bf6`): `printf("%s\n")` with missing `crash_reason`
  argument (UB); `crash_reason` mis-placed as first `%08lx` value, shifting all 32 register
  values one slot; 608-byte dump formatted into a 256-byte stack buffer.
- **Slirp pipe framing** (`4d388ce4`): unchecked `write(len)` return on send path could desync
  the frame stream; unchecked `read(len)` with uninitialised `len` on receive path could
  assert-abort or call `slirp_input` with garbage data.
- **XPRAM I/O** (`4d388ce4`): `read()`/`write()` return values unchecked in Linux path;
  short reads silently left XPRAM partially initialised, short writes silently truncated NVRAM.
- **`strdup` null check** (`4d388ce4`): `open_filehandle()` did not check `strdup()` result;
  OOM would leave `fh->name = NULL` and crash on subsequent `strcmp`/`free`.
- **SheepShaver hardening** (17 commits, `2f7e038b`–`cbad1b93`): bounds checks on ROM reads,
  CPU/metadata parsing, Unix UI paths, preference strings, sheepthreads join/fd cleanup;
  SDL framebuffer allocation, CD audio buffers, SDL3 audio startup, CUE parsing, NVRAM,
  cursor scaling.

### VNC Input

VNC keyboard and mouse work for remote control:
- Keyboard: SDL event queue drain → ADB key injection
- Mouse: direct ADB injection from VNC server thread (bypasses SDL for reliability)
- Port 5999 (configurable via `vncport` pref)

### Opcode Census — 285 Unique PPC Opcodes Inlined as ARM64

| Category | Count | Status |
|----------|-------|--------|
| Integer ALU (immediate) | 12 | ✅ addi/lis/addic/subfic/mulli/ori/oris/xori/xoris/andi./andis. |
| Integer ALU (register) | 15 | ✅ add/addc/adde/addme/addze/subf/subfc/subfe/subfme/subfze/neg/mullw/mulhw/divw |
| Logical (register) | 10 | ✅ and/andc/or/nor/xor/eqv/orc/nand/slw/srw |
| Shift/Rotate | 6 | ✅ sraw/srawi/rlwinm/rlwimi/rlwnm/cntlzw |
| Sign extend | 2 | ✅ extsh/extsb |
| Compare | 4 | ✅ cmp/cmpl/cmpi/cmpli (all with CR field + XER[SO]) |
| Load/Store integer | 14 | ✅ lwz/lwzu/lbz/lbzu/lhz/lhzu/lha/lhau/stw/stwu/stb/stbu/sth/sthu |
| Load/Store indexed | 8 | ✅ lwzx/lbzx/lhzx/lhax/stwx/stbx/sthx/lwbrx/sthbrx |
| Load/Store atomic | 2 | ✅ lwarx/stwcx. |
| Load/Store string | 2 | ✅ lswi/stswi |
| Load/Store FP | 8 | ✅ lfs/lfd/stfs/stfd + indexed variants |
| Branch unconditional | 2 | ✅ b/bl |
| Branch conditional | 5 | ✅ bc (all BO variants)/bdnz/bdz/bclr/bcctr |
| CR logical | 9 | ✅ mcrf/crand/cror/crxor/crnor/crandc/creqv/crorc/crnand |
| SPR/CR move | 5 | ✅ mfspr/mtspr (with XER pack/unpack)/mfcr/mtcrf/mftb |
| FP double arithmetic | 6 | ✅ fadd/fsub/fmul/fdiv/fmadd/fmsub/fnmadd/fnmsub |
| FP single arithmetic | 9 | ✅ fadds/fsubs/fmuls/fdivs/fmadds/fmsubs/fnmadds/fnmsubs/fres |
| FP move/convert | 7 | ✅ fmr/fneg/fabs/fnabs/frsp/fctiw/fctiwz/fsel/frsqrte |
| FP compare | 2 | ✅ fcmpu/fcmpo |
| FPSCR | 5 | ✅ mffs/mtfsf/mtfsfi/mtfsb0/mtfsb1/mcrfs — syncs ARM64 FPCR rounding |
| AltiVec (NEON) | 140 | ✅ Full VMX via AArch64 NEON intrinsics |
| Cache/Sync/NOP | 8 | ✅ dcbf/dcbst/dcbt/dcbtst/dcba/icbi/isync/sync/eieio |
| System | 4 | ✅ sc/mfmsr/eciwx/ecowx (terminators/NOPs) |
| **Total** | **285** | **+ all record forms (. suffix)** |

### FPU Coverage

| Feature | Status |
|---------|--------|
| Double-precision arithmetic | ✅ fadd/fsub/fmul/fdiv/fmadd/fmsub/fnmadd/fnmsub |
| Single-precision (round-to-single) | ✅ fadds/fsubs/fmuls/fdivs/fmadds/fmsubs/fnmadds/fnmsubs/fres |
| FP move/convert | ✅ fmr/fneg/fabs/fnabs/frsp/fctiw/fctiwz/fsel/frsqrte |
| FP compare → CR | ✅ fcmpu/fcmpo with XER[SO] |
| FPSCR rounding modes | ✅ PPC RN → ARM64 FPCR RMode mapping (nearest/zero/+inf/-inf) |
| FP load/store | ✅ lfs (single→double)/lfd/stfs (double→single)/stfd + indexed |
| FP exceptions | ⚠️ Not tracked (ARM64 defaults match PPC defaults) |

### XER (Carry/Overflow) Implementation

XER is a struct `{uint8 so, ov, ca, byte_count}` — NOT a packed uint32.
All JIT access uses byte-level LDRB/STRB at individual field offsets:
- `emit_read_xer_ca()`: LDRB from offset 902
- `emit_write_xer_ca_from_carry()`: CSET CS + STRB
- `emit_read_xer_so()`: LDRB from offset 900
- `mfspr XER`: packs 4 bytes → PPC 32-bit format
- `mtspr XER`: unpacks PPC format → 4 individual bytes

---

## BasiliskII 68K JIT

**Build:** ✅
**Interpreter:** ✅ Boots Mac OS 7.x, idle loop reached
**JIT optlev=0:** ✅ Full boot, zero SEGVs
**JIT optlev=2:** ✅ Full boot, zero SEGVs (mid-block branch side-exit fix applied)
**JIT harness:** ✅ 301/301 vectors pass (score=100)

See `BasiliskII/src/uae_cpu_2021/compiler/` for the 68K → AArch64 JIT.

### Test Harness (68K)

**301 total vectors, all risky, score=100**

### Recent bug fixes (2026-05)

- **Mid-block branch side-exit** (`daea9c94`): the side-exit code was placed immediately after
  the conditional branch with no skip over it for the traced-path fallthrough — both branch
  outcomes executed the side-exit path, corrupting guest PC state. Fix: invert the guard
  condition to skip over the side-exit for the traced path.
- **Stable ROM JIT edge profiling** (`6856d894`): fresh ROM blocks now use a bounded
  first-generation countdown so edge summaries can be committed on subsequent rebuilds.
  Previously all ROM blocks compiled at max opt-level with `bi->count = -2` skipped the
  recompile/profiling path entirely.

| Category | Opcodes Tested |
|----------|---------------|
| Data movement | MOVE (B/W/L), MOVEA, MOVEQ, MOVEM, MOVEP, MOVE16, LEA, PEA, EXG, SWAP, LINK/UNLK |
| Arithmetic | ADD/SUB/CMP (B/W/L + imm + quick + addr), ADDA/SUBA/CMPA, ADDX/SUBX, NEG/NEGX, CLR, MUL, DIV |
| Logic | AND/OR/EOR/NOT, TST |
| Shift/Rotate | ASL/ASR/LSL/LSR/ROL/ROR/ROXL/ROXR (all sizes, all variants) |
| Bit ops | BTST/BSET/BCLR/BCHG, bit fields (BFTST-BFINS) |
| BCD | ABCD/SBCD/NBCD, PACK/UNPK |
| Branch | Bcc, BSR/JSR, DBcc, Scc |
| SR/CCR | MOVE to/from SR, ORI/ANDI/EORI to SR/CCR, RTR |
| Control | MOVEC, MOVES, CINVA, CPUSHA |

## Platform Notes — AArch64 Linux

### ASLR and Fixed-Address Memory Mapping

BasiliskII uses fixed-address `mmap()` calls to place emulated Mac hardware
regions at specific virtual addresses:

| Region | Host Address Range | Mac Address | Purpose |
|--------|-------------------|-------------|---------|
| RAM | `0x10000000` | `0x00000000` | Main memory (16MB) |
| ROM | `0x11000000` | `0x01000000` | Quadra 800 ROM (1MB) |
| I/O | `0x60000000–0x6F000000` | `0x50000000–0x5F000000` | Hardware registers |
| NuBus | `0x100000000–0x110000000` | `0xF0000000–0x100000000` | NuBus slots |
| NuBus-lo | `0x0A815000–0x0FFFFFFF` | `0x0A815000–0x0FFFFFFF` | NuBus low (slot space) |
| Frame buffer | `0x12010000` | via `MacFrameBaseMac` | Video memory |

On AArch64 Linux with ASLR enabled, shared libraries, the heap, and anonymous
mappings can land anywhere in the 48-bit virtual address space. This causes
**random collisions** with BasiliskII's fixed-address regions — particularly
the NuBus-lo range (`0x0A–0x10`), which overlaps with common ASLR placement
for shared libraries on aarch64.

**Symptoms:**
- `MEM: NuBus-lo mprotect failed: Cannot allocate memory`
- Silent `SIGSEGV` on startup
- Intermittent failures (~30% of launches)

**Fix (commit `5d9637d9`):**

BasiliskII now self-disables ASLR at startup using the Linux `personality()`
system call:

```c
#include <sys/personality.h>

int pers = personality(0xffffffff);       // query current personality
if (!(pers & ADDR_NO_RANDOMIZE)) {
    personality(pers | ADDR_NO_RANDOMIZE); // disable ASLR
    execvp(argv[0], argv);                 // re-exec with new personality
}
```

This is the same technique used by QEMU, Wine, and other emulators that
depend on fixed-address memory mappings. The re-exec happens before any
other initialization, so there's no visible effect — the process simply
restarts itself once with ASLR disabled.

**Impact:** The JIT test harness (301 vectors × 2 runs each = 602 emulator
launches) previously saw ~30% failure rate from address collisions. With the
fix, it achieves **100% reliability without external wrappers** like
`setarch -R`.
