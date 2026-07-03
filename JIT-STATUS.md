# MacEmu AArch64 JIT — Status

## SheepShaver PPC JIT (2026-05-17)

**Build:** ✅
**Interpreter:** ✅ Boots Mac OS to desktop (VNC port 5999, ~324 MIPS on Orange Pi 6 Plus)
**JIT boot:** ✅ Boots to "Welcome to Mac OS" splash screen with JIT active
**JIT harness:** ✅ 209/209 opcode vectors pass (score=100)
**ROM harness:** ✅ 1800/1825 ROM blocks pass (98.6%) on 10K-block scan
**Tight-loop benchmark:** ✅ ~737 MIPS (addi+bdnz 100M, intra-block CBNZ, Orange Pi 6 Plus)
**Regression harness:** ✅ 13/13 Rc=1 + rld* regression vectors pass (`ss-record-regression.sh`)

### JIT Boot Status

With JIT active, SheepShaver boots Mac OS to the Welcome splash screen.
Block cache and chaining are active; lazy CR0 has been re-enabled with a stable callee-saved pending-result copy, and register allocation is active only for straight-line non-faultable blocks:
1. **Phase 1:** Hash + chaining block cache (8192 buckets)
2. **Phase 2:** Lazy CR0 flags active again: Rc=1 results are copied to x19 and materialized on CR consumers/block exits
3. **Phase 3:** Register allocation active conservatively for straight-line non-memory blocks; path-sensitive/faultable blocks still use direct struct LDR/STR
4. **Phase 4a:** Fast JIT dispatch inner loop (`a8afdf92`)
5. **Phase 4b:** Compile-time block chaining — `chain_code` entry points (`4bcd9336`)
6. **Phase 4c:** Runtime back-patching — chain site pool, `patch_chain_sites` on insert (`e1f11657`)
7. **Phase 4d:** `rld*` correctness — rldicl/rldicr/rldic masks; rldcl/rldcr ROL; sub-opcode SH[5] decode (`8ad71eed`, `77004daa`)
8. **Phase 4e:** Rc=1 CR0 audit — rlwinm./rlwimi./cntlzw./extsh./extsb./mullw./mulhw./mulhwu./divw. all fixed (`10e8f719`)
9. **Phase 4f:** `rld*` sub-decode fix, dead mask code fix, `rldimi` implemented (`77004daa`, `de8b850a`)

Historical MacBench results from the optimization tranche: CPU 835, FPU 1027.
Tight-loop benchmark (after Phase 4b): ~737 MIPS (intra-block CBNZ).
Latest targeted timing after lazy CR0 re-enable: Rc=1 1B loop improved from a warmed immediate-CR0 baseline of ~2.84s to ~2.39–2.63s; the earlier cold baseline was ~5.97s.

### ROM Harness

Standalone headless tool: `SheepShaver/rom-harness/`

Loads the Mac ROM, scans for PPC basic blocks, JIT-compiles each,
compares against a built-in reference interpreter. No display, no
hardware, no SheepShaver runtime dependencies.

**Score: 1800/1825 (98.6%)** on PowerMac 9500 OldWorld ROM (10K-block scan).

Remaining 25 failures: CR field interactions in multi-instruction blocks
and complex branch BO patterns (CTR+condition combo).

### Recent bug fixes / optimization repairs (2026-06)

- **Lazy CR0 re-enabled safely** (2026-06-13): Rc=1 handlers now copy the result to x19
  (`RCR0`, callee-saved) and defer CR0 materialization until a CR consumer or block exit.
  This avoids the earlier boot-hang class where the pending result lived in a scratch register
  that later code clobbered.
- **Conservative register allocation re-enabled** (2026-06-13): the x21–x28 GPR cache is now
  used only for straight-line, non-faultable blocks. Blocks with conditional branches or
  guest-memory accesses stay on direct struct LDR/STR until per-label/per-fault RA state is
  implemented.

### Recent bug fixes (2026-05)

- **Privileged/trap fallback masking** (2026-05-17): unknown `mfspr`/`mtspr` cases and
  immediate trap opcodes (`tdi`/`twi`) were compiled as harmless zero/NOP behaviour. They now
  return `false` so interpreter/privileged semantics are preserved instead of hidden by the JIT.
- **Gate 2 comment drift** (2026-05-17): `ppc-cpu.cpp` still intentionally requires
  `jblk.complete`, but comments claimed the gate had been removed. The comment now matches
  the actual containment contract: incomplete compile probes are skipped and interpreted.
- **Fallback-only JIT terminators** (2026-05-17): `lswx`/`stswx`, `tw`, and `sc` emitted
  an epilogue at their own PC but still returned `true` from `compile_one()`, allowing the
  containing block to be marked complete and cached as a self-returning native block. These
  now return `false` so compilation truncates cleanly and the interpreter executes the
  fallback-only instruction.
- **SS_TEST cleanup crash** (2026-05-17): opcode-test RAM is allocated with `mmap()` but was
  released with `free()`, causing the recurring harness `Segmentation fault` noise after
  successful `REGDUMP`s. The test path now uses `munmap()`.
- **`bclr`/`bclrl` BO semantics** (2026-05-17): `bclrl` wrote LR before reading the branch
  target, so it branched to `pc+4` instead of the old LR. Conditional `bclr` also ignored
  CTR-decrement/test BO forms such as `bdnzlr`. The handler now computes full BO decision
  state (CTR and CR condition), preserves old LR as the taken target, and applies LK after
  target capture.
- **AltiVec unknown-op fallback masking** (2026-05-17): the secondary VAO switch defaulted to
  `return true`, silently treating unknown/unimplemented AltiVec encodings as compiled NOPs.
  It now returns `false` so the block stops/falls back instead of hiding missing semantics.
- **JIT chain-site refresh** (2026-05-17): refreshed block-cache entries now call
  `patch_chain_sites()` so epilogues recorded while a target was unavailable can be satisfied
  even when an existing cache entry is updated.
- **AArch64 64-bit temp-register clobbers** (2026-05-16): `emit_load_gpr64()` used the opposite
  low temp as its implicit high-word scratch, so loading a second 64-bit operand into `RTMP1`
  clobbered the first operand in `RTMP0`. Added explicit-scratch 64-bit loads and fixed `mulld`,
  `mulhdu`, `mulhd`, `divdu`, and `divd`. The same scratch rule also clobbered effective
  addresses for `stdx`/`stdux`/`stdcx.`, DS-form `std`/`stdu`, and `lq`; those paths now save
  EA in `RTMP2` before helper calls that overwrite `RTMP0`.
- **D-form store absolute addressing** (2026-05-16): `stw`, `stb`, `sth`, `stfs`, and `stfd`
  loaded `rA` directly, treating `rA==0` as GPR0 instead of PPC absolute-addressing base zero.
  These paths now use `emit_load_ea_base()` like the load handlers.
- **`rldimi` high-word preservation** (2026-05-16): the native insert path loaded only the low
  32 bits of `rA` to avoid clobbering the rotated source. It now reloads the full split 64-bit
  `rA` with an explicit scratch and reloads the mask before `BIC`.
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

### Opcode Census — 285+ Unique PPC Opcodes Inlined as ARM64

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
**JIT optlev=2:** ⚠️ Full-JIT default. The historical `040ba0xx` late-ROM spin is **FIXED (2026-06-22)** — see below. With three fixes (lazy-cache-flush staleness + cache-tag aliasing + dispatcher-diagnostic gating) the all-native boot clears the NuBus/Slot-Manager frontier and the `040026f8` aliasing frontier, and prints video-init markers (`VideoDriverOpen` → `SetEntries` → `SetGamma`). The `0402e8d0` slot-ROM `bfextu` blit freeze is **FIXED (2026-06-23, `8195ebc9`)**: it lived specifically in the **optlev-0 interpreter warm-up** (`exec_nostats`) path — itself an interpreter fallback the goal forbids. `optcount[0]` set `10→0` (translate on first execution, never whole-block-interpret); jit-test `302/302 fail_equiv=0`, boot advances past `0402e8d0` (d5→0). **Fixes (8195ebc9 + 18c78439):** optcount[0]=0 (eliminate optlev-0 interp warm-up; fixes 0402e8d0) and SPCFLAG_JIT_EXEC_RETURN cleared at any nesting depth (fixes the 04087926 nested-flush do_nothing spin). Boot now advances through video init + InitAll + SCSIReset. **Current frontier:** late video/resource state remains wrong; full-JIT still reaches `SetEntries table=04002478 count=1` instead of the interpreter's `SetEntries table=000b8a48 count=255` + `GetVideoParameters`. Desktop not yet reached.
**JIT harness:** ✅ 318/318 vectors pass (score=100) on the current AArch64 harness. Note: the harness can spuriously fail (`INFRA missing REGDUMP`) under concurrent shared-box load from timeouts; individual vectors still pass.

#### `040ba0xx` ROOT CAUSE (2026-06-22) — LAZY translation-cache invalidation reused STALE blocks (FIXED)

The `040ba0xx` spin was **NOT** a resource-map `d0` corruption (that earlier hypothesis was disproven 2026-06-22 by interp ground-truth: the `0x0401beb4` offset-shift loop matches the interpreter exactly). The real cause: **lazy translation-cache invalidation (`jitlazyflush=true`) reuses STALE compiled blocks.** Early-boot driver/Slot-Manager init reuses RAM buffers across `_BlockMove`/`FlushCodeCache` cache flushes; the lazy soft-flush (mark `BI_NEED_CHECK` + checksum-reactivate) wrongly reuses an out-of-range stale block (old driver code) → a different driver list (`a1=0000cdc0` vs interp `0000bd00`) → the JIT walks the legit slot declaration ROM (`LowMem 0x824`=`0x05010000`) into the no-exit NuBus slot scanner (`040023xx`→`0400246e`→`040b9874`→the `040b98f2`↔`040ba0xx` SCC poll) — which the interpreter never enters. **Fix:** `jitlazyflush` default → `false` (eager `flush_icache_hard`), forcing recompile so no stale block runs; boot clears NuBus. Verified: NuBus spin gone; jit-test `fail_equiv=0` (no correctness regression). Both modes are 100% JIT (no interpreter fallback). Full campaign analysis (CONT.58–73) in `notes/macemu-jit-io-rootcause.md`. **Second fix (6596f558):** the `040026f8` frontier was cache-tag aliasing (TAGMASK `0xffff` too small for 64MB RAM → distant guest PCs collide in `cache_tags` → wrong block via unchecked direct-linked jumps); enlarged TAGMASK → `0x3ffff` (4x tags). **Third fix (fd4c48fe) — diagnostic hygiene only, NOT a boot advance:** the JIT dispatch loop carried an unconditional per-dispatch `JIT_ENTRY` fprintf + a large DC diagnostic block (committed, default-on); gating them behind `B2_JIT_DIAG` (default off) is correct hygiene (multi-GB stderr otherwise). **CORRECTION (CONT.78):** the commit message's claim that this "fixes the spurious 0402e8d0 spin / advances to video init" was WRONG and is retracted. gdb on the default (diag-off, sync-tick) binary shows the boot still freezes at the `0402e8d0` bfextu loop (`D5=3` stable). The earlier "diagnostic artifact" reading was itself a perturbation misread: the per-call BFX trace I added (capped at 120) let the *traced* passes complete and hid the later frozen pass. **Open frontier:** `0402e8d0` is a real, perturbation-sensitive (CONT.61-class) freeze — the bfextu blit block re-dispatches at its own entry with `d5`/`d6` pinned after one iteration; candidate mechanism is the `subq #1,d5` result not persisting across the block-end re-dispatch due to the mid-block bfextu-fallback `flush(1)`/`was_comp` register-cache interaction.

See `BasiliskII/src/uae_cpu_2026/compiler/` for the 68K → AArch64 JIT.

### BasiliskII performance/QA status

The active post-correctness performance goal is to pursue a measured 2× JIT throughput improvement and lower host CPU load. Treat `980a0451` as the correctness baseline: performance changes must preserve the 301/301 opcode harness and the strict ROM marker contract. Initial performance experiments found that 32768KB cache runs repeatedly hit hard translation-cache flushes, so the harness/default QA cache is raised to 131072KB. Reducing the dispatch `DC[...]` heartbeat or enabling stable-edge direct chaining can change timing enough to expose `SEGV_SKIP`/fallback marker regressions in some ROM windows, so those are not default optimizations yet. Real desktop/VNC captures are still required before claiming GUI CPU-load improvements.

BasiliskII now has a repository-visible end-to-end QA scaffold in `BasiliskII/qa/` plus shared emulator-neutral VNC story tooling in `qa/tests/vnc/`. The intended post-JIT validation path is:

1. `jit-test/run.sh` opcode/vector preflight (`301/301`, score 100).
2. `jit-test/rom-harness.sh` / `BasiliskII/qa/scripts/run-matrix.sh` ROM smoke.
3. VNC/Xvfb desktop reachability with a known-good System 7 disk.
4. Deterministic screenshot assertions in CI: PNG metrics, non-blank checks, hashes, optional Tesseract OCR, optional OpenCV templates.
5. Hardware coverage evidence for safe user-mode networking (`ether slirp` first), dummy/real audio, disk persistence, PRAM/time, display modes, and optional CD/extfs/clipboard assets.
6. Markdown and PDF reports generated from run artifacts.

The shared VNC runner currently defaults to the `noop` driver so both BasiliskII and SheepShaver profiles can validate user stories and reporting in CI without requiring a live desktop. A real VNC capture/input backend is the next automation gap.

### Test Harness (68K)

**301 total vectors, all risky, score=100**

### Recent bug fixes (2026-07)

- **ARM64 Bcc mid-block side exits use M68K-aware condition emission** (2026-07-03):
  the block-link verifier and non-perturbing watchpoints pinned a real control divergence in
  the ROM resource-type lookup block `04016cb0`: the block containing `04016d00: BLS`
  side-exited to the found path (`04016d08`) when the interpreter stayed on the not-found
  path. The end-of-block Bcc emitter already routes `HI/LS` through `compemu_raw_jcc_l_oponly`,
  which handles the JIT's M68K carry convention; the mid-block side-exit emitter used raw
  ARM `CC_B_i`, which is wrong for composite unsigned `HI/LS` conditions. Reusing
  `compemu_raw_jcc_l_oponly` for side-exit skip branches fixes the resource-list growth
  truncation: default L2 now grows the Resource Manager type-list backing store from
  `d858=0x60` to `d858=0x130`, matching the interpreter-growth sequence. Verified:
  `04016cb0` verifier `SKIP-NOREACH` control failure is cleared, `d858` hardware watchpoint
  reaches `0x130`, and `jit-test/run.sh` passes `318/318`, `fail_equiv=0`,
  `risky_fail_equiv=0`. This is still not boot-through: the final full-JIT video state remains
  `SetEntries table=04002478 count=1` (patched run raises the resource map count but remains
  short of the interpreter's `0x50` entries).

- **ARM64 scratch-vreg range for generated 5-scratch bit-op handlers** (2026-07-03):
  generated immediate memory bit-op handlers such as `BTST.B #7,(d8,An,Xn)` can allocate
  five compiler scratch virtual registers (`S1..S5`). ARM64 had only defined `S1..S3`
  (`VREGS=22`), so `S4/S5` were out-of-range virtual registers and bypassed the guarded
  allocator path. Defining `S4/S5` and raising `VREGS/SCRATCH_REGS` routes those temporaries
  through the normal skip-locked/spill-before-reuse allocator. Verified: `0403c02c`
  block verifier now reports `mismatch=0`; `jit-test/run.sh` passes `318/318`,
  `fail_equiv=0`, `risky_fail_equiv=0`. This is a correctness fix, not a boot-through claim:
  full-JIT still reaches the later bad video/resource state (`SetEntries table=04002478 count=1`).

### Recent bug fixes (2026-06)

- **Full-JIT strict boot/soak** (2026-06-13): invalid opcode trap slots now use a native helper
  barrier instead of the interpreter fallback path, AArch64 direct FPU indexed memory helpers
  zero-extend 32-bit guest addresses, NuBus super-slot probes are mapped and filled with the
  empty-slot `0xFF` bus value, and translation-cache exhaustion now performs a hard cache reset
  instead of lazily continuing past the high ARM64 mmap. The strict preserved-log run
  `/workspace/tmp/basiliskii-fulljit-validation/20260613T074106Z-strict-defaultmaxrun-300s`
  reached `DC[64460000] pc=00156f94` with zero fallback/SEGV/verifier/bad-PC markers.

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
