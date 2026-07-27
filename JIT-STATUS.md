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

**Current structural-audit gate (2026-07-19):** ✅
**Build and generator:** ✅ clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build; generated `compemu.cpp` is byte-reproducible at SHA-256 `90b3064253b7d2894cd9ecaed738687ba6b2ff7aec5ec75586afa212db7dd1ee`
**JIT harness:** ✅ 904/904 active-risky vectors, `fail_equiv=0`, `infra_fail=0`, score 100
**Allocator pressure:** ✅ 33/33 complete cells, including permanent NOT and SUBA collision witnesses
**Strict L2 policy:** ✅ fail-closed negative probes pass; runtime reports `opt0=0 fallback=0 exec_nostats=0`
**Opcode registration:** ✅ all 48,282 legal 68040 encodings classified, with zero null/interpreter fallback in byte-identical ordinary and strict tables: 46,087 native-generated, 2,127 semantic services, and 68 architectural traps.
**Finder retirement gate:** ✅ ordinary and strict runs each reached 21 `DiskStatus 43` events and captured 24,120,000 scheduled guest retirements. Their retained 16,777,216-PC windows are byte-identical (`SHA-256 1a05d539dc51f4fa39cd2cc02e5e7c90faeedcab054ab6b4d156d8022db06b73`), with no host signal.

This gate was run host-native on the Orange Pi 6 Plus (`CIX P1`/`CD8180` or `CD8160`, 12 AArch64 CPU cores, 16 GB-class RAM with about 14 GiB visible, Debian Trixie, NVMe root storage). It covers structural opcode-family repairs, helper and exception boundaries, guest-memory coherency, translated-source revalidation, cache-state separation, retirement-clock ownership, register-allocation pressure, and partial JIT initialization/teardown. `MV2SR.W` intentionally remains on its exact legacy semantic-service path pending stronger native proof.

The older frontier narrative below is retained as historical diagnosis; it no longer describes the acceptance frontier of the structural-audit branch.

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

**904 active-risky vectors and 33 allocator-pressure cells, score=100**

The larger exact-native family inventories remain available as focused gates;
the current `OR` inventory is 37/37, the `EOR` inventory is 28/28, the `AND`
inventory is 34/34, the `ADD` inventory is 34/34, the accepted `ROL`/`ROR`
inventory is 92/92, and the accepted register-count
`ASL`/`ASR`/`LSL`/`LSR` inventory is 138/138.

### Recent bug fixes (2026-07)

- **Audit `mov_b_ri` byte-lane constant lifecycle on AArch64** (2026-07-27):
  all eleven configured calls are zero staging in flag-live MOVE.B-to-Dn
  lowering, one per readable source EA. Architectural registers preserve upper
  bits through constant merge or `rmw+BFI`; scratch vregs become exact masked
  constants, and MOVE composition owns flags separately. A **2 focused + 12
  source/destination-EA + 1 pressure** strict-native control proves both
  allocator states and the forced source/destination collision. The 998-row
  inventory promotes only `mov_b_ri`. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_MOV_B_RI_LIFECYCLE.md`.

- **Retire the host-`pow` FTWOTOX chain on AArch64** (2026-07-27): the sole
  retained `ftwotox_rr -> fpowx_rr(2,...)` source root lies after selector
  `0x11`'s unconditional exact-MPFR service return and cannot acquire an
  operand. `raw_fpowx_rr` is consequently definition-only. An **8 service + 1
  strict** focused control covers precision, infinity, NaN, range, and alias
  cases from the accepted 49+4 transcendental matrix. The 998-row inventory
  moves exactly the MIDFUNC/raw pair to unreachable. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPOWX_UNREACHABLE.md`.

- **Retire the legacy binary64 guest-address load chain on AArch64**
  (2026-07-26): configured preprocessing retains only the
  `fp_to_double_rm` extern; no generated, support, compatibility, FPP, or
  reachable MIDFUNC caller exists, so `raw_fp_to_double_rm` is definition-only.
  The live ordinary binary64 import remains the already audited ordered guest
  read and `fmov_rm -> raw_fmov_d_rm` path. A **10/10 strict exact-native**
  sibling control covers all maintained double-source EAs. The 998-row
  inventory moves exactly these two rows to unreachable. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FP_TO_DOUBLE_RM_UNREACHABLE.md`.

- **Retire the legacy extended-memory conversion chains on AArch64**
  (2026-07-26): configured preprocessing retains one ordinary and two static
  FMOVEM compositions in each direction beneath exact MPFR service gates.
  Ordinary FMOVE.X rejects before EA acquisition, static FMOVEM returns before
  `get_fp_ad`, dynamic FMOVEM exits still earlier, and the four FMOVECR
  long-double spellings are absent from the configured build and dominated by
  selector-level service in raw source. `fp_from_exten_mr`, `fp_to_exten_rm`,
  and both raw boundaries are therefore unreachable. A **30 service + 10
  strict** composite control covers ordinary extended FMOVE and static/dynamic
  FMOVEM. The 998-row inventory moves exactly these four rows to unreachable.
  See `BasiliskII/docs/AARCH64_JIT_AUDIT_FP_EXTENDED_MEMORY_UNREACHABLE.md`.

- **Retire the legacy binary64 host-memory store chain on AArch64**
  (2026-07-26): configured preprocessing retains only the
  `fp_from_double_mr` extern. Its sole raw `fmov_mr` source call is confined to
  the inactive non-AArch64 arm of `put_fp_value(size=5)`, while configured
  ordinary-double destinations enter exact MPFR service before that helper.
  `raw_fp_from_double_mr` is consequently definition-only. A **28 service + 3
  strict** control proves the live configured boundary. The 998-row inventory
  moves exactly these two rows to unreachable. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FP_FROM_DOUBLE_MR_UNREACHABLE.md`.

- **Audit integer allocator discard lifecycle** (2026-07-26): closes the
  `forget_about` MIDFUNC by classifying all **304 source references** rather
  than relying on token reachability. The caller set is exactly 299 generated
  private-vreg calls: 124 active MOVEA/ADDA/MOVE16 discards and 175 dormant
  OR/AND/EOR/MOVE/NOT lane-helper calls behind AArch64's hard-false
  `kill_rodent()` policy. Of four support source calls, three active sites own
  opcode-boundary sweep or post-store clobber and dormant `release_scratch()`
  owns only validated S1-S5 IDs; the final reference is the definition. The
  complete split is **127 active / 176 dormant / one definition**. Structural checks
  pin clean-before-evict, `UNDEF`, locked-hold failure, the active/dormant
  policy, exact family/operand counts, and absence of architectural operands. A
  **39 active + 1 dormant-policy** strict-native composite control covers every
  caller class. The 998-row inventory promotes
  only `forget_about`. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FORGET_ABOUT.md`.

- **Retire the legacy `fmovs_rm` single-memory chain on AArch64** (2026-07-26):
  both retained source calls are in inactive non-AArch64 `#else` arms; the
  configured direct and fetched single-source paths use the accepted
  `fmov_s_rr` / `raw_fmov_s_rr` chain. The old raw boundary is definition-only.
  An **18/18 strict exact-native** live-replacement control covers both roots and
  all maintained EA classes. The 998-row inventory moves exactly `fmovs_rm` and
  `raw_fmovs_rm` to unreachable without reclassifying `LDR_sXi` or `FCVT_ds`.
  See `BasiliskII/docs/AARCH64_JIT_AUDIT_FMOVS_RM_UNREACHABLE.md`.

- **Audit the live binary32 destination lifecycle** (2026-07-26): closes
  `fmov_to_s_rr` and `raw_fmov_to_s_rr` across exactly two configured roots:
  direct Dn and writable-memory scratch. A **30/30 strict exact-native** gate
  covers all FPCR modes, normal/subnormal/range edges, signed specials and NaN
  payloads, FPSR replacement/accrual, NZCV and host FP state, Dn, basic
  writeback, d16/indexed, and absolute EAs. The 998-row inventory promotes
  exactly these two rows; generic `FCVT_sd` and `FMOV_ws` remain separately
  audited. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FMOV_TO_S_RR_LIFECYCLE.md`.

- **Retire the dead split-double destination chain** (2026-07-26): the sole
  retained `fmov_to_d_rrr` call is inside `put_fp_value(size=5)`, but every
  configured AArch64 ordinary-double destination enters exact MPFR service and
  returns before `put_fp_value()`, EA acquisition, or native dispatch. The
  shared `raw_fmov_to_d_rrr` boundary is therefore definition-only. A **28
  service + 3 strict** control proves the exact conversion boundary and
  pre-native rejection. The 998-row inventory moves exactly these two rows to
  unreachable; live `FMOV_xd` and `LSR_xxi` emitters remain independently
  classified. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FMOV_TO_D_RRR_UNREACHABLE.md`.

- **Audit the live FP-to-signed-integer destination lifecycle** (2026-07-26):
  closes `fmov_to_{b,w,l}_rr` and `raw_fmov_to_{b,w,l}_rr` as one shared
  implementation unit. Exactly two configured roots per width cover Dn and
  writable-memory destinations. The **54/54 exact-native** matrix proves all
  three widths, byte/word upper-lane preservation, four FPCR rounding modes,
  signed limits and saturation, NaN/infinity sign policy, FPSR replacement and
  accrual, NZCV preservation, basic and extended EA/writeback classes, guarded
  stores, maximum fields, and the all-integer-registers-live pressure route.
  No production repair was required beyond the accepted ordinary-FMOVE
  destination implementation. The deterministic 998-row inventory promotes
  exactly three MIDFUNC and three raw-boundary rows; binary32, double-split, and
  generic emitter contracts remain separately classified. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FMOV_TO_INTEGER_LIFECYCLE.md`.

- **Close the final reachable ordinary integer generator tail** (2026-07-19):
  closes `MULS`, `MULU`, `NOT`, `SUBA`, `SWAP`, and `TST` plus eight directly
  connected reachable MIDFUNC rows with a **32/32 exact-native** strict replay
  matrix. Forced allocator collisions reproduced and repaired two lifecycle
  defects: memory NOT now owns its computed pre-write EA through result flags
  and storage, and SUBA owns its widened source through destination acquisition
  and subtraction. Two permanent pressure cells pass with exact native and
  interpreter parity. Fail-closed structure pins the complete generated
  provider census and keeps twelve namesake NOT/SUBA/SWAP MIDFUNCs unreachable.
  The 998-row inventory promotes exactly six generators and eight MIDFUNCs;
  generic/shared lower layers remain independent. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_INTEGER_TAIL_LIFECYCLES.md`.

- **Retire configured-unreachable MMU generator labels** (2026-07-19): the
  BasiliskII Unix AArch64 build has no opcode definition, generated compiler
  body, or registration slot for `MMUOP030`, `PFLUSH*`, `PLP*`, `PTEST*`,
  `LPSTOP`, or historical ARAnyM `MMUOP`. Fail-closed configured-root checks
  classify exactly eleven generator rows as unreachable. This does not
  implement FULLMMU/MMU or promote any semantic/lower-layer contract; NeXT MMU
  work remains with Previous. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_MMU_UNREACHABLE.md`.

- **Audit and repair the configured AArch64 control/address generator lifecycle**
  (2026-07-19): closes `NOP`, `RTD`, `LINK`, `UNLK`, `RTR`, `JSR`, `JMP`,
  `LEA`, and `PEA` through a **15/15 exact-native** strict replay matrix. Three
  reproduced alias defects are repaired: `LINK A7` now separates its stack
  address and pushed frame value, `UNLK A7` lets the popped longword win after
  postincrement, and `JSR (A7)` snapshots and locks its target before the return
  push. Both generated flag tables and every legal control EA are pinned; shared
  memory/allocator/branch APIs and serviced `RTS`/`BSR` remain independent. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_CONTROL_ADDRESS_LIFECYCLE.md`.

- **Audit and repair the configured AArch64 `i_FScc` lifecycle** (2026-07-18):
  reproduced two native fidelity defects: FScc published temporary `FCMP` NZCV
  as integer CCR, and its inherited x86 CMOV table inverted AArch64 ordered
  relations. The repaired route preserves full `XNZVC`, dispatches through the
  complete sixteen-entry FP pseudo-condition lowerer, preserves the upper 24
  destination bits, rejects illegal conditions before native mutation, and
  services writable-memory forms with exact EA/writeback semantics. The
  fail-closed matrix passes **326/326**: five FPSR classes × 32 defined
  encodings × D0/D7 (**320 exact-native**), four memory-service forms, and two
  strict negative probes. This supersedes the earlier graph-only FScc retirement and
  promotes exactly `i_FScc`, `fp_fscc_ri`, `raw_fp_fscc_ri`,
  `CLEAR_LOW8_xx`, and `SET_LOW8_xx`; shared condition/branch APIs remain
  independent. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FSCC_LIFECYCLE.md`.

- **Close the configured AArch64 `i_FPP` generator lifecycle** (2026-07-18):
  reconciles every live top-level form and ordinary operation selector against
  the accepted focused FPP evidence graph. The fail-closed executable census
  proves **8/8 top-level forms**, exact set equality for **61 operation
  selectors** across **22 semantic owners**, and **10 top-level
  FMOVE/FMOVEM/FMOVECR/control owners**; missing or duplicate ownership,
  missing matrix/report pairs, and new unowned source selectors reject. The
  accepted integration epoch is **904/904**, allocator pressure **31/31**, and
  the strict negative contract passes. Exactly `generator,i_FPP` becomes
  audited; compound MIDFUNC/raw and generic emitter rows remain independently
  classified. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_LIFECYCLE.md`.

- **Audit the AArch64 FMOVE signed-integer source lifecycle** (2026-07-18):
  closes the byte/word/long `fmov_*_rr` MIDFUNC/raw pairs across exact two-root
  Dn/fetched reachability, 32-bit sign extension, `SCVTF_dw` conversion,
  allocator lifetime, and same-number maximum fields. The new fail-closed
  `GROUP=integer` matrix passes **18/18** and the full source owner remains
  **29/29**; invalid groups reject. Exactly six rows become audited. Shared
  `SCVTF_dw` retains its independent audit, while SXTB/SXTH/SBFM and
  `generator,i_FPP` remain separate/unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FMOVE_INTEGER_SOURCE.md`.

- **Retire the definition-only legacy AArch64 FScc raw chain and residual
  low-byte emitters** (2026-07-18; historical, superseded by the complete FScc
  lifecycle audit above): configured `i_FScc` uses the distinct
  `comp_fscc_opp` CMOV route, while `fp_fscc_ri` has no configured caller and
  `raw_fp_fscc_ri` is definition-only. Exact 15-condition switch and global
  13/10 clear/set partition checks—11/10 in dead FScc plus two clear sites in
  unreachable CLR namesakes—classify the raw wrapper plus `CLEAR_LOW8_xx` and
  `SET_LOW8_xx` **unreachable**. The live `i_FScc` generator and shared
  `CSETM_wc`/`BFXIL_xxii` APIs remain **unreviewed**; the passing
  `fscc_false_byte` vector is only a live-route smoke check, not FScc semantic
  closure. This is a three-row graph correction. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_LEGACY_FSCC_RAW.md`.

- **Retire the paired serviced AArch64 FMOD/FREM lower chains and their final
  divide/fused-subtract emitters** (2026-07-18): FMOD and FREM enter exact MPFR
  service; `fmod_rr`/`frem1_rr` have no configured callers and
  `raw_fmod_rr`/`raw_frem1_rr` are definition-only. Exact ordered
  divide→round→fused-subtract checks classify both raw wrappers plus retained
  `FDIV_ddd`, `FMSUB_dddd`, `FRINTZ_dd`, and `FRINTA_dd` **unreachable**. The
  repaired FMOD **31+1** and FREM **33+1** matrices pin exact seven-boundary
  two-pass profiles; direct FDIV/FMSUB/FRINT evidence remains historical.
  `FRINTI_dd` alone stays audited/reachable at two sites. This is a six-row
  lower-chain retirement; `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FMOD_BATCH.md` and
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FREM_BATCH.md`.

- **Retire the serviced AArch64 FSGLMUL lower chain and sole binary32 multiply
  emitter** (2026-07-18): FSGLMUL enters exact MPFR service before operand
  acquisition; `fsglmul_rr` has no configured caller and `raw_fsglmul_rr` is
  definition-only. Exact ordered conversion/multiply/widen checks now classify
  the raw wrapper and its sole-site `FMUL_sss` emitter **unreachable**. The
  accepted FSGLMUL **22+1** matrix owns configured runtime fidelity; direct
  `FMUL_sss` evidence remains historical. Binary64 `FMUL_ddd` is already
  unreachable, while shared FCVT emitters stay audited at 7/6. This is a
  two-row lower-chain retirement; `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_SGLMUL_BATCH.md`.

- **Retire the serviced AArch64 FSGLDIV lower chain and sole binary32 divide
  emitter** (2026-07-18): FSGLDIV enters exact MPFR service before operand
  acquisition; `fsgldiv_rr` has no configured caller and `raw_fsgldiv_rr` is
  definition-only. Exact ordered conversion/divide/widen checks now classify
  the raw wrapper and its sole-site `FDIV_sss` emitter **unreachable**. The
  accepted FSGLDIV **23+1** matrix owns configured runtime fidelity; direct
  `FDIV_sss` evidence remains historical. A later paired remainder closure also
  retires all three binary64 `FDIV_ddd` sites, while shared FCVT emitters stay
  audited at 7/6.
  This is a two-row lower-chain retirement; `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_SGLDIV_BATCH.md`.

- **Retire the definition-only AArch64 distinct-destination single-round raw
  wrapper** (2026-07-18): `fmovs_rr` has no configured production root, and
  exact caller/body checks establish that `raw_fmovs_rr` has only its
  `LOWFUNC`/`LENDFUNC` definition with ordered `FCVT_sd`→`FCVT_ds` conversion.
  The raw row is now **unreachable**. Direct FCVT conformance remains **2,048
  words / 256 native conversions / 64 aliases**, and the live ordinary
  single-destination matrix remains **21/21**. Shared `FCVT_sd`/`FCVT_ds` stay
  audited/reachable at exact 7/6 source sites. This is a one-row graph
  correction, not FSMOVE service evidence; `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FCVT_EMITTERS.md`.

- **Repair current ordinary-FMOVE source acceptance and retire the dead
  split-double raw wrapper** (2026-07-18): the former 43-case native matrix
  retained 14 FP-register cases after those routes moved to exact MPFR service.
  The maintained split now passes **29/29 native Dn/immediate** plus **66+3
  serviced register** cases. `fmov_d_rrr` has no configured caller and
  `raw_fmov_d_rrr` has only its definition, so the raw row is now
  **unreachable**, guarded by exact `BFI_xxii`→`FMOV_dx` order and future-caller
  checks. Shared `BFI_xxii` stays unreviewed/reachable and `FMOV_dx` stays
  audited/reachable. This is a one-row graph correction; `i_FPP` remains
  unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FMOVE_SOURCE_SUBTRANCHE.md`.

- **Retire the definition-only AArch64 constant-10/100 raw wrappers**
  (2026-07-18): FMOVECR already enters exact MPFR service before selector
  dispatch. The intermediate `fmov_l_ri` has no configured root, and its
  `fmov_d_ri_10`/`fmov_d_ri_100` children were already unreachable. Exact
  two-level caller/body checks now classify only `raw_fmov_d_ri_10` and
  `raw_fmov_d_ri_100` **unreachable**. The accepted FMOVECR **36+3** matrix owns
  configured runtime fidelity. Shared `FMOV_di`/`SCVTF_dw` remain audited and
  reachable at exact 5/6 source sites; zero/one wrappers remain unchanged. This
  is a two-row raw retirement, and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FMOVECR_SUBTRANCHE.md`.

- **Retire the definition-only AArch64 cut-to-single raw wrapper**
  (2026-07-18): `fcuts_r` was already unreachable after FSMOVE/FDMOVE moved to
  exact MPFR service before operand acquisition. Exact caller/body checks now
  establish that `raw_fcuts_r` has only its `LOWFUNC`/`LENDFUNC` definition and
  classify it **unreachable**. The accepted explicit-move **13+2** matrix owns
  configured runtime fidelity. `FCVT_sd` and `FCVT_ds` remain audited/reachable
  at exact 7/6 source-site counts, so neither shared emitter is retired. This is
  a one-row raw retirement, and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_EXPLICIT_MOVE_SUBTRANCHE.md`.

- **Retire the definition-only AArch64 integral-rounding raw wrappers**
  (2026-07-18): `frndint_rr` and `frndintz_rr` were already unreachable; exact
  caller/body checks now establish that `raw_frndint_rr` and
  `raw_frndintz_rr` are definition-only and classify both **unreachable**.
  The accepted FINT/FINTRZ **55+2** matrix remains configured runtime evidence.
  A later paired remainder closure also retires both retained `FRINTZ_dd` sites
  plus sole-site `FRINTA_dd`; `FRINTI_dd` stays audited/reachable at two sites.
  This is a bounded raw
  retirement, and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_UNARY_DECOMPOSITION_BATCH.md`.

- **Retire the serviced AArch64 divide MIDFUNC/raw chain**
  (2026-07-18): configured control-flow proof confirms both `fdiv_rr` roots—
  FDIV/FSDIV/FDDIV and FSGLDIV—enter exact MPFR service before operand
  acquisition. With no other configured root or MIDFUNC caller, `fdiv_rr` and
  `raw_fdiv_rr` are now **unreachable**, guarded by two-root control-flow,
  exact edge/lower-chain, and future-caller checks. The **37+3** FDIV-family
  and **23+1** FSGLDIV matrices pass with exact variable-length service
  profiles. Later lower-chain closures retire both `FDIV_sss` and all three
  retained `FDIV_ddd` sites after their remaining wrappers also become
  unreachable. This is a bounded MIDFUNC/raw retirement, and `i_FPP`
  remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_DIVIDE_BATCH.md`.

- **Retire the residual AArch64 native binary64 multiply primitive chain**
  (2026-07-18): configured control-flow proof confirms both `fmul_rr` roots—
  FMUL/FSMUL/FDMUL and FSGLMUL—enter exact MPFR service before operand
  acquisition. With no other configured root or MIDFUNC caller, `fmul_rr`,
  `raw_fmul_rr`, and `FMUL_ddd` are now **unreachable**, guarded by two-root
  control-flow, exact edge/lower-chain, and future-caller checks. The prior
  32,768-word/604-route direct binary64 emitter audit remains historical
  evidence; **30+3** FMUL-family and **22+1** FSGLMUL cases own configured
  runtime fidelity with exact variable-length service profiles. A later
  lower-chain audit also retires definition-only `raw_fsglmul_rr` and its
  sole-site `FMUL_sss` emitter. This is retirement rather than native
  acceptance, and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_MUL_BATCH.md`.

- **Retire the residual AArch64 native subtract primitive chain**
  (2026-07-18): configured control-flow proof confirms all FSUB/FSSUB/FDSUB
  selectors enter exact MPFR service before operand acquisition and `fsub_rr`.
  Configured AArch64 FCMP uses `fcompare_result_rr`; its textual legacy
  `fsub_rr` call is inactive. With no other configured root or MIDFUNC caller,
  `fsub_rr`, `raw_fsub_rr`, and `FSUB_ddd` are now **unreachable**, guarded by
  exact branch/root/edge, lower-chain, and future-caller checks. The prior
  32,768-word and 576-route direct emitter audit remains historical evidence;
  the 40 service plus three strict cases own configured runtime fidelity with
  exact variable-length service profiles. This is retirement rather than
  native acceptance, and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_SUB_BATCH.md`.

- **Retire the residual AArch64 native square-root primitive chain**
  (2026-07-18): configured control-flow proof confirms all
  FSQRT/FSSQRT/FDSQRT selectors enter exact MPFR service before operand
  acquisition and `fsqrt_rr`. With no other configured root or MIDFUNC caller,
  `fsqrt_rr`, `raw_fsqrt_rr`, and `FSQRT_dd` are now **unreachable**, guarded
  by exact root/edge, lower-chain, and future-caller checks. The prior 1,024-word
  and 4,096-route direct emitter audit remains historical evidence; the 54
  service plus three strict cases own configured runtime fidelity. This is
  retirement rather than native acceptance, and `i_FPP` remains unreviewed.
  See `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_SQRT_SUBTRANCHE.md`.

- **Audit the then-reachable generic AArch64 FMSUB_dddd emitter API**
  (2026-07-18): all **1,048,576 four-field encodings** plus **400 native
  routes** now pin true fused `Da−Dn×Dm` cancellation, directed rounding,
  signed overflow/underflow, invalid and three-position qNaN/SNaN ownership,
  **208 destination/source aliases**, preload order, and external FP-state
  restoration. Both remainder-helper sites are pinned. A later paired
  lower-chain audit classifies both definition-only wrappers and `FMSUB_dddd`
  unreachable; the direct audit remains historical while FMOD/FREM matrices
  own configured fidelity and `i_FPP` remains unreviewed.
  See `BasiliskII/docs/AARCH64_JIT_AUDIT_FMSUB_EMITTER.md`.

- **Audit the then-reachable generic AArch64 FDIV_ddd/FDIV_sss emitter pair**
  (2026-07-18): separate binary64/binary32 probes close **65,536 encodings**
  and **1,272 native routes**, pinning ±1/3 rounding, signed overflow/
  underflow, DZC/IOC, zero/infinity rules, left/right qNaN/SNaN, full single
  lanes, **584 aliases**, every field, and external FP-state restoration. All
  3/1 retained sites are pinned. Later lower-chain audits classify both emitters
  unreachable; direct evidence remains historical while divide/FSGLDIV/FMOD/
  FREM matrices own configured fidelity and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FDIV_EMITTERS.md`.

- **Audit the then-reachable generic AArch64 FMUL_sss emitter API**
  (2026-07-18): all **32,768 encodings** plus **608 native binary32 routes**
  now pin 24-bit halfway rounding, signed overflow/underflow, IXC/UFC/OFC,
  both zero×infinity IOC orders, left/right qNaN/SNaN, W-lane images,
  **276 aliases**, full-lane clearing, distinct-value Sn==Sm load ownership,
  all S fields, and external FP-state restoration. The sole
  forced-single composition is pinned. A later complete lower-chain audit
  classified its definition-only wrapper and sole-site emitter unreachable;
  this direct audit remains historical evidence, while the 22+1 FSGLMUL matrix
  owns configured runtime fidelity and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FMUL_S_EMITTER.md`.

- **Audit the then-reachable generic AArch64 FMUL_ddd emitter API**
  (2026-07-18): all **32,768 encodings** plus **604 native semantic routes**
  pin halfway-product and directed rounding, signed overflow/underflow,
  IXC/UFC/OFC, zero×infinity IOC, left/right qNaN/SNaN, **272 aliases**, all D
  fields, and FP-state preservation. A later complete two-root audit retired
  the residual binary64 chain and now classifies `FMUL_ddd`, `raw_fmul_rr`, and
  `fmul_rr` unreachable; the direct probe remains historical evidence. A later
  lower-chain audit likewise retires sole-site binary32 `FMUL_sss`; its direct
  probe also remains historical evidence. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FMUL_D_EMITTER.md`.

- **Audit the then-reachable generic AArch64 FSUB_ddd emitter API**
  (2026-07-18): all **32,768 encodings** plus **576 native semantic routes**
  pin operand order, midpoint/overflow rounding, signed cancellation zero,
  infinity-invalid IOC, left/right qNaN/SNaN propagation, IXC/OFC, **256 alias
  routes**, all D fields, and FP-state preservation. A later complete
  configured-root audit retired the sole residual chain and now classifies
  `FSUB_ddd`, `raw_fsub_rr`, and `fsub_rr` unreachable; the direct probe remains
  historical evidence. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FSUB_EMITTER.md`.

- **Audit the then-reachable generic AArch64 FSQRT_dd emitter API**
  (2026-07-18): all **1,024 encodings** and **4,096 native field/mode routes**
  pin directed √2 rounding, exact roots and subnormal-root behavior, signed
  zero, negative-invalid default NaN/IOC, qNaN/SNaN payload handling, IXC,
  **128 aliases**, source/NZCV/FPCR/FPSR preservation, and external
  D8-D15/FP-state restoration. A later complete configured-root audit retired
  the sole residual chain and now classifies `FSQRT_dd`, `raw_fsqrt_rr`, and
  `fsqrt_rr` unreachable; the direct probe remains historical evidence. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FSQRT_EMITTER.md`.

- **Audit the reachable generic AArch64 FMOV_di immediate emitter API**
  (2026-07-18): all **8,192 encodings** and **32,768 native
  destination/immediate/mode routes** now pin the complete 256-value
  `VFPExpandImm` domain, D0-D31, FPCR-mode independence, NZCV/FPCR/FPSR
  preservation, and external D8-D15/FP-state restoration. All five configured
  constant sites are pinned. Only `FMOV_di` is audited; wrappers, compound
  raw/MIDFUNC paths, and `i_FPP` remain unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FMOV_DI_EMITTER.md`.

- **Audit the reachable generic AArch64 FRINTA/FRINTI/FRINTZ emitter cluster**
  (2026-07-18): all **3,072 encodings** and **12,288 native field/mode
  routes** now pin nearest-away, raw-FPCR-current, and toward-zero rounding,
  signed zero, ties and subnormals, qNaN/SNaN quieting and IOC, finite
  non-`X` IXC silence, **384 aliases**, source/NZCV/FPCR/FPSR preservation,
  and external D8-D15/FP-state restoration. All 1/2/2 configured source sites
  are pinned. Only the three FRINT emitter rows are audited; compound
  raw/MIDFUNC paths and `i_FPP` remain unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FRINT_EMITTERS.md`.

- **Audit the reachable generic AArch64 SCVTF_dw emitter API**
  (2026-07-18): all **1,024 encodings** and **4,096 native field/mode routes**
  now pin exact signed-int32→binary64 conversion, W31/WZR, poisoned X upper
  halves, D31, W0/W30, all callee-saved field numbers, **128 same-number
  cross-bank routes**, FPCR-mode independence, no new FPSR exceptions, and
  external D8-D15/FP-state restoration. All six configured source sites are
  pinned. Only `SCVTF_dw` is audited; compound raw/MIDFUNC paths and `i_FPP`
  remain unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_SCVTF_EMITTER.md`.

- **Audit the reachable generic AArch64 FMOV_dx/FMOV_xd bit-transfer pair**
  (2026-07-18): all **2,048 encodings** and **2,048 native field routes** now
  pin exact 64-bit X↔D copying, X31 XZR source/discard behavior, D31, X0/X30,
  all callee-saved field numbers, **64 same-number cross-bank routes**, exact
  NaN/special payload images, source and NZCV/FPCR/FPSR preservation, and
  external D8-D15/FP-state restoration. All six/four configured source sites
  are pinned. Only `FMOV_dx`/`FMOV_xd` are audited; compound raw/MIDFUNC paths
  and `i_FPP` remain unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FMOV_DX_XD_EMITTERS.md`.

- **Audit the reachable generic AArch64 FMOV_sw/FMOV_ws bit-transfer pair**
  (2026-07-18): all **2,048 encodings** and **2,048 native field routes** now
  pin exact W↔S low-word copying, S upper-lane zeroing, W zero extension,
  W31 source/discard behavior, S31, W0/W30, all callee-saved field numbers,
  **64 same-number cross-bank routes**, source preservation, and external
  D8-D15/FPCR/FPSR restoration. Both configured raw compositions and their
  conversion order are pinned. Only `FMOV_sw`/`FMOV_ws` are audited; compound
  raw/MIDFUNC paths and `i_FPP` remain unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FMOV_SW_WS_EMITTERS.md`.

- **Audit the reachable generic AArch64 FCVT_sd/FCVT_ds emitter pair**
  (2026-07-18): all **2,048 encodings** and **256 native conversions** now pin
  exact widening, FPCR-directed narrowing, normal/subnormal/range edges,
  qNaN/SNaN quieting and IOC, IXC/UFC/OFC, **64 in-place aliases**, source/NZCV
  preservation, and external D8-D15/FPCR/FPSR restoration. All 13 configured
  source sites are pinned; composition evidence is the accepted **21/21**
  single-destination matrix plus mechanically decoded **8/8** Dn/immediate and
  **3/3** memory single-import subsets, with the configured AArch64 memory call
  chain pinned structurally. Only `FCVT_sd`/`FCVT_ds` are audited; compound
  raw/MIDFUNC paths and `i_FPP` remain unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FCVT_EMITTERS.md`.

- **Audit the reachable generic AArch64 FCVTAS_wd emitter API**
  (2026-07-18): all **1,024 W/D encodings** and **256 native vectors** now pin
  nearest-away ties, four FPCR modes, exact/fractional IXC, invalid IOC, signed
  saturation, NaNs, W0/W30/W31 and D31 ownership, source/NZCV preservation, and
  external D8-D15/FPCR/FPSR call-boundary restoration. The sole caller's
  FRINTI→FCVTAS order is structural, while a mechanically selected **36/36**
  strict-native byte/word/long destination subset remains composition evidence.
  Only `FCVTAS_wd` is audited;
  adjacent conversions and `i_FPP` remain unreviewed/unreachable as inventoried.
  See `BasiliskII/docs/AARCH64_JIT_AUDIT_FCVTAS_EMITTER.md`.

- **Audit the reachable generic AArch64 FCMP emitter APIs**
  (2026-07-18): `FCMP_dd` and `FCMP_d0` now have direct generic closure across
  all **1,056 encodings** and **72 native vectors**, including maximum fields,
  self aliases, ordered/equal/unordered classes, qNaN/SNaN in either operand,
  exact NZCV, operand preservation, unchanged FPCR, and FPSR IOC only for
  signalling NaN. All five register-register and three register-zero callers
  are pinned; the accepted 176-vector guest FCMP matrix remains composition
  evidence. Only the two emitter rows are audited; `i_FPP` remains unreviewed.
  See `BasiliskII/docs/AARCH64_JIT_AUDIT_FCMP_EMITTERS.md`.

- **Retire the residual AArch64 native FADD primitive chain**
  (2026-07-18): configured control-flow proof confirms FADD/FSADD/FDADD enter
  exact MPFR service before operand acquisition and `fadd_rr`. With no other
  configured root or MIDFUNC caller, `fadd_rr`, `raw_fadd_rr`, and `FADD_ddd`
  are unreachable rather than unreviewed. Root, graph-edge, raw-wrapper, and
  emitter checks fail closed on any future caller. Existing runtime semantics
  remain owned by the fixed **35 service + 3 strict** matrix; this is source
  retirement, not native acceptance, and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_ADD_BATCH.md`.

- **Retire the residual AArch64 native FABS/FNEG primitive chains**
  (2026-07-18): configured control-flow proof confirms all six sign selectors
  enter exact MPFR service before operand acquisition and before the retained
  native MIDFUNC calls. With no other configured caller, `fabs_rr`/`fneg_rr`,
  `raw_fabs_rr`/`raw_fneg_rr`, and `FABS_dd`/`FNEG_dd` are unreachable rather
  than unreviewed. Structural and inventory gates fail closed if service order
  changes or any chain gains a caller. This is source retirement, not native
  acceptance; `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_SIGN_SUBTRANCHE.md`.

- **Audit the reachable AArch64 FMOV binary64 primitive stack**
  (2026-07-18): `FMOV_dd`, `raw_fmov_rr`, and `fmov_rr` now have direct
  closure evidence after architectural 80-bit register FMOVE was removed from
  this path. A native RW-to-RX probe proves all **1,024 D-register encodings**
  and **10,240 bit-copy vectors**, including **320 self aliases**, ten exact bit
  classes, source preservation, and unchanged NZCV/FPCR/FPSR. Structural
  evidence pins the one-instruction raw wrapper, fixed D6/D7/D8-D15 virtual
  homes, source-before-destination ownership, dirty publication, and complete
  configured caller roles. The three primitive rows are audited; `i_FPP`
  remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FMOV_PRIMITIVES.md`.

- **Retire lossy ordinary register-FMOVE copies to exact MPFR service**
  (2026-07-18): the AArch64 path copied only the binary64 shadow, losing
  extended significand/exponent and NaN metadata. Register-source FMOVE now
  leaves before FP operand acquisition, and MPFR now acquires/stores it at
  extended precision independently of FPCR. A fixed **66 service + 3 strict**
  matrix exhausts every FP0-FP7 source/destination pair and self alias, adds
  single/double-FPCR low-bit witnesses, and proves eight exact 80-bit classes,
  source preservation, signalling-NaN quieting,
  FPSR snapshot, integer CCR/state, and exact fallback attribution. No row is
  promoted: `fmov_rr` remains reachable outside this instruction path and
  `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FMOVE_REGISTER_BATCH.md`.

- **Retire lossy ordinary-FMOVE binary64 destinations to exact MPFR service**
  (2026-07-18): the AArch64 path stored an already narrowed binary64 shadow and
  cleared the instruction's conversion status, losing extended significand,
  exponent, and NaN metadata plus INEX2/OVFL/UNFL/SNAN. Double destinations now
  leave before EA acquisition. A fixed **28 service + 3 strict** matrix proves
  all FPCR directions, exact/inexact normal and range edges, signed specials,
  NaN payload/quieting without source mutation, FP0/FP7, ten writable EA
  classes, guarded bytes, writeback, CCR, and exact fallback attribution. No
  closure row is promoted;
  `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FMOVE_DOUBLE_DESTINATION_BATCH.md`.

- **Audit dynamic-list FPP FMOVEM service** (2026-07-18): the AArch64 compiler
  already rejects register-supplied lists before EA acquisition, and the MPFR
  service correctly consumes the selected Dn low byte. A fixed **12 service +
  3 strict** matrix proves D0/D3/D7 selection, high-bit masking, all/sparse/empty
  lists, exact FP0/FP1/FP7 80-bit order, regular/predecrement mask conventions,
  legal update modes, indexed and PC EAs, poisoned replay, guarded bytes, CCR,
  and exact fallback attribution. This evidence-only checkpoint changes no
  implementation and promotes no closure row; `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FMOVEM_DYNAMIC_BATCH.md`.

- **Retire static-list FPP FMOVEM to exact MPFR service** (2026-07-18): the
  residual AArch64 path serialized binary64 shadows as extended frames and
  could lose low significand bits, extended exponent range, and NaN metadata.
  Static lists now leave before EA acquisition. A fixed **10 service + 3
  strict** matrix proves FP0/FP1/FP7 exact 80-bit order, regular/predecrement
  masks, legal update modes, indexed and PC EAs, poison replay, guarded bytes,
  CCR, and exact fallback attribution. Dynamic lists remain separate; no
  closure row is promoted and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FMOVEM_STATIC_BATCH.md`.

- **Audit indexed FPP control-register memory transfers** (2026-07-18): the
  existing MPFR service correctly composes FPCR/FPSR/FPIAR transfers with
  An/PC brief, full direct, preindexed, and postindexed EAs. A fixed **14
  service + 3 strict** matrix proves all/sparse masks, maximum word-index
  fields, independent pointer cells, guarded bytes, base/index preservation,
  represented FPCR/FPSR, full-width FPIAR, CCR, exact fallback attribution,
  and strict rejection. No source repair or closure promotion was justified;
  `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_CONTROL_MEMORY_INDEXED_BATCH.md`.

- **Audit basic FPP control-register memory transfers** (2026-07-18): the
  existing MPFR service correctly transfers FPCR/FPSR/FPIAR in architectural
  order across `(An)`, postincrement, predecrement, displacement, absolute,
  and PC-relative source forms. A fixed **15 service + 3 strict** matrix proves
  all/sparse masks, guarded bytes, A7 frame updates, represented FPCR/FPSR,
  full-width FPIAR, CCR, native fallback attribution, and strict rejection.
  Indexed forms remain separate; no source repair or closure promotion was
  justified and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_CONTROL_MEMORY_BASIC_BATCH.md`.

- **Make direct FPP control-register transfers fail closed as one service**
  (2026-07-18): FPCR/FPSR/FPIAR Dn, An, and immediate forms now leave AArch64
  compilation before any partial mutation. A fixed **11 service + 4 strict**
  matrix covers legal directions, maximum fields, 68040 FPCR masking, FPSR
  represented-bit masking, full-width FPIAR, sequential visibility, integer
  CCR, native entry/fallback attribution, and strict rejection. Memory control
  forms remain separate; no closure row is promoted and `i_FPP` remains
  unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_CONTROL_DIRECT_BATCH.md`.

- **Repair FPP FSINCOS dual-result service** (2026-07-18): all eight
  cosine-register selectors now retain one extended source, evaluate sine and
  cosine directly at FPCR width, preserve NaN sign, publish sine-derived FPSR,
  and enforce same-register sine-wins ordering. A fixed **18 service + 1
  strict** matrix covers precision/direction, FP7 destinations, specials,
  NaNs, EA effects and FPSR. No closure row is promoted and `i_FPP` remains
  unreviewed. See `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_SINCOS_BATCH.md`.

- **Repair FPP FSGLMUL single-significand/extended-exponent service**
  (2026-07-18): FSGLMUL preserves arbitrary-precision factors and multiplies
  directly into a 24-bit significand under extended exponent limits. A fixed
  **22 service + 1 strict** matrix proves one-sided operands, an exact
  double-round midpoint, directed rounding, extended exponent range, signed
  specials, OPERR, NaNs, aliases, EA effects and FPSR. No closure row is
  promoted and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_SGLMUL_BATCH.md`.

- **Repair FPP FSGLDIV single-significand/extended-exponent service**
  (2026-07-18): FSGLDIV preserves arbitrary-precision inputs, divides directly
  into a 24-bit significand under extended exponent limits, and avoids both
  operand pre-rounding and extended-to-single double rounding. A fixed **23
  service + 1 strict** matrix covers one-sided operands, midpoint and directed
  rounding, extended exponent range, specials, NaNs, aliases, EA effects and
  FPSR. No closure row is promoted and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_SGLDIV_BATCH.md`.

- **Repair FPP FSCALE exponent and range service** (2026-07-18): FSCALE
  now preserves extended operands, chops the source toward zero independently
  of FPCR direction, post-rounds the result at FPCR width, and publishes
  destination-relative huge-factor range plus signed invalid NaNs correctly. A
  fixed **30 service + 1 strict** matrix covers truncation boundaries, low bits,
  rounding, subnormals, range, specials, NaNs, aliases, EA effects and FPSR.
  No closure row is promoted and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_SCALE_BATCH.md`.

- **Repair FPP FREM nearest-even remainder service** (2026-07-18): FREM
  now uses exact extended operands, nearest-even quotient selection, FPCR result
  rounding/range, common binary NaN ownership, and complete quotient-byte
  publication through semantic service. A fixed **33 service + 1 strict**
  matrix proves both half-way parity directions, quotient bit 6, signed
  specials, OPERR, NaNs, aliases, EA effects and FPSR. No closure row is
  promoted and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FREM_BATCH.md`.

- **Repair FPP FSUB/FSSUB/FDSUB operand and result precision**
  (2026-07-18): all three preserve extended operands and destination-minus-
  source order; ordinary FSUB evaluates directly at FPCR width and forced
  subtracts publish 24-/53-bit range, exact cancellation, and common binary
  NaN ownership. Six one-sided pre-rounding witnesses plus rounding, signed
  zero, forced range, infinities, NaNs, aliases, EA effects and FPSR pass in a
  fixed **40 service + 3 strict** matrix. No closure row is promoted and
  `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_SUB_BATCH.md`.

- **Repair FPP FMUL/FSMUL/FDMUL operand and result precision**
  (2026-07-18): all three retain extended factors; ordinary FMUL evaluates
  directly at FPCR width and forced multiplies publish 24-/53-bit range and
  common binary NaN ownership. Four one-sided pre-rounding witnesses, plus
  signed specials, OPERR, range, aliases and EA effects, pass in a fixed **30
  service + 3 strict** matrix. No closure row is promoted. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_MUL_BATCH.md`.

- **Repair FPP FADD/FSADD/FDADD operand and result precision**
  (2026-07-18): all three preserve extended operands; ordinary FADD evaluates
  directly into the FPCR-width result, while forced adds publish 24-/53-bit
  range, cancellation-zero, binary NaN and Motorola status correctly. A fixed
  **35 service + 3 strict** matrix covers extended-only-bit witnesses,
  directed rounding, forced cancellation, range, infinities, NaNs, aliases,
  EA effects and exact FPSR. No row is promoted to audited; the later
  configured-root addendum classifies `fadd_rr`, `raw_fadd_rr`, and `FADD_ddd`
  unreachable, while `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_ADD_BATCH.md`.

- **Repair FPP FMOD truncating remainder and quotient service**
  (2026-07-18): FMOD no longer compiles through IEEE FREM on any host; exact
  MPFR service retains extended operands, computes the truncating quotient
  sign/low-seven byte, post-rounds the result at FPCR width, and applies
  architectural special-value and NaN ownership rules. A fixed **31 service +
  1 strict** matrix covers the `7 mod 4` discriminator, quotient wrap/sign,
  low-bit operands, FPCR range, specials, NaNs, aliases, EA effects and FPSR.
  No closure row is promoted and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FMOD_BATCH.md`.

- **Repair FPP FDIV/FSDIV/FDDIV operand, result and NaN ownership**
  (2026-07-18): ordinary FDIV now preserves full extended operands and rounds
  only the completed FPCR-width result; forced single/double division retains
  extended operands, publishes target exponent-range overflow/underflow, and
  quiets signalling NaNs and applies architectural destination precedence
  explicitly. A fixed **37 service + 3 strict** matrix covers rounding, range,
  zero/infinity status, both-operand NaNs, FP7 replay ownership, aliases, EA
  side effects and exact FPSR. No closure row is promoted and `i_FPP` remains
  unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_DIVIDE_BATCH.md`.

- **Repair FPP FCOSH/FACOS service and retire lossy native FCOS**
  (2026-07-18): all three now acquire extended sources and evaluate directly
  into FPCR-width MPFR results; FCOS exits before AArch64 binary64/native-libm
  lowering. A fixed **36 service + 3 strict** matrix covers source-sensitive
  single/double results, directed rounding, signed zero, infinity/domain rules,
  NaN metadata, FCOSH finite overflow, aliases and exact FPSR. No closure row
  is promoted and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_COSH_ACOS_COS_BATCH.md`.

- **Retire lossy native FSIN/FETOX/FTWOTOX/FLOG2 to exact service**
  (2026-07-18): the four remaining binary64-native transcendental routes now
  exit before narrowing extended operands and evaluate directly into FPCR-width
  MPFR results. A fixed **49 service + 4 strict** matrix covers directed
  single/double results, signed zero, infinity/domain rules, NaN metadata,
  finite overflow/underflow, aliases and exact FPSR. Minimum-extended `FLOG2`
  now returns finite `-16445` instead of binary64 collapse to zero and spurious
  DZ. No closure row is promoted and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_NATIVE_TRANSCENDENTAL_BATCH.md`.

- **Repair FPP FTAN/FTENTOX/FLOGN/FLOG10 service precision**
  (2026-07-18): these four configured MPFR selectors now acquire extended
  sources and evaluate directly into separate FPCR-width results, avoiding
  source narrowing and transcendental double rounding. A fixed **45 service +
  4 strict** matrix covers source-sensitive single/double results, all single
  rounding modes, signed zero, infinity/domain rules, NaN metadata, finite and
  extended underflow, aliases and FPSR. No closure row is promoted and
  `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_TAN_EXP10_LOG_BATCH.md`.

- **Repair FPP FATAN/FASIN/FATANH service precision and DZ status**
  (2026-07-17): these three configured MPFR selectors now acquire sources at
  extended precision/range and evaluate directly into a separate FPCR-width
  result, avoiding source narrowing and transcendental double rounding.
  FATANH now explicitly publishes DZ for `±1` rather than relying on an MPFR
  flag without the architectural status split. A fixed **38 service + 3
  strict** matrix covers source-sensitive single/double results, every single
  rounding mode, signed zero, `±pi/2`, domains, NaN metadata, underflow,
  aliasing and FPSR. No closure row is promoted and `i_FPP` remains
  unreviewed. See `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_INVERSE_BATCH.md`.

- **Repair FPP FSINH/FLOGNP1/FETOXM1/FTANH service precision**
  (2026-07-17): these four configured MPFR selectors acquired architectural
  operands in a temporary already narrowed to FPCR single/double precision.
  They now load at extended precision/range and evaluate directly into a
  separate FPCR-width result, avoiding both source loss and transcendental
  double rounding. A fixed **48 service + 4 strict** matrix covers
  source-sensitive single/double witnesses for every selector, directed
  rounding, signed zero, infinity/domain rules, NaN payload/quieting,
  extended-to-single underflow, FP7 aliasing, operation-local/accrued FPSR and
  strict rejection. No closure row is promoted and `i_FPP` remains
  unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_HYPERBOLIC_LOG1P_BATCH.md`.

- **Repair FPP FINT/FINTRZ/FGETEXP/FGETMAN unary decomposition service**
  (2026-07-17): the four configured AArch64 MPFR selectors allocated their
  shared source/result temporary at FPCR single/double precision before source
  acquisition. They now acquire architectural sources at full extended
  precision/range, perform exact decomposition, then round and range-check a
  distinct result at FPCR precision. FINT honours FPCR rounding direction;
  FINTRZ forces toward zero. The batch also repairs the one-power extended-
  denormal import error and FGETEXP/FGETMAN infinity OPERR/NaN-sign handling.
  Fixed matrices pass **55/55 + 2 strict** integral cases and **38/38 + 2
  strict** exponent/mantissa cases, including immediate operation-FPSR
  snapshots before a later FMOVE clears exception status and successor FNEG
  consumption of infinity-derived NaN sign metadata. No closure row is
  promoted and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_UNARY_DECOMPOSITION_BATCH.md`.

- **Retire lossy FPP FSQRT/FSSQRT/FDSQRT to exact MPFR service**
  (2026-07-17): the AArch64 path acquired every source through its binary64
  shadow and emitted host `FSQRT D`, losing extended range/significand state,
  forced 24-/53-bit precision, directed rounding, and complete FPSR semantics.
  All three selectors now exit before operand acquisition. Fifty-four fixed
  80-bit/FPSR service vectors cover signed zero, invalid negative input,
  NaN payload/quieting, extended-range and low-bit inputs, all FPCR precision
  and rounding modes, FP7 aliasing, accrued exceptions, and mixed-mode replay;
  three strict cases reject native entry. A distinguishing FDSQRT/FPCR-single
  vector also repaired shared MPFR source narrowing: forced operations now
  acquire their architectural operand under extended precision and exponent
  range, then round only the
  result to 24/53 bits. No closure row is promoted and
  `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_SQRT_SUBTRANCHE.md`.

- **Retire lossy FPP sign operations and repair mixed-mode FP ownership**
  (2026-07-17): ordinary FABS/FNEG could narrow an architectural 80-bit source
  merely by acquiring it through the binary64 shadow; FS/FD variants also
  omitted forced precision and exception semantics. All six selectors now use
  exact MPFR service before operand acquisition. A runtime dirty mask prevents
  untouched shadows and stale lazy FP results from overwriting wider MPFR/FPSR
  state, while the universal fallback seam now disassociates caller-clobbered
  allocator registers and rematerialises integer CCR after C. The bounded gate
  passes **31/31** exact service vectors and **6/6** strict rejections; adjacent
  FCMP/FTST and four service families remain clean. The new private call boundary
  expands the inventory to 998 rows and is audited here; no pre-existing row is
  promoted and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_SIGN_SUBTRANCHE.md`.

- **Retire mixed-precision FMOVECR dispatch to exact MPFR service**
  (2026-07-17): the AArch64 path mixed binary32/binary64 constants and fallback
  helpers within one architectural constant-ROM family; π reproduced with only
  binary32 precision. FMOVECR now exits before selector dispatch. Thirty-six
  service vectors prove all 22 defined selectors, powers through `10^4096`,
  eight π FPCR precision/rounding combinations, undefined-selector zero policy,
  exact 80-bit output and FPSR; three strict FP7 cases reject native entry.
  Integrated evidence is **904/904** with **31/31** pressure; no closure row is
  promoted and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FMOVECR_SUBTRANCHE.md`.

- **Retire unrounded FSMOVE/FDMOVE copies to exact MPFR service** (2026-07-17):
  the AArch64 path previously grouped ordinary FMOVE and explicit 24-/53-bit
  moves into one binary64 copy, omitting forced precision and exceptions.
  Thirteen service vectors now prove all four single rounding directions,
  double halfway/overflow, exact signed zero/infinity, guarded 80-bit outputs,
  and FPSR; two strict FP7 self-alias cases reject native entry. Ordinary FMOVE
  remains on its audited native route. Integrated evidence is **904/904** with
  **31/31** pressure; no closure row is promoted and `i_FPP` remains
  unreviewed. See `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_EXPLICIT_MOVE_SUBTRANCHE.md`.

- **Audit ordinary packed-decimal FMOVE as exact MPFR service** (2026-07-17):
  the AArch64 compiler already rejects static/dynamic packed sources and
  destinations before EA calculation or writeback. Nine service cases prove
  static/dynamic K=17, K=5 decimal rounding, signed mantissa/exponent, signed
  zero, and infinity with guarded exact bytes; four strict cases reject native
  source/destination entry without SIGSEGV. No implementation or closure status
  changes are needed and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FMOVE_PACKED_FORMAT_SUBTRANCHE.md`.

- **Retire lossy ordinary FMOVE.X native conversion to exact MPFR service**
  (2026-07-17): the binary64 AArch64 shadow cannot preserve the 80-bit format's
  64-bit significand and 15-bit exponent, while the old immediate-source route
  also passed a host pointer as a guest vreg and reproduced a null SIGSEGV.
  Ordinary extended sources/destinations now fail before EA side effects and
  execute through MPFR. Eight service cases round-trip full 80-bit bytes and
  four strict cases reject native source/destination execution without SIGSEGV;
  integrated evidence remains **904/904** with **31/31** allocator pressure.
  No closure row is promoted and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FMOVE_EXTENDED_FORMAT_SUBTRANCHE.md`.

- **Repair and audit ordinary FMOVE extended destination EAs** (2026-07-17):
  `d16(An)`, brief/full indexed An, and absolute short/long stores pass
  **26/26** strict exact-native cases across byte/word/long/single/double,
  guarded writes, direct/preindexed/postindexed forms, maximum fields, and an
  all-integer-registers-live case. A strict **3/3** negative matrix now rejects
  source-only d16 PC, indexed PC, and immediate destination encodings; d16 PC
  and immediate previously compiled and wrote natively. The active-risky corpus
  remains **904/904** and isolated allocator pressure **31/31**. No closure row
  is promoted and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FMOVE_DESTINATION_EXTENDED_EA_SUBTRANCHE.md`.

- **Repair and audit ordinary FMOVE IEEE-single destinations** (2026-07-17):
  AArch64 `FCVT S,D` now publishes MPFR-compatible SNAN/OVFL/UNFL/INEX2 and
  accrued IOP/OVFL/UNFL/INEX while preserving guest NZCV and host FPSR. The
  MPFR/native boundary now retains NaN payload as well as sign. The bounded
  exact-native matrix passes **21/21** across all FPCR modes, normal/subnormal,
  overflow/underflow, infinity, signed zero, and quiet-NaN payload cases; the
  active-risky corpus remains **904/904** and isolated allocator pressure
  **31/31**. No closure row is promoted and `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FMOVE_SINGLE_DESTINATION_SUBTRANCHE.md`.

- **Repair and audit ordinary FMOVE basic destinations** (2026-07-17):
  byte/word/long integer destinations now match MPFR rounding, signed
  saturation, OPERR/INEX status replacement, and accrued IOP/INEX; single and
  double happy-path stores remain on typed conversion and guest-memory
  boundaries, with exact single/double destinations also replacing stale
  exception status. JIT entry maps all four 68k FPCR rounding modes and
  preserves MPFR NaN sign across the native shadow boundary. The bounded
  exact-native matrix passes **45/45**, the active-risky corpus **904/904**, and allocator
  pressure **31/31**. This is a no-promotion checkpoint: `i_FPP` remains
  unreviewed, and single special-value/range fidelity plus extended destination
  EAs remain separate. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FMOVE_DESTINATION_BASIC_SUBTRANCHE.md`.

- **Repair and audit ordinary FMOVE extended source EAs** (2026-07-17):
  d16/indexed An, absolute short/long, d16 PC, and indexed PC pass **39/39**
  strict exact-native vectors across byte/word/long/single/double values,
  brief/full indexed forms, indirection, signed displacements, maximum fields,
  FPSR, and integer CCR. PC-indexed sources no longer fail compilation; they
  materialise the extension-word PC as a distinct base and use the shared
  68020 indexed-EA decoder. Integrated evidence remains **904/904** with
  **31/31** allocator pressure. `i_FPP` remains unreviewed. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FMOVE_EXTENDED_EA_SUBTRANCHE.md`.

- **Audit ordinary FMOVE basic memory sources** (2026-07-17): `(An)`,
  `(An)+`, and `-(An)` pass **18/18** strict exact-native vectors across
  byte/word/long/single/double values, exact writeback, A7 byte geometry,
  maximum A7/FP7 fields, FPSR, and integer CCR. No implementation change or
  closure promotion was needed; `i_FPP` remains unreviewed. Integrated evidence
  remains **904/904** with **31/31** allocator pressure. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FMOVE_MEMORY_BASIC_SUBTRANCHE.md`.

- **Repair the native FPP ordinary-FMOVE source subfamily** (2026-07-16):
  AArch64 integer FMOVE inputs no longer pass the host `temp_fp` pointer as a
  virtual integer register through the legacy x86 compatibility shim. Dn and
  immediate byte/word/long/single sources now use typed register-to-FP
  conversions directly; double immediates and all FP0-FP7 copy/self-alias
  routes were value-observed. At landing, the combined strict-native matrix
  passed **43/43**, with active-risky **904/904** and allocator pressure
  **31/31**. FP-register copies later moved to exact MPFR service; the current
  maintained split is **29/29 native Dn/immediate** plus **66+3 serviced
  register** cases. This remains bounded and `i_FPP` is still unreviewed.
  See `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_FMOVE_SOURCE_SUBTRANCHE.md`.

- **Repair the native FPP FCMP/FTST condition-result subfamily**
  (2026-07-16): native FCMP no longer approximates comparison with floating
  subtraction, which misclassified equal infinities as NaN and leaked Infinity
  into FPSR for unequal infinite operands. A direct AArch64 `FCMP` classifier
  now publishes exact negative/equal/positive/unordered classes, including
  `N|Z` for equal negative zero and negative infinity but plain `Z` for equal
  negative finite values. FCMP and FTST preserve integer CCR, and REGDUMP now
  includes exact FPSR evidence. Strict exact-native matrices pass **176/176
  FCMP** and **128/128 FTST**; the active-risky corpus remains **904/904** and
  allocator pressure **31/31**. This is a bounded no-promotion checkpoint:
  `i_FPP` remains unreviewed pending its remaining subfamilies. See
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FPP_COMPARE_FTST_SUBTRANCHE.md`.

- **Repair and close the configured native FBcc generator lifecycle**
  (2026-07-16): all sixteen 68881 predicates now lower through an explicit
  AArch64 FP-condition namespace across word/long signed displacements and both
  successors. The repair removes inherited x87 parity IDs, preserves integer
  XNZVC across temporary `FCMP` NZCV, teaches mid-block exits FP predicate
  complementation, and makes the previously declared MPFR/native-double
  boundary real by importing/exporting FP registers plus FPSR condition state
  on every C/JIT transition. The fail-closed focused matrix passes 160/160 at
  exact native entry over positive, zero, negative, positive-NaN, and
  negative-NaN classes; the
  existing active-risky corpus remains 904/904. The deterministic 997-row
  inventory promotes only `i_FBcc`. Full evidence is in
  `BasiliskII/docs/AARCH64_JIT_AUDIT_FBCC_LIFECYCLE.md`.

- **Close the complete EXT generator lifecycle** (2026-07-16): all six
  generated handlers (three per compiler table) are covered across EXT.W
  byte-to-word with upper-word preservation, EXT.L word-to-long, EXTB.L
  byte-to-long, negative/zero/positive values, maximum fields, chained widening,
  no-flags execution, and exact XNZVC semantics. Focused replay passes 16/16,
  the active-risky corpus 904/904, and allocator pressure 31/31; the EXT.W
  witness rejects the forced widened-scratch/source alias with `skip=1`. The
  deterministic 997-row inventory promotes only `i_EXT`. Full evidence is in
  `BasiliskII/docs/AARCH64_JIT_AUDIT_EXT_LIFECYCLE.md`.

- **Close the complete EXG generator lifecycle** (2026-07-16): all six
  generated handlers (three per compiler table) are covered across Dn/Dn,
  An/An, and Dn/An forms, simultaneous full-width exchange, self aliases,
  maximum register fields, roundtrips, no-flags table execution, and complete
  XNZVC preservation. Focused replay passes 12/12, the active-risky corpus
  888/888, and allocator pressure 30/30; the EXG witness rejects the forced
  temporary/source alias with `skip=1`. The deterministic 997-row inventory
  promotes only `i_EXG`. Full evidence is in
  `BasiliskII/docs/AARCH64_JIT_AUDIT_EXG_LIFECYCLE.md`.

- **Close the complete CLR generator lifecycle** (2026-07-16): all 48
  generated handlers (24 per compiler table) are covered across byte/word/long
  Dn and every writable memory form, upper-lane preservation, A7 byte geometry,
  special-memory routing, no-flags table execution, and fixed XNZVC semantics.
  The live generator emits zero and stores it before publishing flags, preventing
  memory-helper NZCV from escaping into a following branch. Focused replay
  passes 15/15, the active-risky corpus 876/876, and allocator pressure 29/29;
  the CLR witness rejects the forced zero/EA alias with `skip=1`. The
  deterministic 997-row inventory promotes only `i_CLR`; all six namesake
  MIDFUNCs remain unreachable. Full evidence is in
  `BasiliskII/docs/AARCH64_JIT_AUDIT_CLR_LIFECYCLE.md`.

- **Close the complete Bcc generator lifecycle** (2026-07-16): all 90 generated
  handlers (45 per compiler table) are covered across BRA and all fourteen
  conditional pairs, byte/word/long signed target arithmetic, extension-word
  PC semantics, forward/backward edges, both outcomes, and XNZVC preservation.
  The focused matrix passes 34/34 at exact native entry, the active-risky corpus
  861/861, and allocator pressure 28/28. Structural evidence locks the explicit
  byte/word sign extension, signed long guest-offset/host-base conversion,
  pointer-width cursor folds, historical-x86-to-AArch64 condition translation
  at both side-exit boundaries, and the absence of dynamic allocator ownership.
  The deterministic 997-row inventory promotes only `i_Bcc`; raw
  `compemu_raw_jcc_l_oponly` lowering remains a separate unreviewed boundary.
  Full evidence is in
  `BasiliskII/docs/AARCH64_JIT_AUDIT_BCC_LIFECYCLE.md`.

- **Repair and close the complete ADDA lifecycle** (2026-07-16): all 52
  generated handlers and four reachable no-flags MIDFUNC routes are covered
  across exact ADDA.W sign extension, ADDA.L full-width arithmetic, 32-bit
  address-register wrap, dynamic/immediate/constant operands, every readable
  EA, aliases, postincrement/predecrement, special memory, and complete XNZVC
  preservation. Forced allocator pressure reproduced the same-register
  `ADDA.W/L (A0)+,A0` lifetime defect at two boundaries: A0 writeback could
  steal the fetched source before arithmetic, yielding `0x00000006`/`0x0000000a`
  instead of `0x0000a003`/`0x0000a005`. Sequential generated pins now own the
  source across writeback and destination RMW while public `is_const()` keeps
  immediate and fully folded routes intact. `jnf_ADDA_w_imm` also publishes
  folded results through `set_const()` to enforce 32-bit guest width. Focused
  replay passes 29/29 (27 exact-native plus two fold-equivalence vectors), the
  full active-risky corpus 827/827, and allocator pressure 28/28; both ADDA
  witnesses reject both unsafe aliases with `skip=2`. The deterministic
  997-row inventory promotes only `i_ADDA` and its four reachable MIDFUNCs.
  Full evidence is in
  `BasiliskII/docs/AARCH64_JIT_AUDIT_ADDA_LIFECYCLE.md`.

- **Generic SUB/SUBS emitter width, alias, field, and NZCV closure**
  (2026-07-16): the seven reachable AArch64 SUB/SUBS APIs now have 11
  independent exact-word checks and 70 direct native vectors: 42 arithmetic
  results, four explicit `S=0` NZCV-preservation cases, and 24 `S=1` NZCV
  cases. Coverage includes W/X width, immediate and shift boundaries, maximum
  register fields, destination/lhs and destination/rhs aliases, no-borrow C,
  and signed overflow. A fail-closed census covers all 115 raw source callers
  and every immediate/shift argument source. No encoder defect was found. The
  997-row inventory promotes only these seven APIs; unreachable SUB/SUBS forms
  remain unreachable and reachable `SBCS_www` remains unreviewed. Full evidence
  is in `BasiliskII/docs/AARCH64_JIT_AUDIT_SUB_EMITTERS.md`.

- **Repair and close the complete SUB lifecycle** (2026-07-16): all 208
  generated handlers and twelve reachable MIDFUNC routes are covered across
  byte/word/long flag-live and no-flags tables, Dn and immediate lowering, all
  nine readable and seven writable EA classes, aliases, A7 byte geometry,
  special memory, and exact NZVCX borrow semantics. Exact-native allocator
  pressure reproduced a production lifetime defect in `SUB.B D0,(A0)+`: FLAGX
  collided with the unowned private pre-write EA, so the interpreter reloaded
  `0xff` with SR `0x2718` while the JIT reloaded stale `0x00` with SR `0x2714`.
  The generator now emits 126 balanced destination-EA pins and no redundant
  source pins. Focused replay passes 37/37, full active-risky replay 798/798,
  and allocator pressure 26/26; the two SUB cells retain exact native entry
  with `skip=1` and `skip=2`. The deterministic 997-row inventory promotes
  only `i_SUB` and its twelve lifecycle MIDFUNCs. The seven reachable generic
  `SUB_*` / `SUBS_*` emitters are audited separately. Full evidence is in
  `BasiliskII/docs/AARCH64_JIT_AUDIT_SUB_LIFECYCLE.md`.

- **Complete OR lifecycle, flags, EA classes, and allocator ownership**
  (2026-07-16): all 156 generated handlers and twelve reachable MIDFUNC routes
  are covered across byte/word/long Dn, immediate, and all nine readable-memory
  source classes; register and all seven writable-memory destination classes;
  flag-live and no-flags lowering; aliases; A7 byte geometry; and special
  memory. Focused replay passes 37/37 before and after a clean build; the
  complete active-risky corpus passes 761/761 and all 24 allocator cells pass.
  Two OR-specific pressure cells reject read-source-to-D0 and
  RMW-value-to-pre-write-EA collisions while retaining exact native entry. No
  production repair was required beyond the accepted shared logical
  writable-EA fix. The 997-row inventory promotes only `i_OR` and its twelve
  lifecycle MIDFUNCs; generic
  `ORR_*` emitters remain separate. Full evidence is in
  `BasiliskII/docs/AARCH64_JIT_AUDIT_OR_LIFECYCLE.md`.

- **Generic EOR emitter encoding, alias, bit, and no-flags closure** (2026-07-16):
  the four reachable callable AArch64 EOR encoders and shared `immOP_EOR` base
  now have 13 independent exact-word checks, 18 direct native result vectors,
  and four explicit NZCV-preservation vectors. The probe covers W/X semantics,
  LSL counts through the masked-32 boundary, single-bit logical immediates
  through bit 63, C-bit toggling, all alias directions, and maximum register
  fields. Fail-closed structure covers 53 configured references and 64 raw
  source compositions. No encoder defect was found. The 997-row closure
  inventory promotes only `EOR_www`, `EOR_wwwLSLi`, `EOR_xxCflag`, `EOR_xxbit`,
  and `immOP_EOR`; unreachable `EOR_xxx*` variants remain unpromoted. The full
  active-risky corpus passes 725/725 and all 22 allocator cells pass. Full
  evidence is in `BasiliskII/docs/AARCH64_JIT_AUDIT_EOR_EMITTERS.md`.

- **Complete EOR lifecycle, flags, and writable-EA ownership** (2026-07-16):
  all 96 generated handlers and twelve reachable MIDFUNC routes are covered
  across byte/word/long Dn and immediate sources, flag-live and no-flags
  lowering, self aliases, all seven writable EAs, A7 byte geometry, and special
  memory. The matrix passes 28/28 before and after a clean build; the complete
  active-risky corpus passes 725/725 and all 22 allocator cells pass. Two
  EOR-specific pressure cells reject source-to-destination and pre-write-EA-to-
  destination collisions while retaining exact native entry. No new production
  repair was required beyond the accepted shared logical EA fix. The 997-row
  inventory promotes only `i_EOR` and its twelve lifecycle MIDFUNCs; this
  lifecycle evidence does not itself promote generic `EOR_*` emitters. Full
  evidence is in `BasiliskII/docs/AARCH64_JIT_AUDIT_EOR_LIFECYCLE.md`.

- **Generic AND emitter width, field, alias, and no-flags closure** (2026-07-16):
  the three reachable non-flag-setting AArch64 AND APIs now have nine
  independent exact-word checks, 24 direct native result vectors, and three
  explicit NZCV-preservation vectors. The probe covers W/X width, the fixed
  `#0x3f` logical immediate, all source/destination alias shapes, and the
  architectural register-field maximum. A fail-closed census covers all 83 raw
  production callers. No encoder defect was found. The 997-row closure
  inventory promotes only `AND_ww3f`, `AND_www`, and `AND_xxx`; `AND_ww1f` and
  `AND_xx1f` remain unreachable, while all `ANDS_*` APIs remain separate. Full
  evidence is in `BasiliskII/docs/AARCH64_JIT_AUDIT_AND_EMITTERS.md`.

- **AND lifecycle and shared OR/AND/EOR pre-write EA ownership** (2026-07-16):
  the complete reachable byte/word/long AND family now has exact-native coverage
  across flags, no-flags, immediates, aliases, every readable source and writable
  destination EA, A7 byte geometry, and special memory. A forced allocator
  collision proved that writable logical destinations did not retain their
  fetched pre-write EA through MIDFUNC allocation and ordered storage:
  `AND.B D0,(A0)+` reloaded stale `0xff` instead of stored `0x0f`. The shared
  generator now emits 84 balanced destination-EA pins for each of OR, AND, and
  EOR. The adjacent OR and EOR lifecycles are now independently audited rather
  than promoted by this AND evidence. Focused replay passes 34/34 AND and 2/2
  shared-path vectors; the complete active-risky gate passes 698/698 and all 20
  allocator cells pass.
  The 997-row closure census promotes `i_AND` and twelve reachable MIDFUNCs;
  generic AND/ANDS emitters are audited separately. Full evidence is in
  `BasiliskII/docs/AARCH64_JIT_AUDIT_AND_LIFECYCLE.md`.

- **Generic ADD emitter width, field, and no-flags closure** (2026-07-16):
  the seven reachable non-flag-setting AArch64 ADD APIs now have 12 independent
  exact-word checks, 39 direct native result vectors, and seven explicit NZCV
  preservation vectors. A fail-closed census covers all 72 raw source callers,
  including imm12 guards, the configured zero/sign-extension options, and every
  shifted-register count source. No encoder defect was found. The complete
  active-risky gate remains 695/695 and all 18 allocator cells pass after a
  clean deterministic build. The 997-row closure inventory promotes only these
  seven APIs; `ADD_xxxLSLi` remains unreachable. Full evidence is in
  `BasiliskII/docs/AARCH64_JIT_AUDIT_ADD_EMITTERS.md`.

- **ADD pre-write EA ownership and complete lifecycle closure** (2026-07-15):
  memory-destination `ADD` now pins its private effective address after fetch
  and releases it only after the ordered store. This preserves the original
  destination across postincrement/predecrement and flag-X allocation without
  adding redundant generator source locks: the six shared MIDFUNC register
  routes already own both arithmetic operands. Exact-native coverage passes
  34/34 across byte/word/long flags, no-flags, immediates, aliases, every
  readable source and writable destination EA, A7 byte geometry, and special
  memory. The complete active-risky gate passes 695/695; all 18 allocator
  pressure cells pass, including the witnessed FLAGX-to-EA collision. Full
  evidence is in `BasiliskII/docs/AARCH64_JIT_AUDIT_ADD_LIFECYCLE.md`.

- **ROL/ROR six-bit counts, carry lifecycle, aliases, and no-flags memory paths**
  (2026-07-14): AArch64 register wrappers now preserve the 68040 low-six-bit
  count before width-periodic rotation, distinguish count zero from non-zero
  multiples for C, and support legal count/data aliases through explicit
  `readreg()` then destination `rmw()` ownership. The generator selects
  flag-producing helpers before emission instead of reconstructing flags from
  a no-flags result, while memory `ROLW`/`RORW` no-flags handlers now call their
  `jnf` helpers across every addressing mode. Patched runtime joins and
  branchless carry publication replace fixed emitted skip distances. Focused
  exact-native coverage passes 92/92; the complete active gate passes 647/647.
  Full evidence is in `BasiliskII/docs/AARCH64_JIT_AUDIT_ROTATES.md`.

- **Register-count ASL/ASR/LSL/LSR counts, overflow, X lifecycle, and aliases**
  (2026-07-14): all register helpers implement the guest low-six-bit domain
  rather than AArch64 W-form modulo-32 shifts. Runtime joins materialise old X
  before branching, non-zero carry publication no longer creates unmatched
  allocator ownership, and ASL overflow uses the complete sign-transition
  contract including zero at large counts. AArch64 generated handlers accept
  legal count/data aliases and retain other-backend containment. The focused
  exact-native gate passes 138/138 and the accepted full corpus passed 579/579.
  Full evidence is in
  `BasiliskII/docs/AARCH64_JIT_AUDIT_REGISTER_SHIFTS.md`.

- **DIVS/DIVL zero, overflow, flags, aliases, and branch geometry**
  (2026-07-14): signed 32/32 DIVL now widens before division so
  `INT32_MIN / -1` takes the architectural overflow path instead of inheriting
  `SDIV.W` saturation. Conditional result registers use read/modify/write
  allocation; all 28 DIVL zero/fit/overflow joins are patched structurally;
  signed word and long overflow restore incoming Z after host fit comparisons.
  Sixteen exact-PC vectors cover flag-live/no-flags, 32/64-bit signed/unsigned,
  distinct and aliased result registers, source aliases, overflow, and precise
  vector-5 state. Full evidence is in
  `BasiliskII/docs/AARCH64_JIT_AUDIT_DIVISION_LIFECYCLE.md`.

- **ABCD/SBCD/NBCD arithmetic, flags, and A7 predecrement** (2026-07-13):
  the old AArch64 helpers used per-digit approximations instead of the
  authoritative 68040 correction equations, split flag-live from flag-dead
  handling, and hard-coded one-byte source/destination predecrements. The
  complete family now shares exact arithmetic cores and one X/C/sticky-Z
  lifecycle, preserves N/V, patches all seven variable-length correction joins,
  and uses `areg_byteinc[]` for both ordered predecrements. Exact-PC replay also
  restores skipped register/CCR state and mutable memory before each trace/native
  pass. Mismatch-first witnesses exposed invalid-nibble result/flag differences
  and A7 ending one or two bytes high. The focused fail-closed gate passes 31/31,
  including source-A7, destination-A7, `-(A7),-(A7)`, opcode-only, decimal-edge,
  invalid-nibble, alias, X/C-chain, and sticky-Z cases. Full evidence is in
  `BasiliskII/docs/AARCH64_JIT_AUDIT_BCD.md`.

- **ADDX/SUBX and immediate-CCR flag lifecycle** (2026-07-13):
  byte/word ADC now propagates incoming X through the shifted operand lane, and
  byte/word ADC/SBC reconstruct Z from the architectural narrow result without
  disturbing N/C/V or carry polarity. Selective sticky-Z merging no longer
  relabels SUBX's inverted physical carry before X duplication. The authoritative
  generator now derives ORI/ANDI/EORI-to-CCR masks from the guest immediate,
  rather than from its JIT virtual-register identifier. Mismatch-first vectors
  exposed wrong ADDX.B/W results and wrong SUBX.B/W/L X/C before repair. Focused
  strict-native coverage passes 48/48; all twelve effective-zero AS/LS register
  controls passed without an emitter change; the complete gate passes 476/476.
  Full evidence is in
  `BasiliskII/docs/AARCH64_JIT_AUDIT_ADDX_SUBX_CCR.md`.

- **Register-count ROXL/ROXR effective-zero flags and structural branches** (2026-07-13):
  the AArch64 byte/word/long flag-setting helpers used numeric `CBNZ`/`B` instruction
  displacements around variable-length flag emission. Their effective-zero path also
  derived N/Z and cleared V but left C clear instead of copying unchanged X as required
  by the 68040 contract. All six helpers now patch symbolic rotate/end targets and merge
  X into NZCV.C after the size-correct result test. Forced-native vectors cover both
  directions and all widths, the deepest low-six-bit modulo reductions (63→0 mod 9,
  51→0 mod 17, 33→0 mod 33), raw count zero, zero/negative size results, stale-V clearing,
  C=X, upper-bit preservation, and populated guest-register mappings. The generated
  opcode surface has no separate no-flags ROX path: all 24 handlers call the flag-setting
  family. Full validation passes 421/421 with zero fallback/null legal encodings.

- **ARM64 native DBF exits use the runtime PC** (2026-07-04):
  the remaining post-`151b1853` bad video/resource wall was narrowed to the
  `04037520`/`0403754c` QuickDraw bitfield-copy loops. Forcing the real block
  starts `04037520,04037528,04037530,0403754c,04037552` to optlev-0, or using
  the DBcc barrier, cleared the bad `SetEntries table=04002478 count=1` wall;
  Scc and BFEXT helper invalidation/splitting did not. Root cause: native DBF
  (`cc=1`) was allowed to trace-follow one observed loop outcome. ARM64 DBF now
  materializes `PC_P` from the pre-decrement counter and the DBcc runtime-PC
  endblock path includes DBF/DBRA, so both loop and exit edges dispatch via the
  actual runtime PC. Verified: `jit-test/run.sh` passes `318/318`, `fail_equiv=0`,
  and default L2 reaches the later good `SetEntries table=000b8a48 count=255`.
  This is still not boot-through; the next frontier is a later `newpc=10001000`
  bad-PC path around `04002600/04002636/04002642`.

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
