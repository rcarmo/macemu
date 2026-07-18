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

**Current structural-audit gate (2026-07-16):** ✅
**Build and generator:** ✅ clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build; generated `compemu.cpp` is byte-reproducible at SHA-256 `17e9d3510ceb4e479d6e64520b90433278f6a15cfcf1c7d5daf1d3f36a4d12e0`
**JIT harness:** ✅ 798/798 active-risky vectors, `fail_equiv=0`, `infra_fail=0`, score 100
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

**761 active-risky vectors, score=100**

The larger exact-native family inventories remain available as focused gates;
the current `OR` inventory is 37/37, the `EOR` inventory is 28/28, the `AND`
inventory is 34/34, the `ADD` inventory is 34/34, the accepted `ROL`/`ROR`
inventory is 92/92, and the accepted register-count
`ASL`/`ASR`/`LSL`/`LSR` inventory is 138/138.

### Recent bug fixes (2026-07)

- **Repair FPP FADD/FSADD/FDADD operand and result precision**
  (2026-07-18): all three preserve extended operands; ordinary FADD evaluates
  directly into the FPCR-width result, while forced adds publish 24-/53-bit
  range, cancellation-zero, binary NaN and Motorola status correctly. A fixed
  **35 service + 3 strict** matrix covers extended-only-bit witnesses,
  directed rounding, forced cancellation, range, infinities, NaNs, aliases,
  EA effects and exact FPSR. No closure row is promoted and `i_FPP` plus
  generic `FADD_ddd` remain unreviewed. See
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
  routes are value-observed. The strict exact-native matrix passes **43/43**,
  the active-risky corpus **904/904**, and allocator pressure **31/31**. This
  remains a bounded no-promotion checkpoint: `i_FPP` is still unreviewed, with
  explicit precision, memory-EA, store, and other FPP subfamilies outstanding.
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
