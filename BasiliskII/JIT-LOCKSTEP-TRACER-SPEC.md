# JIT Lockstep Differential Tracer — Build-Ready Spec (Option A)

Status: **DESIGN ONLY — not built.** Ready to execute if Rui selects (A).
Target bug: pure-JIT boot hang at `0x0100254e` (CRC/Bcc-liveness region,
blocks `253e`/`2556`). Author: @previous slot deliverable.

---

## 1. Why the existing oracle is structurally blind (the thing we are replacing)

Two snapshot oracles exist today in `compemu_support_arm.cpp`:

- **Per-block** `jit_block_verify_run()` (≈ line 752): on each compiled block it
  captures the JIT's *live* entry state, runs the interpreter from that entry to
  the first `fl_end_block`, restores, compiles+runs the native block, compares.
- **Per-op** `jit_verify_pre/post()` (≈ lines 837/850, emitted at ≈ 6502): wraps
  one instrumented op; re-runs the interpreter on that single op from the
  captured pre-state and compares.

Both share **two fatal properties** for this class of bug:

1. **Re-seeding.** Each comparison reseeds the gold interpreter from the JIT's
   *own current live state*. So if the JIT drifts in block N and that wrong
   value only faults/hangs in block N+k, every per-block comparison still reads
   `mismatch=0`, because interp-replay and native-replay start from the *same
   already-drifted* state and agree. This is exactly the observed
   "clean everywhere I window, yet 780s hang at `0100254e`."

2. **Forced flag materialization.** The per-op path emits `flush(1)` *before*
   the verify callout (line ≈ 6505), and every block boundary flushes flags.
   The CRC bug is a **flag-liveness drop** (`needed_flags` drops EOR.B's N
   because the terminal Bcc's own cc-use isn't OR'd in). Instrumenting with a
   flush **materializes the very flag the bug drops**, hiding it. Snapshot
   granularity therefore cannot see an intra-block, never-materialized NZCV.

Plus the comparator carries known **layout artifacts**: stale `regs.pc`
(native `regs.pc` = block-start while `pc_p` is correct → c74 red herring),
and raw `nzcv` vs `cznv` word compares (`flag_struct.cznv` is the byte-shuffled
x86-mirror layout: N=bit7, Z=bit6, V=bit11, C=bit0; host PSTATE NZCV is
N=31/Z=30/C=29/V=28 — comparing raw words is meaningless).

**Conclusion:** we need *two continuously-independent* architectural states,
advanced in true lockstep at **instruction granularity**, compared in
**canonical M68K layout**, halting at the **first** real divergence — and the
JIT side must be observed **without any added flush**.

---

## 2. Design principle

```
  GOLD (interpreter)            DUT (JIT, real machine)
  ----------------              -----------------------
  own regs' + own RAM' copy     real regs + real RAM
  step exactly 1 m68k insn      run 1 m68k insn (native handler)
        |                              |
        +---------- compare ----------+   canonical CCR + 16 regs + next-PC + touched mem
        |
   first mismatch  -> dump both states in canonical layout, halt, exit(42)
```

- The gold side never reads DUT state after arming (no re-seed). It is seeded
  **once** when the window is first entered, then runs free.
- Comparison is **per-instruction**, not per-block, so an intra-block dropped
  flag is caught at the exact producer op.
- The DUT is observed by a **read-only, flush-free** state-dump callout
  (the "same-PC full-state-dump" family). It must not perturb liveness.

---

## 3. Non-perturbation — the hard constraint

The DUT callout must capture live NZCV **without** calling `flush()`,
`flush_flags()`, `dont_care_flags()`, or anything that mutates the
register-allocator / flag-liveness bookkeeping. Requirements:

- **Flags:** emit a raw `MRS Xn, NZCV` (host PSTATE) into a scratch GPR, then
  store that word to a fixed C global (`g_ls_dut_pstate`). This reads the *same*
  live NZCV the next op would consume. It does **not** invoke `flush_flags()`,
  so the don't-care drop under test is preserved. Add one raw encoder
  `compemu_raw_mrs_nzcv(reg)` in `codegen_arm64.h` (MRS NZCV = `0xD53B4200|Rt`)
  — pure read, no allocator state touched.
- **X flag:** the X bit is kept in `regflags.x`, materialized by the existing
  flag machinery; capture it by storing `live_flags`'s x slot only if it is
  already resident. Simplest correct option: in the window, force X to be
  materialized to memory per op via the existing `preserve_flags_before_nzcv_clobber`
  *only when X is the operand under test*; otherwise read `regflags.x`. (X is not
  the c74 producer; N is. Keep X handling minimal and document it as a known
  lower-fidelity field until needed.)
- **GP/addr regs:** store live vregs to the `regs.regs[0..15]` mirror via a
  **copy-out that does not free/anti-alias** the allocator. Use the existing
  `flush(1)` *machinery internals* only in a non-committing form — i.e. add
  `jit_ls_writeback_regs()` that, for each of D0..D7/A0..A7, if the vreg is
  resident emits `STR` to `&regs.regs[i]` **without** marking it clean/free
  (no `remove_offset`, no `f_disassociate`). Registers are not the perturbation
  risk (the bug is flags), so a plain non-freeing writeback is sufficient and
  proven safe by analogy to the existing `flush` STR path.
- **Next-PC:** do **not** read `regs.pc` (stale). Emit `compemu_raw_set_pc_i`-style
  materialization of `pc_hist[i+1].location` → guest PC = `host_to_m68k(loc)` and
  store to `g_ls_dut_nextpc`. This is the value the comparator treats as
  authoritative PC.

The callout target is a C function `jit_ls_dut_dump(uae_u32 cur_m68k_pc, uae_u32 opcode)`
that reads `g_ls_dut_pstate`, `g_ls_dut_nextpc`, the `regs.regs[]` mirror, and
`regflags.x`, packs them into the canonical vector (§5), and runs the compare (§6).

---

## 4. Hook sites (exact anchors)

### 4.1 Arming / window gate
Add env ranges parsed by the existing `jit_pc_in_env_ranges()` machinery
(`compemu_support_arm.cpp` ≈ line 517 env table):

- `B2_JIT_LOCKSTEP_PCS` — window range(s), e.g. `0x01002400-0x01002700`.
- `B2_JIT_LOCKSTEP_MAXSTEPS` — safety cap (default 200000).
- `B2_JIT_LOCKSTEP_DUMP_RADIUS` — bytes of touched-mem window to diff (default 64).

Add `static inline bool jit_lockstep_target_pc(uae_u32 pc)` next to
`jit_trace_target_pc` (≈ line 576).

### 4.2 DUT per-op dump emission
In the compile loop, in the **same `if (_verify_this_op || _trace_this_op)`
family** at ≈ 6502, add a parallel `_lockstep_this_op = jit_lockstep_target_pc(op_m68k_pc)`
branch that, **after** `comptbl[...](opcode)` compiles the op (so we capture the
post-op state) and **without** the pre-op `flush(1)`, emits:

```
  jit_ls_writeback_regs();              // non-freeing STR of resident vregs
  compemu_raw_mrs_nzcv(scratch);        // live host PSTATE, NO flush_flags
  compemu_raw_mov_l_rm? -> store scratch to &g_ls_dut_pstate
  set g_ls_dut_nextpc = host_to_m68k(pc_hist[i+1].location)
  compemu_raw_mov_l_ri(REG_PAR1, op_m68k_pc);
  compemu_raw_mov_l_ri(REG_PAR2, opcode);
  compemu_raw_call((uintptr)jit_ls_dut_dump);
  // re-init_comp(); restore comp_pc_p; (same pattern as trace branch)
```

Critical: the dump is emitted **inline mid-block**, between ops, and must
`init_comp()`/restore `comp_pc_p` like the trace path so the next op still
compiles into the same block (do **not** set `was_comp=0` unless the bug
reproduces only at block heads — keep block shape identical to an uninstrumented
run so liveness is unchanged).

### 4.3 GOLD interpreter step + compare driver
`jit_ls_dut_dump()` is the synchronization point. On each call:

1. If gold not yet armed for this window: seed gold state once
   (see §4.4), set `g_ls_armed=true`, record `g_ls_expect_pc = cur_m68k_pc`.
2. Assert `cur_m68k_pc == g_ls_expect_pc`; a control-flow mismatch here is
   itself a divergence (DUT took a different branch) → dump+halt.
3. Advance GOLD by exactly one instruction at `g_ls_gold_pc`:
   `op = get_opcode_cft_map(get_word(g_ls_gold_pc)); (*cpufunctbl[op])(op);`
   executed against the **gold shadow** (see §4.4), updating gold regs/flags/mem.
4. Build canonical vectors for GOLD and DUT (§5), compare (§6).
5. Set `g_ls_expect_pc = g_ls_dut_nextpc` (DUT-authoritative next PC) and
   `g_ls_gold_pc = ` gold's own computed next PC; if they differ → divergence.

### 4.4 Gold shadow state
Two viable implementations, cheapest first:

- **(Cheap, recommended first) single-RAM swap.** Keep one extra `regstruct
  g_ls_gold_regs`, `flag_struct g_ls_gold_flags`, and a malloc'd
  `g_ls_gold_mem` (RAMSize+ROMSize), seeded once on arming. To step gold,
  temporarily swap the globals (`regs`/`regflags` and a RAM pointer indirection)
  to the gold copies, run one `cpufunctbl` op, swap back. This reuses the
  proven `jit_block_verify_snapshot_capture/restore` primitives (≈ 624/643) but
  **without re-seeding from DUT** — seed once, then only swap. Cost: per-op two
  `regstruct` swaps + RAM-pointer swap (no full RAM memcpy per step). RAM is
  shared storage; to keep gold and DUT memory independent you must mirror writes
  — see (b) if shared RAM is unacceptable.
- **(Correct, heavier) dual RAM.** Gold gets its own `RAMBaseHost'`; the
  interpreter's `get/put` for the gold step is redirected to the gold bank via a
  thread-local base. This fully isolates memory. Only needed if the divergence
  is a memory-write divergence; for the CRC/flag bug, registers+flags+next-PC
  catch it first, so start with (a) and diff only a **touched-mem window**
  (`B2_JIT_LOCKSTEP_DUMP_RADIUS` around each op's EA) rather than full RAM.

For the `0100254e` CRC bug specifically, **(a) with register+flag+next-PC
compare and no RAM diff** is the cheapest path to first-divergence and is
expected to fire at the EOR.B/BPL producer the moment N is read stale.

---

## 5. Canonical state vector (kills the 3 known artifacts)

Reduce **both** sides to this before compare — never compare raw host words:

```c
struct ls_arch {
    uae_u32 d[8], a[8];   // D0..D7, A0..A7 (A7 = active SP)
    uae_u32 next_pc;      // guest PC of next insn (NOT regs.pc)
    uae_u8  ccr;          // canonical M68K CCR: bit4=X bit3=N bit2=Z bit1=V bit0=C
};
```

- **PC:** gold uses its computed next PC; DUT uses `g_ls_dut_nextpc`
  (`host_to_m68k(pc_hist[i+1].location)`). `regs.pc`, `pc_oldp`, `fault_pc`
  are **never** compared. Kills the stale-pc / c74 artifact.
- **CCR (kills nzcv/cznv artifact):** decode each side to the 5 boolean bits.
  - GOLD: from `regflags.cznv` via `GET_NFLG/GET_ZFLG/GET_VFLG/GET_CFLG` and
    `regflags.x` (m68k.h: N=bit7, Z=bit6, V=bit11, C=bit0).
  - DUT: from the captured host PSTATE `g_ls_dut_pstate`
    (N=bit31, Z=bit30, C=bit29, V=bit28) + `regflags.x`.
  - Compare only the assembled 5-bit `ccr`. Layout differences become
    structurally impossible to misread.
- **spcflags / countdown / interrupt_flags:** excluded (dispatcher state).

---

## 6. Divergence detection + dump

```
compare(gold.ls_arch, dut.ls_arch):
  if equal: g_ls_steps++; if g_ls_steps>MAXSTEPS -> "no divergence in window" exit(0)
  else:
    fprintf(stderr,
      "LOCKSTEP_DIVERGE step=%lu pc=%08x op=%04x field=%s\n", ...);
    // per-field, only the differing fields:
    //   reg d%d/a%d  gold=%08x dut=%08x
    //   nextpc       gold=%08x dut=%08x
    //   ccr          gold=X?N?Z?V?C? dut=X?N?Z?V?C?
    // plus a 4-op back-trace ring of (pc,opcode) leading in
    halt: raise(SIGABRT) or exit(42)
```

The **first** line is the answer: the earliest PC + field where JIT and a
free-running interpreter disagree, in canonical layout, with no snapshot
reseed and no flush masking. For the CRC bug the predicted first hit is:

```
LOCKSTEP_DIVERGE pc=01002c7e op=6a.. field=ccr  gold=...N0... dut=...N1...
```

(i.e. BPL at `2c7e` reads N — gold N reflects EOR.B `2c7c`, DUT N is stale)
— or one op earlier at the EOR.B if we compare CCR post-producer. Either way it
names the exact instruction, which the per-block oracle structurally cannot.

---

## 7. Cheapest path to first-divergence at `0100254e`

1. Arm `B2_JIT_LOCKSTEP_PCS=0x01002400-0x01002700` (the confirmed spin window).
2. Gold = single-RAM-swap shadow (§4.4a), **register+flag+next-PC compare only**,
   no RAM diff (DUMP_RADIUS=0). This is the minimal config that catches a
   register/flag/branch divergence and is enough for a CRC/Bcc-liveness bug.
3. Run pure-JIT boot (`optlev=2`, no Bcc barrier) until LOCKSTEP_DIVERGE fires.
4. If it fires on `next_pc` only (branch taken differently) walk back the 4-op
   ring to the flag producer; if on `ccr`, you already have the producer.
5. Only if no register/flag/PC divergence appears in the whole window (unlikely)
   escalate to dual-RAM (§4.4b) + touched-mem diff to catch a silent memory
   write divergence.

Expected total new code: ~1 raw encoder (`mrs_nzcv`), ~1 non-freeing reg
writeback helper, ~3 globals, ~1 env gate, ~1 compile-loop branch (~25 lines
mirroring the existing trace branch), ~1 `jit_ls_dut_dump` + gold-step driver
(~120 lines reusing snapshot capture/restore). No gencomp regeneration needed
(all in `compemu_support_arm.cpp` + `codegen_arm64.h`).

---

## 8. Build / run / validation plan (when A is greenlit)

```bash
cd BasiliskII/src/Unix && make -j$(nproc)          # no gencomp change
# regression must stay green (tracer is default-OFF / env-gated):
cd /workspace/projects/macemu && ./jit-test/run.sh # expect pass=297 fail=0

# first-divergence run:
cd BasiliskII/src/Unix
B2_JIT_LOCKSTEP_PCS=0x01002400-0x01002700 \
timeout 120 ./BasiliskII --rom /workspace/projects/rpi-basilisk2-sdl2-nox/Quadra800.ROM \
  --disk /workspace/fixtures/basilisk/images/HD200MB --ramsize 8388608 \
  --modelid 14 --cpu 4 --nogui 2>&1 | grep -m1 LOCKSTEP_DIVERGE
```

Acceptance gates:
- Tracer default-off ⇒ `jit-test/run.sh` unchanged (297/0) and a normal boot
  byte-identical in block shape to pre-change (diff `JIT_CODEGEN` sizes if needed).
- Tracer-on ⇒ emits exactly one `LOCKSTEP_DIVERGE` line naming a concrete
  `pc`+`field`, reproducible across runs.
- Self-test: arm the window on a **known-good** block (e.g. a plain ALU chain in
  the ROM that already verifies clean) ⇒ must report `no divergence` to prove
  the tracer doesn't manufacture false positives from its own layout decode.

---

## 9. Risks & mitigations

- **R1 — the dump callout itself perturbs liveness.** Mitigation: dump is
  MRS-read + non-freeing STR only; no `flush_flags/dont_care/flush(1)`. Validate
  R1 by comparing `JIT_CODEGEN` block boundaries with tracer on vs off — block
  shapes must match. If they don't, the instrumentation moved a boundary and the
  result is suspect.
- **R2 — gold shadow desync from shared RAM (§4.4a).** For pure register/flag
  bugs this is fine; if the window writes memory that feeds back into flags,
  promote to dual-RAM (§4.4b). Documented as the escalation step, not the default.
- **R3 — A7/SP and supervisor-stack aliasing** when the window crosses an
  exception. Mitigation: if `cur_m68k_pc` leaves the window or SR S-bit toggles,
  stop the window cleanly (`g_ls_armed=false`) rather than chase trap frames;
  re-arm on re-entry. The `0100254e` CRC spin is user-mode steady-state so this
  should not trigger.
- **R4 — X-flag fidelity** (§3). N/Z/V/C are exact; X is best-effort until a bug
  needs it. The CRC bug is N, so this does not block.

---

## 10. One-paragraph summary for the decision

This replaces a snapshot oracle that *re-seeds the gold from the DUT every block*
and *flushes flags at every instrumented op* — two properties that make it
structurally unable to see accumulated drift or a never-materialized NZCV — with
a free-running interpreter held in true per-instruction lockstep against the real
JIT machine, observed by a flush-free MRS-NZCV + non-freeing register dump, and
compared only in canonical M68K CCR+reg+next-PC layout. It halts at the first PC
where the two architectures actually disagree. For `0100254e` the cheapest
config (single-RAM gold, register/flag/next-PC compare) is predicted to name the
CRC loop's flag producer directly — the answer the per-block oracle can only
red-herring around.
