# BasiliskII AArch64 JIT implementation review — 2026-09-06

Base: `3e799295` (`master`). Scope: source-cache revalidation/lifecycle and
width-sensitive no-flags constant folding. This is emulation-correctness work,
not security work or a performance tranche. July Finder work remains closed.

## Findings and fixes

### 1. Instruction permutations reactivated stale native code

`compemu_support_arm.cpp::calc_checksum` used an additive checksum and word XOR.
Both ignore word order. A replay changing the aligned groups
`7001 4E71 / 7002 4E71` to `7002 4E71 / 7001 4E71` preserved both sums.
The interpreter returned **D0=1**; cached native execution returned **D0=2**
with `direct_checksum=1 check_checksum=1 good=1 bad=0`.

The first experiment used `B2_TEST_REWRITE_HEX` for both engines. Its host-write
hook already invalidated the block, so it demonstrated checksum acceptance but
not stale execution. The retained regression instead uses existing
`B2_TEST_REPLAY_BYTES` to restore RAM in the JIT replay without that hook, while
forcing the existing `direct_pcc` validation boundary. No new production bypass
was added. Interpreter execution uses the rewritten stream as the oracle.
Full REGDUMP equality and the A6 completion sentinel are required, as well as
exact direct/helper/good/bad counters.

The secondary checksum now mixes four bytes per loaded word with XOR and
unsigned multiplication by 16777619. The accumulator persists across all span
links. The additive checksum, zero-source convention, span alignment/padding,
and lazy/direct-entry policies remain unchanged.

Independent early review rejected a wordwise multiply candidate: swapping
`[1, 0x80000001]` still preserved both values. Bytewise mixing fixes that
mechanism; an actual-body regression retains this case alongside the guest
instruction permutation. This remains a **non-cryptographic probabilistic
checksum**, not collision-free source comparison. No cryptographic machinery
or extra source snapshot allocation was introduced.

### 2. No-flags folds exceeded the guest operand width

In `compemu_midfunc_arm64_2.cpp`, `live.state[d].val` is host-width `uintptr`.
Five constant paths retained bits outside the guest result:

- `jnf_LSL_b_imm` / `jnf_LSL_w_imm`: mask the shifted result before merging
  preserved upper register bits.
- `jnf_LSL_l_imm`: shift a `uae_u32` operand.
- `jnf_ROL_l_imm` / `jnf_ROR_l_imm`: use a `uae_u32` temporary for both arms.

Adapted the Previous actual-body regression from commit `a137f14`. It extracts
production bodies and uses host-width state; unexpected runtime emission aborts.
Counts 0–63 over nine edge/pattern inputs use independent width/bit-rotation
oracles, including a following LSR.L that consumes excess bits.
Before: **1,846 failures / 7,488 checks**. After: **7,488/7,488**, under UBSan.
Production full-flags/no-flags selection is unchanged. Normal opcode equivalence
alone does not prove these no-flags constant paths executed. PC_P and other host
pointers are not globally truncated.

### 3. Incomplete checksum coverage could be accepted

Read-only lifecycle review found that invalid/oversized spans were skipped,
while `bi->csi != NULL` counted as sufficient checksum presence. An all-skipped
chain looked like valid zero-filled code; mixed chains ignored invalid spans.
This is reproduced at the actual-function level, **not demonstrated as a
reachable default guest failure**: normal traces are basic-block bounded.

`calc_checksum` now returns explicit validity. Missing metadata, null source,
nonpositive raw lengths and lengths exceeding `MAX_CHECKSUM_LEN` after alignment
are rejected before arithmetic. Revalidation requires validity AND matching
values. Valid all-zero code remains valid. Compilation may retain an invalid
span, but subsequent validation rejects it; no new fallback policy was added.

The actual-body checksum test reads the ARM backend's limit and runs under
ASan/UBSan. It covers permutations, zero source, missing/invalid metadata,
negative/zero/over-limit lengths (including extreme signed values), mixed
chains, all alignment offsets, rounding, chain order and the final maximum-span
word: **8,237/8,237**.

### 4. Harness exit status was masked

`if ! env ...; then emu_rc=$?` recorded the status of negation (zero), not the
failed emulator. Replaced it with `env ... || emu_rc=$?`. A failing command
returning 7 reproduced old `emu_rc=0`, corrected `emu_rc=7`; full validation then
passed with genuine exit-status checks. No emulator semantics changed here.

## Adjacent review

Independent read-only review traced descriptor/span allocation, rebuild/free,
lazy NEED_CHECK promotion, direct checksum PC publication, preferred-direct
repatching, mismatch invalidation and strict guest-cache disable. No additional
demonstrated lifecycle defect was found. This bounded review is not proof that
the whole emulator has no remaining defects.

## Validation

Hardware: Orange Pi 6 Plus, CIX P1 12-core AArch64 SoC, 16 GB class RAM,
NVMe storage; Debian Trixie, host-native agent runtime. Correctness runs used
private test disks and isolated X displays. No frequency control, timing
reservation, ROM edits or RAM presets were used.

| Gate | Result |
|---|---|
| Clean generated JIT-object rebuild (`make rebuild NPROC=1`) | pass |
| Final included-support rebuild (`make build NPROC=1`) | pass |
| Actual constant-fold bodies / UBSan | 7,488/7,488 |
| Actual checksum body / ASan + UBSan | 8,237/8,237 |
| Raw checksum interpreter/replay matrix | 4/4 ordinary; 4/4 strict |
| Strict negative contracts | pass |
| Maintained opcode vectors | 904/904; zero equivalence/infrastructure failures |
| Complete emitter/raw-boundary phase | 48 bounded suites; pass |
| Allocator pressure | 33/33 |
| Structural audit | pass |
| Closure regeneration, repeated hashes | 999 rows; zero unreviewed; deterministic |
| `git diff --check` | pass |

The first combined run exceeded its 1,800-second outer limit before final
vector totals. It is not counted as acceptance. Separate complete
`strict,vectors` and `structural,emitters` runs exited zero with
`validation_complete=1`.

The regenerated closure CSV changes only source-line coordinates (100 rows),
not classification/counts. Historical predecessor proofs retain their original
hashes by undoing only the two inserted constant-fold source lines during
reconstruction. `AARCH64_JIT_STRUCTURAL_AUDIT_COMPLETE.md` is untouched.

Evidence: `/workspace/reports/basilisk-jit-review-20260905/` contains failing
baseline logs, final build/body/replay/vector/emitter/pressure/structural logs
and repeated inventory hashes. Independent read-only review by `@previous`
approved the final changes and checked the saved acceptance logs and hashes.
Two initial non-blocking test notes (unsigned production span-length fidelity
and requiring validity from every valid-span call) were fixed, rerun and
independently confirmed closed before publication. The reviewer did not build
or run emulators. Separate session review used the same model family; automated
different-family delegation was unavailable under the configured exclusions.
No new boot, Finder responsiveness or performance claim is made.

## Reproduction

```sh
make test-constfold test-checksum
# Included .cpp dependencies are not tracked by the legacy Makefile:
touch BasiliskII/src/uae_cpu_2026/compiler/compemu_support.cpp
rm -f BasiliskII/src/Unix/obj/compemu_support.o
make build NPROC=1
./jit-test/raw-checksum-boundary-matrix.sh
./jit-test/run.sh --phases strict,vectors --build-mode skip
./jit-test/run.sh --phases structural,emitters --build-mode skip
./jit-test/regalloc-pressure.sh
bun jit-test/closure-inventory.ts
bun jit-test/structural-audit.ts
git diff --check
```
