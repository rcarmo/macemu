# AArch64 JIT division lifecycle audit

Date: 2026-07-14

Branch: `structural-audit`

Base: `1aeb577e` (`ABCD`/`SBCD`/`NBCD` family accepted)

## Scope

This tranche re-audits division as one result, flag, and exception lifecycle:

- signed word overflow in `jff_DIVS`;
- signed and unsigned 32/32 DIVL in `jnf_DIVLS32`, `jff_DIVLS32`,
  `jnf_DIVLU32`, and `jff_DIVLU32`;
- signed and unsigned 64/32 DIVL in `jnf_DIVLS64`, `jff_DIVLS64`,
  `jnf_DIVLU64`, and `jff_DIVLU64`;
- divide-by-zero request publication and exact format-2 exception state;
- quotient overflow, destination preservation, incoming Z/X, and outgoing N/V/C;
- quotient/remainder and divisor/remainder aliases;
- generated flag-live and no-flags reachability.

The audit was source-inventory-led. It did not use a ROM PC, workload encounter
order, or a guessed ARM64 instruction count as a fix.

## Mismatch-first evidence

Before the repair, exact-PC forced-native vectors for signed 32/32
`INT32_MIN / -1` both failed:

- the flag-live form overwrote the distinct remainder register instead of
  leaving both result registers unchanged and publishing overflow;
- the no-flags form made the same architectural write even though a following
  `MOVEQ` made the DIVL flags dead.

The focused pre-fix gate therefore passed 0/2. Both failures entered native L2
at the DIVL opcode; neither was an interpreter fallback or opt-level-zero run.

A second witness seeded Z before signed 64/32 overflow. The old `jff_DIVLS64`
performed `CMP` and then copied the resulting host NZCV while claiming to
preserve incoming Z. It returned SR `271a`; the interpreter returned `271e`.
The same lifecycle defect existed in signed word overflow and the newly audited
signed 32/32 path.

## Root causes

### Signed 32/32 overflow was not representable

The old signed 32-bit helpers used AArch64 `SDIV.W`. For
`0x80000000 / 0xffffffff`, AArch64 returns `0x80000000`; the helper then treated
that saturated low word as a valid quotient. The 68040 contract instead sets
N/V, clears C, preserves Z/X, and leaves both destination registers unchanged.

### Exception and overflow paths skipped pure-write destinations

The 32-bit helpers allocated `rem` with `writereg(rem)` before checking for a
zero divisor. A branch around the arithmetic could therefore leave a pure-write
mapping on a path where the architectural remainder register must not change.

### Signed fit comparisons destroyed incoming Z

Signed word and long helpers used `ANDS`/`CMP` to detect overflow, then read
host NZCV to build the architectural result. At that point host Z described the
fit comparison, not the incoming M68K Z bit which overflow must preserve.

### Internal targets encoded emitter length

The no-flags DIVL helpers retained hard-coded branch distances over exception,
overflow, and store sequences. These targets silently depended on the number of
ARM64 instructions emitted by each path.

## Structural repair

- Signed 32/32 division now sign-extends dividend and divisor, performs
  `SDIV.X`, sign-extends the low quotient, and compares it with the full
  quotient. This makes `INT32_MIN / -1` an explicit overflow path.
- All 32-bit remainder destinations use read/modify/write allocation, preserving
  their old value across divide-by-zero and overflow.
- Successful helpers retain interpreter ordering: remainder first, quotient
  second, so quotient wins when Dq aliases Dr.
- Every zero, fit, and overflow join in all eight DIVL helpers is emitted with a
  placeholder and patched by `write_jmp_target()`. The family now contains 28
  structurally patched joins and no non-zero numeric internal displacement.
- Signed DIVL flag-live paths restore overflow flags from the saved incoming
  `FLAGTMP` value after host comparisons. Signed word DIVS snapshots NZCV before
  its fit tests. N/V are set, C is cleared, and incoming Z/X survive.
- `jit-test/structural-audit.ts` rejects fixed non-zero DIVL joins,
  `writereg(rem)` on the conditional-write paths, a return to `SDIV.W`, missing
  saved-flag restoration, or loss of exact-PC test state.

## Exact-native coverage

Sixteen new vectors cover:

- signed word overflow with incoming Z set, through register and immediate divisors;
- signed 32/32 `INT32_MIN / -1`, flag-live and no-flags;
- signed and unsigned 32/32 divide-by-zero with distinct Dq/Dr;
- signed and unsigned successful no-flags quotient/remainder writes;
- Dq/Dr alias ordering in both signedness modes;
- divisor/Dr alias ordering in both signedness modes;
- signed and unsigned 64/32 overflow, flag-live and no-flags.

Every vector replays at its exact division opcode PC with explicit D0-D7,
A0-A7, and SR restoration. Accepted JIT logs contain `NATEXEC` at that PC and
strict summaries with `opt0=0 fallback=0 exec_nostats=0`.

## Acceptance evidence

- mismatch-first signed 32/32 overflow gate before repair: 0/2;
- post-repair exact-PC division gate: 16/16, score 100;
- existing division regression subset: 19/19, score 100;
- complete strict-native risky corpus: 523/523, score 100, with zero semantic,
  infrastructure, timeout, emulator-exit, dump, or sentinel failures;
- structural DIVL branch joins: 28/28 patched; zero non-zero numeric joins;
- allocator-pressure control: interpreter/JIT state identical, 32 native
  entries and two first-seen trace observations; teardown exits cleanly;
- generated `compemu.cpp` unchanged and reproducible at SHA-256
  `09758be160430afd9222fe57499207eb361093e7f036d4fba63ff2e31aecefea`;
- deterministic ordinary and strict Finder schedules each reached 24,120,000
  retirements, retained 16,777,216 PCs, reached 21 `DiskStatus 43` events, and
  had no host fault. Captures are byte-identical at SHA-256
  `1a05d539dc51f4fa39cd2cc02e5e7c90faeedcab054ab6b4d156d8022db06b73`;
  strict execution reports `opt0=0 fallback=0 exec_nostats=0`;
- clean AArch64 build, shell syntax, structural audit, and `git diff --check`:
  pass.

## Validation host

Host-native Orange Pi 6 Plus, CIX P1 (`CD8180`/`CD8160`) 12-core AArch64 SoC,
16 GB-class RAM (about 14 GiB visible), Debian Trixie, NVMe root storage.
