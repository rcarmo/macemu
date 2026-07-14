# AArch64 JIT long-multiply lifecycle audit

Date: 2026-07-14

Branch: `structural-audit`

Base: `01a04904` (fixed-memory shift and ROX tranche accepted)

## Scope

This tranche audits 68020/68040 `MULL` as one generator, MIDFUNC, allocator,
result, and flag lifecycle:

- signed and unsigned 32x32 multiplication;
- selected 32-bit and 64-bit result forms;
- flag-live and no-flags paths;
- full-product N/Z and signed/unsigned overflow;
- low/high destination ordering and aliasing;
- source/low, source/high, low/high, and all-three register aliases;
- register, immediate, and memory sources;
- generated declaration and legacy-compatibility signatures;
- live virtual-register ownership while a memory source allocates scratch state.

The audit was source-inventory-led. It did not use a ROM PC, workload encounter
order, or a guessed ARM64 instruction count as a fix.

## Mismatch-first evidence

Four exact-PC forced-native vectors failed before the repair:

- a negative signed product which fits 32 bits set V;
- a distinct source register was overwritten by the high half of a 64-bit
  unsigned product;
- a source/low alias lost its required low result;
- an aliased low/high destination published the wrong architectural result.

The pre-fix gate passed 0/4. The harness classified the failures as explicit
architectural-register mismatches; they were not timeouts, missing dumps,
opt-level-zero translations, or interpreter fallbacks.

After the MIDFUNC repair, a dedicated memory-source pressure cell exposed a
second contract failure. Forced scratch allocation evicted and reused a live
aliased Dl virtual before `jnf_MULU64` consumed it. Interpreter and JIT state
diverged (`D0=3428e2d6` versus `D0=b7b4e09f`, with different D1 and SR), so a
baseline register-rich pass could not close the family.

## Root causes

### The source operand was also an implicit destination

The old 64-bit MIDFUNC ABI accepted `(d, s)`, formed the low product in `d`, and
published the high product through `s`. That made a source operand an
undocumented write destination. It corrupted a distinct architectural source
and made source/result aliases depend on allocator accident rather than 68040
write ordering.

### Selected-32 flags described the truncated low word

The old selected-32 paths used a 32-bit multiply followed by a 32-bit test.
They therefore could not distinguish a full product of zero from a non-zero
product whose low word was zero, and signed overflow was inferred from host
multiply state rather than from whether the mathematical 64-bit product fits a
signed 32-bit result.

### Generator lifetime ended before source materialisation was safe

For a memory source, `genamode()` can allocate the S1 scratch virtual. Under a
forced S1-to-Dl host-register collision, that allocation could overwrite the
still-live Dl value before the MULL MIDFUNC staged its operands. Pinning or
choosing a fixed work register inside the MIDFUNC cannot repair a value already
lost in the generator.

## Structural repair

- The AArch64 64-bit MULL ABI is now explicit: `(dl, dh, s)`. Low and high
  halves are published only to architectural destinations; the source is
  read-only.
- All 64-bit variants stage both multiplicands before any architectural result
  publication. They compute one full 64-bit product, publish high before low,
  and therefore retain the interpreter's rule that Dl wins when Dl equals Dh.
- Signed and unsigned selected-32 flag-live variants test the full 64-bit
  product for N/Z. Signed V compares the product with the sign extension of its
  low word; unsigned V tests whether the high word is non-zero. C remains clear
  and X remains untouched.
- The authoritative `i_MULL` generator binds explicit Dl and Dh destinations,
  and keeps Dl under `jit_value_lock` while the source effective address is
  generated and fetched. The lock is released once S1 is safely allocated;
  the MIDFUNC then stages Dl before any later operand acquisition can evict it.
  This prevents scratch allocation from destroying a live input while
  preserving existing allocator policy.
- AArch64 declarations and the legacy compatibility wrapper use the same
  explicit three-operand contract. Generated `compemu.cpp` is derived from
  `gencomp.c`, not hand-patched.
- `jit-test/structural-audit.ts` rejects a return to the two-operand 64-bit ABI,
  source publication, low-word-only flags, missing full-product fit checks,
  missing Dl locking, or loss of the exact-PC/pressure witnesses.

## Exact-native coverage

Fourteen vectors cover:

- signed selected-32 negative fit and positive/negative overflow;
- unsigned selected-32 low-sign, high-overflow, and low-zero/full-nonzero flags;
- signed and unsigned selected-64 N/Z behavior;
- distinct source preservation;
- source/low, source/high, low/high, and all-three aliases;
- immediate and memory no-flags paths.

Every vector replays at the MULL opcode PC `0x1000`, restores explicit D0-D7,
A0-A7, SR, and replay memory where applicable, records `NATEXEC` at that exact
PC, and reports strict `opt0=0 fallback=0 exec_nostats=0` accounting.

## Acceptance evidence

- mismatch-first exact-PC gate before repair: 0/4;
- post-repair focused exact-PC gate: 14/14, score 100, with zero semantic or
  infrastructure failures;
- complete active-risky corpus: 671/671, score 100, with zero semantic,
  infrastructure, timeout, emulator-exit, dump, or sentinel failures;
- forced S1-to-Dl collision cell: interpreter/JIT state byte-identical, 32
  native entries and two first-seen trace observations; the established MULL
  and memory-ROX pressure controls also pass;
- structural MULL generator, ABI, product, flag, alias, and allocator-lifetime
  contracts: pass;
- post-registration coverage remains exhaustive: 48,282 legal encodings =
  46,087 native-generated + 2,127 ordered semantic services + 68 architectural
  traps, with zero fallback/null slots and zero normal/no-flags parity gaps;
- generated `compemu.cpp` reproduced byte-for-byte twice at SHA-256
  `eba0b5b0de7159f833c36839428f604cbf7d1ffaa6298108553804cd70c645a6`;
- clean AArch64 build followed by the 14/14 exact-PC gate and all pressure cells:
  pass;
- deterministic ordinary and strict Finder schedules each reached 24,120,000
  retirements, retained 16,777,216 PCs, reached 21 `DiskStatus 43` events, and
  had no host fault. Captures are byte-identical at SHA-256
  `1a05d539dc51f4fa39cd2cc02e5e7c90faeedcab054ab6b4d156d8022db06b73`;
  all 24 strict summaries report `opt0=0 fallback=0 exec_nostats=0`;
- the ordinary Finder run intentionally emitted no `JIT_STRICT_SUMMARY` because
  strict-full mode was disabled; ordinary acceptance is instead the completed
  bounded retirement path, matching byte count/hash, and zero host faults;
- shell syntax, structural audit, and `git diff --check`: pass.

## Validation host

Host-native Orange Pi 6 Plus, CIX P1 (`CD8180`/`CD8160`) 12-core AArch64 SoC,
16 GB-class RAM (about 14 GiB visible), Debian Trixie, NVMe root storage.
