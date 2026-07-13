# AArch64 JIT ADDX/SUBX and immediate-CCR audit

## Scope

This tranche audits one flag-lifecycle boundary rather than individual ROM PCs:

- register `ADDX` and `SUBX`, byte/word/long;
- aliased and distinct source/destination registers;
- incoming X, result C/X, N, V, and sticky Z;
- `ORI`, `ANDI`, and `EORI` to CCR before and after arithmetic flags;
- effective-zero register-count `ASL`, `ASR`, `LSL`, and `LSR` controls.

No workload address, encounter-order gate, or guessed host branch displacement is
part of the repair.

## Confirmed defects

### Narrow ADC/SBC arithmetic

The legacy AArch64 compatibility layer implements byte and word ADC/SBC by
placing the architectural operands in the high lane of a 32-bit ARM operation.
The previous ADC path filled the padding below that lane with zeroes, so incoming
X never propagated into the byte or word result. Both ADC and SBC also inherited
ARM Z from the padded 32-bit result, rather than deriving Z from the
architectural byte/word result.

The repaired ADC path fills the low padding with ones. ARM carry-in therefore
rolls that padding and enters the architectural lane exactly when X is set.
After ADC/SBC, `legacy_set_z_from_narrow_result()` reconstructs only NZCV.Z from
the final narrow result. The reconstruction is branchless (`CMP` + `CSET` +
`BFI`) and preserves N, C, V, and the current physical-C polarity contract.

### Sticky Z and SUBX carry polarity

Generated `ADDX`/`SUBX` performs the arithmetic first, snapshots its Z result,
then merges that value with the incoming sticky Z through `set_zero()`.
`set_zero()` modified only NZCV.Z but nevertheless reset
`flags_carry_inverted`. After narrow `SUBX`, this relabelled ARM's physical
no-borrow C as architectural borrow before X was duplicated, producing wrong
X/C while the numeric result could remain correct.

`set_zero()` now preserves the caller's carry-polarity state. It still changes
only Z.

### Immediate operations on CCR

The generator materialised each immediate into a JIT virtual register named
`src`, then used the numeric virtual-register identifier itself to construct the
CCR mask. Consequently `ORI`/`ANDI`/`EORI` to CCR could apply allocator metadata
instead of the guest immediate.

`gencomp.c` is authoritative. For byte-size ORSR/ANDSR/EORSR it now reads the
known extension word at compile time into `ccr_imm` and passes the mapped guest
bits to `jff_ORSR`, `jff_ANDSR`, or `jff_EORSR`. The generated
`BasiliskII/src/Unix/compemu.cpp` is committed and regeneration is byte-stable.

## Mismatch-first evidence

Before the family repair, forced-native alias vectors produced:

- `ADDX.B/W D2,D2` with incoming X: wrong zero result instead of `D2=1`;
- `SUBX.B/W/L D2,D2` with incoming X: the numeric all-ones result survived, but
  JIT SR was `0x2708` instead of interpreter SR `0x2719`.

The effective-zero `ASL`/`ASR`/`LSL`/`LSR` controls passed for all three widths,
so no shift emitter change was justified.

## Dynamic coverage

The focused strict-native gate has 48 vectors and covers:

- all `ADDX`/`SUBX` widths;
- aliased and distinct register allocation;
- X=0 and X=1;
- carry/borrow and signed overflow;
- zero and nonzero results with incoming sticky Z both set and clear;
- exact and post-borrow `ORI`/`ANDI`/`EORI` CCR lifecycles;
- a cleared-X ROX control to guard cross-family flag contamination.

Every JIT case is forced through L2 native execution and fails closed on
opt-level-zero compilation, interpreter fallback, or unstated execution.

## Acceptance evidence

- Focused family gate: **48/48**, `fail=0`, `infra_fail=0`,
  `fail_equiv=0`.
- Complete active gate: **476/476**, score 100, `fail=0`, `infra_fail=0`,
  `fail_equiv=0`, `risky_fail_equiv=0`.
- Allocator-pressure replay: interpreter and JIT dumps byte-identical,
  `natexec=32`, `interpop=2` at the explicit reference boundary.
- Opcode registration: all **48,282** legal encodings classified as 46,087
  native-generated, 2,127 semantic services, and 68 architectural traps;
  zero null/interpreter fallback and zero normal/no-flags parity gaps.
- Generated `compemu.cpp` is reproducible across repeated regeneration, SHA-256
  `961a3558ef7f09e86b6750f05c36f0035a363bbbf389ed093e11059982121b9b`.
- Structural audit, shell syntax check, and `git diff --check` pass.
- Ordinary and strict Finder runs each scheduled 24,120,000 retirements,
  retained 16,777,216 PCs, reached 21 `DiskStatus 43` events, and reported no
  host fault. Captures are byte-identical, SHA-256
  `1a05d539dc51f4fa39cd2cc02e5e7c90faeedcab054ab6b4d156d8022db06b73`.
  All 24 strict summaries retain `opt0=0 fallback=0 exec_nostats=0`.

## Validation host

Host-native Orange Pi 6 Plus, CIX P1 (`CD8180`/`CD8160`) 12-core AArch64 SoC,
16 GB-class RAM (about 14 GiB visible), Debian Trixie, NVMe root storage.
