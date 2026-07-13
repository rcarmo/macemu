# AArch64 JIT ABCD/SBCD/NBCD audit

## Scope

This tranche audits `ABCD`, `SBCD`, and `NBCD` as one architectural family:

- register and predecrement memory forms;
- the 68040 decimal-correction equations, including non-decimal input nibbles;
- incoming X, result C/X, and sticky Z;
- preservation of the architecturally unchanged N and V bits;
- source/destination aliasing and ordered same-register predecrement;
- A7's two-byte byte-access stride;
- exact-opcode, fail-closed native execution.

No ROM address, workload encounter order, interpreter escape, or fixed host
instruction count is part of the repair.

## Confirmed defects

### Arithmetic model

The old AArch64 helpers implemented plausible per-digit BCD arithmetic rather
than the authoritative 68040 equations in `gencpu.c`. That diverged on decimal
correction boundaries and on invalid input nibbles. The family now shares three
arithmetic cores which preserve the interpreter's exact intermediate widths and
correction predicates:

- `emit_abcd_b()`;
- `emit_sbcd_b()`;
- `emit_nbcd_b()`.

All conditional correction joins use emitted placeholders followed by
`write_jmp_target()`. No numeric AArch64 displacement crosses variable-length
immediate materialisation.

### X/C and sticky-Z lifecycle

BCD instructions always publish C, copy C to X, and update sticky Z as
`old_Z && byte_result == 0`; N and V are unchanged. The old split flag/no-flags
path could leave architectural flags stale at a block or observer boundary.

`emit_bcd_flags()` now owns the family lifecycle. It snapshots incoming NZCV,
merges only Z, replaces C from the decimal carry/borrow, restores NZCV, and the
handler copies the same carry/borrow to `FLAGX`. `gencomp.c` routes every
`ABCD`, `SBCD`, and `NBCD` form through `jff_*`; no `jnf_*` BCD handler remains.

### A7 predecrement geometry

The hand-written `ABCD`/`SBCD` predecrement generator subtracted one byte from
every address register. On 68040 byte accesses A7 decrements by two. Exact-PC
native replay exposed this directly: source-A7, destination-A7, and
`-(A7),-(A7)` JIT cases ended with A7 one or two bytes too high while the
interpreter produced the architectural addresses.

Both source and destination updates now use
`-areg_byteinc[reg]`, in source-read then destination-read order. The aliased
A7 form therefore performs both two-byte decrements before the destination
read. `NBCD` already used the generic effective-address path and was the clean
single-EA control.

## Harness repair required for exact evidence

A replay anchored after a setup prefix must restore the architectural input
state. Memory-EA vectors additionally need their source/destination bytes
restored before every trace/native replay; otherwise the first BCD pass mutates
the oracle for the next pass.

`B2_TEST_REPLAY_BYTES` is a test-only RAM-relative address/value list consumed
by `basilisk_glue.cpp` before each replay. `run.sh` supplies it only for the
seven BCD predecrement vectors. Prefix-bearing vectors use two exact-PC
replays: the first compiles the audited anchor and the second must enter it
natively. The four opcode-only vectors need one replay.

This closes the earlier validation gap where native entry was asserted at
`0x1000`, the start of a setup sequence, rather than at the BCD opcode.

## Mismatch-first evidence

Before repair:

- exact opcode-only invalid-nibble vectors disagreed on BCD result/flags;
- exact `ABCD`/`SBCD` predecrement replay left source or destination A7 one
  byte too high;
- exact `-(A7),-(A7)` replay left A7 two bytes too high;
- interpreter controls for the same memory images and replay PCs passed.

The repair was applied to the complete family and generator contracts, not to
the individual witnesses.

## Dynamic coverage

The focused gate contains 31 vectors:

- all three operations with X=0 and X=1;
- sticky-Z set, clear, retained, and cleared histories;
- carry/borrow chains and zero/nonzero results;
- decimal `00`, `01`, `09`, `10`, and `99` boundaries;
- non-decimal nibbles which distinguish the 68040 equations;
- aliased and distinct data registers;
- source-A7, destination-A7, same-A7, and single-EA A7 predecrement;
- four opcode-only initial-state vectors;
- exact native entry at every audited BCD opcode PC.

Every JIT replay fails closed on opt-level-zero compilation, fallback, or
unreported execution. The accepted focused result is **31/31**, with
`fail=0`, `infra_fail=0`, `fail_equiv=0`, and score 100.

## Structural guards

`jit-test/structural-audit.ts` now requires:

- one shared BCD flag lifecycle and no `jnf_*` BCD handlers;
- seven patched local correction joins;
- `areg_byteinc[]` source and destination predecrement geometry;
- generated `jff_*` routing in both `gencomp.c` and `compemu.cpp`;
- exact-PC replay state and replay-memory restoration.

## Acceptance evidence

- focused exact-PC BCD gate: 31/31;
- exact memory/predecrement subset: 7/7;
- complete risky corpus: 507/507, score 100, with zero equivalence,
  infrastructure, timeout, emulator-exit, dump, and sentinel failures;
- allocator-pressure control: interpreter/JIT state identical, with 32 native
  entries and two first-seen trace observations;
- legal opcode classification: 48,282/48,282 = 46,087 native-generated +
  2,127 semantic services + 68 architectural traps + zero fallback/null;
- normal/no-flags table parity gaps: zero;
- clean AArch64 rebuild: pass;
- generated `compemu.cpp`: byte-reproducible, SHA-256
  `09758be160430afd9222fe57499207eb361093e7f036d4fba63ff2e31aecefea`;
- deterministic ordinary and strict Finder schedules: 24,120,000 retirements,
  16,777,216-PC retained windows, 21 `DiskStatus 43` events, and no host fault
  in each mode; windows byte-identical at SHA-256
  `1a05d539dc51f4fa39cd2cc02e5e7c90faeedcab054ab6b4d156d8022db06b73`,
  with strict `opt0=0 fallback=0 exec_nostats=0`;
- strict negative contracts, structural audit, shell syntax, and source hygiene:
  pass.

## Validation host

Host-native Orange Pi 6 Plus, CIX P1 (`CD8180`/`CD8160`) 12-core AArch64 SoC,
16 GB-class RAM (about 14 GiB visible), Debian Trixie, NVMe root storage.
