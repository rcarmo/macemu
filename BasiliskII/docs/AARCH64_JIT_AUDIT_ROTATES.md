# AArch64 JIT ROL/ROR audit

## Scope

This tranche audits `ROL` and `ROR` as one architectural family across:

- register counts and immediate counts;
- byte, word, and long register destinations;
- word memory destinations;
- ordinary and no-flags generated handlers;
- the complete low-six-bit register-count contract;
- count-zero and non-zero-multiple carry semantics;
- legal source/destination aliases;
- constant-folded count values;
- allocator ownership; and
- authoritative/generated-source consistency.

No workload PC, ROM patch, encounter-order exception, or interpreter escape is
part of the repair.

## Confirmed defects

### Register counts used host modulo-32 behaviour

The original AArch64 helpers did not implement one explicit 68040 count
contract. `ROL` reduced the register count with a five-bit field operation;
`ROR` passed an unnormalised register directly to an AArch64 W-form rotate in
several paths. AArch64 therefore supplied modulo-32 behaviour where the guest
first requires the low six source bits. This loses the distinction between an
architectural zero count and a non-zero count of 32 for carry publication.

All register wrappers now mask the source to six bits before result and carry
work. Byte and word values are replicated into a 32-bit rotate lane, so the
result remains periodic at the guest width while the six-bit count remains
available for the architectural carry decision.

Constant-valued register sources are also reduced to six bits before entering
an immediate helper. This keeps constant and runtime wrapper contracts equal,
including a source value of 64 becoming architectural count zero.

### Flag-setting helpers were selected too late

The authoritative generator emitted the rotate through a no-flags wrapper and
then reconstructed N/Z/V/C with x86-oriented operations. On AArch64 this lost
the rotate helper's distinction between count zero and a non-zero multiple of
the operand width.

For AArch64, `gencomp.c` now starts the flag-producing region before emitting
the rotate. The wrapper therefore selects `jff_ROL_*` or `jff_ROR_*`, which owns
the complete N/Z/V/C lifecycle. The x86 post-operation reconstruction remains
unchanged behind its target conditional.

### Legal count/data aliases fell back

Generated register-count handlers rejected `srcreg == dstreg` before reaching
the AArch64 helper. The encoding is legal: the count is read from the original
register value before destination writeback.

AArch64 helpers now acquire the count with `readreg()`, acquire the destination
with `rmw()`, and release both ownerships after emission. The generator no
longer emits an alias fallback for AArch64. The old fallback remains for other
backends whose alias contract has not been proved by this tranche.

### Count-zero and carry joins depended on emitted instruction lengths

Several flag paths used fixed numeric `CBZ`/`TBZ` skip distances. Their target
therefore depended on the instruction count emitted by flag publication.
`ROR` immediate, register, and memory paths also duplicated this fragile carry
sequence.

Runtime joins now emit placeholder branches and patch their targets with
`write_jmp_target()`. Non-zero `ROR` carry is published with the shared
branchless `PUBLISH_CARRY_FROM_BIT` contract. Effective register count zero
clears C after the size-correct N/Z test, clears V, leaves the destination
unchanged, and does not modify X. `ROL` publishes C from result bit zero only on
the non-zero path.

### Memory no-flags handlers always generated flags

`ROLW` and `RORW` ignored the generator's `noflags` mode. Both generated
variants always entered `start_needflags()`, called `jff_ROLW` or `jff_RORW`,
and published flags even when a following instruction made them dead.

The authoritative generator now calls `jnf_ROLW` or `jnf_RORW` in no-flags
handlers while preserving the same `genamode()` fetch and `genastore()`
writeback order. Regeneration applies this contract to every legal memory
addressing mode.

## Dynamic coverage

The exact-native inventory contains 92 vectors.

The 72-vector register matrix covers both operations and all three widths with:

- runtime counts 0, 31, 32, 33, and 63;
- ordinary and no-flags handlers; and
- legal source/destination aliases in both flag modes.

Twenty supplemental vectors cover:

- constant-valued register count 64 for both operations and flag modes;
- encoded immediate count 8 for both operations, all widths, and both flag
  modes; and
- memory `ROLW`/`RORW` flag-live and no-flags writeback.

Every vector uses forced L2 replay at the audited opcode PC, requires a
`NATEXEC` observation, compares the final interpreter and JIT register state,
and fails closed unless strict summaries report `opt0=0`, `fallback=0`, and
`exec_nostats=0`.

The active risky corpus promotes 68 rotate vectors: the count-zero, count-32,
count-63, alias, constant, immediate, and memory lifecycle priorities. The
remaining adjacent-boundary vectors remain available through the focused exact
family gate.

## Structural guards

`jit-test/structural-audit.ts` requires:

- explicit six-bit count reduction in every runtime wrapper;
- masked constant wrapper values;
- `readreg()` before destination `rmw()` and balanced releases;
- patched count-zero joins rather than numeric skip geometry;
- branchless `ROR` carry publication;
- count-zero C clearing without X writes;
- AArch64 alias-native generated handlers in both flag modes;
- flag-setting helper selection before generated rotate emission;
- generated immediate and register helper calls across all widths;
- `jff`/`jnf` memory helper selection and writeback;
- exact replay metadata, unique sentinels, and active-corpus membership; and
- a complete 92-vector exact-native inventory.

## Acceptance evidence

- focused rotate-family gate: **92/92**, `fail=0`, `infra_fail=0`,
  `fail_equiv=0`, score 100;
- complete active-risky corpus: **647/647**, with zero semantic and
  infrastructure failures;
- allocator-pressure control: interpreter/JIT register dumps byte-identical,
  32 exact native entries, and two interpreter observations;
- clean AArch64 build: pass;
- generated `compemu.cpp`: byte-reproducible across two forced regenerations,
  SHA-256
  `2ab571a7bb6ba26e4c37a19e2cfeb8604f51333c17504b164c55c2ad69f6d1b0`;
- shell syntax, structural audit, and `git diff --check`: pass.

## Validation host

Host-native Orange Pi 6 Plus, CIX P1 (`CD8180`/`CD8160`) 12-core AArch64 SoC,
16 GB-class RAM (about 14 GiB visible), Debian Trixie, NVMe root storage.
