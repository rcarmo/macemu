# AArch64 JIT register-count AS/LS audit

## Scope

This tranche audits register-count `ASL`, `ASR`, `LSL`, and `LSR` as one
architectural family across byte, word, and long widths.  The contract includes:

- the complete low-six-bit count domain, including 0, 31, 32, 33, and 63;
- ordinary and no-flags generated paths;
- N/Z/V/C publication and count-zero X preservation;
- ASL sign-transition overflow, including a zero source at large counts;
- legal source/destination register aliasing;
- constant-folded and exposed immediate-helper contracts;
- allocator ownership across emitted runtime branches; and
- generated-source reproducibility.

No ROM PC, workload encounter order, guessed host displacement, or interpreter
escape is part of the repair.

## Confirmed defects

### Host count width

The original register helpers used AArch64 W-form variable shifts.  Those
instructions mask the host count modulo 32, whereas 68040 register shifts use
the low six bits and define counts 32 through 63.  This affected both result and
carry calculations.

All register-count helpers now mask the guest count to six bits and use X-form
host shifts.  Byte and word operands are explicitly extended before the shift;
long results are normalised back to 32 bits.  Constant no-flags paths saturate
logical results at the guest width rather than invoking an out-of-range C++ or
host immediate shift.

### Source/destination aliasing

`gencomp.c` rejected legal `srcreg == dstreg` forms for all four families.
AArch64 generation now copies the count to a temporary, masks that temporary,
and shifts the destination in place.  The old alias rejection remains for
other back ends.  Flag-live ASL routes to dedicated `jff_ASL_*_reg` helpers so
V is not silently treated as logical-LSL overflow.

### Count-zero X lifecycle

Several flag-live handlers emitted a runtime count-zero branch around
`DUPLICACTE_CARRY`.  The allocator nevertheless observed both emitted paths as
one linear stream: the non-zero path could publish a new `FLAGX` binding while
the zero path skipped it, leaving unmatched ownership at the join.

Branching handlers now materialise and lock old X before the emitted branch,
publish carry only on the non-zero path, patch every join from an emitted
placeholder, and release X after the common target.  Long LSL uses a branchless
merge, `X = count == 0 ? old_X : carry`, with one allocator write.

### ASL overflow

ASL V is set when the sign changes at any point, not merely from the final
result.  The old register path either fell back when V was live or compared the
count with an unqualified `CLS` result.  For a zero operand AArch64 `CLS.W`
returns 31, which falsely reported overflow at larger legal counts.

The family now computes the leading-sign capacity, maps the zero-source
sentinel to 63, and publishes V with `CSEL`.  Register and constant-count
helpers share the same rule.  Count zero still clears C/V, derives N/Z from the
unchanged width-specific value, and preserves X.

### Fixed internal flag branches

Carry publication used numeric `TBZ` skip distances whose correctness depended
on the number of emitted instructions in the flag path.  All 24 flag-live
register/immediate helpers now extract the carry bit and insert it into NZCV
branchlessly.  Remaining control-flow joins use emitted placeholders followed
by `write_jmp_target()`; the structural gate rejects any fixed non-zero branch
argument in this family.

The long constant-count LSR flag-live helper also explicitly produces zero for
counts at or above 32 before publishing count-32 carry.  The exposed flag-dead
long LSL and LSR immediate helpers now apply the same saturation contract before
using a W-form immediate shift.  Current register wrappers already pre-saturate
those flag-dead calls, so this last source-review repair is classified as a
latent interface-contract defect rather than a demonstrated mismatch.

## Mismatch-first evidence

Before repair, exact native replay showed:

- count 32 wrapping through W-form host shifts;
- legal same-register count/data forms falling back instead of entering the
  audited native opcode;
- count-zero X failures under lifecycle/allocator inspection;
- zero-source ASL at count 32 taking a V-set branch (`D2=1`) while the
  interpreter took the V-clear branch (`D2=2`).

The pressure-shaped count-zero witness itself passed before and after; source
inspection established the allocator-state mismatch at the emitted join.  It
is retained to keep the pressure geometry visible rather than treating one
passing allocation as proof of the lifecycle.

## Dynamic coverage

The exact-native inventory contains 138 vectors:

- all four operations and all three widths at count 32;
- adjacent/maximal counts 31, 33, and 63 in ordinary and no-flags paths;
- all 12 legal source/destination alias forms in both flag modes;
- count-zero X preservation across all widths and operations;
- a pressure-shaped count-zero ASR case;
- ASL zero-source V witnesses at long/32, word/33, and byte/63;
- complete-block constant-count ASL and LSR witnesses.

Each selected opcode has a `NATEXEC` observation and a strict summary with
native execution, `opt0=0`, `fallback=0`, and `exec_nostats=0`.

## Structural guards

`jit-test/structural-audit.ts` requires:

- X-form six-bit result shifts and no W-form variable-shift regression;
- patched count-zero/carry-range joins;
- balanced X materialisation around every runtime join;
- branchless ASL overflow and carry publication;
- no fixed non-zero emitter branch in the 24 flag-live helpers;
- flag-live and flag-dead long logical-immediate saturation;
- generated source/destination alias support and ASL V routing;
- a deduplicated 138-vector exact-native inventory and sentinel generation; and
- active-risk membership for the 66 core lifecycle vectors plus the two
  promoted adjacent-boundary priorities (68 shift vectors in the 579-name
  active corpus).

## Acceptance evidence

- exact-native shift-family gate: **138/138**, `fail=0`, `infra_fail=0`,
  `fail_equiv=0`, score 100;
- complete active-risky corpus: **579/579**, with zero semantic and
  infrastructure failures;
- allocator-pressure control: interpreter/JIT register dumps byte-identical,
  with 32 native entries and two interpreter observations;
- clean AArch64 build: pass;
- generated `compemu.cpp`: byte-reproducible before and after a forced native
  generator rebuild, SHA-256
  `384311e425efa0442d89ab4f293929fd37bbf3e875c4f820d7a93795371774e3`;
- shell syntax, structural audit, `git diff --check`, and focused source review:
  pass.

## Validation host

Host-native Orange Pi 6 Plus, CIX P1 (`CD8180`/`CD8160`) 12-core AArch64 SoC,
16 GB-class RAM (about 14 GiB visible), Debian Trixie, NVMe root storage.
