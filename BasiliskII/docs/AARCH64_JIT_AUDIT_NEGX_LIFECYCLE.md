# AArch64 JIT NEGX lifecycle audit

Date: 2026-07-14

Branch: `structural-audit`

Base: `6d7336eb4a2b57706ebe8fd39012d3d0c7562392` (authoritative closure census)

## Scope

This report closes the live AArch64 `i_NEGX` generator path as one arithmetic,
flags, memory-RMW, effective-address, and allocator-lifetime family:

- byte, word, and long register forms;
- incoming X clear and set;
- incoming sticky Z clear and set;
- zero and signed-minimum operands;
- N/Z/V/C/X publication and narrow-register upper-lane preservation;
- flag-live and no-flags generated variants;
- `(An)`, `(An)+`, `-(An)`, `d16(An)`, brief indexed, absolute-word, and
  absolute-long memory forms;
- byte postincrement and predecrement through A7's two-byte geometry;
- normal and forced special-memory helper paths;
- exact-PC native entry plus forced source/result and result/effective-address allocator pressure.

The audit is source-led. It follows the configured generated compiler rather
than similarly named definitions, ROM encounter order, or textual occurrence.

## Reachability finding

The six AArch64 MIDFUNC definitions named `jff_NEGX_{b,w,l}` and
`jnf_NEGX_{b,w,l}` are unreachable from the configured generated, support, and
FPU compiler roots. They are not the implementation of live `NEGX` opcodes and
were not modified.

The executable path is:

1. `i_NEGX` in authoritative `src/uae_cpu_2026/compiler/gencomp.c` fetches the
   source and creates a private zero-valued destination scratch;
2. `genflags(flag_subx, ...)` reloads architectural X as the subtraction carry
   input;
3. generated `src/Unix/compemu.cpp` calls shared `sbb_b`, `sbb_w`, or `sbb_l`;
4. the compatibility layer publishes the arithmetic result and flags;
5. `genastore()` writes the result to the register or memory effective address.

This is the same shared subtraction-with-extend lifecycle used by live SUBX.

## Structural result

No new NEGX-specific semantic defect was found. The live path already includes
the accepted shared ADDX/SUBX narrow-lane repair:

- byte and word operands are shifted into the host sign lane before `SBCS`, so
  host N/V/C describe the guest-width subtraction;
- `BFXIL` restores only the low guest lane and preserves the upper D-register
  bits;
- `legacy_set_z_from_narrow_result()` reconstructs guest-width Z without
  destroying physical carry polarity;
- generated sticky-Z handling computes `old_Z && result_zero`;
- carry is duplicated to architectural X when X remains live;
- the no-flags variant still reloads and consumes incoming X, but omits dead
  sticky-Z and carry-to-X publication;
- long width uses the same ordered carry lifecycle directly through 32-bit
  `SBCS`.

The audit therefore closes `i_NEGX` by proving the repaired shared service,
not by reviving dead namesakes or adding an opcode-local workaround.

## Effective-address and flag evidence

The exact-native matrix has 27 vectors:

- 15 flag-live register vectors: five X/Z/overflow classes across all three
  widths;
- 3 no-flags register vectors, one per width;
- 9 memory vectors spanning every legal EA class used by NEGX, three forced
  through special-memory helpers, and both A7 byte update modes.

Memory vectors snapshot SR immediately after NEGX with `MOVE SR,D2` before
loading the modified memory value. This separates NEGX flag evidence from the
verification MOVE's architecturally correct N/Z/V/C update. Replay memory is
restored before each exact-PC pass, and every vector requires `NATEXEC` at
`0x1000`, strict full-JIT accounting, one deterministic register dump, and
interpreter/JIT byte equivalence.

## Allocator ownership

NEGX's zero destination is a constant-backed scratch. Its first physical
read/modify/write allocation occurs inside `sbb_b/w/l`, after the shared
`INIT_REGS_b/w/l` macro has acquired and locked the live source. The allocator
pressure hook now covers constant-backed `rmw()` scratches as well as
write-only `writereg()` scratches.

For byte, word, and long cells, a preceding TST materialises D0, then forced S1
to D0 host-register aliasing attempts to acquire the destination while the
source is live. All three attempts are rejected by the source lock:

```text
REGPRESSURE cell=negx_b_source_dst_collision status=PASS pin=0 skip=1 natexec=1 interpop=1
REGPRESSURE cell=negx_w_source_dst_collision status=PASS pin=0 skip=1 natexec=1 interpop=1
REGPRESSURE cell=negx_l_source_dst_collision status=PASS pin=0 skip=1 natexec=1 interpop=1
```

### Corrective EA-ownership extension

The subsequent NEG family audit forced the private result scratch onto the
still-live pre-write effective address, a collision class not exercised by the
three original source/result cells. Before repair, `NEGX.B (A0)+` executed
natively but left memory at `01` instead of `FE` and ended at SR `2710` instead
of `2718`; the allocator reported `REGPRESSURE_PIN_HIT scratch_vreg=22
pin_vreg=20`.

The authoritative `i_NEGX` generator now locks `srca` after `genamode()` and
releases it only after `genastore()`. Regeneration emits 42 balanced
`__negxealock` pairs across all flag-live and no-flags memory handlers. The
permanent `negx_b_postinc_result_ea_collision` cell now reports `skip=1`,
`natexec=1`, `interpop=1`, and exact interpreter/JIT equality. See
`AARCH64_JIT_AUDIT_NEG_LIFECYCLE.md` for the paired NEG/NEGX fault witness.

The interpreter and JIT dumps are identical in each cell. This is a positive
lifetime proof, not a baseline register-rich pass.

## Structural gates

`jit-test/structural-audit.ts` fails closed if any of these contracts changes:

- authoritative `i_NEGX` -> `flag_subx` generator routing;
- generated flag-live and no-flags `sbb_b/w/l` calls;
- sticky-Z and X publication in flag-live variants;
- absence of dead-flag publication in no-flags variants;
- byte/word shift, `SBCS`, `BFXIL`, and narrow-Z reconstruction;
- 27 exact-native vectors, 9 memory-EA vectors, 3 special-memory vectors, and
  3 width-specific pressure witnesses.

Expected structural metrics are:

```text
METRIC structural_negx_shared_subx_lowering=1
METRIC structural_negx_narrow_lane_flags=1
METRIC structural_negx_no_flags_lifecycle=1
METRIC structural_negx_exact_native_vectors=27
METRIC structural_negx_memory_ea_classes=9
METRIC structural_negx_generated_ea_locks=42
METRIC structural_negx_allocator_pressure_cells=4
```

## Acceptance evidence

Focused exact-native matrix:

```text
METRIC pass=27
METRIC fail=0
METRIC total=27
METRIC infra_fail=0
METRIC fail_equiv=0
METRIC risky_pass=27
METRIC risky_fail=0
METRIC score=100
```

The complete active-risky campaign passes **683/683**, with zero semantic,
infrastructure, timeout, emulator-exit, missing-dump, multiple-dump, sentinel,
or native-evidence failures. The complete seven-cell allocator-pressure suite
passes, including all three NEGX widths and the pre-existing MULL, MOVEM, and
memory-ROX controls.

The authoritative generator reproduced `src/Unix/compemu.cpp` byte-for-byte in
two independent runs:

```text
SHA-256 14efd5a008fb6ca20065a56991f8e1a3ef8a574348127b0207fcea071a25a6dd
```

`bash -n` for both shell harnesses, the structural audit, the regenerated
997-row closure inventory, a clean AArch64 build followed by the focused gate,
and `git diff --check` are tranche acceptance gates.

## Validation host

Host-native Orange Pi 6 Plus, CIX P1 (`CD8180`/`CD8160`) 12-core AArch64 SoC,
16 GB-class RAM (about 14 GiB visible), Debian Trixie, NVMe root storage.

## Closure boundary

This report closes only the live `i_NEGX` family and the specific shared
contracts it executes. The six dead NEGX MIDFUNC rows remain classified as
unreachable. It does not classify TAS, MOVE, remaining emitter APIs, raw
boundaries, or any other unreviewed closure-inventory row.
