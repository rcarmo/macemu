# AArch64 JIT MOVEM lifecycle and ownership audit

## Scope

This report closes the live `i_MVMEL` and `i_MVMLE` generator paths for the
AArch64 JIT. The authoritative implementation is emitted by
`genmovemel()` / `genmovemle()` in
`src/uae_cpu_2026/compiler/gencomp.c`; the four similarly named
`jnf_MVMEL_{w,l}` / `jnf_MVMLE_{w,l}` MIDFUNC definitions are unreachable
from generated AArch64 compiler roots and were not used as repair points.

The audit covers:

- word and long transfers;
- register-to-memory and memory-to-register directions;
- ascending, postincrement, and predecrement transfer order;
- a transfer mask containing its own effective-address base register;
- all 16 architectural mask positions under allocator pressure;
- no-writeback `(An)` and all legal control addressing modes;
- `d16(PC)` and brief `d8(PC,Xn)` extension decoding;
- zero masks;
- normal and forced special-memory helper paths;
- exact-PC native entry, interpreter/JIT state equivalence, and deterministic
  generated-source output.

## Defect

The prior AArch64 generator selected cursor ownership according to addressing
mode:

- memory-to-register snapshotted only plain `(An)` and otherwise walked the
  `srca` selected by `genamode()`;
- register-to-memory snapshotted non-predecrement modes but walked `srca`
  directly for `-(An)`.

That was not a stable ownership contract. `srca` can denote an architectural
A-register, and a legal MOVEM mask can name that same register. Consequently:

1. a load could overwrite the object still being used as the transfer cursor;
2. a predecrement store could read an already decremented base rather than the
   original 68020+ architectural value;
3. final update semantics depended on the incidental storage choice made by
   `genamode()` rather than on the MOVEM addressing mode;
4. the alias defect was width-sensitive. The baseline focused campaign exposed
   `movem_w_predec_base_alias_native` as a semantic register mismatch
   (`D3 != 0x00003000`) while native translation itself was present.

This is an ownership/lifecycle defect, not an isolated opcode encoding error.

## Structural repair

Both directions now allocate one private transfer cursor unconditionally on
AArch64:

- `movem_srca` owns every memory-to-register transfer address;
- `movem_dsta` owns every register-to-memory transfer address;
- architectural D/A registers are only transfer sources or destinations;
- `(An)+` publishes `movem_srca` to `An` once, after all loads;
- `-(An)` publishes `movem_dsta` to `An` once, after all stores;
- no-update modes discard the private cursor;
- predecrement subtracts from the cursor before each store, but reads the
  selected architectural register before final base writeback;
- the register-mask word is consumed before `genamode()` consumes any EA
  extension word, including PC-relative forms.

The repair deliberately does not revive or patch the four dead MOVEM MIDFUNCs.
The generated compiler remains the live semantic authority.

## Generated closure

Deterministic generation currently emits:

| Contract | Generated handlers |
|---|---:|
| private `movem_srca` load cursor | 32 |
| private `movem_dsta` store cursor | 24 |
| postincrement load writeback | 4 |
| predecrement store writeback | 4 |

`jit-test/structural-audit.ts` fails closed if these counts, cursor ownership,
writeback order, mask/EA extension order, or exact-native vector registration
change.

## Exact-native semantic matrix

The focused acceptance matrix contains 11 vectors:

1. `movem_l_postinc_base_alias_native`
2. `movem_w_postinc_base_alias_native`
3. `movem_l_predec_base_alias_native`
4. `movem_w_predec_base_alias_native`
5. `movem_l_aind_load_base_alias_native`
6. `movem_l_aind_store_base_alias_native`
7. `movem_l_all_live_roundtrip_native`
8. `movem_l_all_live_special_native`
9. `movem_zero_mask_native`
10. `movem_l_control_modes_native`
11. `movem_l_pc_modes_native`

Each vector is in the one-vector-at-a-time risky inventory. Prefix-bearing
vectors restore their exact architectural input and memory bytes, trace the
internal MOVEM anchor once, and then require `NATEXEC` at that exact MOVEM PC.
Thus a native marker for a preceding setup instruction is not accepted as
MOVEM evidence.

The PC-relative vector resolves both `d16(PC)` and brief `d8(PC,D4.W)` to the
same data at `0x3000`; its encodings place the MOVEM mask before the EA
extension word, matching the interpreter decoder.

## Acceptance evidence

Focused post-repair result:

```text
METRIC structural_movem_private_cursor_ownership=1
METRIC structural_movem_base_alias_writeback=1
METRIC structural_movem_mask_ea_extension_order=1
METRIC structural_movem_exact_native_vectors=11
METRIC structural_movem_generated_load_handlers=32
METRIC structural_movem_generated_store_handlers=24
METRIC pass=11
METRIC fail=0
METRIC infra_fail=0
METRIC fail_equiv=0
METRIC risky_pass=11
METRIC risky_fail=0
METRIC score=100
```

The focused result establishes exact native execution and interpreter/JIT
architectural-state equivalence for the matrix. The complete active-risky
campaign also passes **682/682**, with zero semantic, infrastructure, timeout,
missing-dump, sentinel, or native-evidence failures. Neither result closes
unrelated generator, emitter, raw-boundary, or runtime-boundary inventory rows.

The forced allocator witness targets private cursor virtual register 22 and
A5/base virtual register 13 while all non-SP architectural registers are live.
It records both an attempted pin and a source-lock rejection, enters the exact
MOVEM block natively, and preserves full interpreter/JIT state equivalence:

```text
REGPRESSURE cell=movem_predec_cursor_base_locked status=PASS pin=1 skip=1 natexec=1 interpop=1
```

## Regeneration gate

The authoritative source is `gencomp.c`. Two independent `make obj/gencomp`
runs reproduced identical `src/Unix/compemu.cpp` bytes:

```text
SHA-256 14efd5a008fb6ca20065a56991f8e1a3ef8a574348127b0207fcea071a25a6dd
```

The source gates are:

```sh
bun jit-test/structural-audit.ts
bash -n jit-test/run.sh
bun jit-test/closure-inventory.ts
git diff --check
```

The complete active-risky and allocator-pressure campaigns remain tranche-level
gates in addition to the focused matrix.
