# AArch64 JIT Audit — BFINS Runtime Contract

## Scope

This audit covers the UAE2026 ARM64 JIT implementation of 68040 `BFINS` for
register and memory destinations.

Primary files:

- `compiler/gencomp.c`
- `compiler/compemu_legacy_arm64_compat.cpp`
- `gencpu.c`
- `newcpu.cpp`

## Confirmed defects

### Compile-time decoding used a virtual-register ID

The generated register-destination path evaluated expressions such as
`(extra >> 12)` in the compiler function. `extra` is a JIT virtual-register ID,
not the bit-field extension word held by that virtual register. The selected
source, offset, width, and helper/inline path therefore depended on allocator
numbering rather than the guest instruction.

All BFINS forms now use one native runtime-helper contract. The generated code
stores the extension word and encoded destination in `regstruct`, materialises
allocator state, calls the helper, and ends the block so its CCR result is
reloaded canonically.

### Dynamic memory offsets were reduced modulo 32

The old helper masked a register-specified offset with `31` before deciding
whether the destination was a register or memory. A memory offset is a signed
32-bit displacement: its byte component must adjust the EA, while only the
in-byte component is consumed by `get_bitfield()`.

The helper now preserves the signed offset for memory and follows the
interpreter's exact `EA + (offset >> 3)`, `get_bitfield()`, and `put_bitfield()`
contract.

### Five-byte fields were accumulated in 32 bits

A width-32 memory field at a non-zero bit offset spans five bytes. The old
byte-loop shifted all five bytes through a `uae_u32`, discarding the first byte
before writeback.

Using the shared bit-field primitives removes the truncated accumulator and
preserves the interpreter's two-word `bdata[]` writeback semantics.

### Wrapped register fields used a single truncated shift

For `offset + width > 32`, a register field wraps through bit 31 to bit 0. The
old helper added 32 to one shift count but still applied a single 32-bit mask
and insert, so the wrapped portion was lost.

The helper now rotates the destination, preserves the low non-field bits,
inserts the source field at the top, and rotates back. All shifts are guarded
for offset zero and width 32.

## Structural gate

`jit-test/structural-audit.ts` requires:

- BFINS to end the block and use `GENA_GETV_NO_FETCH` plus `jit_op_bfins`;
- no compile-time extension-word decoding from `extra`;
- signed memory offset handling;
- shared `get_bitfield()`/`put_bitfield()` writeback;
- explicit wrapped-register and width-32 handling.

## Opcode regressions

The equivalence harness covers:

- immediate narrow and wrapped register fields;
- dynamic register offset and width, including width zero meaning 32;
- width-32 memory fields spanning five bytes;
- negative and positive signed dynamic memory offsets;
- the two exact BFINS forms observed during the frozen-clock ROM boot:
  - `0403939c: EFC6 0800` — source and dynamic-offset alias, width 32;
  - `04030d30: EFD2 0900` — signed D4 memory offset, width 32.

## Verification

- generated `compemu.cpp` is stable after regeneration;
- clean structural audit passes;
- opcode equivalence: `329/329`, `fail=0`, `infra_fail=0`, `score=100`;
- frozen-clock full JIT reaches the known desktop framebuffer background;
- compared with the prior accepted desktop image, all pixels outside the
  top-left `28x23` cursor rectangle are identical; the captured cursor frame
  leaves the whole-image mean at `42877.3`, so the historical exact `42849`
  whole-image gate remains open rather than being relaxed.
