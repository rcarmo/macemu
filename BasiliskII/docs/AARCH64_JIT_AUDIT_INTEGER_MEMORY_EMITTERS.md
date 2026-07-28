# AArch64 generic integer load/store emitter audit

Date: 2026-07-28
Base: `ed6b2d550ae8973b8e08e008763dba9cac3e8a2d`

## Scope

This bounded audit covers 22 mechanically adjacent reachable integer memory
encoder APIs:

- pair: `LDP_xxXi`, `LDP_xxXpost`, `STP_wwXi`, `STP_xxXi`, `STP_xxXpre`;
- unsigned immediate and writeback: `LDR_wXi`, `LDR_xXi`, `LDR_xXpost`,
  `LDRH_wXi`, `STR_wXi`, `STR_xXi`, `STR_xXpre`, `STRH_wXi`;
- register offset/scaled register: `LDR_wXx`, `LDR_wXxLSLi`,
  `LDR_xXxLSLi`, `LDRB_wXx`, `LDRH_wXx`, `STR_wXx`,
  `STR_wXxLSLi`, `STRB_wXx`, `STRH_wXx`.

`LDR_xPCi` remains separate because it is PC-relative rather than base-register
memory. `LDR_{s,d}*` and `STR_d*` remain separate because they own FP-register
lane semantics. Unreachable sibling forms are not promoted by this report.

## Encoding and caller contract

The 22 definitions are in `codegen_arm64.h:120-155`. Their configured closure
reference total is **168**; the bounded four-source structural root
(`compemu_midfunc_arm64{,_2}.cpp`, compatibility, and codegen) contains **170**
raw calls. The difference is expected because the closure graph removes
inactive or unreachable MIDFUNC roots while also following header composition.

Immediate forms encode byte offsets in the architecture-defined scaled fields:
4-byte, 8-byte, and 2-byte scaling as appropriate. Pair forms encode signed
7-bit scaled offsets. Pre/post-index forms preserve signed 9-bit or signed
7-bit displacement and update the base exactly once.

The six direct guest-memory helpers deliberately reverse their macro parameter
roles when encoding:

```text
LDR/STR{B,H,W}_wXx(value, guest_offset_w, natmem_base_x)
                         -> [natmem_base_x, guest_offset_w, UXTW]
```

This is required: the guest address is a 32-bit unsigned M68K offset and the
natmem register is the 64-bit host base. Historical `SXTW` behavior could wrap
bit-31 guest offsets below natmem on hosts mapping natmem above 2 GiB.

## Exact and native oracle

`jit-test/emitter-memory-conformance.cpp` checks:

- **22/22** canonical boundary instruction words;
- **31/31** native value, pair-order, scaling, and writeback checks;
- **22/22** NZCV-preservation checks, one for every API;
- **6/6** direct byte/halfword/word load/store cells at guest offsets
  `0x80000000+`, using a 2 GiB `MAP_NORESERVE` virtual span to distinguish
  `UXTW` from a below-base `SXTW` wrap;
- byte, halfword, word, and doubleword lane widths;
- W-load zero extension and W-store low-lane truncation;
- pair source/destination order and pre/post base ownership.

Focused result:

```text
METRIC emitter_memory_apis=22
METRIC emitter_memory_exact_words=22
METRIC emitter_memory_native_value_vectors=31
METRIC emitter_memory_nzcv_vectors=22
METRIC emitter_memory_uxtw_highbit_vectors=6
METRIC emitter_memory_pair_order=1
METRIC emitter_memory_writeback=1
METRIC emitter_memory_widths_8_16_32_64=1
```

## Finding

No production encoder defect was reproduced. Canonical words, scaling,
writeback, pair order, lane width, NZCV preservation, and the guest-offset UXTW
contract all match the intended A64 semantics. This tranche changes no
production or generated source.

## Closure candidate

The committed predecessor inventory has **998 rows**, `125 audited / 66
unreviewed` emitter APIs, and CSV hash:

`fa880dd456f1ad6112b56a90ea15ede909e932f7d5d939c86096a03d467c477d`

Acceptance must promote exactly these 22 rows to `audited`, yielding
`147 audited / 44 unreviewed`, with every other layer/status unchanged.

## Candidate evidence and review history

Completed on the current candidate:

- focused memory probe: **22/22 exact words**, **31/31 value/writeback**,
  **22/22 NZCV**, and **6/6 UXTW high-bit** cells;
- complete integrated emitter/boundary phase: pass (`validation_complete=1`),
  with opcode vectors intentionally skipped by that phase;
- allocator pressure: **33/33**;
- pending-state deterministic inventory regeneration: byte-identical CSV
  `fa880dd456f1ad6112b56a90ea15ede909e932f7d5d939c86096a03d467c477d`
  and Markdown
  `00965376f073ef9cb138a49df21aec9008e686ddebc9e966b0a8e095b6d020ad`;
- source hygiene and `git diff --check`: pass;
- production and generated source: unchanged from published base `ed6b2d55`,
  whose clean build and 904-vector corpus are accepted evidence.

The first current vector-phase log contained 688 individual opcode metrics but
no terminal aggregate and was rejected as incomplete evidence. The targeted
rerun completed with **904/904**, zero failure, zero infrastructure failure,
`validation_complete=1`, and `VECTOR_RC=0`.

Initial independent verdict: **reject** — the narrow judge identified no
source, encoding, ABI, UXTW, counter, or scope objection, but correctly refused
to call the intentionally pending report and unpromoted rows final acceptance.

Final promoted inventory hashes:

- CSV: `85a99c8a3f81c791f61f83aae4ec049f1f1c3c4c9eae42eea4b9346b73ce17cd`;
- Markdown: `df08168879f71d302b181f06c368c548496def42140dc97abd7fbaaf74f6cd90`.

Final structural and deterministic gates: pass.

final re-review: **approve**.
