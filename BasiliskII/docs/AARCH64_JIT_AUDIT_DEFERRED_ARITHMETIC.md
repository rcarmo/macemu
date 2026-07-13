# AArch64 JIT deferred arithmetic audit

## Scope

This tranche audits the deferred arithmetic-exception and division families in
`uae_cpu_2026` after the accepted native `CHK.W/L` work:

- `DIVU.W` and `DIVS.W`;
- 68020 `DIVU.L` and `DIVS.L`, including 64-bit dividends;
- quotient/remainder register aliasing in the 64/32 forms;
- `TRAPV` taken and non-taken paths.

The audit was source-inventory-led. It did not use a workload PC, ROM patch, or
encounter-order exception as an implementation input.

## Architectural contract

A divide-by-zero request must preserve the dividend registers and enter vector
5 with:

- the consumed successor as the ordinary stacked PC;
- the exact opcode PC from `pc_hist[]` as the 68020 format-2 instruction field;
- the pre-exception CCR in the frame;
- no stale request or exact-PC metadata after delivery.

A taken `TRAPV` uses the same lifecycle with vector 7. A non-taken `TRAPV` must
leave X/N/Z/V/C and the internal carry representation unchanged.

For 64/32 `DIVL`, the interpreter's `m68k_divl()` is authoritative for the
observable result-write order. It writes the remainder first and quotient
second. When `dr == dq`, the final architectural value is therefore the
quotient. Both flag-producing and no-flags native handlers must preserve that
ordering.

## Structural repairs

### Tagged deferred exception request

`register_possible_exception()` now carries a full-width tagged request rather
than an untyped byte. Arithmetic handlers publish the exact opcode PC and the
successor mapping before emitting vector 5 or 7. The common exception boundary
uses the tag to supply the format-2 PC and clears both request and old-PC state
after delivery.

### Word division control flow

The old word `DIVU`/`DIVS` emitters used conditional branches whose immediate
values encoded assumptions about the number of subsequently emitted AArch64
instructions. Flag-publication changes invalidated those displacements and
made a successful `DIVU.W` fall into the wrong path.

All success and overflow branches now use emitted placeholders plus
`write_jmp_target()` patching. Their correctness no longer depends on host
instruction counts.

### Long division and flags

The 68020 long-division generator now selects native handlers for all supported
32/32 and 64/32 signed and unsigned forms. The flag-producing paths publish
N/Z from the quotient and V/C according to the architectural success/overflow
case. Divide-by-zero paths defer vector 5 without modifying destination
registers.

`jff_DIVLS64` is implemented alongside the pre-existing unsigned form. All
four native 64/32 handlers stage remainder before quotient so `dr == dq`
matches `m68k_divl()`.

### TRAPV

`TRAPV` materialises the incoming guest flags, tests V without changing the
carry representation, and emits a tagged vector-7 request only on the taken
path.

## Dynamic proof

Focused strict forced-L2 vectors cover:

- word and long signed/unsigned divide-by-zero frames;
- 64-bit-dividend divide-by-zero register preservation;
- exact stacked successor, format-2 opcode PC, and frame CCR;
- taken `TRAPV` and non-taken full-CCR preservation;
- unsigned and signed 64/32 `dr == dq` aliasing;
- both flag-producing alias paths and flag-dead paths selected by an immediate
  NZVC-overwriting successor.

The alias vectors were mismatch-first: before the family repair, interpreter
replay produced the quotient while native replay left the remainder. After the
repair, all focused vectors pass with native-execution evidence.

Final acceptance evidence:

- focused deferred arithmetic gate: 12/12, score 100;
- complete interpreter/JIT equivalence: 411/411, score 100;
- strict contract: `opt0=0 fallback=0 exec_nostats=0`;
- legal-opcode classification: 48,282/48,282, zero fallback/null slots;
- allocator-pressure replay: identical interpreter/JIT state, native execution;
- generated `compemu.cpp`: byte-reproducible, SHA-256
  `cef9647d7b4ef1359a3ee75da7876e6758ef59e97364e83244c122730fa8a595`;
- ordinary and strict Finder captures: 24,120,000 retirements scheduled,
  16,777,216 PCs retained, 21 `DiskStatus 43` events, zero host faults, and
  byte-identical SHA-256
  `1a05d539dc51f4fa39cd2cc02e5e7c90faeedcab054ab6b4d156d8022db06b73`.

## Validation host

The gates ran host-native on an Orange Pi 6 Plus with a CIX P1
(CD8180/CD8160) 12-core AArch64 SoC, 16 GB-class RAM (about 14 GiB visible),
NVMe storage, and Debian Trixie. BasiliskII used the AArch64 JIT with forced
translation and fail-closed strict execution; the container test layout was
not used.
