# AArch64 JIT Audit — Ordered Semantic Services

## Scope

This audit covers UAE2026 instructions whose architectural result depends on
ordered extension fetches, effective-address side effects, privilege checks,
memory faults, or multiple writes. The repaired families are:

- CAS and CAS2;
- MOVES;
- BFTST, BFEXTU, BFCHG, BFEXTS, BFCLR, BFFFO, BFSET, and BFINS;
- RESET, STOP, RTE, USP moves, MOVEC, and CPUSH/cache transitions.

MV2SR.W remains on the legacy/interpreter path until its complete SR, stack,
trace, and exception contract has equivalent proof.

## Structural contract

Generated handlers call one ordered whole-instruction service rather than
mixing partially emitted native effects with C helpers. Before a service call,
the emitter:

1. flushes allocator and architectural state;
2. publishes the exact opcode PC from `pc_hist[]` to `PC_P` and the integer PC;
3. passes the decoded opcode in `REG_PAR0`;
4. passes the linear successor in `REG_PAR1` where the helper ABI requires it;
5. performs the helper call through the AAPCS64-safe call path;
6. ends the block so the dispatcher reloads canonical state.

The opcode PC must not be reconstructed from `comp_pc_p + m68k_pc_offset`.
Compiler-PC linearisation is not authoritative after in-block control flow.

## Family ordering

### CAS and CAS2

CAS services fetch extension words at the opcode PC, calculate the complete EA,
and preserve byte/word/long partial-register semantics. EA auto-update, memory
read, comparison flags, compare-register replacement on failure, and memory
write on success follow interpreter order. CAS2 preserves the two-read,
two-compare, conditional two-write transaction and register alias behaviour.

### MOVES

MOVES checks privilege before fetching its extension word. Register-to-memory
auto-update commits before a faultable write. Memory-to-register auto-update
commits only after a successful read, after which a destination register that
aliases the EA register wins. Indexed/full-format EA decoding advances the PC
through the canonical 68020 displacement decoder.

### Bitfields

One runtime decoder covers all eight bitfield operations and all supported
register, An-relative, absolute, and PC-relative forms. It preserves signed
dynamic memory offsets, width zero as 32, wrapped register fields, five-byte
memory fields, destination-register aliasing, and read-before-write fault
ordering. Fixed-format operations publish the successor only after success;
indexed forms retain the decoder's advanced PC.

### System and cache controls

RESET, STOP, RTE, USP moves, MOVEC, and CPUSH receive the exact opcode PC.
Privilege checks precede extension fetches where required. Helpers preserve
exception-frame, SR/CCR/NZCV/X, cache-state, and successor ordering. Invalid
opcode slots remain architectural traps rather than interpreter fallback.

## Acceptance evidence

Validated on an Orange Pi 6 Plus host:

- CIX P1 (CD8180/CD8160), 12 AArch64 CPU cores;
- 16 GB class RAM (about 14 GiB visible);
- Debian Trixie, host-native build;
- NVMe workspace storage.

Final gates for this tranche:

- generated `BasiliskII/src/Unix/compemu.cpp` is byte-reproducible;
- structural audit and `git diff --check` pass;
- ordinary equivalence: 394/394, score 100, zero equivalence or infrastructure failures;
- strict equivalence: 394/394, score 100, zero equivalence or infrastructure failures;
- all 48,282 legal encodings classified: 46,087 native-generated, 2,127 semantic services, 68 architectural traps, zero fallback/null slots;
- ordinary and strict allocator-pressure states match;
- deterministic Finder runs each schedule 24,120,000 retirements, retain a 16,777,216-PC (64 MiB) window, and reach 21 `DiskStatus 43` events without a host fault;
- ordinary and strict Finder windows are byte-identical, SHA-256 `1a05d539dc51f4fa39cd2cc02e5e7c90faeedcab054ab6b4d156d8022db06b73`;
- every strict Finder summary reports `opt0=0 fallback=0 exec_nostats=0`.
