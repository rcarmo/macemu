# AArch64 JIT Audit — CHK Exception Semantics

## Scope

This audit covers native `CHK.W` and `CHK.L` on the UAE2026 AArch64 JIT. It
compares the destination register against the signed bound, preserves the
non-selected CCR bits, and delivers vector 6 with the same architectural state
and format-2 frame as the interpreter.

`CHK2` remains a separate, untagged vector-6 path and is not changed by this
contract.

## Structural contract

A trapping native CHK must publish state at the common deferred-exception
boundary rather than continue into a successor instruction:

1. the generated handler terminates the trace at CHK;
2. the incoming guest flags are materialised before native comparisons clobber
   host NZCV;
3. the inline signed comparison selects negative or upper-bound failure;
4. a full-width tagged request carries vector 6 and the required N value;
5. the exact opcode PC from `pc_hist[]` is carried independently of `PC_P` and
   the compiler cursor;
6. immediately before `Exception(6)`, the boundary changes only N and supplies
   the carried opcode PC for the format-2 instruction-address field;
7. the request and exact-PC carrier are cleared after delivery.

Non-trapping CHK changes no guest flags. A negative failure sets N; an
upper-bound failure clears N. X, Z, V, and C are preserved in both trap cases.
The request uses `LOAD_U32`; a 16-bit emitter would truncate the tag and silently
turn it into an ordinary vector-6 request.

## Native replay proof

Focused vectors cover:

- `CHK.W` negative and upper-bound failures;
- `CHK.L` negative and full-width upper-bound failures;
- `CHK.L` full-width in-range flag preservation;
- the pre-existing `CHK.W` in-range, zero, and equal cases.

The trap handler copies the stacked SR, stacked PC, and format-2 instruction
address into registers, so the ordinary interpreter/JIT comparison observes the
entire exception contract. Each CHK vector replays from the exact opcode anchor
through forced RAM L2 promotion and explicitly restores operands established by
any skipped setup prefix; otherwise the older non-trapping vectors collapse to
an unintended `0 <= 0` case. A third execution is required because the first
replay can trace the alternate anchor and only the final replay proves native
entry.

The MOVES privilege vector used by the complete gate enters user mode at IPL7.
This masks unrelated guest timer interrupts while preserving the intended
vector-8 privilege path.

## Acceptance evidence

Validated on an Orange Pi 6 Plus host:

- CIX P1 (CD8180/CD8160), 12 AArch64 CPU cores;
- 16 GB class RAM (about 14 GiB visible);
- Debian Trixie, host-native build;
- NVMe workspace storage.

Final gates:

- generated `BasiliskII/src/Unix/compemu.cpp` is byte-reproducible, SHA-256
  `6761266f7a992d884e17916a50fc0427582a70aaf9640516809aefb02ae5f3c8`;
- structural audit and `git diff --check` pass;
- ordinary equivalence: 399/399, score 100, zero equivalence or infrastructure
  failures;
- strict equivalence: 399/399, score 100, zero equivalence or infrastructure
  failures;
- ten repeated MOVES privilege-vector comparisons pass with no infrastructure
  failure;
- all 48,282 legal encodings remain classified: 46,087 native-generated, 2,127
  semantic services, 68 architectural traps, zero fallback/null slots;
- ordinary and strict allocator-pressure states match;
- deterministic ordinary and strict Finder runs each schedule 24,120,000
  retirements, retain a 16,777,216-PC (64 MiB) window, reach 21 `DiskStatus 43`
  events, and report no host fault;
- Finder windows are byte-identical, SHA-256
  `1a05d539dc51f4fa39cd2cc02e5e7c90faeedcab054ab6b4d156d8022db06b73`;
- all 24 strict Finder summaries report `opt0=0 fallback=0 exec_nostats=0`.
