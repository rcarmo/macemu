# AArch64 JIT Audit — Area 6: Guest-Memory Access Contracts

## Scope

This audit covers the active BasiliskII UAE2026 AArch64 paths for direct guest
memory, interpreter-backed bank callbacks, open-bus regions, host-address
translation, and memory-helper flag ownership.

Primary files:

- `src/uae_cpu_2026/memory.h`
- `src/uae_cpu_2026/compiler/compemu_midfunc_arm64_2.cpp`
- `src/uae_cpu_2026/compiler/compemu_support_arm.cpp`
- `src/uae_cpu_2026/compiler/compemu_support.cpp`
- `src/Unix/main_unix.cpp`
- `src/Unix/Makefile.in`

Validation target: Orange Pi 6 Plus, CIX P1 AArch64 SoC, 12 CPU cores,
16 GB-class RAM, Debian Trixie, GCC/G++ AArch64 build, 64 MB BasiliskII full-JIT
Finder workload, and Bun-based interpreter/native replay tests.

## Active access families

### Direct 32-bit guest addressing

Trusted byte, word, and long accesses emit native loads/stores indexed from
`R_MEMSTART`. Guest addresses are consumed through W registers/UXTW. Big-endian
M68K word and long values are byte-reversed at the native boundary.

Any emitter-only comparisons used for device/open-bus guards must preserve
incoming NZCV. They are address plumbing, not guest arithmetic.

### Interpreter-backed special access

Distrusted and explicitly special accesses dispatch through `regs.mem_banks`.
Every bank points at the shared `jit_io_bank` callback table, whose get/put/xlate
entries call `memory.h` directly. Read and write calls run across the normal
allocator/helper barrier; 32-bit callback returns are W-normalised, while xlate
returns retain pointer width.

### 24-bit access

The ARM64 helpers exist, but the active BasiliskII preference bridge hard-codes
`currprefs.address_space_24 = false`; the current build does not reach them. No
speculative repair was made to that dead family.

## Confirmed defect 1: transformed direct byte writes

`jnf_MEM_WRITE_OFF_b` previously transformed nearly every byte written in the
`0x50xxxxxx` range to `-2 * value`. Only two scanner offsets escaped or skipped
the transformation. `memory.h::put_byte`, the interpreter oracle and special
callback implementation, stores the original byte unchanged except that
scanner-data writes are ignored.

A forced-L2 native replay at runtime-register address `0x50001000` measured:

- interpreter: source/readback `0x11`, `D1=0x00000011`;
- JIT before fix: stored/read back `0xde`, `D1=0x000000de` and different CCR.

The direct helper now mirrors `put_byte`: compare the shared scanner-data mask,
ignore that one device write, and otherwise store the architectural source byte
unchanged. The guard saves/restores NZCV.

## Confirmed defect 2: guest low-NuBus addresses exposed host JIT storage

For RAM sizes up to 128 MiB, guest range `0x0a014000..0x0a814fff` overlaps the
host reservation used by the JIT cache. `main_unix.cpp` intentionally leaves
that part out of the surrounding `0xff` low-NuBus mapping.

Before this fix:

- interpreter direct reads could expose host reservation/cache bytes;
- native reads used separate byte/word guards but returned a hard-coded `0x10`
  for long accesses;
- direct writes had no guard and could modify native JIT storage.

A two-pass long read at guest `0x0a014100` measured the concrete divergence:

- interpreter: `D1=0x0041010a` (host-reservation contents leaked);
- native JIT: `D1=0x00000010` (address/path-specific symptom value).

## Structural fix

`memory.h` now owns one shared low-NuBus open-bus predicate:

- active only when `RAMSize <= 0x08000000`;
- range constants are shared with the ARM64 emitter;
- byte/word/long reads return `0xff`, `0xffff`, and `0xffffffff`;
- byte/word/long writes are ignored.

The emitted direct path uses shared read/write guard generators:

- all three read widths return the same all-ones contract;
- all three write widths branch around the native store;
- every guard restores NZCV;
- with more than 128 MiB RAM, no gap guard is emitted because the guest range is
  ordinary RAM.

This removes host-cache disclosure/corruption and the old address-specific long
value without introducing opcode fallback or ROM patches.

## Native replay gate

`jit-test/run.sh` now has an explicit `NATIVE_REPLAY_TESTS` class. Marked tests:

1. run once to trace/compile;
2. reset architectural input;
3. force RAM L2 promotion for the JIT run;
4. re-enter at guest `0x1000` and execute the native block.

This distinguishes native equivalence from a test that only exercised the
interpreter tracer before compilation.

`io_byte_write_roundtrip` covers:

- runtime-register direct write/read at `0x50001000`;
- ignored byte, word, and long writes into the JIT-cache alias gap;
- width-correct all-ones byte, word, and long open-bus reads.

The structural audit rejects source-byte transforms, missing write guards,
unshared gap constants, the old `0x10` long value, and a replay test lacking
forced L2/two-pass execution.

## Build coherency

`memory.h` is now an explicit dependency of the complete generated JIT object
family in both `Makefile.in` and the configured `Makefile`. An inline memory
contract change cannot leave old `compemu1.o..compemu8.o` objects linked against
new support code.

## Verification at landing

- clean AArch64 build: pass;
- structural audit: all metrics `1`;
- focused forced-L2 native replay: `1/1`;
- full active equivalence gate: `331/331`, `fail=0`, `infra_fail=0`, score 100;
- allocator-pressure cell: pass, `natexec=126`, interpreter/JIT dumps equal;
- generated `compemu.cpp`: regeneration-stable at SHA-256
  `84f195108c5b6bbc6984fd527130ad60f9133e56b7c82f1ddb21b4942e322d2b`;
- frozen-clock full JIT: interactive Finder reached; guest input displayed the
  improper-shutdown dialog and Return revealed the populated desktop;
- frozen-clock diagnostic removed and production timer rebuilt before commit.

## Contributor rule

Guest memory semantics belong in one shared contract. Native direct access may
inline that contract, but it must not invent value transforms, expose host cache
storage, or depend on address/opcode-specific stale destination values.
