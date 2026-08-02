# Bounded SheepShaver interpreter/JIT benchmark

## Scope

This is a deterministic, register-only PPC microbenchmark for comparing the
SheepShaver interpreter and AArch64 direct JIT. **This is not a Mac OS or
application benchmark.** It does not measure boot, Finder, devices, memory,
MMU behaviour, graphics, or representative application performance.

Timing and execution-path coverage are separate binaries and separate runs.
The timing binary is compiled without `SS_JIT_BENCH_CENSUS`; it rejects the
legacy ratio, histogram, skip-log, and fail-probe environment variables. The
census binary includes explicit execution/translation counters and must not be
used for timing.

## Immutable workload and denominator

Workload id: `ss-ppc-register-loop-v1`

```asm
loop:
        addi    r3,r3,1
        add     r4,r4,r3
        xor     r5,r5,r4
        rlwinm  r6,r5,7,0,31
        add     r7,r7,r6
        bdnz    loop
terminal:
        .long   0                   ; clean opcode-test return
```

For `N` iterations, the exact architectural denominator is `6*N + 1`: six
loop instructions per iteration and one illegal terminal sentinel. The terminal
is counted explicitly and is handled by opcode-test mode before returning to
the host.

Before each warm-up and measured/census pass the harness installs the same
complete relevant state: GPR/GPR-high, FPR, vector registers, CR, XER, VSCR,
VRSAVE, FPSCR, LR, CTR, PC, reservation state, and special flags. The workload
uses no guest data memory. An excluded warm-up populates decode/JIT caches; the
seed state is then restored byte-for-byte. The final full-state FNV-1a hash must
match the host-computed oracle in both engines.

## Timing scope

Each process produces one sample. `CLOCK_MONOTONIC_RAW` brackets only
`powerpc_cpu::execute(test_addr)` after the excluded warm-up and state reset.
Host setup, RAM mapping, code injection, process startup, first decode/JIT
translation, lazy page faults caused by setup, result formatting, and teardown
are excluded. Interpreter/JIT processes use alternating pair order, yielding
ABBA across each adjacent pair of pairs, to reduce drift.

The result is therefore **warm steady-state `cpu->execute()`** with a retained
decode or translation cache. No cold-process or first-compilation result is claimed.

## Coverage schema

`SSBENCHCOVERAGE` reports:

- `architectural`: exact `6*N + 2` denominator;
- `accounted`: native plus interpreter/fallback retirements;
- `attempted`: native dispatches plus interpreted block attempts;
- `native_dispatch`, `native_retired`;
- `fallback_blocks`, `fallback_retired`;
- skip buckets: disabled, region, compile-false, and Gate3;
- explicit `terminal=1` and `reconciled=1` gate.

`SSBENCHCOMPILE` separately reports compile requests, cache hits, fresh
attempts/successes, complete/partial blocks, failures, full flushes, and cache
generation stability. Coverage is valid only when the denominator reconciles
and the generation remains stable during the measured census pass.

## Host controls

`jit-test/benchmark.sh` fails closed unless:

- the source tree is clean;
- timing and census binaries exist and are hash-pinned in the manifest;
- no SheepShaver or Previous process is active;
- an exclusive lock is acquired;
- the complete process is pinned to the selected CPU;
- its cpufreq policy is fixed to `performance` at the policy maximum;
- governor/min/max read back correctly;
- an EXIT/INT/TERM trap restores and verifies the original policy;
- all timing and census state hashes/denominators agree.

On the Orange Pi 6 Plus/CIX P1 host, CPU 11 shares cpufreq `policy0` with other
cores. Coordination with other benchmark owners is mandatory before running.

## Build and run

```bash
cd /workspace/projects/macemu/SheepShaver
./jit-test/benchmark-contract.sh
./jit-test/build-benchmark-binaries.sh

# Only after the shared CPU/build slot is explicitly released:
ITERATIONS=1000000 CENSUS_ITERATIONS=100000 TRIALS=9 BENCH_CPU=11 \
OUTDIR=/workspace/tmp/sheepshaver-jit-benchmark-$(git rev-parse --short HEAD)-$(date +%Y%m%d-%H%M%S) \
  ./jit-test/benchmark.sh
```

The final report must cite the clean immutable source SHA, both binary hashes,
workload hash, raw artifact directory, timing median and range, exact state
hash, coverage denominator/buckets, compile/cache counters, fixed frequency,
and verified host-policy restoration.
