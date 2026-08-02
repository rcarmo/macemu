# SheepShaver bounded JIT benchmark result — 2026-08-02

## Scope

This result is a **warm steady-state `cpu->execute()`** microbenchmark of one
register-only, dispatch-heavy PPC loop. It is not a cold startup, first-compile,
Mac OS boot, Finder, device, memory, or application-performance result.

The retained warm-up populates the interpreter decode cache or direct-JIT
translation cache. Timing brackets only the subsequent `cpu->execute()` call.
Compile/cache/generation accounting comes from separate instrumented census
binaries and runs; census overhead is absent from the timing binary.

## Immutable identity

- Harness/source SHA: `23782a4d2d5dcd2e6be0a6a11b54a829f518d5c5`
- Timing binary SHA-256: `d069e7bcc5f4872dc5a1488b2db48cb30bb34b4e60184c3bf2942eea475c0840`
- Census binary SHA-256: `65d93e84f196e4b45931d8906725afa8ae741df432688d39cfc3dc23f3a8bffe`
- Workload id: `ss-ppc-register-loop-v1`
- Workload SHA-256: `475586b4ccc5287b5a5219b29928ed0bf27b738fdbea17a7b193ea1cd3639522`
- Raw artifact: `/workspace/tmp/sheepshaver-jit-benchmark-final-23782a4d-20260802-122236`
- Host: Orange Pi 6 Plus, CIX P1, 12 CPU cores, approximately 14 GiB visible RAM, Debian Linux arm64
- Timing CPU: CPU11, cpufreq `policy0`, fixed `performance` at `2,600,198 kHz`

The repository was clean and equal to upstream before and after the run. CPU11
was online; no SheepShaver, Previous, build, display `:140`, or port `9983`
workload overlapped. The runner acquired an exclusive lock. Its EXIT trap
restored and verified the original policy: `schedutil`, minimum `799,865 kHz`,
maximum `2,600,198 kHz`.

## Workload and exact state

The workload is five register ALU operations followed by `bdnz` back to the
leader. On final fall-through it reaches one zero-word terminal sentinel, which
opcode-test mode handles as a clean return. For `N` iterations the exact
architectural denominator is `6*N + 1`.

Every timing sample used `N=5,000,000`, therefore `30,000,001` architectural
instructions. All 18 samples reached identical full-state hash
`c1fc9a7d704b4152`. The state hash covers GPR and GPR-high state, FPRs, vector
registers, CR, XER, VSCR, VRSAVE, FPSCR, LR, CTR, PC, special flags, and
reservation state.

Nine alternating engine pairs were recorded: four complete ABBA quartets plus
a final AB pair:

```text
interp, jit, jit, interp, interp, jit, jit, interp,
interp, jit, jit, interp, interp, jit, jit, interp,
interp, jit
```

## Timing result

Nine samples were recorded per engine.

| Engine | Median | Mean | Range | Sample SD | CV |
|---|---:|---:|---:|---:|---:|
| Interpreter | 99.411010 ms | 99.429481 ms | 99.386050–99.494350 ms | 0.040461 ms | 0.040693% |
| AArch64 direct JIT | 187.762350 ms | 187.498601 ms | 185.871030–188.244700 ms | 0.825492 ms | 0.440266% |

Median ratios:

- interpreter / JIT: `0.529451245×`;
- JIT / interpreter: `1.888748037×`.

Thus the direct JIT is **1.889× slower than the interpreter on this bounded
loop**. This is a measured result, not a failure of parity: the architectural
state and denominator match exactly. The loop terminates a native block at
`bdnz` every iteration so special flags can be observed at dispatcher
boundaries. It therefore measures a deliberately dispatch-heavy workload and
must not be generalized to larger straight-line blocks, chained forward
blocks, boot, or applications.

## Separate coverage census

Each census arm used `N=100,000`, hence `600,001` architectural instructions
and final full-state hash `3bb85fe1cea53b38`.

Interpreter:

```text
architectural=600001 accounted=600001 reconciled=1
native_dispatch=0 native_retired=0
fallback_blocks=100001 fallback_retired=600001
```

JIT:

```text
architectural=600001 accounted=600001 reconciled=1
native_dispatch=100000 native_retired=600000
fallback_blocks=1 fallback_retired=1
skip_compile_false=1 skip_region=0 skip_gate3=0
```

Coverage for this workload is therefore:

- loop body: `600,000 / 600,000 = 100%` native;
- complete architectural stream including terminal: `600,000 / 600,001 = 99.999833%` native;
- explicit terminal fallback: `1 / 600,001 = 0.000167%`.

The fallback is the designed zero-word terminal sentinel, not a workload opcode.
No region or Gate3 fallback occurred.

After the excluded JIT warm-up, the measured census reported:

```text
compile_requests=100002 cache_hits=100000
fresh_attempts=2 failures=2
full_flushes=0 generation_start=0 generation_current=0 stable=1
```

The 100,000 loop-entry requests hit the retained translation. After the
post-warm-up counter reset, the two fresh failures are two dispatch-layer
compile probes of the same measured zero-word terminal (fast redispatch, then
normal block entry) before its single interpreter retirement. There were no
translation flushes or generation changes during the census interval.

The census schema does not expose eviction counts, peak generated-code bytes,
cache occupancy, or headroom, so this report makes no claim about them. Thermal
or background-load telemetry and post-restoration values are likewise not
stored inside the raw artifact. Idle-host preflight and restoration were
observed independently after release; they are host-method evidence rather
than artifact-contained telemetry.

## Independent review

A separate `@previous` review recomputed the raw ordering, hashes, medians,
ranges, reciprocal ratios, exact census identity, terminal accounting, and
compile-request identity from the accepted artifact. It accepted the artifact
with the documentation corrections incorporated here: `6*N+1`, precise
nine-pair ordering, and explicit non-claims for eviction/occupancy and
artifact-contained thermal/load telemetry.

## Validation and exclusions

Before the final run:

- structural benchmark contract: pass;
- timing/census binary build: pass;
- complete opcode interpreter/JIT suite: `303/303`, fail `0`;
- short timing parity: exact matching state/denominator;
- short census reconciliation: exact;
- negative controls: timing binary rejected census mode, census binary rejected
timing mode, and timing rejected legacy observers;
- full runner smoke: passed summary generation and exact host-policy restoration;
  smoke artifact deleted and excluded.

Two earlier host attempts are excluded: one aborted before emulator launch and
one completed samples but failed summary generation. Both artifacts were
deleted, their results were not reused, and policy restoration was verified.
The final artifact is the only accepted series.

## Reproduction

```bash
cd /workspace/projects/macemu/SheepShaver
./jit-test/benchmark-contract.sh
./jit-test/build-benchmark-binaries.sh

ITERATIONS=5000000 CENSUS_ITERATIONS=100000 TRIALS=9 BENCH_CPU=11 \
OUTDIR=/workspace/tmp/sheepshaver-jit-benchmark-final-23782a4d-$(date -u +%Y%m%d-%H%M%S) \
  ./jit-test/benchmark.sh
```

Run only with explicit host-slot ownership. Do not call the timing result cold,
compile-inclusive, or representative Mac OS performance.
