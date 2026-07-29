# AArch64 strict native-entry counter optimisation

Date: 2026-07-29
Base commit: `d3a047c343b469485f751f787c84c8b85159be76`

## Result

Strict-full AArch64 JIT evidence accounting no longer enters C on every native
block activation. The generated entry now increments the 64-bit evidence
counter inline and calls the existing summary reporter only when the count is a
power of two. Explicit `B2_NATIVE_ASSERT_PC` diagnostics retain the old full
observer save/call/restore path.

This removes measurement overhead rather than changing guest DBcc semantics,
block formation, dispatch, fallback policy, or coherence. On the branch-heavy
`ADDQ.L`/`DBRA` kernel, the fixed-frequency median changed from the previous
strict result of 8.608 s to 1.288 s. The matched interpreter median is 3.391 s,
so strict JIT is now **2.632x faster** (95% bootstrap CI 2.627-2.636) and takes
**62.0% less elapsed time**. The previous strict result was 0.394x interpreter
speed, or 2.54x slower.

## Root cause

The strict evidence path previously called `b2_test_native_entry()` at every
native block entry. The observer saved and restored x0-x18, NZCV, FPCR, FPSR,
and d0-d7 around an AAPCS C call which incremented one counter. The branch
kernel enters roughly one native block for each inner DBRA iteration and reaches
at least 67,108,864 entries, while the large arithmetic block amortises entry
over about 1,000 guest operations. Strict instrumentation therefore dominated
the branch kernel it was intended to observe.

The replacement entry sequence is:

1. load the counter address and current 64-bit count;
2. increment and store it;
3. test `count & (count - 1)`;
4. skip the observer on the ordinary non-power-of-two path;
5. use the existing full observer boundary only for sparse summaries.

It is emitted at `bi->direct_handler`, before countdown and incoming guest-NZCV
restoration, so direct chains are counted and the flag-setting power-of-two test
cannot alter architectural flags. Reserved work registers are used. The
emulator CPU/JIT loop is single-threaded, so the evidence counter does not need
an atomic read-modify-write. Unsigned wrap would report a synthetic zero after
2^64 entries; no accepted run approaches that unreachable process lifetime.

## Host and protocol

Measurements ran host-native on the Orange Pi 6 Plus (`orangepi6plus`): CIX P1
12-core AArch64 SoC, 16 GB-class RAM (about 14 GiB visible), Debian Trixie,
NVMe root storage. Trials were pinned to CPU 11. The SCMI cpufreq policy was
locked to the `userspace` governor with minimum, maximum, requested, observed
start and observed end frequency all **2,600,198 kHz**. The original `schedutil`
policy and 799,865-2,600,198 kHz bounds were restored after each series.

No Previous process appeared before, between, or after accepted trials. CPU
series contamination logs are empty. Five samples per interpreter/JIT/kernel
arm were alternated by order. Seven Finder/VNC pairs were similarly alternated.
The binary SHA-256 for all accepted trials is
`bbf72915527216a364ec542645545b7471a11a2d2de33e2645c30e78c2b61942`.
Confidence intervals use 100,000 deterministic bootstrap resamples of median
speedup with seed `0x5eed1234`.

## Fixed-frequency CPU results

| Kernel | Interpreter median | Strict JIT median | Raw speedup | 95% CI | JIT elapsed reduction |
|---|---:|---:|---:|---:|---:|
| Startup baseline | 0.388 s | 0.387 s | 1.004x | 0.998-1.016 | 0.4% |
| Large hot arithmetic block | 1.889 s | 0.488 s | **3.873x** | 3.841-3.894 | 74.2% |
| 16-op DBRA arithmetic | 1.890 s | 0.487 s | **3.881x** | 3.849-4.856 | 74.2% |
| Branch-heavy ADDQ/DBRA | 3.391 s | 1.288 s | **2.632x** | 2.627-2.636 | 62.0% |

All matched final register states are identical. Every substantive strict run
emitted power-of-two summaries with `warmup=0 verify=0 opt0=0 fallback=0
exec_nostats=0`.

## Finder/VNC result and scope

The optimisation preserves real strict Finder operation but does not establish
a boot-speed win:

| Visual endpoint | Interpreter median | Strict JIT median | Speedup | 95% CI |
|---|---:|---:|---:|---:|
| Finder desktop | 1.194 s | 2.300 s | 0.519x | 0.508-0.530 |
| Open boot-disk window | 61.8 ms | 65.5 ms | 0.944x | 0.623-1.056 |

The desktop series has 14 valid trials, fixed frequency throughout, zero host
faults, and 21 zero-fallback strict summaries in each JIT trial. It demonstrates
that the accepted claim is workload-specific: translated CPU kernels are
faster, and the branch regression is removed, but strict Finder startup remains
slower than the interpreter under this deterministic visual protocol.

A separate interactive strict proof reached Finder and exercised keyboard,
pointer, Apple menu, boot-disk window and close actions. It captured 11
screenshots, emitted 25 valid strict summaries, and logged no host fault.

## Correctness and closure gates

- Focused DBcc/DBRA state vectors: 16/16 exact interpreter/JIT matches.
- Explicit native replay and strict fail-closed gates: pass.
- AArch64 branch-emitter conformance: pass.
- Maintained full harness: **904/904**, score 100, zero failures and zero
  infrastructure failures.
- Allocator pressure: **33/33**.
- Complete structural audit and `git diff --check`: pass.
- Closure inventory: the new audited raw boundary raises the deterministic
  inventory from 998 to 999 rows and raw boundaries from 83 to 84, with zero
  unreviewed/deferred rows.
- Independent bounded final-patch review: **APPROVE**, no blocker. Its NZCV
  wording correction was applied before the final structural/emitter rerun.

The first full-harness attempt was infrastructure-invalid after stale completed
harness trees filled `/tmp`; it produced `No space left on device` and is not
part of acceptance. The stale harness-owned trees were removed, `/tmp` returned
to 8% use, and the complete clean rerun above passed.

## Evidence

Accepted evidence is under:

- `/workspace/reports/basiliskii-strict-entry-optimisation-d3a047c3/cpu-final`
- `/workspace/reports/basiliskii-strict-entry-optimisation-d3a047c3/vnc-final`
- `/workspace/tmp/basiliskii-strict-entry-optimisation/full-harness-rerun.log`
- `/workspace/tmp/basiliskii-strict-entry-optimisation/regalloc-pressure.log`
- `/workspace/tmp/basiliskii-strict-entry-optimisation/finder-strict`

The prior `d3a047c3` validation report and its completed structural-audit verdict
remain unchanged.
