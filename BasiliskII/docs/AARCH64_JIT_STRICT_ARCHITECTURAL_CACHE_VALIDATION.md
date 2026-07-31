# AArch64 strict architectural-cache validation

Date: 2026-07-31
Base commit: `b9215b8779c9a6990e6fb625bcc2edfdad298fad`

## Result

Strict full-JIT architectural instruction-cache invalidation now validates
translated source lazily instead of discarding the complete translation cache.
The generic `flush_icache()` bridge and compiled CINV/CPUSH instruction-cache
forms share one policy selector. Allocation, teardown and code-cache exhaustion
remain hard-flush boundaries.

On the host-native Orange Pi 6 Plus, the visually proved responsive-Finder
median falls from **56.829 s** at the base to **5.210 s** with the candidate:
**10.908x faster** and **90.832% less elapsed time**. The deterministic paired
bootstrap 95% interval is **10.173-11.143x**. The candidate remains slower than
the **2.614 s** interpreter median, so this is a strict-JIT regression removal,
not an interpreter-superiority claim.

## Root cause

Strict Finder startup repeatedly executes architectural instruction-cache
invalidations. Both the generic bridge and compiled cache-control helper used a
whole-cache hard flush. A diagnostic run reached about 3.20 million fresh
compilations, only 50 recompilations and 21,276 hard flushes by 44 seconds. The
startup loss was therefore a hard-flush/retranslation storm, not cold-RAM
policy or generally poor generated code.

## Lifecycle change

`flush_icache_architectural(reason)` now selects:

- strict full-JIT: `flush_icache_lazy(reason)`;
- ordinary configured lazy mode: `flush_icache_lazy(reason)`;
- ordinary default mode: `flush_icache_hard(reason)`.

A strict architectural transition marks active blocks `BI_NEED_CHECK` and
routes each target's inbound cache-line/dependency edges through that target's
`direct_pcc`. An unchanged RAM block becomes active only after its own checksum
passes. A changed block invalidates and retraces.

Strict mode does not recursively validate successors after a block passes its
local checksum. Lazy flush already gates every target's inbound edges through
that target's own `direct_pcc`; reactivating a source restores only edges into
that source, while its outgoing edges remain gated by their targets. Ordinary
lazy mode retains the historical recursive walk.

The following remain direct `flush_icache_hard()` boundaries:

- translation-cache allocation and teardown;
- cache-state replacement;
- code-cache exhaustion after the final use of the just-built block.

## Correctness acceptance

Candidate binary SHA-256:

```text
0134d65a3587d37668a99ac5f847c1061dd16bdbbe04226a4f30b118996a1312
```

Accepted gates:

- complete maintained validation: **904/904**, score 100;
- equivalence failures: **0**;
- infrastructure failures: **0**;
- allocator pressure: **33/33**;
- raw checksum boundary: unforced control clean, unchanged source accepted,
  changed source rejected;
- cache-disabled self-modification, host-code reuse, zero-source RAM, cache
  privilege and successor controls: pass;
- closure inventory: **999 rows**, zero unreviewed rows, byte-stable regeneration;
- structural audit and `git diff --check`: pass;
- strict Finder proof: Finder reached, shutdown dialog dismissed, keyboard and
  pointer accepted, Apple-menu target exercised and desktop icons selected;
  **25** strict summaries, zero bad summaries and zero host faults.

## Fixed-frequency Finder protocol

The accepted run is under
`/workspace/reports/basiliskii-strict-architectural-flush-b9215b87/vnc-finder-valid`.
It contains seven rotating interpreter/base/candidate triplets (21 trials).

Hardware and controls:

- Orange Pi 6 Plus, CIX P1 AArch64 SoC, 12 CPU cores;
- 16 GB-class RAM (about 14 GiB visible), Debian Trixie, NVMe root;
- CPU 11 pinned at **2,600,198 kHz** under `userspace`;
- frequency checked before and after every trial;
- no Previous or Borg process before, between or after trials;
- original `schedutil`, 799,865-2,600,198 kHz policy restored afterward;
- every strict trial emitted 25 summaries with `warmup=0 verify=0 opt0=0
  fallback=0 exec_nostats=0` and zero fault markers.

Compared binaries:

```text
bbf72915527216a364ec542645545b7471a11a2d2de33e2645c30e78c2b61942  base b9215b87
0134d65a3587d37668a99ac5f847c1061dd16bdbbe04226a4f30b118996a1312  candidate
```

The visual oracle was derived from accepted Finder proof frames. It first
requires the actual white Finder menu bar with the expected menu-glyph density,
then sends `Tab` and requires the Macintosh HD icon/label to paint. Eleven fixture
checks reject the Welcome splash, early boot frame, blank post-dialog desktop
and improper-shutdown dialog while accepting five real Finder frames. This
measures launch plus a proved post-launch input/paint response.

| Endpoint | Interpreter | Base strict JIT | Candidate strict JIT | Candidate vs base | 95% CI |
|---|---:|---:|---:|---:|---:|
| Finder menu | 2.485 s | 53.454 s | 4.880 s | **10.954x** | 10.816-11.187x |
| Responsive Finder | 2.614 s | 56.829 s | 5.210 s | **10.908x** | 10.173-11.143x |

The candidate's responsive-Finder elapsed-time reduction is **90.832%**
(95% interval **90.170-91.025%**). It runs at 0.502x interpreter speed at this
endpoint (95% interval 0.465-0.542x).

## Retracted VNC numbers

Earlier reports labelled 1.194/2.300-second frames as “Finder desktop” and
61.8/65.5-millisecond frames as “disk window”. Endpoint inspection disproved
both labels: those screenshots were early boot/Welcome frames, and the old disk
classifier was already true at action poll zero because a large white splash or
dialog region exceeded its threshold. Those figures are invalid and must not be
used as Finder performance evidence. All timing claims above use the repaired,
fixture-tested oracle for every arm.

## Independent review

`github-copilot/gemini-3.1-pro-preview` returned **APPROVE** after reviewing the
full edge-repatch, checksum and lazy-flush context. It confirmed that per-target
`direct_pcc` gating makes recursive successor validation redundant only in
strict mode. A preceding flash-model BLOCK was rejected because its claims
contradicted the supplied source and successful rebuild.

## Reproduction

```sh
./jit-test/run.sh
./jit-test/regalloc-pressure-matrix.sh
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
bun /workspace/reports/basiliskii-strict-architectural-flush-b9215b87/scripts/test-finder-ready-oracle.ts
/workspace/reports/basiliskii-strict-architectural-flush-b9215b87/scripts/run-finder-valid-series.sh
bun /workspace/reports/basiliskii-strict-architectural-flush-b9215b87/scripts/analyse-finder-valid.ts
git diff --check
```
