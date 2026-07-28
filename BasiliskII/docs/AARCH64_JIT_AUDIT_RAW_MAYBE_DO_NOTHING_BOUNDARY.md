# AArch64 JIT raw specialty-exit boundary audit

Date: 2026-07-28

Base: `de8ac7bb` (`master`, published raw condition-only branch closure)

## Scope

This tranche audits only the mechanically selected
`compemu_raw_maybe_do_nothing`. The downstream `popall_do_nothing` unwind,
FPU-shadow publication, `do_nothing()` specialty service, and generic branch
encoders remain independently classified. This report proves the conditional
raw handoff and its cycle ownership at every configured caller.

## Boundary contract

For each interpreter/fallback barrier that cannot safely hot-chain past a
pending specialty, the body must:

1. load the 32-bit `regs.spcflags` field from fixed `R_REGSTRUCT`;
2. fall through without reading or changing `countdown` when the field is zero;
3. otherwise load the signed 32-bit global `countdown`, subtract the exact
   compile-time retired-cycle value once, using imm12 lowering for `0..4095`
   and a materialised 32-bit register outside that range, then store the
   wrapped 32-bit result; and
4. branch through the range-checked/patched `B` terminal to
   `popall_do_nothing`.

The terminal is exclusive: `popall_do_nothing` publishes the FPU shadow,
restores preserved registers, and tail-enters `do_nothing()`. The emitted code
following this raw call is reachable only from the zero-flags fall-through.
Consequently a caller may place another terminal after the raw boundary
without double-consuming cycles: exactly one of those terminals executes.

## Exact-native proof

`jit-test/raw-maybe-do-nothing-conformance.sh` extracts the production
`LOAD_U32`, `LOAD_U64`, and raw body into a native AArch64 probe. Four cases
cross zero/nonzero `spcflags` with cycle values `0xfff` and `0x1000`:

| Flags | Cycles | Route | Countdown |
|---:|---:|---|---|
| zero | `0xfff` | fall-through | unchanged |
| nonzero | `0xfff` | terminal | subtract once |
| zero | `0x1000` | fall-through | unchanged |
| nonzero | `0x1000` | terminal | subtract once |

The probe requires the `0xfff` body to contain immediate `SUB`, the `0x1000`
body to contain register `SUB`, and the latter to be exactly one emitted word
longer. Both taken cases use hostile `0x80000001` flags and a nontrivial
`0x12345678` seed, so neither truthiness nor 32-bit arithmetic is inferred from
an all-zero fixture.

## Configured runtime proof

`jit-test/raw-maybe-do-nothing-boundary-matrix.sh` uses the restored-SR
interpreter barrier in an L2 RAM block. A replay-only hook injects either zero
or `SPCFLAG_JIT_END_COMPILE`; the already-audited following
`execute_normal_cycles` counters identify which exclusive route ran.

| Case | Injected flags | Following terminal | Following countdown |
|---|---:|---|---:|
| fall-through | zero | `direct_execute_normal=1`, `execute_normal_cycles=1` | `10000 -> 8976` |
| taken | `SPCFLAG_JIT_END_COMPILE` | not entered: both counters zero | not observed there |

Both cases retain the exact terminal register dump. Combined with the direct
native probe's exact subtraction oracle, the paired result proves the raw
terminal and following terminal are mutually exclusive rather than additive.
The injected JIT-only flag is accepted by `m68k_do_specialties()` and is
cleared without introducing a guest-visible interrupt or exception.

## Reachability and structure

The configured source has eight production calls plus the definition, for nine
whole-root references. They cover runtime-PC barriers, dynamic returns, DBcc,
fallback control transfer, explicit interpreter barriers, diagnostic fallback
termination, mid-block fallback continuation, and fallback-only block
finalisation. Structural acceptance pins all eight caller contexts, the
load/branch/subtract/store/terminal ordering, both lowering arms, gated
instrumentation, bounded replay parsing, exact probe extraction, live matrix,
and one-row closure promotion.

## Acceptance results

Final acceptance:

- exact-extracted native matrix: **4/4**;
- zero-flags fall-throughs: **2/2**;
- nonzero-flags terminals: **2/2**;
- imm12/register lowering boundary: **2/2**;
- once-only subtraction: **4/4**;
- configured live matrix: **2/2**;
- exclusive following terminals: **2/2**;
- configured whole-root references: **9**;
- complete emitter/boundary phase: pass, including
  `emitter_fmsub_exact_words=1048576`;
- complete active-risky corpus: **904/904**;
- allocator pressure: **33/33**;
- clean full AArch64 build: pass;
- complete structural audit: pass;
- deterministic 998-row closure regeneration: exactly one row promoted,
  leaving **70 emitter APIs** and **4 raw boundaries** unreviewed;
- published predecessor CSV SHA-256:
  `f3a79573a57e2d6664910b445dbfb779a56c401684e62b878154971e858999f5`;
- repeated current hashes: inventory CSV
  `ccad95c24f1975dbfb0e7c2bc5de24fc6d331bbb19f8815da6a59d41fe885091`,
  Markdown
  `e2b31beee21aab8655ffb45342f07e7cae59dce017878edb19c5407fe06c9f8a`,
  and generated `compemu.cpp`
  `37dfc019905a6e3c6a377201066fc7262ce475ba7caf85b0e2b4efda620550aa`;
- production source changes: replay-only test injection in `basilisk_glue.cpp`;
  the emitted raw body and ordinary runtime path are unchanged;
- source hygiene: pass;
- independent bounded review: first attempt timed out without a verdict; the
  bounded retry approved branch patching, zero-path no-touch, exact 32-bit
  arithmetic/lowering, replay injection timing, mutually exclusive terminal
  inference, caller census, and full-file one-row hash proof; final re-review:
  **approve**.

## Closure effect

Deterministic regeneration must move exactly
`compemu_raw_maybe_do_nothing` from `unreviewed` to `audited`, leaving 70
emitter APIs and 4 raw boundaries unreviewed. Whole-engine closure is not
claimed.

## Reproduction

```sh
./jit-test/raw-maybe-do-nothing-conformance.sh
./jit-test/raw-maybe-do-nothing-boundary-matrix.sh
./jit-test/run.sh --phases emitters --build-mode skip
bun jit-test/structural-audit.ts
bun jit-test/closure-inventory.ts
git diff --check
```
