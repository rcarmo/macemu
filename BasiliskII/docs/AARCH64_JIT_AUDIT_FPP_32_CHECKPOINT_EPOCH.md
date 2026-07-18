# AArch64 FPP 32-checkpoint acceptance epoch

Date: 2026-07-18
Branch: `jit-audit-next`
Accepted range: `dedbc96e..cf305242`

## Scope

This epoch validates the exact 32-checkpoint FPP batch accumulated after the
previous full gate. It is an integration acceptance record, not an additional
closure promotion and not whole-engine completion. `generator,i_FPP` remains
unreviewed.

## Runtime acceptance

The complete default `jit-test/run.sh` passed both before and after a clean
AArch64 `CPU_AARCH64`/`USE_JIT_FPU` rebuild:

```text
METRIC pass=904
METRIC fail=0
METRIC total=904
METRIC infra_fail=0
METRIC fail_equiv=0
METRIC risky_total=904
METRIC score=100
```

The default gate includes every accepted generic emitter conformance probe plus
the complete active-risky guest campaign.

Allocator pressure also passed before and after the clean build:

```text
REGPRESSURE_SUMMARY selected=31 pass=31 fail=0
```

The post-clean strict full-JIT negative contract passed ordinary allocation
fallback plus all four expected abort classes:

```text
METRIC strict_allocation_fallback=1
METRIC strict_allocation_abort=1
METRIC strict_optlev0=1
METRIC strict_opcode_fallback=1
METRIC strict_verifier_reference=1
METRIC strict_full_jit_negative_gate=1
```

## Clean build and determinism

`make clean && make -j12 BasiliskII` completed from
`BasiliskII/src/Unix/Makefile`, whose configured definitions include
`CPU_aarch64`, `CPU_AARCH64`, `USE_JIT`, and `USE_JIT_FPU`.

Consecutive no-source-change `gencomp`/`gencpu` runs produced identical hashes:

```text
55fb6af9005d0077f91b3168707c67106824a5c43fa27c3deaf5bfeaabeee260  compemu.cpp
45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b  compstbl.cpp
67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1  comptbl.h
da11c3b18b695fea4b1afd449f3afaa03bf7053fe56710e1ba8d2347b04f1c60  cpuemu.cpp
e69fd69076f9f6202f451a4f2edf932eadbbc5f2ee8eb7ee2cc02a18b98c95de  cpudefs.cpp
781ad7b6565e9e211fb4d70b809999072fd3ecbe1e30f0dab2e9427d8af676ab  cpustbl.cpp
4f08689786bd25452d4aa6e28ee5a7c6603b38ec32f9b6663d66411578935f60  cputbl.h
2731d4db9f26d6e56b23faabb553d9b8dff104418bccbd724641508246819f5d  cpufunctbl.cpp
```

The deterministic closure inventory remained 998 rows:

```text
CLOSURE_INVENTORY rows=998 generator=130 midfunc=422 emitter_api=294 raw_boundary=83 runtime_boundary=69
19ab0730c17d634af9c474670ca232d30ffab87e4fdfb344cfa76e0baaf006a4  AARCH64_JIT_CLOSURE_INVENTORY.csv
d7b2f4962df69e42368eeca28cc3bc0a15bb40dd1965a059675afc967619d67c  AARCH64_JIT_CLOSURE_INVENTORY.md
```

## Hygiene and boundary

All shell files pass `bash -n`; `git diff --check` passes; the accepted
worktree was clean before this evidence record. Scoped checkpoint and epoch
temporary files are removed after publication.

This epoch does not close the explicit MMU runtime gap: the harness uses a 68040
model but a `DIRECT_ADDRESSING` non-`FULLMMU` build. It also does not replace the
final whole-engine exact-native, sustained-runtime, and strict Finder-retirement
gates required after the closure inventory is exhausted.
