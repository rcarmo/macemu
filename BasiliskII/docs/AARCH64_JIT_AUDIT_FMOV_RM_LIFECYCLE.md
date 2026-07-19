# AArch64 JIT binary64 memory-source load lifecycle

Date: 2026-07-19  
Branch: `jit-audit-next`  
Base: `d9cea0e0`

## Scope

This checkpoint audits the live `fmov_rm` MIDFUNC and its shared lower boundary
`raw_fmov_d_rm`. Together they load an already assembled host-memory IEEE
binary64 value into a floating virtual register.

The only control-flow-reachable configured root is the ordinary FPP
`get_fp_value(size=5)` double-memory source path. Four additional `fmov_rm`
spellings remain below the configured FMOVECR exact-MPFR service barrier and do
not enlarge runtime scope. The previously retired `fmov_d_rm` synonym remains
unreachable.

## Source and memory contract

Guest memory is not read directly by `raw_fmov_d_rm`. `get_fp_value()` first
uses the ordered guest-memory helpers to assemble the Motorola big-endian
double in static `temp_fp` host storage:

1. read the guest high 32-bit word at the effective address;
2. store it at `temp_fp + 4` on the little-endian AArch64 host;
3. advance the effective address by four;
4. read the guest low 32-bit word;
5. store it at `temp_fp`;
6. call `fmov_rm(FS1, temp_fp)`.

The MIDFUNC acquires FS1 through `f_writereg`, which selects its fixed D7 home
and sets its allocator state `DIRTY`. `f_mark_runtime_dirty` intentionally does
not set an architectural dirty-mask bit for FS1 because it is scratch
(`FS1=9`, beyond `FP_RESULT=8`). It then calls the raw boundary and completes
the fixed-home release operation.
`raw_fmov_d_rm` materialises the host pointer and performs one binary64 load.
Ordinary opcode cleanup later retires FS1 through the separately accepted
`f_forget_about` contract.

The chain does not alter architectural integer CCR. Subsequent ordinary-FMOVE
logic publishes the loaded value to its destination and lazy `FP_RESULT`
through already accepted `fmov_rr` composition.

## Configured-root proof

The closure and structural checks fail closed unless:

- raw FPP source has exactly five `fmov_rm` spellings;
- exactly one, `fmov_rm(FS1, temp_fp)`, precedes the FMOVECR service block;
- all four constant-table spellings remain after its pre-selector return;
- the double high/low assembly and load order remains exact;
- `fmov_rm` retains allocation -> raw load -> release ordering;
- FS1 retains its D7 scratch home, dirty marking, and opcode cleanup;
- the retired `fmov_d_rm` synonym stays outside the reachable graph; and
- `raw_fmov_d_rm` retains one live caller and its pointer/load body.

## Runtime evidence

`bash jit-test/fmov-rm-native-matrix.sh` runs every existing strict exact-native
double-source case from the accepted ordinary-FMOVE source matrices:

- `(A0)`, `(A0)+`, and `-(A0)`;
- `d16(A0)` and brief indexed A0;
- absolute short and absolute long;
- PC-relative d16 and brief indexed PC;
- absolute long to FP7, proving the maximum destination field.

All ten cases require exact binary64 shadow bits, FPSR, unchanged `SR=0x271f`,
correct address-register writeback/preservation, strict second-pass native
entry with no fallback, restored memory fixtures, and isolated CoW/HOME
cleanup through the underlying matrices.

Expected focused result:

```text
FMOV_RM_NATIVE_MATRIX pass=10 fail=0 total=10
```

The complete accepted source matrices remain broader evidence: basic memory
**18/18** and extended EA **39/39** across all five source formats.

## Closure decision

The following rows become **audited**:

- `midfunc,fmov_rm`;
- `raw_boundary,raw_fmov_d_rm`.

`midfunc,fmov_d_rm` remains unreachable. No generic emitter API row changes,
and no production or generated source changes. Whole-engine closure is not
claimed.

## Acceptance

- focused strict exact-native double-source matrix: **10/10**;
- independently rerun complete source matrices: basic **18/18** and extended EA
  **39/39**;
- structural audit: pass for the one live root, four dead FMOVECR spellings,
  high/low assembly order, FS1 allocator and dirty-mask boundaries, raw load,
  cleanup, and exact wrapper inventory;
- deterministic inventory: **998 rows**, exactly `fmov_rm` and
  `raw_fmov_d_rm` unreviewed -> audited; MIDFUNC totals become 280 audited /
  123 unreachable / 19 unreviewed, raw totals become 31 audited / 21
  unreachable / 31 unreviewed, and total unreviewed becomes **177**;
- `AARCH64_JIT_CLOSURE_INVENTORY.csv`:
  `e47eaaa544f17bca6b3caf477aee7f794c13758b8b2a9c81297bbeeccc07e5e4`;
- `AARCH64_JIT_CLOSURE_INVENTORY.md`:
  `375e2474eba60ca2b1bfb958c1fdf553e0f2c6bbd8cd90bee73d8bdb139b2f1b`;
- independent bounded review: **APPROVE** for control-flow roots, endian
  assembly, fixed-home scratch ownership, non-architectural FS1 dirty-mask
  behavior, raw load, all ten cases, CoW cleanup, and exact two-row scope;
- executable source is unchanged from canonical `d9cea0e0`. The carried
  integration baseline remains active corpus **904/904**, allocator pressure
  **33/33**, strict policy pass, clean AArch64 `USE_JIT_FPU` build, and stable
  generated sources;
- accepted unchanged artifacts:
  - `compemu.cpp`: `90b3064253b7d2894cd9ecaed738687ba6b2ff7aec5ec75586afa212db7dd1ee`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
  - AArch64 `BasiliskII`: `23d3ffce585ad7fd8512e7565ad7258a5a380a2c08e651afbc8dcdd06f3dfe5b`.

Shell/Bun syntax, source hygiene, `git diff --check`, and scoped CoW/HOME
cleanup pass. Acceptance logs are removed after publication.
