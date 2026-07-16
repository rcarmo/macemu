# AArch64 JIT Bcc lifecycle audit

Date: 2026-07-16

## Scope

This report closes the reachable integer `i_Bcc` generator lifecycle. It covers
BRA plus all fourteen conditional Bcc conditions, byte/word/long displacement
decoding, signed forward/backward target arithmetic, extension-word-relative PC
semantics, flag preservation, dynamic block exits, exact native replay, and the
absence of dynamic allocator ownership.

BSR, DBcc/Scc, FBcc, and generic branch-emitter APIs are separate accepted or
remaining clusters and are not promoted here.

## Generator and target contracts

The configured AArch64 generator produces 90 handlers: 45 flag-live table
entries and 45 no-flags table entries. Each table contains three displacement
widths for BRA and all fourteen conditional conditions:

- byte displacements are explicitly sign-extended with `sign_extend_8_rr`;
- word displacements are explicitly sign-extended with `sign_extend_16_rr`;
- long displacements enter `arm_ADD_l_ri_hostptr`, whose constant and dynamic
  routes both sign-extend the guest 32-bit value before adding the host pointer;
- `arm_ADD_ptr_ri` performs the later compile-cursor fold at host pointer width;
- all 84 conditional handlers register exact not-taken/taken host targets and
  materialise the existing flags only after target registration;
- all six BRA handlers assign the target directly and re-anchor `comp_pc_p`;
- no generated Bcc handler takes a JIT-value lock, stores guest data, or emits
  flag-setting arithmetic.

The generator retains the historical x86 condition numbering used by shared
compiler state. Both the mid-block side-exit path and final-edge path translate
that numbering to AArch64 conditions before calling the raw branch boundary.
HI/LS retain their dedicated composite carry/Z lowering in
`compemu_raw_jcc_l_oponly`; that raw boundary remains a separate closure row.

## Exact-native runtime matrix

The focused matrix contains 34 exact-native vectors:

- 28 byte-displacement conditional vectors: taken and not-taken for HI, LS, CC,
  CS, NE, EQ, VC, VS, PL, MI, GE, LT, GT, and LE;
- three forward BRA vectors, one for each byte/word/long displacement width;
- three signed backward BNE loops, one for each byte/word/long displacement
  width, with replay anchored at the branch opcode after a setup prefix.

Every conditional vector uses non-CCR-mutating MOVEA markers on both paths and
checks the exact final SR. This proves all XNZVC bits survive both branch
outcomes rather than relying only on interpreter/JIT equality. Native replay
uses two passes at the exact branch PC.

Focused result: **34/34**, zero semantic or infrastructure failures, score 100.

## Structural result

The fail-closed structural audit locks:

- one generator case and exact 16-entry condition map;
- 90 generated handlers split 45/45 across flag tables;
- 30 byte and 30 word explicit sign extensions;
- 90 signed guest-displacement/host-base conversions;
- 90 source and 90 fallthrough pointer-width cursor folds;
- 84 conditional target registrations and flag materialisations;
- six direct BRA target assignments;
- six generated width/table routes for each used historical condition code;
- both x86-to-AArch64 condition translation boundaries;
- all 34 vector encodings, expected path/SR results, initial states, exact-native
  replay anchors, risky tags, and active-corpus entries.

## Acceptance evidence

- focused exact-native matrix: **34/34**, zero semantic or infrastructure
  failures, score 100;
- complete active-risky replay: **861/861**, zero semantic or infrastructure
  failures, score 100;
- complete allocator-pressure replay: **28/28**; Bcc owns no dynamic JIT values,
  and existing allocator-family witnesses remain clean;
- strict full-JIT negative gate passes, including the expected allocation abort;
- clean AArch64 `uae_cpu_2026` / `USE_JIT_FPU` build produces an AArch64 ELF;
- generated output is byte-reproducible before clean, after clean, and after two
  explicit regenerations:
  - `compemu.cpp`: `55fb6af9005d0077f91b3168707c67106824a5c43fa27c3deaf5bfeaabeee260`;
  - `compstbl.cpp`: `45c041a4403ee8027ae06b3f55a9aac4deabddb2491921046c06613d8537c16b`;
  - `comptbl.h`: `67118d1c2fa1c268b67f034da563c074dea72c959b668e92b7d8c28ead16e6d1`;
- deterministic 997-row closure inventory promotes exactly generator `i_Bcc`:
  - generator `audited=54`, `serviced=44`, `unreviewed=32`;
  - MIDFUNC remains `audited=262`, `unreachable=118`, `unreviewed=42`;
  - emitter API remains `audited=49`, `unreachable=91`, `unreviewed=154`;
  - raw boundary remains `audited=24`, `unreviewed=58`;
  - CSV: `feaef3986eb02ffe54a03881ea6f02208c017855c82fa8bb2962f7e088fca768`;
  - Markdown: `072a30abf8d95b275d576582c4abceac1db02e706b29fd8b6badbc2aa91c416a`;
- shell syntax, structural audit, deterministic closure regeneration, source
  hygiene, and diff hygiene are clean.

The raw `compemu_raw_jcc_l_oponly` boundary and its callers remain separately
unreviewed; this report uses but does not promote it. Whole-engine closure is not
claimed.
