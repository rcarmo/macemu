# AArch64 JIT FPP ordinary FMOVE source subtranche

## Scope

This is the second bounded subtranche of the reachable `i_FPP` generator audit.
It originally covered ordinary `FMOVE` inputs across FP-register, Dn, and
immediate sources. The maintained native scope now covers:

- Dn byte, word, long, and IEEE single sources;
- immediate byte, word, long, IEEE single, and IEEE double sources;
- exact native-double shadow values, FPSR condition classes, and integer-CCR
  preservation.

FP-register copies were later moved to exact MPFR service because the binary64
shadow cannot preserve architectural extended values. Their complete current
owner is `AARCH64_JIT_AUDIT_FPP_FMOVE_REGISTER_BATCH.md`, not this native
matrix.

It does **not** promote `generator,i_FPP`. Explicit-precision `FSMOVE`/`FDMOVE`,
extended precision, memory effective-address lifecycle, FMOVE stores, FMOVECR,
FMOVEM, control-register moves, arithmetic, exceptions, and remaining semantic
services are separate subfamilies.

## Defect found and repaired

The AArch64 compatibility shim mapped legacy `fmovi_rm(d, m)` to
`fmov_l_rr(d, m)`. `get_fp_value()` first stored an integer source in the
host-global `temp_fp`, then passed that host pointer as `m`. The AArch64 MIDFUNC
interpreted it as a virtual integer-register number. Native FMOVE therefore
read invalid allocator state and faulted at a null address before REGDUMP.

The configured AArch64 path now bypasses the x86-era memory shuttle and uses the
existing typed register conversion MIDFUNCs directly:

- `fmov_b_rr` for signed byte;
- `fmov_w_rr` for signed word;
- `fmov_l_rr` for signed long;
- `fmov_s_rr` for IEEE single bits.

The same direct conversion applies after guest-memory/immediate fetch into S2,
but this checkpoint tests only immediate addressing; arbitrary memory EA and
writeback ownership remain deferred.

## Exact-native evidence

`bun jit-test/fpp-fmove-source-matrix.ts` now runs 29 fail-closed strict native
cases:

- signed integer extrema and positive boundaries for byte/word/long;
- signed zero, infinities, NaNs, and fractional single/double values;
- maximum D7 and FP7 encoding fields;
- exact second-pass native entry at each audited FMOVE;
- exact 64-bit native shadow values, exact FPSR CCB, and `SR=0x271f`.

Accepted current results:

```text
FPP_FMOVE_SOURCE_MATRIX pass=29 fail=0 total=29
FPP_REGISTER_MOVE_MATRIX service_pass=66 strict_pass=3 fail=0 total=69
```

The previous 43-case aggregate mixed 29 still-native Dn/immediate cases with 14
FP-register cases whose execution policy was later intentionally changed. Its
default expectation is retired; all 64 register pairs, eight aliases, exact
extended values, and maximum fields are now covered by the 66+3 service owner.

REGDUMP exposes FP0-FP7 only when `B2_TEST_DUMP_FP=1`. This keeps the ordinary
interpreter/JIT equivalence contract stable: non-FPU interpreter runs leave the
native shadows zero while JIT block entry deliberately initializes them from
architectural MPFR state (often NaN). The dedicated FMOVE matrix opts into the
observer because it compares native FPU values directly.

Integrated evidence:

```text
active-risky: pass=904 fail=0 infra_fail=0 score=100
allocator pressure: pass=31 fail=0
```

FP allocator ownership is statically partitioned on AArch64: FP0-FP7 map to
callee-saved d8-d15 and FS1 maps to d7. Integer scratch-alias injection cannot
collide with those destinations. The accepted register-service matrix replays
all eight architectural FP registers and checks all 64 source/destination
pairs; the existing 31-cell integer matrix remains cross-subsystem evidence.

## Structural contracts

- AArch64 Dn and fetched/immediate integer sources use typed register conversion
  MIDFUNCs, never the host `temp_fp` pointer as a virtual register.
- All four conversion widths are required in both Dn and fetched-source paths.
- The focused native matrix requires strict full-JIT, exact native entry, CoW
  disk isolation, exact SR/FPSR, exact FP shadow values, and an exact total of
  29; it rejects superseded FP-register-source cases.
- The separate register-service matrix pins all 64 pairs, 66 service vectors,
  three strict rejections, exact extended storage, and service attribution.
- Explicit-precision operation names are rejected from the bounded matrix.

## Closure decision

The original repair promoted no row to audited. It created direct configured
call paths to `fmov_b_rr`, `fmov_w_rr`, `fmov_s_rr`, and `fmov_l_rr`; those
current compound MIDFUNC classifications remain separate.

A later configured-root audit established that the legacy split-word
`fmov_d_rrr` MIDFUNC has no production caller and that `raw_fmov_d_rrr` is
therefore definition-only. The raw wrapper is now **unreachable**, guarded by
its exact `BFI_xxii` then `FMOV_dx` body and future-caller checks. This is a
one-row graph correction, not native acceptance: shared `BFI_xxii` remains
reachable/**unreviewed**, `FMOV_dx` remains reachable/**audited**, and the live
immediate-double route remains in the 29-case native matrix.

`generator,i_FPP` remains **unreviewed** until its remaining reachable
subfamilies have direct evidence or explicit serviced/unreachable
classification.
