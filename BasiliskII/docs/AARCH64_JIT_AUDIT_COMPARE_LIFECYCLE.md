# AArch64 JIT compare lifecycle audit

Date: 2026-07-14
Branch: `structural-audit`

## Scope

This tranche audits the complete configured compare family through its actual
shared lowering rather than through mnemonic names alone:

- `CMP.B/W/L <ea>,Dn`, including CMPI encodings and constant propagation;
- `CMPM.B/W/L (An)+,(An)+`, including same-register and A7 geometry;
- `CMPA.W/L <ea>,An`, including word-source sign extension;
- X preservation and complete N/Z/V/C replacement;
- M68K borrow polarity versus native AArch64 subtraction carry;
- flag-live and flag-dead generation;
- register aliases, ordered memory reads, EA writeback, special memory, and
  source/destination allocator ownership.

The authoritative generator is
`src/uae_cpu_2026/compiler/gencomp.c`; `src/Unix/compemu.cpp` is generated.

## Actual reachability

`i_CMP` and `i_CMPM` both use `genflags(flag_cmp, size, src, dst)`. The ARM64
legacy boundary maps `cmp_b/w/l` directly to six live MIDFUNCs:

- `jff_CMP_b`, `jff_CMP_w`, and `jff_CMP_l`;
- their `_imm` forms, reached when the source is compile-time constant.

`i_CMPA` does not call the four namesake `jff_CMPA_{w,l}[_imm]` definitions.
The generator sign-extends a word source, or aliases a long source, and then
uses the same live `jff_CMP_l` route. The namesake CMPA MIDFUNCs therefore remain
unreachable and are not promoted as audited implementations.

The generated flag-live call counts are:

```text
cmp_b(dst,src)  22
cmp_w(dst,src)  23
cmp_l(dst,src)  23
```

Flag-dead handlers retain operand reads and EA updates but emit no compare.
The bare emitter APIs named `CMP_*` serve wider backend users and remain
separate unreviewed closure rows; exercising them through this family does not
claim their global API audit.

## Demonstrated defect

### CMPM could lose its first fetched operand during the second read

CMPM performs two ordered memory fetches. The first private byte remained live
while the second EA and destination byte were allocated, but the generator did
not explicitly own that first value. A forced S4-to-S2 collision reproduced the
failure in exact native execution:

```text
REGPRESSURE cell=cmpm_b_source_dst_collision status=FAIL pin=1 skip=0 natexec=1 interpop=1
interpreter D2=22222710 SR=2710
JIT         D2=22222714 SR=2714
```

The second read took the first byte's host mapping. CMPM then compared the
second byte with itself and published false equality.

The generator now locks the fetched source before destination acquisition and
releases it after `genflags`. This applies the two-operand ownership contract to
all CMP/CMPM forms, not only the observed byte witness. Generated source has 136
matched CMP/CMPM locks and unlocks across the flag-live and nominal no-flags
tables. The repaired witness is:

```text
REGPRESSURE cell=cmpm_b_source_dst_collision status=PASS pin=0 skip=1 natexec=1 interpop=1
interpreter D2=22222710 SR=2710
JIT         D2=22222710 SR=2710
```

CMPA uses the same ownership rule across destination acquisition and source
widening. Its `(A0)+,A0` collision passes at `pin=0 skip=1`; generated source has
48 matched CMPA locks and unlocks.

## Proved semantic contracts

### Width and values

- Byte compares isolate operands by shifting both selected low bytes into bits
  31:24 before a 32-bit native compare.
- Word compares similarly isolate bits 15:0 in bits 31:16.
- Long compares use the full 32-bit lanes.
- Constant-folded long comparisons compute subtraction, signed overflow,
  unsigned borrow, sign, and zero in explicit `uae_u32`/`uae_s32` domains.
- CMPA.W sign-extends its source to 32 bits before the shared long compare;
  CMPA.L uses the original 32-bit source.
- Compare operations never write either architectural operand.

### Flags

AArch64 CMP publishes C as no-borrow; M68K CMP requires C as borrow. Every live
non-constant route reads NZCV, flips only the physical C bit, writes NZCV back,
and records `flags_carry_inverted=false`. Constant-folded CMP.L constructs the
same architectural NZVC directly. X is held separately and is neither read nor
written by any compare MIDFUNC.

The exact matrix covers equal, borrow, negative, and signed-overflow outcomes in
all widths, with X initially set. It also feeds subsequent SR snapshots so stale
or inverted physical carry cannot pass by interpreter/JIT equivalence alone.

### Memory and no-flags ordering

CMP memory forms perform their source read and any postincrement/predecrement
before flag publication. CMPM performs source read/writeback followed by
destination read/writeback, including two ordered updates when both operands
use the same An. A7 byte CMPM advances twice by two bytes.

Flag-dead handlers preserve all architecturally visible accesses and An updates.
The generated no-flags CMPM.B body contains two reads and two postincrements but
no `cmp_*` or `start_needflags`; corresponding exact-native vectors assert the
resulting An state after a later flag setter.

## Exact-native matrix

The focused matrix contains 31 vectors:

- seventeen CMP/CMPI vectors covering byte/word/long, dynamic and immediate
  routes, constant and runtime operands, aliases, all source EA classes,
  PC-relative forms, special memory, carry/overflow edges, and no-flags access;
- seven CMPM vectors covering all widths, distinct and same An, A7 byte
  geometry, special memory, ordered dual reads, and no-flags writeback;
- seven CMPA vectors covering word sign extension, long sources, immediate,
  Areg/memory/PC-relative forms, source/destination aliasing, special memory,
  and no-flags postincrement.

Every vector starts exact native replay at the compare opcode and requires two
native entries. Memory fixtures are restored before replay. Current focused
result:

```text
METRIC pass=31
METRIC fail=0
METRIC total=31
METRIC infra_fail=0
METRIC fail_equiv=0
METRIC score=100
```

## Acceptance gates

Post-clean acceptance is:

```text
focused exact-native       31/31
complete active-risky      693/693
allocator-pressure          14/14
compare collision witnesses  2/2 at pin=0 skip=1
strict fail-closed contracts  6/6
closure inventory          997 rows
```

Shell syntax, structural contracts, closure regeneration, `git diff --check`,
and a clean build pass. Two explicit regenerations and the clean-build output
match byte-for-byte at generated `compemu.cpp` SHA-256
`dff217a685f0fe8727ad98630750d1ea99c906ece78e0e4a88fd25489e5ae16a`.
The focused and active selections are both asserted nonzero before execution.

## Closure classification

Promote as audited:

- generators `i_CMP`, `i_CMPM`, and `i_CMPA`;
- live MIDFUNCs `jff_CMP_{b,w,l}` and their `_imm` forms.

Retain the four namesake `jff_CMPA_{w,l}[_imm]` MIDFUNCs as unreachable. Bare
`CMP_*` emitter APIs remain unreviewed pending their cross-caller encoding and
range audit. Whole-engine completion is not claimed by this tranche.
