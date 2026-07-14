# AArch64 JIT DBcc / Scc lifecycle audit

Date: 2026-07-14
Branch: `structural-audit`

## Scope

This tranche closes the paired integer condition-code families:

- `i_DBcc`: condition consumption, low-word decrement, high-word retention,
  displacement calculation, loop/terminal selection, dynamic `PC_P`, CCR/X
  preservation, counter ownership, and runtime block termination;
- `i_Scc`: all sixteen M68K conditions, `0xff`/`0x00` publication, Dn upper-lane
  retention, every writable memory EA, An/A7 writeback, special-memory routing,
  CCR/X preservation, result/EA ownership, and exact-native entry.

The authoritative generator remains
`src/uae_cpu_2026/compiler/gencomp.c`; `src/Unix/compemu.cpp` is regenerated
from it.

## Reachability

### DBcc

The live path is generator-owned. It uses:

- `dbf_dec_test_ne_w` for cc=1 (DBF/DBRA);
- `dbcc_dec_w -> jnf_SUB_w_imm(..., 1)` for cc=2..15;
- `dbcc_cond_move_ne_w` for the terminal counter test;
- `cmov_l_rr` for condition-dependent counter/PC restoration;
- `preserve_flags_before_nzcv_clobber`, `discard_flags_in_nzcv`, and
  `save_and_discard_flags_in_nzcv` for CCR ownership;
- the AArch64 runtime-PC end-block boundary for every cc>=1 DBcc.

`jff_DBCC` has no caller from the configured generated/support roots and remains
unreachable. The generic `jnf_SUB_w_imm` has callers outside DBcc, so this
tranche proves its decrement-by-one use but does not promote that broader row.

### Scc

Before this tranche, live `i_Scc` used the compatibility sequence
`make_flags_live -> setcc -> sub_b_ri`. The repaired path is now
`make_flags_live -> jnf_SCC`, passing the architectural M68K condition number
0..15 directly. `jnf_SCC`, formerly an uncalled namesake, is now the single live
AArch64 truth-byte implementation.

## Demonstrated defects

### 1. Scc used ARM HI/LS for M68K borrow semantics

The generator emitted flags_x86-style condition numbers. The compatibility
`setcc` conversion mapped HI/LS to AArch64 HI/LS, but the JIT's normalized C bit
uses M68K carry/borrow polarity. Therefore:

- M68K HI is `!C && !Z`, implemented by ARM `CC && NE`;
- M68K LS is `C || Z`, implemented by ARM `CS || EQ`.

An exact-native `SHI.B (A0)` witness with C=0,Z=0 produced:

```text
interpreter D0=a5a500ff SR=2708
JIT         D0=a5a50000 SR=2704
```

The SR difference is the later verification MOVE.B observing the wrong stored
byte; a pre-load SR snapshot remained `2700` in both runs, proving Scc itself
preserved CCR while selecting the wrong Boolean value.

### 2. Memory Scc did not own its EA through result allocation

Memory Scc computes its Boolean result only after the full effective address and
any An writeback are live. Once condition normalization stopped incidentally
locking the alias host register, the forced S2-to-S1 postincrement witness could
pin the result onto the private EA mapping and redirect the byte store.

The generator now locks `srca` after EA calculation and releases it only after
`genastore`. The accepted pressure witness reports:

```text
REGPRESSURE cell=scc_b_ea_value_collision status=PASS pin=0 skip=2 natexec=1 interpop=1
```

### 3. DBcc shared the HI/LS conditional-move defect

`cmov_l_rr` consumed the same flags_x86-style numbers and treated x86 HI/LS as
native ARM HI/LS. A pre-fix exact-native DBHI witness with C=0,Z=0 showed the
condition incorrectly false and decremented the low word:

```text
interpreter D0=a5a50002
JIT         D0=a5a50001
REGPRESSURE cell=dbcc_w_counter_copy_collision status=FAIL pin=0 skip=1 natexec=1 interpop=1
```

The helper now composes M68K HI/LS with two flag-preserving CSEL stages while
retaining the original destination. The post-fix witness is identical to the
interpreter and remains `pin=0 skip=1`.

Final source review also caught an allocator-bookkeeping error in the revised
helper before publication: after `src = readreg(s)`, the unlock path initially
released virtual ID `s` rather than physical host register `src`. The accepted
helper releases `src`, and the structural gate rejects any return to
`unlock2(s)` in this function.

## Structural repairs

### Direct Scc condition map

`jnf_SCC` now:

1. normalizes an inverted physical carry when required;
2. accepts only architectural conditions 0..15;
3. maps T/F and every C/Z/N/V pair explicitly;
4. composes HI as `CC && NE` and LS as `CS || EQ`;
5. emits the final `0xffffffff` or `0` value with flag-preserving instructions;
6. inserts only the low byte into the destination virtual register.

The generator no longer uses legacy `setcc/sub_b_ri` lowering for Scc.

### Complete DBcc edge lifecycle

The existing DBcc structure was retained where already correct:

1. sign-extend the word displacement and resolve both target and fall-through
   host pointers;
2. reset compile-time `m68k_pc_offset` after materializing runtime `PC_P`;
3. copy the pre-decrement counter before changing Dn.W;
4. preserve Dn's upper word and never publish decrement flags;
5. restore counter/PC when the condition is true;
6. select terminal versus taken edge from the pre-decrement low word;
7. preserve C/Z/N/V and X across temporary host control flags;
8. store Dn.W, discard stale NZCV, and end cc>=1 blocks at runtime `regs.pc_p`.

The only semantic source change required in this path is the shared
M68K-correct HI/LS conditional move.

## Generated-source census

The regenerated compiler contains:

```text
jnf_SCC calls                   256
memory Scc EA locks/unlocks     224 / 224
dbf_dec_test_ne_w calls           2
conditional DBcc cmov pairs      28
dbcc_cond_move_ne_w calls        30
```

These counts cover both nominal ff/nf compiler tables. DBT remains outside the
dynamic runtime-PC boundary because it neither decrements nor branches.

## Exact-native matrix

The focused matrix contains 35 vectors.

### Scc: 17

- eight Dn vectors pair all sixteen conditions and prove upper-byte/word/long
  retention plus exact CCR preservation;
- nine memory vectors cover `(An)`, `(An)+`, `-(An)`, `(d16,An)`, indexed,
  absolute word/long, A7 postincrement, and A7 predecrement;
- three memory vectors force special-memory helpers;
- memory vectors snapshot SR before verification loads.

### DBcc: 18

- DBT true/no-decrement;
- DBF terminal, taken, and `ffff -> fffe` wrap states;
- true and false/taken members of HI/LS, CC/CS, NE/EQ, VC/VS, PL/MI, GE/LT,
  and GT/LE;
- every vector starts at the DBcc opcode, preserves an SR with X populated,
  checks Dn upper-word retention, and uses flag-preserving MOVEA markers to
  distinguish displacement edges.

Focused result:

```text
METRIC pass=35
METRIC fail=0
METRIC total=35
METRIC infra_fail=0
METRIC fail_equiv=0
METRIC score=100
```

The complete active-risky corpus also passes:

```text
METRIC pass=689
METRIC fail=0
METRIC total=689
METRIC infra_fail=0
METRIC fail_equiv=0
METRIC score=100
```

All eleven allocator-pressure cells pass, including both new DBcc/Scc cells.

## Closure classification

Promote as audited:

- generator `i_DBcc`;
- generator `i_Scc`;
- MIDFUNC `dbf_dec_test_ne_w`;
- MIDFUNC `dbcc_cond_move_ne_w`;
- MIDFUNC `jnf_SCC`.

Retain as unreachable:

- `jff_DBCC`.

Retain as unreviewed outside this family-level proof:

- generic `jnf_SUB_w_imm` beyond DBcc's decrement-by-one use.

Whole-engine completion is not claimed by this tranche.

## Acceptance gates

The final pass was run after `make clean` and a full rebuild.

```text
CLEAN_BUILD=PASS
focused exact-native: pass=35 fail=0 total=35 infra_fail=0 score=100
active corpus:        pass=689 fail=0 total=689 infra_fail=0 score=100
allocator pressure:   pass=11 fail=0
strict allocation fallback/abort, optlev0, opcode fallback,
verifier reference, and full-JIT negative gate: all 1
bash -n run.sh / regalloc-pressure.sh: PASS
git diff --check: PASS
```

The active-corpus gate explicitly rejects a zero-test selection. Its accepted
run reported `ACTIVE_NONZERO_GATE=PASS` with exactly 689 tests. An intermediate
"missing SR=271F" diagnostic was not treated as semantic evidence; retained raw
output contained a register dump, no parser relaxation was retained, and the
final clean focused run parsed all 35 exact expectations with `infra_fail=0`.

Two consecutive authoritative generator runs produced:

```text
2537a8b6578719c50aefaa8e99b7bad9e1d592dbce8b706ed67272622ad12822
2537a8b6578719c50aefaa8e99b7bad9e1d592dbce8b706ed67272622ad12822
GENCOMP_REPRO=1
```

The regenerated closure census remains 997 rows. After promotion it reports:

```text
generator:        audited=39 serviced=44 unreachable=0   unreviewed=47
midfunc:          audited=164 serviced=0 unreachable=118 unreviewed=140
emitter_api:      audited=0  serviced=0 unreachable=91  unreviewed=203
raw_boundary:     audited=24 serviced=0 unreachable=0   unreviewed=58
runtime_boundary: audited=0  serviced=40 unreachable=29 unreviewed=0
```
