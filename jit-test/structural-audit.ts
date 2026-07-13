#!/usr/bin/env bun

/**
 * Source-level structural invariants for the ARM64 JIT emitter.
 *
 * These checks deliberately inspect emitter ordering rather than opcode output:
 * an endblock may return to C through several branches, and every one of those
 * branches must publish the retired successor PC first.
 */

const sourcePath = new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.cpp",
  import.meta.url,
);
const source = await Bun.file(sourcePath).text();

function fail(message: string): never {
  console.error(`STRUCTURAL_AUDIT_FAIL ${message}`);
  process.exit(1);
}

function bodyBetween(start: string, end: string): string {
  const begin = source.indexOf(start);
  if (begin < 0) fail(`missing start marker: ${start}`);
  const finish = source.indexOf(end, begin + start.length);
  if (finish < 0) fail(`missing end marker after: ${start}`);
  return source.slice(begin, finish);
}

function requireText(body: string, text: string, context: string): number {
  const offset = body.indexOf(text);
  if (offset < 0) fail(`${context}: missing ${text}`);
  return offset;
}

function requireBefore(
  body: string,
  first: string,
  second: string,
  context: string,
): void {
  const firstOffset = requireText(body, first, context);
  const secondOffset = requireText(body, second, context);
  if (firstOffset >= secondOffset) {
    fail(`${context}: ${first} must precede ${second}`);
  }
}

const makefileTemplate = await Bun.file(new URL(
  "../BasiliskII/src/Unix/Makefile.in",
  import.meta.url,
)).text();
for (const layoutDependency of [
  "JIT_LAYOUT_DEPS = Makefile sysdeps.h $(UAE_PATH)/newcpu.h",
  "$(UAE_PATH)/registers.h $(UAE_PATH)/memory.h $(UAE_PATH)/fpu/types.h",
  "$(UAE_PATH)/compiler/compemu.h",
  "JIT_SUPPORT_DEPS = $(UAE_PATH)/compiler/compemu_support_arm.cpp",
  "$(UAE_PATH)/compiler/compemu_legacy_arm64_compat.cpp",
  "$(UAE_PATH)/compiler/codegen_arm64.cpp",
  "$(UAE_PATH)/compiler/compemu_midfunc_arm64.cpp",
  "$(JIT_LAYOUT_OBJECTS): $(JIT_LAYOUT_DEPS)",
  "JIT_MEMORY_INLINE_OBJECTS =",
  "$(OBJ_DIR)/cpuemu1_nf.o",
  "$(OBJ_DIR)/basilisk_glue.o $(OBJ_DIR)/newcpu.o",
  "$(JIT_MEMORY_INLINE_OBJECTS): $(UAE_PATH)/memory.h",
  "$(OBJ_DIR)/compemu_support.o: $(JIT_SUPPORT_DEPS)",
]) {
  requireText(makefileTemplate, layoutDependency, "JIT object layout epoch");
}
const harnessSource = await Bun.file(new URL("./run.sh", import.meta.url)).text();
const strictHarnessSource = await Bun.file(new URL("./strict-full-jit.sh", import.meta.url)).text();
requireText(harnessSource, "rm -f obj/compemu*.o", "JIT object layout epoch");

const callEmitter = bodyBetween(
  "STATIC_INLINE void compemu_raw_call(uintptr t)\n{",
  "STATIC_INLINE void compemu_raw_call_r",
);
requireText(callEmitter, "LOAD_U64(R18_INDEX, t)", "helper-call ABI");
requireText(callEmitter, "BLR_x(R18_INDEX)", "helper-call ABI");
if (callEmitter.includes("LOAD_U64(REG_WORK1, t)")) {
  fail("helper-call ABI: call target clobbers x2/argument 3");
}
requireText(
  source,
  "always_used[] = {2,3,4,5,18,R_MEMSTART,R_REGSTRUCT,-1}",
  "helper-call ABI reserved target register",
);

const observerStart = source.indexOf("STATIC_INLINE void compemu_raw_observer_save(void)");
const observerEnd = source.indexOf("LOWFUNC(WRITE,READ,1,compemu_raw_cmp_pc", observerStart);
if (observerStart < 0 || observerEnd < 0) fail("missing diagnostic observer boundary");
const observerBody = source.slice(observerStart, observerEnd);
for (const preserved of [
  "STP_xxXi(r, r + 1, RSP_INDEX, r * 8)",
  "STR_xXi(R18_INDEX, RSP_INDEX, JIT_OBSERVER_X18_OFF)",
  "MRS_NZCV_x(R18_INDEX)",
  "MRS_FPCR_x(R18_INDEX)",
  "MRS_FPSR_x(R18_INDEX)",
  "STR_dXi(r, RSP_INDEX, JIT_OBSERVER_D0_OFF + r * 8)",
  "MSR_FPSR_x(R18_INDEX)",
  "MSR_FPCR_x(R18_INDEX)",
  "MSR_NZCV_x(R18_INDEX)",
  "LDP_xxXi(r, r + 1, RSP_INDEX, r * 8)",
  "compemu_raw_call_observer_i",
  "compemu_raw_call_observer_ii",
  "compemu_raw_call_observer_ri",
]) {
  requireText(observerBody, preserved, "diagnostic observer preservation");
}

const midfuncPath = new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu_midfunc_arm64.cpp",
  import.meta.url,
);
const midfuncSource = await Bun.file(midfuncPath).text();
const midfunc2Source = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu_midfunc_arm64_2.cpp",
  import.meta.url,
)).text();
const codegenSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.cpp",
  import.meta.url,
)).text();
const memorySource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/memory.h",
  import.meta.url,
)).text();
if (
  codegenSource.includes("jit_trace_setpc_value") ||
  midfuncSource.includes("jit_trace_setpc_value")
) {
  fail("diagnostic residue: set-PC tracing remains in production JIT paths");
}
const directByteWriteStart = midfunc2Source.indexOf("MIDFUNC(2,jnf_MEM_WRITE_OFF_b");
const directByteWriteEnd = midfunc2Source.indexOf("MENDFUNC(2,jnf_MEM_WRITE_OFF_b", directByteWriteStart);
if (directByteWriteStart < 0 || directByteWriteEnd < 0) fail("missing direct byte-write helper");
const directByteWriteBody = midfunc2Source.slice(directByteWriteStart, directByteWriteEnd);
for (const contract of [
  "MRS_NZCV_x(REG_WORK4)",
  "LOAD_U32(REG_WORK1, 0xff001fff)",
  "LOAD_U32(REG_WORK3, 0x50000006)",
  "STRB_wXx(b, adr, R_MEMSTART)",
  "MSR_NZCV_x(REG_WORK4)",
]) {
  requireText(directByteWriteBody, contract, "direct byte-write interpreter contract");
}
for (const forbidden of ["NEG_ww", "CSEL_wwwc", "STRB_wXx(REG_WORK3, adr, R_MEMSTART)"]) {
  if (directByteWriteBody.includes(forbidden)) {
    fail(`direct byte-write interpreter contract: transformed source remains: ${forbidden}`);
  }
}
for (const contract of [
  "#define LOW_NUBUS_OPEN_BUS_START 0x0a014000u",
  "#define LOW_NUBUS_OPEN_BUS_END   0x0a815000u",
  "RAMSize <= 0x08000000u",
  "if (is_low_nubus_open_bus_gap(addr))\n        return 0xffffffffu;",
  "if (is_low_nubus_open_bus_gap(addr))\n        return 0xffffu;",
  "if (is_low_nubus_open_bus_gap(addr))\n        return 0xffu;",
  "if (is_low_nubus_open_bus_gap(addr) || addr == 0x5ffffffc)",
  "if (is_low_nubus_open_bus_gap(addr) || is_50f_scanner_data(addr))",
]) {
  requireText(memorySource, contract, "shared low-NuBus open-bus contract");
}
for (const contract of [
  "emit_low_nubus_gap_write_skip",
  "emit_low_nubus_gap_read_value",
  "LOW_NUBUS_OPEN_BUS_START",
  "LOW_NUBUS_OPEN_BUS_END",
  "RAMSize > 0x08000000u",
  "emit_low_nubus_gap_read_value(adr, d, 0xffffffffu)",
]) {
  requireText(midfunc2Source, contract, "emitted low-NuBus open-bus contract");
}
for (const helper of ["jnf_MEM_WRITE_OFF_b", "jnf_MEM_WRITE_OFF_w", "jnf_MEM_WRITE_OFF_l"]) {
  const start = midfunc2Source.indexOf(`MIDFUNC(2,${helper}`);
  const end = midfunc2Source.indexOf(`MENDFUNC(2,${helper}`, start);
  if (start < 0 || end < 0) fail(`missing ${helper}`);
  const body = midfunc2Source.slice(start, end);
  requireText(body, "emit_low_nubus_gap_write_skip(adr)", `${helper} JIT-cache alias protection`);
  requireText(body, "finish_low_nubus_gap_skip(gap_done)", `${helper} JIT-cache alias protection`);
}
if (midfunc2Source.includes("MOV_wi(d, 0x10)")) {
  fail("emitted low-NuBus open-bus contract: address-specific long value remains");
}

for (const contract of [
  "declare -A NATIVE_REPLAY_TESTS",
  "[io_byte_write_roundtrip]=1",
  "B2_TEST_TWO_PASS=1 B2_TEST_SECOND_PC=0x1000",
  "B2_TEST_FORCE_L2_RAM=1",
]) {
  requireText(harnessSource, contract, "native replay opcode gate");
}

const helperStart = midfuncSource.indexOf("MIDFUNC(1,call_helper,(IMPTR addr))");
const helperEnd = midfuncSource.indexOf("MENDFUNC(1,call_helper", helperStart);
if (helperStart < 0 || helperEnd < 0) fail("missing call_helper midfunc");
const helperBody = midfuncSource.slice(helperStart, helperEnd);
requireBefore(
  helperBody,
  "prepare_for_call_1()",
  "prepare_for_call_2()",
  "helper-call allocator barrier",
);
requireBefore(
  helperBody,
  "prepare_for_call_2()",
  "compemu_raw_call(addr)",
  "helper-call allocator barrier",
);

const regHelper = bodyBetween(
  "STATIC_INLINE void compemu_raw_set_pc_full_from_reg",
  "STATIC_INLINE void compemu_raw_set_pc_full_const",
);
for (const field of ["regs.pc_p", "regs.pc_oldp", "regs.pc"]) {
  requireText(regHelper, field, "register successor-PC helper");
}
requireText(regHelper, "MEMBaseDiff", "register successor-PC helper");

const constHelper = bodyBetween(
  "STATIC_INLINE void compemu_raw_set_pc_full_const",
  "LOWFUNC(NONE,WRITE,2,compemu_raw_mov_l_mi",
);
requireText(
  constHelper,
  "compemu_raw_set_pc_full_from_reg(REG_WORK2)",
  "constant successor-PC helper",
);

const inreg = bodyBetween(
  "LOWFUNC(NONE,NONE,2,compemu_raw_endblock_pc_inreg",
  "LENDFUNC(NONE,NONE,2,compemu_raw_endblock_pc_inreg",
);
requireBefore(
  inreg,
  "compemu_raw_set_pc_full_from_reg(rr_pc)",
  "TBZ_xii(REG_WORK1, 31, 0)",
  "register endblock countdown exit",
);
requireBefore(
  inreg,
  "compemu_raw_set_pc_full_from_reg(rr_pc)",
  "LDR_wXi(REG_WORK4, R_REGSTRUCT, idx_spc_hot)",
  "register endblock spcflags exit",
);
requireBefore(
  inreg,
  "compemu_raw_set_pc_full_from_reg(rr_pc)",
  "popall_do_nothing",
  "register endblock C return",
);
if (source.includes("jit_endblock_inreg_count")) {
  fail("register endblock hot path: unconditional diagnostic counter remains");
}

const isconst = bodyBetween(
  "STATIC_INLINE uae_u32* compemu_raw_endblock_pc_isconst",
  "/*************************************************************************\n* FPU stuff",
);
requireBefore(
  isconst,
  "compemu_raw_set_pc_full_const(v)",
  "TBZ_xii(REG_WORK1, 31, 0)",
  "constant endblock countdown exit",
);
requireBefore(
  isconst,
  "compemu_raw_set_pc_full_const(v)",
  "LDR_wXi(REG_WORK4, R_REGSTRUCT, idx_spc_hot2)",
  "constant endblock spcflags exit",
);
requireBefore(
  isconst,
  "compemu_raw_set_pc_full_const(v)",
  "popall_do_nothing",
  "constant endblock C return",
);

const allocatorPath = new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu_support_arm.cpp",
  import.meta.url,
);
const allocatorSource = await Bun.file(allocatorPath).text();
if (allocatorSource.includes("jit_trace_setpc_value")) {
  fail("diagnostic residue: set-PC tracing remains in the allocator");
}
const supportSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu_support.cpp",
  import.meta.url,
)).text();
const timerSource = await Bun.file(new URL(
  "../BasiliskII/src/timer.cpp",
  import.meta.url,
)).text();
const mainUnixSource = await Bun.file(new URL(
  "../BasiliskII/src/Unix/main_unix.cpp",
  import.meta.url,
)).text();
const compatSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu_legacy_arm64_compat.cpp",
  import.meta.url,
)).text();
const compemuHeaderSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu.h",
  import.meta.url,
)).text();
const gencompSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/gencomp.c",
  import.meta.url,
)).text();
const generatedSource = await Bun.file(new URL(
  "../BasiliskII/src/Unix/compemu.cpp",
  import.meta.url,
)).text();
const newcpuSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/newcpu.cpp",
  import.meta.url,
)).text();
const gencpuSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/gencpu.c",
  import.meta.url,
)).text();
const basiliskGlueSource = await Bun.file(new URL(
  "../BasiliskII/src/uae_cpu_2026/basilisk_glue.cpp",
  import.meta.url,
)).text();

if (midfuncSource.includes("arm64_low32_hostptr_imm")) {
  fail("pointer arithmetic contract: numeric host-range inference remains");
}
const hostBaseStart = midfuncSource.indexOf("MIDFUNC(2,arm_ADD_l_ri_hostptr");
const hostBaseEnd = midfuncSource.indexOf("MENDFUNC(2,arm_ADD_l_ri_hostptr", hostBaseStart);
if (hostBaseStart < 0 || hostBaseEnd < 0) fail("missing signed guest-offset + host-base contract");
const hostBaseBody = midfuncSource.slice(hostBaseStart, hostBaseEnd);
for (const contract of ["(uae_s32)(uae_u32)live.state[d].val", "LOAD_U64(REG_WORK1, base)", "EX_SXTW"]) {
  requireText(hostBaseBody, contract, "signed guest-offset + host-base contract");
}
const ptrAddStart = midfuncSource.indexOf("MIDFUNC(2,arm_ADD_ptr_ri");
const ptrAddEnd = midfuncSource.indexOf("MENDFUNC(2,arm_ADD_ptr_ri", ptrAddStart);
if (ptrAddStart < 0 || ptrAddEnd < 0) fail("missing pointer-width immediate-add contract");
const ptrAddBody = midfuncSource.slice(ptrAddStart, ptrAddEnd);
for (const contract of ["ADD_xxi", "SUB_xxi", "ADD_xxx"]) {
  requireText(ptrAddBody, contract, "pointer-width immediate-add contract");
}
const guestAddStart = midfuncSource.indexOf("MIDFUNC(2,arm_ADD_l_ri,(RW4 d, IMPTR i))");
const guestAddEnd = midfuncSource.indexOf("MENDFUNC(2,arm_ADD_l_ri", guestAddStart);
if (guestAddStart < 0 || guestAddEnd < 0) fail("missing 32-bit guest immediate-add contract");
const guestAddBody = midfuncSource.slice(guestAddStart, guestAddEnd);
for (const contract of ["const uae_u32 i32", "(uae_u32)(live.state[d].val + i32)", "ADD_wwi", "ADD_www"]) {
  requireText(guestAddBody, contract, "32-bit guest immediate-add contract");
}
if (guestAddBody.includes("ADD_x") || guestAddBody.includes("PC_P")) {
  fail("32-bit guest immediate-add contract: pointer-width path remains");
}
const registerAddStart = midfuncSource.indexOf("MIDFUNC(2,arm_ADD_l,(RW4 d, RR4 s))");
const registerAddEnd = midfuncSource.indexOf("MENDFUNC(2,arm_ADD_l", registerAddStart);
if (registerAddStart < 0 || registerAddEnd < 0) fail("missing register-sourced long-add contract");
const registerAddBody = midfuncSource.slice(registerAddStart, registerAddEnd);
requireText(
  registerAddBody,
  "COMPCALL(arm_ADD_ptr_ri)(d, (uae_s32)(uae_u32)live.state[s].val)",
  "constant PC_P plus signed guest displacement contract",
);
requireText(registerAddBody, "ADD_xxwEX(d, d, s", "runtime PC_P plus signed guest displacement contract");
for (const contract of [
  "arm_ADD_l_ri_hostptr(src,(uintptr)comp_pc_p)",
  "arm_ADD_l_ri_hostptr(offs,(uintptr)comp_pc_p)",
  "arm_ADD_ptr_ri(src,m68k_pc_offset)",
  "arm_ADD_ptr_ri(offs,m68k_pc_offset)",
  "arm_ADD_ptr_ri(PC_P,m68k_pc_offset)",
]) {
  requireText(gencompSource, contract, "generator pointer arithmetic contract");
  requireText(generatedSource, contract, "generated pointer arithmetic contract");
}
for (const sourceText of [gencompSource, generatedSource]) {
  requireBefore(
    sourceText,
    "preserve_flags_before_nzcv_clobber();",
    "dbf_dec_test_ne_w(src);",
    "DBF architectural CCR preservation",
  );
  requireBefore(
    sourceText,
    "dbf_dec_test_ne_w(src);",
    "discard_flags_in_nzcv();",
    "DBF temporary NZCV discard",
  );
}
for (const contract of [
  "[dbra_ccr_preserve_z_clear]=1",
  "[dbra_ccr_preserve_z_set]=1",
]) {
  requireText(harnessSource, contract, "DBF native replay CCR regression");
}

for (const forbidden of [
  "arm_ADD_l_ri(src,(uintptr)comp_pc_p)",
  "arm_ADD_l_ri(offs,(uintptr)comp_pc_p)",
]) {
  if (gencompSource.includes(forbidden) || generatedSource.includes(forbidden)) {
    fail(`pointer arithmetic contract: ambiguous generated call remains: ${forbidden}`);
  }
}

for (const contract of [
  "jit_block_verify_compiled_ops = i + 1",
  "jit_block_verify_compiled_ops = i;",
  "const int reference_ops = jit_block_verify_compiled_ops > 0",
  "for (int step = 0; step < reference_ops; step++)",
  "native_ops=%d REACHED",
  "native_ops=%d SKIP-NOREACH",
]) {
  requireText(allocatorSource, contract, "block verifier exact retirement bound");
}
if (allocatorSource.includes("const int maxsteps = blocklen * 16 + 64")) {
  fail("block verifier exact retirement bound: first-stop-PC loop remains");
}

for (const contract of [
  "B2_JIT_STRICT_FULL",
  "strict full-JIT: translator unavailable",
  "strict full-JIT: optlev-0 block",
  "strict full-JIT: non-L2 block",
  "strict full-JIT: opcode fallback",
  "strict full-JIT: exact exec_nostats",
  "strict full-JIT: verifier interpreter reference",
  "strict full-JIT: verifier opcode reference",
  "JIT_STRICT_SUMMARY native=%llu trace=%llu warmup=%llu verify=%llu blocks=%llu opt0=0 fallback=0 exec_nostats=0",
  "if (block_m68k_pc < ROMBaseMac && blocklen > 0)",
  "bi->handler_to_use = (cpuop_func*)popall_check_checksum",
  "set_dhtu_validated(bi, bi->direct_pcc)",
  "bi->status = BI_NEED_CHECK",
  "STRICT_RAM_HOT_THRESHOLD = 10",
  "jit_strict_trace_warmups++",
]) {
  requireText(allocatorSource, contract, "strict full-JIT fallback gate");
}
for (const contract of [
  "strict full-JIT: exec_nostats runtime entry",
  "strict full-JIT: exec_nostats_limited runtime entry",
  "if (!jit_strict_full_jit_env())",
  "first-seen tracer observe the code and compile an L2 block normally.",
  "jit_strict_note_trace_op(jit_current_interp_pc, opcode)",
  "jit_strict_defer_cold_ram_trace(pc_hist, blocklen)",
]) {
  requireText(compatSource, contract, "strict full-JIT runtime gate");
}
for (const forbidden of ["jit_execute_ori_b_run_native", "jit_strict_note_native_zero_op"]) {
  if (compatSource.includes(forbidden) || allocatorSource.includes(forbidden))
    fail(`strict full-JIT: zero-RAM semantic helper remains: ${forbidden}`);
}
const emulopStart = allocatorSource.indexOf("static void op_emulop_comp_ff(uae_u32 opcode)\n{");
const emulopEnd = allocatorSource.indexOf("static void op_aline_trap_comp_ff", emulopStart);
if (emulopStart < 0 || emulopEnd < 0) fail("strict full-JIT: missing EMUL_OP compiler handler");
const emulopBody = allocatorSource.slice(emulopStart, emulopEnd);
requireText(emulopBody, "jit_emit_runtime_helper_barrier((uintptr)jit_runtime_emulop", "native EMUL_OP boundary");
if (emulopBody.includes("cpufunctbl") || emulopBody.includes("cputbl")) {
  fail("strict full-JIT: EMUL_OP compiler handler still emits an interpreter-table call");
}
requireText(
  allocatorSource,
  "m68k_dispatch_emulop(opcode);",
  "native EMUL_OP shared dispatcher",
);
for (const contract of [
  "void m68k_dispatch_emulop(uae_u32 opcode)",
  "if (opcode == M68K_EXEC_RETURN)",
  "if (!regs.s)",
  "m68k_emulop_return();",
  "m68k_emulop(opcode);",
  "m68k_incpc(2);",
]) {
  requireText(newcpuSource, contract, "shared EMUL_OP semantics");
}
for (const contract of [
  'm68k_dispatch_emulop(0x7100)',
  'm68k_dispatch_emulop(opcode)',
]) {
  requireText(gencpuSource, contract, "generated reference EMUL_OP dispatcher");
}
for (const forbidden of [
  "jit_force_optlev0_block_exact",
  "B2_JIT_UNFORCE_OPT0_PCS",
  "B2_JIT_NO_FORCE_OPT0",
  "pc >= 0x04000000 && pc <= 0x0400ffff",
  "pc >= 0x040b0000 && pc <= 0x040bffff",
]) {
  if (allocatorSource.includes(forbidden)) {
    fail(`strict full-JIT: hard-coded optlev-0 ROM gate remains: ${forbidden}`);
  }
}
requireText(
  allocatorSource,
  "jit_force_optlev0() || jit_force_optlev0_block_env(block_m68k_pc)",
  "strict full-JIT explicit optlev-0 diagnostics",
);
for (const contract of [
  "static inline bool jit_strict_probe_opcode_fallback(void)",
  "if (!jit_strict_full_jit_env())",
  "jit_strict_probe_opcode_fallback())",
]) {
  requireText(allocatorSource, contract, "strict full-JIT fallback fault injection");
}
if (allocatorSource.split("(*cpufunctbl[opcode])(opcode);").length - 1 !== 2) {
  fail("strict full-JIT: unexpected direct cpufunctbl execution site in ARM64 support");
}
if (compatSource.split("(*cpufunctbl[opcode])(opcode);").length - 1 !== 3) {
  fail("strict full-JIT: unexpected direct cpufunctbl execution site in ARM64 compatibility layer");
}
for (const contract of [
  "[strict_zero_ram_native]=1",
  "B2_JIT_STRICT_FULL=1",
  "B2_NATIVE_ASSERT_PC=0x1000",
  "^NATEXEC pc=00001000 ",
  "strict-full-jit.sh",
]) {
  requireText(harnessSource, contract, "strict full-JIT native replay gate");
}
for (const contract of [
  "B2_JIT_FORCE_OPTLEV0=1",
  "B2_JIT_STRICT_PROBE_OPCODE_FALLBACK=1",
  "B2_JIT_VERIFY_BLOCKS=0x1000",
  "grep -q '^REGDUMP:'",
  "METRIC strict_full_jit_negative_gate=1",
]) {
  requireText(strictHarnessSource, contract, "strict full-JIT negative gate");
}
if (supportSource.includes("jit_strict_full_jit_env()\n\t\treturn;")) {
  fail("strict full-JIT: guest CACR/cache-maintenance semantics are conditionally suppressed");
}
for (const contract of [
  "if (jit_strict_full_jit_env())\n\t\tjit_abort(\"strict full-JIT: %s\", reason)",
  "UseJIT = false;",
  "TimerRestoreAsyncOwnership();",
  "case i_CPUSHL:",
  "case i_CPUSHP:",
  "case i_CPUSHA: return \"generated_cache_push_helper\";",
]) {
  requireText(allocatorSource, contract, "strict initialization and coverage taxonomy");
}
requireText(
  allocatorSource,
  "bool uses_fpu = (nftbl[i].specific & COMP_OPCODE_USES_FPU) != 0;",
  "no-flags FPU table registration",
);
for (const contract of [
  "static void jit_runtime_fpu_semantic(uae_u32 opcode)",
  "case i_FPP:",
  "case i_FDBcc:",
  "case i_FScc:",
  "case i_FTRAPcc:",
  "case i_FBcc:",
  "case i_FSAVE:",
  "case i_FRESTORE:",
  "jit_emit_runtime_helper_barrier((uintptr)jit_runtime_fpu_semantic",
  "if (avoid_fpu) {",
  "compfunctbl[cft_map(opcode)] = op_fpu_semantic_comp_ff;",
  "nfcompfunctbl[cft_map(opcode)] = op_fpu_semantic_comp_ff;",
  'if (handler == op_fpu_semantic_comp_ff) return "fpu_semantic_service";',
]) {
  requireText(allocatorSource, contract, "disabled-FPU semantic service coverage");
}
for (const vector of [
  "[fpp_semantic_successor]=1",
  "[fscc_false_byte]=1",
  "[fbcc_false_operand_lengths]=1",
]) {
  requireText(harnessSource, vector, "disabled-FPU focused native replay");
}
requireText(
  allocatorSource,
  'if (legal) trap_count++;',
  "legal-opcode coverage taxonomy",
);
requireText(
  supportSource,
  "if (UseJIT)\n\t\t\tdisable_jit_runtime",
  "ordinary lazy JIT initialization failure",
);
const ordinaryFallback = supportSource.slice(
  requireText(supportSource, "void m68k_compile_execute(void)", "ordinary lazy JIT fallback"),
  requireText(supportSource, "void readbyte(int address", "ordinary lazy JIT fallback"),
);
requireBefore(
  ordinaryFallback,
  "if (!UseJIT) {",
  "m68k_execute();",
  "ordinary lazy JIT initialization fallback",
);
requireBefore(
  ordinaryFallback,
  "m68k_execute();",
  "return;",
  "ordinary lazy JIT initialization fallback",
);
requireText(
  timerSource,
  "Restore60HzAsyncOwnership()",
  "ordinary lazy JIT initialization restores 60 Hz ownership",
);
requireText(
  mainUnixSource,
  "if (tick_thread_active)\n\t\treturn true;",
  "idempotent 60 Hz ownership restoration",
);
for (const contract of [
  "return jit_guest_path_enabled() || jit_retirement_tick_every() != 0;",
  "if (tick_every && (++retirement_count % tick_every) == 0)",
  "jit_guest_instruction_retired(pc);",
]) {
  requireText(allocatorSource, contract, "retirement ticks independent of path capture");
}
requireText(
  supportSource,
  "if (use_sync_ticks && !use_retirement_ticks)",
  "retirement ticks suppress dispatcher wall-clock ticks",
);
if (supportSource.includes("jit_guest_path_is_armed")) {
  fail("retirement tick ownership is still coupled to path-capture arming");
}
const referenceObserverStart = allocatorSource.indexOf('extern "C" void jit_guest_path_record_reference');
const referenceObserverEnd = allocatorSource.indexOf('extern "C" void jit_guest_path_record_nostats', referenceObserverStart);
if (referenceObserverStart < 0 || referenceObserverEnd < 0) fail("missing verifier path observer");
const referenceObserverBody = allocatorSource.slice(referenceObserverStart, referenceObserverEnd);
if (referenceObserverBody.includes("jit_guest_instruction_retired")) {
  fail("verifier replay advances architectural retirement ticks");
}
requireText(referenceObserverBody, "jit_guest_path_record(pc);", "verifier path-only observer");
if (supportSource.includes("B2_PATH_RING_TARGET") ||
    supportSource.includes("SCAN2F98_ENTRY") ||
    supportSource.includes("ROM_TO_RAM") ||
    supportSource.includes("REGDUMP2")) {
  fail("workload-specific dispatch diagnostics remain in active ARM64 support");
}
requireText(
  allocatorSource,
  "jit_collect_edge_profile(bi)",
  "opt-in edge profiling",
);
if (allocatorSource.includes("jit_maybe_promote_stable_edge") ||
    allocatorSource.includes("compemu_raw_call((uintptr)jit_maybe_promote_stable_edge)")) {
  fail("stable direct edges retain a per-exit runtime promotion callback");
}
if (supportSource.includes("jit_abort(\"ARM64 JIT dispatcher stubs were not initialized")) {
  fail("ordinary lazy JIT initialization still aborts instead of falling back");
}
requireText(
  allocatorSource,
  'getenv("B2_JIT_PROBE_CODE_ALLOC_FAIL")',
  "deterministic JIT allocation lifecycle probe",
);
const popallStart = allocatorSource.indexOf("STATIC_INLINE void create_popalls(void)");
const popallEnd = allocatorSource.indexOf("static inline void reset_lists(void)", popallStart);
if (popallStart < 0 || popallEnd < 0) fail("missing popallspace initialization lifecycle");
const popallBody = allocatorSource.slice(popallStart, popallEnd);
if (popallBody.includes("jit_abort(")) {
  fail("ordinary lazy JIT popallspace allocation still aborts before policy fallback");
}
const disableStart = allocatorSource.indexOf("static void disable_jit_runtime(const char* reason)");
const disableEnd = allocatorSource.indexOf("#ifdef NOFLAGS_SUPPORT_GENCOMP", disableStart);
if (disableStart < 0 || disableEnd < 0) fail("missing JIT disable lifecycle");
const disableBody = allocatorSource.slice(disableStart, disableEnd);
requireBefore(
  disableBody,
  "compiler_exit();",
  "cache_size = 0;",
  "partial JIT allocation teardown preserves allocation size",
);
const compilerExitStart = allocatorSource.indexOf("void compiler_exit(void)");
const compilerExitEnd = allocatorSource.indexOf("/********************************************************************", compilerExitStart);
if (compilerExitStart < 0 || compilerExitEnd < 0) fail("missing compiler exit lifecycle");
const compilerExitBody = allocatorSource.slice(compilerExitStart, compilerExitEnd);
for (const contract of [
  "flush_icache_hard(3);",
  "reset_lists();",
  "pushall_call_handler = NULL;",
  "popall_execute_normal = NULL;",
  "current_compile_p = NULL;",
  "memset(cache_tags, 0, sizeof(cache_tags));",
]) {
  requireText(compilerExitBody, contract, "JIT executable-storage teardown");
}
requireText(
  allocatorSource,
  "if (cache_enabled && !strict_cache_disable_boundary_seen)\n            flush_icache_hard(3);\n        cache_enabled = 1;",
  "strict full-JIT guest cache transition preserves invalidation",
);

requireText(gencompSource, "NATIVE_CC_VC,NATIVE_CC_VS", "ARM64 overflow condition codegen");
const arm64OverflowCases = "#if defined(CPU_aarch64) || defined(CPU_AARCH64)\n\t case 8:\n\t case 9:";
if (gencompSource.split(arm64OverflowCases).length - 1 !== 3) {
  fail("ARM64 overflow condition codegen: Bcc/DBcc/Scc must all handle VC/VS natively");
}
if (allocatorSource.split("switch (real_opcode & 0x0038)").length - 1 < 2) {
  fail("full-SR EA decoding: mode field must exclude the register bits in both directions");
}
if (allocatorSource.includes("switch (real_opcode & 0x003f)")) {
  fail("full-SR EA decoding: mode switch still includes register bits");
}
for (const mvsr2Contract of [
  "static void jit_runtime_mvsr2_full(uae_u32 opcode)",
  "if (!ccr_only && !regs.s)",
  "m68k_dreg(regs, dstreg) = (m68k_dreg(regs, dstreg) & 0xffff0000u) | value;",
  "dsta = get_disp_ea_020(m68k_areg(regs, dstreg), next_iword());",
  "regs.fault_pc = m68k_getpc();",
  "if (table68k[opcode].mnemo == i_MVSR2)",
  "jit_emit_runtime_helper_barrier((uintptr)jit_runtime_mvsr2_full",
]) {
  requireText(allocatorSource, mvsr2Contract, "complete MOVE SR/CCR helper family");
}
requireText(
  allocatorSource,
  "cflow = f ? prop[cft_map(table68k[opcode].handler)].cflow\n                      : table68k[opcode].cflow;",
  "fallback architectural control-flow classification",
);
requireText(
  allocatorSource,
  "? compfunctbl[cft_map(base)] : NULL;",
  "explicit compiler-handler propagation",
);
requireText(
  allocatorSource,
  "jit_same_compiler_shape(table68k[opcode], table68k[probe])",
  "shape-safe compiler-handler propagation",
);
for (const shapeField of [
  "a.mnemo == b.mnemo", "a.cc == b.cc", "a.size == b.size",
  "a.smode == b.smode", "a.dmode == b.dmode",
  "a.spos == b.spos", "a.dpos == b.dpos",
  "a.cflow == b.cflow", "a.flagdead == b.flagdead", "a.flaglive == b.flaglive",
]) {
  requireText(allocatorSource, shapeField, "shape-safe compiler-handler propagation");
}
if (allocatorSource.includes("table68k[probe].mnemo == mnemo")) {
  fail("explicit compiler-handler propagation: mnemonic-only handler substitution remains");
}
requireText(
  allocatorSource,
  "if ((prop[cft_map(opcode)].cflow & fl_end_block) != 0) {",
  "fallback control-flow runtime successor",
);

const bfinsGeneratorStart = gencompSource.indexOf("     case i_BFINS:");
const bfinsGeneratorEnd = gencompSource.indexOf("     case i_PACK:", bfinsGeneratorStart);
if (bfinsGeneratorStart < 0 || bfinsGeneratorEnd < 0) fail("missing BFINS generator");
const bfinsGenerator = gencompSource.slice(bfinsGeneratorStart, bfinsGeneratorEnd);
for (const contract of [
  "isjump;",
  "GENA_GETV_NO_FETCH",
  "mov_l_mr((uintptr)&regs.jit_exception, extra)",
  "mov_l_mr((uintptr)&regs.scratchregs[0], dsta)",
  "call_helper((uintptr)jit_op_bfins)",
]) {
  requireText(bfinsGenerator, contract, "BFINS runtime extension-word contract");
}
for (const forbidden of [
  "GENA_GETV_FETCH_ALIGN",
  "int dn = (extra >> 12)",
  "int off = (extra >> 6)",
  "int wid = extra & 31",
]) {
  if (bfinsGenerator.includes(forbidden)) {
    fail(`BFINS runtime extension-word contract: compile-time decode remains: ${forbidden}`);
  }
}
if (allocatorSource.includes("(prop[cft_map(opcode)].cflow & fl_end_block) != 0 && i + 1 < blocklen")) {
  fail("fallback control-flow runtime successor: terminal fallback remains position-gated");
}
requireText(
  allocatorSource,
  "const uae_u32 opcode = tagged_opcode & 0xffffu;",
  "diagnostic verifier tagged-opcode decode",
);
for (const observer of [
  "trace_emuneigh_entry",
  "jit_trace_pc_hit",
  "jit_verify_pre",
  "jit_verify_post",
  "jit_flush_delta_compare",
  "jit_trace_add",
  "trace_emulop_resume",
  "b2_test_native_entry",
]) {
  if (allocatorSource.includes(`compemu_raw_call((uintptr)${observer})`)) {
    fail(`diagnostic observer preservation: raw call remains for ${observer}`);
  }
}
const registersPath = new URL(
  "../BasiliskII/src/uae_cpu_2026/registers.h",
  import.meta.url,
);
const registersSource = await Bun.file(registersPath).text();
requireText(registersSource, "uae_u32 scratchregs[5]", "helper scratch backing");
requireText(registersSource, "uintptr_t jit_scratch_vregs[5]", "pointer-width scratch spill backing");
requireText(
  allocatorSource,
  "sizeof(regs.jit_scratch_vregs) / sizeof(regs.jit_scratch_vregs[0]) >= SCRATCH_REGS",
  "scratch spill backing compile-time cardinality assertion",
);
requireText(
  allocatorSource,
  "sizeof(regs.jit_scratch_vregs[0]) == sizeof(uintptr)",
  "scratch spill backing compile-time width assertion",
);
requireText(
  allocatorSource,
  "live.state[i].mem = (uae_u32*)&regs.jit_scratch_vregs[i - S1]",
  "scratch spill mapping",
);
const pointerWidthScratchPaths = allocatorSource.match(/if \(r == PC_P \|\| r >= S1\)/g)?.length ?? 0;
if (pointerWidthScratchPaths < 2) {
  fail("pointer-width scratch spill path: both reload and writeback must be 64-bit");
}
const evictStart = allocatorSource.indexOf("static void evict(int r)");
const evictEnd = allocatorSource.indexOf("static inline void free_nreg", evictStart);
if (evictStart < 0 || evictEnd < 0) fail("missing allocator evict function");
const evictBody = allocatorSource.slice(evictStart, evictEnd);
requireText(
  evictBody,
  'jit_abort("register %d in nreg %d is locked!"',
  "allocator locked-register eviction",
);
if (evictBody.includes("force-unlock") || evictBody.includes("live.nat[rr].locked = 0")) {
  fail("allocator locked-register eviction: silent force-unlock remains");
}

const releaseScratchStart = allocatorSource.indexOf("void release_scratch(int i)");
const releaseScratchEnd = allocatorSource.indexOf("static void freescratch", releaseScratchStart);
if (releaseScratchStart < 0 || releaseScratchEnd < 0) fail("missing release_scratch");
const releaseScratchBody = allocatorSource.slice(releaseScratchStart, releaseScratchEnd);
requireText(
  releaseScratchBody,
  'jit_abort("release_scratch(): %d is not a scratch reg."',
  "scratch range ownership",
);
requireText(
  releaseScratchBody,
  'jit_abort("release_scratch(): %d not in use."',
  "scratch double-release ownership",
);

const freeScratchStart = allocatorSource.indexOf("static void freescratch(void)");
const freeScratchEnd = allocatorSource.indexOf("/********************************", freeScratchStart);
if (freeScratchStart < 0 || freeScratchEnd < 0) fail("missing freescratch");
const freeScratchBody = allocatorSource.slice(freeScratchStart, freeScratchEnd);
requireText(
  freeScratchBody,
  "for (i = 0; i < N_REGS; i++)",
  "scratch lock ownership",
);
requireText(
  freeScratchBody,
  'jit_abort("physical register %d still locked at opcode boundary"',
  "scratch lock ownership",
);
if (freeScratchBody.includes("live.nat[i].locked = 0")) {
  fail("scratch lock ownership: silent lock clearing remains");
}

const dhtuValidatedStart = allocatorSource.indexOf("static inline void set_dhtu_validated");
const dhtuValidatedEnd = allocatorSource.indexOf("void invalidate_block", dhtuValidatedStart);
if (dhtuValidatedStart < 0 || dhtuValidatedEnd < 0) fail("missing validated dependency repatcher");
const dhtuValidatedBody = allocatorSource.slice(dhtuValidatedStart, dhtuValidatedEnd);
requireText(
  dhtuValidatedBody,
  "set_dhtu_policy(bi, dh, false)",
  "validated dependency repatching",
);

const lazyFlushStart = allocatorSource.indexOf("static inline void flush_icache_lazy");
const lazyFlushEnd = allocatorSource.indexOf("int failure;", lazyFlushStart);
if (lazyFlushStart < 0 || lazyFlushEnd < 0) fail("missing flush_icache_lazy");
const lazyFlushBody = allocatorSource.slice(lazyFlushStart, lazyFlushEnd);
requireText(
  lazyFlushBody,
  "set_dhtu_validated(bi, bi->direct_pcc)",
  "lazy-flush direct-edge validation",
);

const invalidateStart = allocatorSource.indexOf("void invalidate_block(blockinfo* bi)");
const invalidateEnd = allocatorSource.indexOf("static inline void create_jmpdep", invalidateStart);
if (invalidateStart < 0 || invalidateEnd < 0) fail("missing invalidate_block");
const invalidateBody = allocatorSource.slice(invalidateStart, invalidateEnd);
requireText(
  invalidateBody,
  "bi->edge_exec_count[i] = 0",
  "invalidated edge profile",
);
requireText(
  invalidateBody,
  "bi->edge_target_pc[i] = 0",
  "invalidated edge profile",
);

const recompileStart = allocatorSource.indexOf("static inline void block_need_recompile");
const recompileEnd = allocatorSource.indexOf("static inline blockinfo* get_blockinfo_addr_new", recompileStart);
if (recompileStart < 0 || recompileEnd < 0) fail("missing block_need_recompile");
const recompileBody = allocatorSource.slice(recompileStart, recompileEnd);
requireBefore(
  recompileBody,
  "bi->direct_handler = bi->direct_pen",
  "set_dhtu(bi, bi->direct_pen)",
  "recompile dependency invalidation",
);

const resetListsStart = allocatorSource.lastIndexOf("static inline void reset_lists(void)");
const resetListsEnd = allocatorSource.indexOf("static void prepare_block", resetListsStart);
if (resetListsStart < 0 || resetListsEnd < 0) fail("missing reset_lists");
const resetListsBody = allocatorSource.slice(resetListsStart, resetListsEnd);
requireBefore(
  resetListsBody,
  "free_blockinfo(hold_bi[i])",
  "hold_bi[i] = NULL",
  "reserved blockinfo reclamation",
);

const finalizationStart = allocatorSource.lastIndexOf("bi->nexthandler = current_compile_p");
const finalizationEnd = allocatorSource.indexOf("jit_end_write_window();", finalizationStart);
if (finalizationStart < 0 || finalizationEnd < 0) fail("missing compile_block finalization");
const finalizationBody = allocatorSource.slice(finalizationStart, finalizationEnd);
requireBefore(
  finalizationBody,
  "bi->status = BI_ACTIVE",
  "flush_icache_hard(3)",
  "cache-exhaustion blockinfo lifetime",
);
requireBefore(
  finalizationBody,
  "if (redo_current_block)",
  "flush_icache_hard(3)",
  "cache-exhaustion blockinfo lifetime",
);

const zeroContainmentStart = allocatorSource.indexOf("/* RAM blocks compiled from zeroed source");
const zeroContainmentEnd = allocatorSource.indexOf("jit_trace_edge_snapshot(\"BUILD\"", zeroContainmentStart);
if (zeroContainmentStart < 0 || zeroContainmentEnd < 0) fail("missing zero-source containment");
const zeroContainmentBody = allocatorSource.slice(zeroContainmentStart, zeroContainmentEnd);
requireBefore(
  zeroContainmentBody,
  "bi->handler_to_use = (cpuop_func*)popall_check_checksum",
  "bi->status = BI_NEED_CHECK",
  "strict zero-source checksum validation",
);
requireBefore(
  zeroContainmentBody,
  "bi->direct_handler = bi->direct_pen",
  "set_dhtu(bi, bi->direct_pen)",
  "ordinary zero-source interpreter containment",
);

const checksumValidationStart = allocatorSource.indexOf("static inline int block_check_checksum");
const checksumValidationEnd = allocatorSource.indexOf("static int called_check_checksum", checksumValidationStart);
if (checksumValidationStart < 0 || checksumValidationEnd < 0) fail("missing checksum validation");
const checksumValidationBody = allocatorSource.slice(checksumValidationStart, checksumValidationEnd);
requireText(
  checksumValidationBody,
  "isgood = bi->csi != NULL",
  "zero-valued checksum validity",
);
if (checksumValidationBody.includes("if (bi->c1 || bi->c2)")) {
  fail("zero-valued checksum validity: checksum value is still overloaded as presence");
}

const blockBuilderPath = new URL(
  "../BasiliskII/src/uae_cpu_2026/compiler/compemu_legacy_arm64_compat.cpp",
  import.meta.url,
);
const blockBuilder = await Bun.file(blockBuilderPath).text();
requireText(blockBuilder, "case 0: return NATIVE_CC_VS;", "complete legacy condition mapping");
requireText(blockBuilder, "case 1: return NATIVE_CC_VC;", "complete legacy condition mapping");
const bfinsHelperStart = blockBuilder.indexOf('extern "C" void jit_op_bfins(void)');
const bfinsHelperEnd = blockBuilder.indexOf("/* --- ROXL/ROXR register helpers --- */", bfinsHelperStart);
if (bfinsHelperStart < 0 || bfinsHelperEnd < 0) fail("missing BFINS helper");
const bfinsHelper = blockBuilder.slice(bfinsHelperStart, bfinsHelperEnd);
for (const contract of [
  "uae_s32 offset = (ext & 0x800)",
  "const uae_u32 dsta = ea_info + (offset >> 3)",
  "(void)get_bitfield(dsta, bdata, offset, width)",
  "put_bitfield(dsta, bdata, field, offset, width)",
  "const uae_u32 rotated = roff ?",
  "const uae_u32 keep_mask = width == 32 ? 0",
]) {
  requireText(bfinsHelper, contract, "BFINS signed/wrapping field semantics");
}
if (bfinsHelper.includes("bytes_needed") || bfinsHelper.includes("offset = do_reg ?")) {
  fail("BFINS signed/wrapping field semantics: truncated byte-loop or early modulo remains");
}
const blockBuilderStart = blockBuilder.indexOf("void execute_normal(void)");
if (blockBuilderStart < 0) fail("missing execute_normal block builder");
const blockBuilderBody = blockBuilder.slice(blockBuilderStart);
requireText(
  blockBuilderBody,
  "if (!must_end && end_block(opcode))\n\t\t\t\tmust_end = true;",
  "basic-block formation",
);
for (const forbidden of [
  "forbid_trace_follow",
  "new_pcp > cur_insn",
  "cur_guest_pc == 0x0401b70c",
]) {
  if (blockBuilderBody.includes(forbidden)) {
    fail(`basic-block formation: forbidden trace-follow policy remains: ${forbidden}`);
  }
}

for (const contract of [
  "extern void jit_notify_guest_memory_write",
  "JIT_NOTIFY_GUEST_WRITE(addr, 4)",
  "JIT_NOTIFY_GUEST_WRITE(addr, 2)",
  "JIT_NOTIFY_GUEST_WRITE(addr, 1)",
]) {
  requireText(memorySource, contract, "cache-disabled tracer write coherency");
}
for (const contract of [
  "emit_strict_cache_disabled_write_barrier(adr, 1)",
  "emit_strict_cache_disabled_write_barrier(adr, 2)",
  "emit_strict_cache_disabled_write_barrier(adr, 4)",
]) {
  requireText(midfunc2Source, contract, "cache-disabled native integer-write coherency");
}
for (const contract of [
  "emit_strict_cache_disabled_write_barrier(REG_WORK1, 1)",
  "emit_strict_cache_disabled_write_barrier(REG_WORK1, 2)",
  "emit_strict_cache_disabled_write_barrier(REG_WORK1, 4)",
]) {
  requireText(midfunc2Source, contract, "24-bit alias write coherency");
}
const read24ByteStart = midfunc2Source.indexOf("MIDFUNC(2,jnf_MEM_READ24_OFF_b");
const read24ByteEnd = midfunc2Source.indexOf("MENDFUNC(2,jnf_MEM_READ24_OFF_b", read24ByteStart);
if (read24ByteStart < 0 || read24ByteEnd < 0) fail("missing 24-bit byte read emitter");
const read24ByteBody = midfunc2Source.slice(read24ByteStart, read24ByteEnd);
requireBefore(read24ByteBody, "MRS_NZCV_x(REG_WORK4)", "CMP_wi(REG_WORK3, 2)", "24-bit byte-read flag preservation");
requireBefore(read24ByteBody, "CMP_wi(REG_WORK3, 2)", "MSR_NZCV_x(REG_WORK4)", "24-bit byte-read flag preservation");
for (const contract of [
  "emit_strict_cache_disabled_write_barrier(adr, 12)",
  "emit_strict_cache_disabled_write_barrier(adr, 8)",
]) {
  requireText(midfuncSource, contract, "cache-disabled native FPU-write coherency");
}
for (const contract of [
  "if (value_reg <= R18_INDEX)",
  "MOV_xx(REG_PAR1, value_reg)",
  "jit_emitted_guest_memory_write = true",
  "compemu_raw_call_observer_ri((uintptr)jit_notify_guest_memory_write",
]) {
  requireText(codegenSource, contract, "cache-disabled native write barrier");
}
for (const contract of [
  "static int guest_cache_enabled = 0",
  "static bool strict_cache_disable_boundary_seen = false",
  "if (cache_enabled && !strict_cache_disable_boundary_seen)",
  "strict_cache_disable_boundary_seen = true",
  "strict_cache_disable_boundary_seen = false;\n    set_cache_state(0)",
  "void jit_notify_guest_memory_write",
  "jit_write_overlaps_checksum",
  "block_need_recompile(bi)",
  "jit_emitted_guest_memory_write &&",
  "!(prop[cft_map(opcode)].cflow & fl_end_block)",
  "static void jit_runtime_fsave",
  "static void jit_runtime_frestore",
  "table68k[opcode].mnemo == i_FSAVE",
  "table68k[opcode].mnemo == i_FRESTORE",
]) {
  requireText(allocatorSource, contract, "strict native lifecycle services");
}
requireText(
  harnessSource,
  "TESTS[cache_disabled_selfmod_replay]",
  "cache-disabled self-modifying RAM regression",
);
const hostCodeInvalidateStart = allocatorSource.indexOf(
  "void jit_invalidate_host_code_write(uae_u32 address, uae_u32 size)",
);
const hostCodeInvalidateEnd = allocatorSource.indexOf(
  "void jit_notify_guest_memory_write",
  hostCodeInvalidateStart,
);
if (hostCodeInvalidateStart < 0 || hostCodeInvalidateEnd < 0) {
  fail("host-injected code coherency: missing dedicated invalidation path");
}
const hostCodeInvalidateBody = allocatorSource.slice(
  hostCodeInvalidateStart,
  hostCodeInvalidateEnd,
);
requireText(
  hostCodeInvalidateBody,
  "jit_invalidate_guest_code_range(address, size, false)",
  "host-injected code coherency",
);
if (hostCodeInvalidateBody.includes("jit_strict_cache_disabled_coherence")) {
  fail("host-injected code coherency: invalidation still depends on guest CACR/strict mode");
}
for (const contract of [
  "jit_invalidate_host_code_write(test_addr",
  "jit_invalidate_host_code_write(m68k_areg(regs, 7), 4)",
  "jit_invalidate_host_code_write(m68k_areg(regs, 7), 6)",
]) {
  requireText(basiliskGlueSource, contract, "host-injected code coherency");
}
for (const contract of [
  "TESTS[host_code_reuse_coherence]",
  "B2_TEST_REWRITE_HEX",
  'EXPECTED_D0[host_code_reuse_coherence]="00000002"',
]) {
  requireText(harnessSource, contract, "host-injected code reuse regression");
}
for (const contract of [
  "#define JIT_TRACE_SOURCE_BYTES 22",
  "uae_u16 opcode;",
  "uae_u8 source[JIT_TRACE_SOURCE_BYTES];",
]) {
  requireText(compemuHeaderSource, contract, "trace source snapshot");
}
for (const contract of [
  "hist->opcode = (uae_u16)do_get_mem_word(hist->location)",
  "memcpy(hist->source, hist->location, JIT_TRACE_SOURCE_BYTES)",
]) {
  requireText(compatSource, contract, "trace source snapshot");
}
const traceSnapshotStart = requireText(
  allocatorSource,
  "void compile_block(cpu_history* pc_hist",
  "trace source coherency",
);
const traceSnapshotEnd = allocatorSource.indexOf(
  "if (jit_strict_full_jit_env() &&",
  traceSnapshotStart,
);
if (traceSnapshotEnd < 0) fail("trace source coherency: missing strict gate after snapshot guard");
const traceSnapshotGuard = allocatorSource.slice(traceSnapshotStart, traceSnapshotEnd);
requireBefore(
  traceSnapshotGuard,
  "const uae_u16 current_opcode = (uae_u16)DO_GET_OPCODE(pc_hist[i].location)",
  "if (current_opcode != pc_hist[i].opcode ||",
  "trace source coherency",
);
requireText(
  traceSnapshotGuard,
  "memcmp(pc_hist[i].source, pc_hist[i].location,",
  "trace extension-word coherency",
);
requireText(harnessSource, "B2_TEST_REPLAY_COUNT=2", "three-pass coherency proof");
requireText(
  harnessSource,
  "TESTS[movea_l_sp_postinc_cov]",
  "runtime-helper logical opcode regression",
);
const runtimeHelperStart = allocatorSource.indexOf("static void jit_runtime_mvsr2_full");
const runtimeHelperEnd = allocatorSource.indexOf("static void op_trap_comp_ff", runtimeHelperStart);
if (runtimeHelperStart < 0 || runtimeHelperEnd < 0)
  fail("missing runtime semantic helper region");
const runtimeHelperBody = allocatorSource.slice(runtimeHelperStart, runtimeHelperEnd);
if (runtimeHelperBody.includes("cft_map(opcode)"))
  fail("runtime semantic helpers must decode the logical opcode, not the compiler-table index");
requireText(harnessSource, "TESTS[branch_flush_bgt_zero]", "cross-op BGT regression");

console.log("METRIC structural_jit_object_layout_epoch=1");
console.log("METRIC structural_fullsr_ea_mode_decode=1");
console.log("METRIC structural_complete_mvsr2_helper_family=1");
console.log("METRIC structural_complete_legacy_condition_mapping=1");
console.log("METRIC structural_arm64_overflow_condition_codegen=1");
console.log("METRIC structural_shape_safe_handler_propagation=1");
console.log("METRIC structural_explicit_handler_propagation=1");
console.log("METRIC structural_fallback_architectural_cflow=1");
console.log("METRIC structural_fallback_controlflow_runtime_pc=1");
console.log("METRIC structural_bfins_runtime_contract=1");
console.log("METRIC structural_bfins_signed_wrapping_semantics=1");
console.log("METRIC structural_helper_call_abi=1");
console.log("METRIC structural_diagnostic_observer_abi=1");
console.log("METRIC structural_diagnostic_verifier_opcode_decode=1");
console.log("METRIC structural_block_verifier_retirement_bound=1");
console.log("METRIC structural_helper_allocator_barrier=1");
console.log("METRIC structural_allocator_locked_evict=1");
console.log("METRIC structural_scratch_spill_cardinality=1");
console.log("METRIC structural_scratch_spill_width=1");
console.log("METRIC structural_scratch_ownership=1");
console.log("METRIC structural_recompile_dependency_invalidation=1");
console.log("METRIC structural_lazy_flush_direct_validation=1");
console.log("METRIC structural_invalidated_edge_profile_reset=1");
console.log("METRIC structural_reserved_blockinfo_reclamation=1");
console.log("METRIC structural_cache_exhaustion_blockinfo_lifetime=1");
console.log("METRIC structural_zero_source_dependency_containment=1");
console.log("METRIC structural_dbf_ccr_preservation=1");
console.log("METRIC structural_strict_full_jit_gate=1");
console.log("METRIC structural_native_emulop_boundary=1");
console.log("METRIC structural_endblock_successor_pc=1");
console.log("METRIC structural_basic_block_control_boundary=1");
console.log("METRIC structural_cache_disabled_write_coherency=1");
console.log("METRIC structural_host_code_reuse_coherency=1");
console.log("METRIC structural_cache_transition_idempotence=1");
console.log("METRIC structural_coverage_taxonomy=1");
console.log("METRIC structural_trace_source_coherency=1");
console.log("METRIC structural_native_fpu_state_boundary=1");
console.log("METRIC structural_disabled_fpu_semantic_service=1");
console.log("METRIC structural_runtime_helper_logical_opcode=1");
