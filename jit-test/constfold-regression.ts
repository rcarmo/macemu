#!/usr/bin/env bun
/** Exercise the actual ARM64 constant paths without changing production ff/nf policy. */
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const source = readFileSync(join(root, "BasiliskII/src/uae_cpu_2026/compiler/compemu_midfunc_arm64_2.cpp"), "utf8");
const names = ["jnf_LSL_b_imm", "jnf_LSL_w_imm", "jnf_LSL_l_imm", "jnf_LSR_b_imm", "jnf_LSR_w_imm", "jnf_LSR_l_imm", "jnf_ROL_l_imm", "jnf_ROR_l_imm"];
const bodies = names.map(name => {
  const start = source.indexOf(`MIDFUNC(2,${name},`);
  const end = source.indexOf(`MENDFUNC(2,${name},`, start);
  if (start < 0 || end < start) throw new Error(`Missing midfunc ${name}`);
  // Retain the entire production body; runtime emission is an error in this test.
  return source.slice(start, end);
}).join("\n");
const program = `
#include <cstdint>
#include <cstdio>
#include <cstdlib>
using uae_u32 = uint32_t;
using uintptr = uintptr_t;
struct { struct { uintptr val; } state[1]; } live;
static bool isconst(int) { return true; }
[[noreturn]] static void unexpected_emit() { std::abort(); }
static int rmw(int) { unexpected_emit(); }
static void unlock2(int) { unexpected_emit(); }
#define RW1 int
#define RW2 int
#define RW4 int
#define IM8 unsigned
#define MIDFUNC(n,name,args) static void name args
#define INIT_REG_b(d) unexpected_emit()
#define INIT_REG_w(d) unexpected_emit()
#define LSL_wwi(...) unexpected_emit()
#define LSR_wwi(...) unexpected_emit()
#define ROR_wwi(...) unexpected_emit()
#define BFI_wwii(...) unexpected_emit()
#define MOV_wi(...) unexpected_emit()
#define UNSIGNED8_REG_2_REG(...) unexpected_emit()
#define UNSIGNED16_REG_2_REG(...) unexpected_emit()
${bodies}
static unsigned checks, failures;
static void check(const char *op, unsigned width, uint32_t input, unsigned count, uint32_t expected) {
    ++checks;
    if (live.state[0].val == expected) return;
    if (++failures <= 12)
        std::fprintf(stderr, "%s width=%u input=%08x count=%u expected=%08x actual=%016llx\\n",
            op, width, input, count, expected, (unsigned long long)live.state[0].val);
}
int main() {
    static_assert(sizeof(uintptr) == 8, "This regression requires a 64-bit host");
    using Fn = void (*)(int, unsigned);
    const Fn lsl[] = {jnf_LSL_b_imm, jnf_LSL_w_imm, jnf_LSL_l_imm};
    const Fn lsr[] = {jnf_LSR_b_imm, jnf_LSR_w_imm, jnf_LSR_l_imm};
    const uint32_t inputs[] = {0, 1, 0x80, 0x8000, 0x80000000, 0xffffffff, 0x11223280, 0x11228000, 0x76543210};
    const unsigned widths[] = {8, 16, 32};
    for (unsigned k = 0; k < 3; ++k) {
        const unsigned width = widths[k];
        const uint32_t mask = uint32_t((uint64_t(1) << width) - 1);
        for (uint32_t input : inputs) for (unsigned count = 0; count < 64; ++count) {
            const uint32_t upper = input & ~mask;
            const uint32_t left = upper | (count >= width ? 0 : uint32_t((uint64_t(input & mask) << count) & mask));
            live.state[0].val = input;
            lsl[k](0, count);
            check("LSL", width, input, count, left);
            jnf_LSR_l_imm(0, 1);
            check("LSL;LSR.L", width, input, count, left >> 1);
            live.state[0].val = input;
            lsr[k](0, count);
            check("LSR", width, input, count, upper | (count >= width ? 0 : (input & mask) >> count));
        }
    }
    for (uint32_t input : inputs) for (unsigned count = 0; count < 64; ++count) {
        // Independent bit-by-bit rotation oracle, avoiding host-width shift UB.
        uint32_t expected = input;
        for (unsigned n = 0; n < (count & 31); ++n)
            expected = uint32_t(uint64_t(expected) * 2) | (expected >> 31);
        live.state[0].val = input;
        jnf_ROL_l_imm(0, count);
        check("ROL", 32, input, count, expected);
        jnf_LSR_l_imm(0, 1);
        check("ROL;LSR.L", 32, input, count, expected >> 1);
        expected = input;
        for (unsigned n = 0; n < (count & 31); ++n)
            expected = (expected >> 1) | ((expected & 1) ? 0x80000000u : 0);
        live.state[0].val = input;
        jnf_ROR_l_imm(0, count);
        check("ROR", 32, input, count, expected);
        jnf_LSR_l_imm(0, 1);
        check("ROR;LSR.L", 32, input, count, expected >> 1);
    }
    std::printf("constfold checks=%u failures=%u\\n", checks, failures);
    return failures ? 1 : 0;
}
`;
const out = mkdtempSync(join(tmpdir(), "basilisk-constfold-"));
try {
  const cpp = join(out, "test.cpp");
  const bin = join(out, "test");
  writeFileSync(cpp, program);
  const build = Bun.spawnSync([process.env.CXX || "c++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror", "-fsanitize=undefined", "-fno-sanitize-recover=all", cpp, "-o", bin], { stdout: "inherit", stderr: "inherit" });
  if (build.exitCode !== 0) throw new Error(`Compilation failed: ${build.exitCode}`);
  const run = Bun.spawnSync([bin], { stdout: "inherit", stderr: "inherit" });
  process.exitCode = run.exitCode;
} finally {
  rmSync(out, { recursive: true, force: true });
}
