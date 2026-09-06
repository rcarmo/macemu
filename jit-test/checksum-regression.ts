#!/usr/bin/env bun
/** Exercise the actual source checksum body, independent of dispatch/replay hooks. */
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
const root = resolve(import.meta.dir, "..");
const source = readFileSync(join(root, "BasiliskII/src/uae_cpu_2026/compiler/compemu_support_arm.cpp"), "utf8");
const header = readFileSync(join(root, "BasiliskII/src/uae_cpu_2026/compiler/compemu_arm.h"), "utf8");
const start = source.indexOf("static bool calc_checksum(");
const end = source.indexOf("\nint check_for_cache_miss", start);
const max = header.match(/^#define MAX_CHECKSUM_LEN\s+(\d+)/m)?.[1];
if (start < 0 || end < start || !max) throw new Error("Missing checksum body/limit");
const program = `
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <algorithm>
using uae_u32 = uint32_t;
using uae_s32 = int32_t;
using uintptr = uintptr_t;
#define MAX_CHECKSUM_LEN ${max}
#define Dif(x) if (x)
struct checksum_info { unsigned char *start_p; uint32_t length; checksum_info *next; };
struct blockinfo { checksum_info *csi; };
${source.slice(start, end)}
static unsigned checks, failures;
static void check(bool ok, const char *name) {
    ++checks;
    if (!ok) { ++failures; std::fprintf(stderr, "FAIL %s\\n", name); }
}
static void require_valid(blockinfo *bi, uint32_t &a, uint32_t &b) {
    if (!calc_checksum(bi, &a, &b)) {
        std::fprintf(stderr, "FAIL valid checksum span rejected\\n");
        std::exit(1);
    }
}
static void checksum(uint32_t *words, unsigned n, uint32_t &a, uint32_t &b) {
    checksum_info span{reinterpret_cast<unsigned char *>(words), n * 4, nullptr};
    blockinfo bi{&span}; require_valid(&bi, a, b);
}
int main() {
    uint32_t a, b, c, d;
    uint32_t original[] = {0x714e0170, 0x714e0270, 0xa0a67c2c, 0x00000100};
    checksum(original, 4, a, b);
    checksum(original, 4, c, d);
    check(a == c && b == d, "unchanged");
    std::swap(original[0], original[1]);
    checksum(original, 4, c, d);
    check(a == c && b != d, "guest instruction-group permutation");
    uint32_t high[] = {1, 0x80000001};
    checksum(high, 2, a, b);
    std::swap(high[0], high[1]); checksum(high, 2, c, d);
    check(a == c && b != d, "high-bit permutation");
    uint32_t zeros[16]{};
    checksum(zeros, 16, a, b); check(a == 0 && b == 0, "zero-source convention");
    checksum_info good{reinterpret_cast<unsigned char *>(zeros), 16, nullptr};
    blockinfo valid{&good};
    check(calc_checksum(&valid, &a, &b), "valid all-zero span");
    for (int32_t length : {0, -1, INT32_MIN, MAX_CHECKSUM_LEN + 1, INT32_MAX}) {
        for (unsigned offset = 0; offset < 4; ++offset) {
            checksum_info invalid{reinterpret_cast<unsigned char *>(zeros) + offset, uint32_t(length), nullptr};
            blockinfo bad{&invalid};
            check(!calc_checksum(&bad, &a, &b), "invalid raw/adjusted span");
            good.next = &invalid;
            check(!calc_checksum(&valid, &a, &b), "mixed valid/invalid chain");
            good.next = nullptr;
        }
    }
    blockinfo absent{nullptr};
    check(!calc_checksum(&absent, &a, &b), "absent metadata");
    checksum_info invalid{nullptr, 16, nullptr};
    blockinfo bad{&invalid};
    check(!calc_checksum(&bad, &a, &b), "null source");
    invalid.start_p = reinterpret_cast<unsigned char *>(zeros) + 1;
    invalid.length = MAX_CHECKSUM_LEN;
    check(!calc_checksum(&bad, &a, &b), "oversized after alignment");
    uint32_t words[MAX_CHECKSUM_LEN / 4 + 2];
    for (unsigned i = 0; i < sizeof(words)/sizeof(*words); ++i) words[i] = 0x12345678u + 0x10203u * i;
    for (unsigned offset = 0; offset < 4; ++offset) {
        for (unsigned len = 1; len <= MAX_CHECKSUM_LEN - offset; ++len) {
            checksum_info span{reinterpret_cast<unsigned char *>(words) + offset, len, nullptr};
            blockinfo bi{&span}; require_valid(&bi, a, b);
            unsigned rounded = (offset + len + 3) / 4;
            checksum(words, rounded, c, d);
            check(a == c && b == d, "unaligned/rounded span");
        }
    }
    checksum(words, 16, a, b);
    checksum_info tail{reinterpret_cast<unsigned char *>(words + 5), 44, nullptr};
    checksum_info head{reinterpret_cast<unsigned char *>(words), 20, &tail};
    blockinfo bi{&head}; require_valid(&bi, c, d);
    check(a == c && b == d, "carry through checksum chain");
    tail.next = &head; head.next = nullptr; bi.csi = &tail;
    require_valid(&bi, c, d);
    check(a == c && b != d, "permuted checksum chain");
    checksum(words, MAX_CHECKSUM_LEN / 4, a, b);
    words[MAX_CHECKSUM_LEN / 4 - 1] ^= 0x80000000;
    checksum(words, MAX_CHECKSUM_LEN / 4, c, d);
    check(a != c || b != d, "last word at maximum span");
    std::printf("checksum checks=%u failures=%u\\n", checks, failures);
    return failures ? 1 : 0;
}
`;
const out = mkdtempSync(join(tmpdir(), "basilisk-checksum-"));
try {
  const cpp = join(out, "test.cpp"), bin = join(out, "test");
  writeFileSync(cpp, program);
  const build = Bun.spawnSync([process.env.CXX || "c++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", cpp, "-o", bin], { stdout: "inherit", stderr: "inherit" });
  if (build.exitCode !== 0) throw new Error(`Compilation failed: ${build.exitCode}`);
  process.exitCode = Bun.spawnSync([bin], { stdout: "inherit", stderr: "inherit" }).exitCode;
} finally { rmSync(out, { recursive: true, force: true }); }
