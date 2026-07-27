#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

using uae_u32 = std::uint32_t;
static std::vector<uae_u32> emitted;
static void emit_long(uae_u32 word) { emitted.push_back(word); }
#include "../BasiliskII/src/uae_cpu_2026/compiler/codegen_arm64.h"

struct Output { std::uint64_t result, nzcv; };
enum class FieldApi { Signed, Unsigned };
enum class AliasApi { SXTBW, SXTBX, SXTHW, SXTHX, SXTWX, UXTBW, UXTBX, UXTHW, UXTHX };
enum class TransformApi { REVW, REVX, REV16W, REV16X, REV32X, CLSW };
struct Case { std::size_t offset; FieldApi api; unsigned bits, immr, imms; };

static void fail(const char* label, std::uint64_t expected, std::uint64_t found)
{
    std::fprintf(stderr, "TRANSFORM_EMITTER_FAIL %s expected=%016llx found=%016llx\n",
        label, static_cast<unsigned long long>(expected), static_cast<unsigned long long>(found));
    std::exit(1);
}
static uae_u32 one_word(const char* label)
{
    if (emitted.size() != 1) fail(label, 1, emitted.size());
    const auto word = emitted.front(); emitted.clear(); return word;
}
static uae_u32 field_word(FieldApi api, unsigned bits, unsigned d, unsigned n, unsigned immr, unsigned imms)
{
    emitted.clear();
    if (api == FieldApi::Signed) {
        if (bits == 32) SBFM_wwii(d, n, immr, imms); else SBFM_xxii(d, n, immr, imms);
    } else {
        if (bits == 32) UBFM_wwii(d, n, immr, imms); else UBFM_xxii(d, n, immr, imms);
    }
    return one_word("field count");
}
static uae_u32 alias_word(AliasApi api, unsigned d, unsigned n)
{
    emitted.clear();
    switch (api) {
    case AliasApi::SXTBW: SXTB_ww(d, n); break; case AliasApi::SXTBX: SXTB_xx(d, n); break;
    case AliasApi::SXTHW: SXTH_ww(d, n); break; case AliasApi::SXTHX: SXTH_xx(d, n); break;
    case AliasApi::SXTWX: SXTW_xw(d, n); break; case AliasApi::UXTBW: UXTB_ww(d, n); break;
    case AliasApi::UXTBX: UXTB_xx(d, n); break; case AliasApi::UXTHW: UXTH_ww(d, n); break;
    case AliasApi::UXTHX: UXTH_xx(d, n); break;
    }
    return one_word("alias count");
}
static uae_u32 transform_word(TransformApi api, unsigned d, unsigned n)
{
    emitted.clear();
    switch (api) {
    case TransformApi::REVW: REV_ww(d, n); break; case TransformApi::REVX: REV_xx(d, n); break;
    case TransformApi::REV16W: REV16_ww(d, n); break; case TransformApi::REV16X: REV16_xx(d, n); break;
    case TransformApi::REV32X: REV32_xx(d, n); break; case TransformApi::CLSW: CLS_ww(d, n); break;
    }
    return one_word("transform count");
}
static std::uint64_t mask(unsigned width)
{
    return width == 64 ? ~std::uint64_t{0} : ((std::uint64_t{1} << width) - 1);
}
static std::uint64_t sign_extend(std::uint64_t value, unsigned sign_bit, unsigned bits)
{
    const auto full = mask(bits); value &= full;
    if (value & (std::uint64_t{1} << sign_bit)) value |= full & ~mask(sign_bit + 1);
    return value & full;
}
static std::uint64_t expected_field(FieldApi api, unsigned bits, unsigned immr,
    unsigned imms, std::uint64_t source)
{
    const auto full = mask(bits); source &= full; std::uint64_t value; unsigned top;
    if (imms >= immr) {
        const unsigned width = imms - immr + 1;
        value = (source >> immr) & mask(width); top = width - 1;
    } else {
        const unsigned width = imms + 1, lsb = bits - immr;
        value = (source & mask(width)) << lsb; top = lsb + width - 1;
    }
    return api == FieldApi::Signed ? sign_extend(value, top, bits) : (value & full);
}
static uae_u32 expected_field_word(FieldApi api, unsigned bits, unsigned d, unsigned n,
    unsigned immr, unsigned imms)
{
    const uae_u32 base = api == FieldApi::Signed ? (bits == 32 ? 0x13000000u : 0x93400000u)
                                                  : (bits == 32 ? 0x53000000u : 0xd3400000u);
    return base | (immr << 16) | (imms << 10) | (n << 5) | d;
}
static void append_case(std::vector<uae_u32>& code, std::vector<Case>& cases,
    FieldApi api, unsigned bits, unsigned immr, unsigned imms)
{
    const auto word = field_word(api, bits, 0, 0, immr, imms);
    const auto expected = expected_field_word(api, bits, 0, 0, immr, imms);
    if (word != expected) fail("field encoding", expected, word);
    const auto offset = code.size();
    code.insert(code.end(), {0xd51b4201u, word, 0xd53b4203u, 0xf9000040u, 0xf9000443u, 0xd65f03c0u});
    cases.push_back({offset, api, bits, immr, imms});
}
static void* executable(const std::vector<uae_u32>& code, std::size_t& mapped)
{
    const auto page = static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
    const auto bytes = code.size() * sizeof(uae_u32); mapped = (bytes + page - 1) & ~(page - 1);
    void* memory = mmap(nullptr, mapped, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (memory == MAP_FAILED) { std::perror("mmap"); std::exit(1); }
    std::memcpy(memory, code.data(), bytes);
    if (mprotect(memory, mapped, PROT_READ | PROT_EXEC)) { std::perror("mprotect"); std::exit(1); }
    __builtin___clear_cache(static_cast<char*>(memory), static_cast<char*>(memory) + bytes); return memory;
}
static Output run_word(uae_u32 word, std::uint64_t source)
{
    std::vector<uae_u32> code {0xd51b4201u, word, 0xd53b4203u, 0xf9000040u,
        0xf9000443u, 0xd65f03c0u};
    std::size_t mapped = 0; void* memory = executable(code, mapped);
    using Fn = void (*)(std::uint64_t, std::uint64_t, Output*);
    Output output {};
    reinterpret_cast<Fn>(memory)(source, 0xa0000000u, &output);
    munmap(memory, mapped); return output;
}
static std::uint64_t reverse_bytes(std::uint64_t value, unsigned lane_bytes, unsigned total_bytes)
{
    std::uint64_t result = 0;
    for (unsigned base = 0; base < total_bytes; base += lane_bytes)
        for (unsigned i = 0; i < lane_bytes; ++i)
            result |= ((value >> (8 * (base + i))) & 0xffu) << (8 * (base + lane_bytes - 1 - i));
    return result;
}
static unsigned cls32(std::uint32_t value)
{
    const bool sign = value >> 31; unsigned count = 0;
    for (int bit = 30; bit >= 0 && static_cast<bool>((value >> bit) & 1u) == sign; --bit) ++count;
    return count;
}
int main()
{
#if !defined(__aarch64__)
    std::fprintf(stderr, "TRANSFORM_EMITTER_FAIL native AArch64 host required\n"); return 1;
#endif
    std::vector<uae_u32> code; std::vector<Case> cases;
    code.reserve(11000 * 6); cases.reserve(11000);
    for (auto api : {FieldApi::Signed, FieldApi::Unsigned})
        for (unsigned bits : {32u, 64u})
            for (unsigned immr = 0; immr < bits; ++immr)
                for (unsigned imms = 0; imms < bits; ++imms)
                    append_case(code, cases, api, bits, immr, imms);
    std::size_t mapped = 0; void* memory = executable(code, mapped);
    using Fn = void (*)(std::uint64_t, std::uint64_t, Output*);
    const std::uint64_t source = 0x936cc639923456f8ull, hostile = 0xa0000000u;
    unsigned field_native = 0;
    for (const auto& test : cases) {
        Output out {};
        reinterpret_cast<Fn>(static_cast<char*>(memory) + test.offset * sizeof(uae_u32))(source, hostile, &out);
        const auto expected = expected_field(test.api, test.bits, test.immr, test.imms, source);
        if (out.result != expected) fail("field native", expected, out.result);
        if ((out.nzcv & 0xf0000000u) != hostile) fail("field NZCV", hostile, out.nzcv & 0xf0000000u);
        ++field_native;
    }
    munmap(memory, mapped);

    unsigned anchors = 0, alias_native = 0, transform_native = 0;
    const AliasApi aliases[] = {AliasApi::SXTBW, AliasApi::SXTBX, AliasApi::SXTHW,
        AliasApi::SXTHX, AliasApi::SXTWX, AliasApi::UXTBW, AliasApi::UXTBX,
        AliasApi::UXTHW, AliasApi::UXTHX};
    const uae_u32 alias_anchors[] = {0x13001d49u,0x93401d49u,0x13003d49u,0x93403d49u,
        0x93407d49u,0x53001d49u,0xd3401d49u,0x53003d49u,0xd3403d49u};
    const unsigned alias_widths[] = {32,64,32,64,64,32,64,32,64};
    const unsigned alias_bits[] = {8,8,16,16,32,8,8,16,16};
    const bool alias_signed[] = {true,true,true,true,true,false,false,false,false};
    for (unsigned index = 0; index < 9; ++index) {
        if (alias_word(aliases[index], 9, 10) != alias_anchors[index])
            fail("alias anchor", alias_anchors[index], alias_word(aliases[index], 9, 10));
        const auto max_expected = (alias_anchors[index] & ~0x3ffu) | (31u << 5) | 31u;
        if (alias_word(aliases[index], 31, 31) != max_expected)
            fail("alias max fields", max_expected, alias_word(aliases[index], 31, 31));
        anchors += 2;
        for (const auto input : {std::uint64_t{0}, source, ~std::uint64_t{0}}) {
            auto expected = input & mask(alias_bits[index]);
            if (alias_signed[index]) expected = sign_extend(expected, alias_bits[index] - 1, alias_widths[index]);
            expected &= mask(alias_widths[index]);
            const auto out = run_word(alias_word(aliases[index], 0, 0), input);
            if (out.result != expected) fail("alias native", expected, out.result);
            if ((out.nzcv & 0xf0000000u) != 0xa0000000u)
                fail("alias NZCV", 0xa0000000u, out.nzcv & 0xf0000000u);
            ++alias_native;
        }
    }

    const TransformApi transforms[] = {TransformApi::REVW,TransformApi::REVX,TransformApi::REV16W,
        TransformApi::REV16X,TransformApi::REV32X,TransformApi::CLSW};
    const uae_u32 transform_anchors[] = {0x5ac00949u,0xdac00d49u,0x5ac00549u,0xdac00549u,0xdac00949u,0x5ac01549u};
    for (unsigned index = 0; index < 6; ++index) {
        if (transform_word(transforms[index], 9, 10) != transform_anchors[index])
            fail("transform anchor", transform_anchors[index], transform_word(transforms[index], 9, 10));
        const auto max_expected = (transform_anchors[index] & ~0x3ffu) | (31u << 5) | 31u;
        if (transform_word(transforms[index], 31, 31) != max_expected)
            fail("transform max fields", max_expected, transform_word(transforms[index], 31, 31));
        anchors += 2;
        for (const auto input : {std::uint64_t{0}, source, ~std::uint64_t{0}}) {
            std::uint64_t expected = 0;
            switch (transforms[index]) {
            case TransformApi::REVW: expected = reverse_bytes(input,4,4); break;
            case TransformApi::REVX: expected = reverse_bytes(input,8,8); break;
            case TransformApi::REV16W: expected = reverse_bytes(input,2,4); break;
            case TransformApi::REV16X: expected = reverse_bytes(input,2,8); break;
            case TransformApi::REV32X: expected = reverse_bytes(input,4,8); break;
            case TransformApi::CLSW: expected = cls32(static_cast<std::uint32_t>(input)); break;
            }
            const auto out = run_word(transform_word(transforms[index], 0, 0), input);
            if (out.result != expected) fail("transform native", expected, out.result);
            if ((out.nzcv & 0xf0000000u) != 0xa0000000u)
                fail("transform NZCV", 0xa0000000u, out.nzcv & 0xf0000000u);
            ++transform_native;
        }
    }
    std::printf("METRIC emitter_transform_apis=19\n");
    std::printf("METRIC emitter_transform_field_encodings=%zu\n", cases.size());
    std::printf("METRIC emitter_transform_anchor_words=%u\n", anchors);
    std::printf("METRIC emitter_transform_field_native=%u\n", field_native);
    std::printf("METRIC emitter_transform_alias_native=%u\n", alias_native);
    std::printf("METRIC emitter_transform_operation_native=%u\n", transform_native);
    std::printf("METRIC emitter_transform_native_vectors=%u\n", field_native + alias_native + transform_native);
    std::printf("METRIC emitter_transform_preserves_nzcv=1\n");
    return cases.size() == 10240 && anchors == 30 && field_native == 10240 &&
        alias_native == 27 && transform_native == 18 ? 0 : 1;
}
