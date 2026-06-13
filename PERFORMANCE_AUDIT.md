# Basilisk II Performance Audit

> Full codebase and build settings audit — February 2026
> Focus: Raspberry Pi (ARM64/ARMhf) with SDL2 framebuffer/KMS
>
> **Implementation status updated: 2026-06-13**

## Executive Summary

This audit identified **27 optimization opportunities** across 7 subsystems. **14 of the top recommendations have been implemented** (see status markers below). The most impactful findings were:

1. ~~**ARM byte-swap uses byte-at-a-time fallback**~~ — ✅ **FIXED** — now uses `__builtin_bswap32`/`__builtin_bswap16` (single `REV` instruction)
2. ~~**ARM flag optimizations are dead code**~~ — ✅ **FIXED** — `OPTIMIZED_FLAGS` / `ARM_ASSEMBLY` / `AARCH64_ASSEMBLY` now defined; full aarch64 flag assembly added
3. ~~**No `-O3`, no `-march`, no LTO**~~ — ✅/⚠️ **MOSTLY FIXED** — `-O3`/ARM tuning and no-exceptions/no-RTTI are set; LTO remains intentionally disabled for the experimental AArch64 BasiliskII JIT because it strips runtime gate checks that are semantically live.
4. ~~**VNC per-pixel conversion blocks the display thread**~~ — ✅ **FIXED** — moved to background thread with scanline-level memcpy + async pixel conversion
5. ~~**Audio callback blocks on a semaphore**~~ — ✅ **FIXED** — replaced with lock-free ring buffer; default buffer reduced to 2048 frames

Estimated combined speedup from the **implemented** changes: **30–55%** on Raspberry Pi. Remaining items could add another 15–30%.

**2026-06-13 ARM64 JIT performance lane:** Full-JIT correctness is now strict-clean and default (`JIT-STATUS.md`, commit `980a0451`). The 2×/CPU-load target is a measured optimization tranche, not a correctness bring-up tranche. First experiments showed 32768KB translation-cache churn (18 hard flushes in a 20s ROM/headless profile window versus 2 with 131072KB), so the default full-JIT harness/QA cache has been raised to 131072KB. Apparently low-risk runtime-output and stable-edge direct-chain changes can alter timing enough to expose strict marker regressions, so they remain investigation items rather than defaults. Follow-up profiling found a larger safe win: zero-filled RAM probes were being traced and compiled repeatedly; the AArch64 dispatcher now interprets those zero-RAM chunks directly with a MAXRUN cap instead of generating throwaway optlev0 blocks. In a 20s diagnostic ROM window this reduced compile calls from ~6.4M to ~79k and hard flushes from 5 to 1 while preserving strict markers. Keep strict marker checks (`JIT_FALLBACK`, `SEGV_SKIP`, `JITBLOCKVERIFY`, `op=8c4c`, `bad_pcp`, and fatal host signal markers) mandatory after every speed change; desktop CPU-load claims still require real VNC/display evidence.

---

## Table of Contents

- [1. Build System & Compiler](#1-build-system--compiler)
- [2. CPU Emulation Core](#2-cpu-emulation-core)
- [3. Video / Display Pipeline](#3-video--display-pipeline)
- [4. Audio Subsystem](#4-audio-subsystem)
- [5. Disk I/O & Filesystem](#5-disk-io--filesystem)
- [6. Networking](#6-networking)
- [7. Timing & Threading](#7-timing--threading)
- [Master Recommendation Table](#master-recommendation-table)

---

## 1. Build System & Compiler

### Current State

| Setting | Before | After | Status |
|---------|--------|-------|--------|
| Optimization level | `-O2` (autoconf default) | `-O3` for ARM targets | ✅ B.1 Done |
| `-march` / `-mtune` | None | `-march=armv8-a -mtune=cortex-a72` (arm64), `-march=armv7-a -mfpu=neon-vfpv4 -mtune=cortex-a53` (armhf) | ✅ B.2 Done |
| LTO | Disabled | Non-AArch64 ARM/RPi paths may use `-flto=auto`; BasiliskII AArch64 JIT keeps LTO disabled because it removes live gate checks | ⚠️ B.3 Partial |
| PGO | Not available | Not available | — |
| `-fno-exceptions` | i386 only | All GCC targets (ARM via configure.ac) | ✅ B.5 Done |
| `-fno-rtti` | Not set | All GCC targets globally | ✅ B.5 Done |
| Debian hardening | `hardening=+all` | `hardening=+format,+fortify,+relro,-pie,-stackprotector` | ✅ B.4 Done |

### Findings

**B.1 — No explicit optimization level.**
The build relies on autoconf defaults (`-g -O2`). `-O3` enables auto-vectorization and more aggressive inlining, which directly benefits the CPU emulation tight loop.

**B.2 — No ARM architecture tuning.**
`configure.ac` detects `HAVE_I386`, `HAVE_X86_64`, `HAVE_SPARC`, `HAVE_POWERPC`, `HAVE_M68K` — but has **no** `HAVE_ARM` or `HAVE_AARCH64` variables. No `-march=armv8-a`, no `-mtune=cortex-a72` (RPi 4) or `-mtune=cortex-a76` (RPi 5). The compiler generates generic ARMv8 code that misses microarchitecture-specific scheduling.

**B.3 — LTO not enabled / not universally safe.**
Link-Time Optimization allows cross-TU inlining — critical when the CPU loop in `newcpu.cpp` calls instruction handlers in generated `cpuemu*.cpp` files. However, current BasiliskII AArch64 JIT builds intentionally do **not** enable LTO because previous builds stripped runtime JIT gate checks that the optimizer considered dead. Revisit only with a strict harness/ROM soak comparison and explicit checks for removed gates.

**B.4 — Debian hardening overhead.**
`hardening=+all` enables `-fstack-protector-strong` (canary checks in hot loops) and `-fPIE`/`-pie` (costs a register for GOT on 32-bit ARM). For an emulator with a tight inner loop, PIE + stack-protector can cause **5–15% slowdown on ARM**.

**B.5 — `-fno-exceptions` and `-fno-rtti` not applied on ARM.**
The codebase doesn't use C++ exceptions or RTTI. These flags are only set for i386 at `configure.ac:1599`. Applying them globally saves exception table space and vtable overhead.

### Recommendations

| ID | Change | Impact | Effort | Status |
|----|--------|--------|--------|--------|
| B.1 | Set explicit `-O3` in configure.ac for GCC | Medium | Low | ✅ Done |
| B.2 | Add `-march=armv8-a -mtune=cortex-a72` for arm64, `-march=armv7-a -mfpu=neon-vfpv4` for armhf | Medium | Low | ✅ Done |
| B.3 | Enable `-flto=auto` where safe; keep BasiliskII AArch64 JIT LTO-disabled until gate-stripping is solved | High | Low | ⚠️ Partial |
| B.4 | Change `debian/rules` to `hardening=+format,+fortify,+relro,-pie,-stackprotector` | Medium | Low | ✅ Done |
| B.5 | Apply `-fno-exceptions -fno-rtti` globally for all GCC C++ builds | Low | Low | ✅ Done |

**Files changed:** `configure.ac` (ARM optimization blocks, global `-fno-rtti`), `debian/rules` (hardening flags), `.github/workflows/build-deb-rpi.yml` (`-march`/`-flto` for arm64+armhf jobs), `docker/Dockerfile` and `docker/Dockerfile.armhf` (`CFLAGS`/`CXXFLAGS`/`LDFLAGS` with `-march` and `-flto=auto`).

---

## 2. CPU Emulation Core

### Architecture Overview

- **Dispatch**: 64K function-pointer table, indirect call per instruction (`newcpu.cpp:1539`)
- **Memory access**: Direct addressing (pointer + offset + endian swap)
- **Flags**: Generic C path on ARM (5 separate memory stores per flag update)
- **FPU**: IEEE doubles on ARM (fast for basic ops)
- **spcflags**: Mutex-based on ARM (x86 uses `lock or`)

### Critical Findings

**C.1 — Byte-swap uses byte-at-a-time fallback on ARM.** ✅ **FIXED**

In `sysdeps.h:216`, the `CPU_CAN_ACCESS_UNALIGNED` macro is defined for `__i386__`, `__powerpc__`, `__m68k__`, `__x86_64__` — but **NOT** for `__arm__` or `__aarch64__`. This means on ARM, `do_get_mem_long()` falls through to (`sysdeps.h:449`):

```c
/* Other little-endian CPUs which can not do unaligned accesses (this needs optimization) */
static inline uae_u32 do_get_mem_long(uae_u32 *a) {
    uint8 *b = (uint8 *)a; 
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
}
```

**Four separate byte loads + three shifts + three ORs** for every 32-bit memory access. ARMv6+ supports unaligned access natively, and `__builtin_bswap32` compiles to a single `REV` instruction. This function is called on **every instruction fetch, every memory read, and every memory write**.

Fix: Add `__arm__` and `__aarch64__` to the `CPU_CAN_ACCESS_UNALIGNED` check, and add an ARM-specific `do_get_mem_long` using `__builtin_bswap32`:

```c
#elif defined(__arm__) || defined(__aarch64__)
static inline uae_u32 do_get_mem_long(uae_u32 *a) { return __builtin_bswap32(*a); }
static inline uae_u32 do_get_mem_word(uae_u16 *a) { return __builtin_bswap16(*a); }
static inline void do_put_mem_long(uae_u32 *a, uae_u32 v) { *a = __builtin_bswap32(v); }
static inline void do_put_mem_word(uae_u16 *a, uae_u32 v) { *a = __builtin_bswap16(v); }
```

**C.2 — ARM flag optimizations are dead code.** ✅ **FIXED**

`m68k.h:449` contains ARM-specific flag assembly guarded by `#elif defined(CPU_arm) && defined(ARM_ASSEMBLY)`. However, `configure.ac` **never defines** `-DCPU_arm`, `-DARM_ASSEMBLY`, or `-DOPTIMIZED_FLAGS` for ARM targets. The entire ARM flag optimization section is unreachable.

On ARM builds, the code falls through to the generic C implementation (`m68k.h` after line ~650) which uses **5 separate struct members** (`c`, `z`, `n`, `v`, `x`) — each a separate memory write per arithmetic instruction. The ARM assembly version stores all flags in a single `nzcv` register-width word, read directly from the ARM CPSR.

Additionally, there is **no aarch64-specific flag code at all** — even if `ARM_ASSEMBLY` were defined, it only covers 32-bit ARM (`mrs cpsr` is not valid on aarch64).

Fix: In `configure.ac`, after the x86_64 section (~line 1697), add:

```sh
elif [[ "x$HAVE_GCC27" = "xyes" ]]; then
  case "$target_cpu" in
  arm*)
    DEFINES="$DEFINES -DCPU_arm -DARM_ASSEMBLY -DOPTIMIZED_FLAGS -DUNALIGNED_PROFITABLE"
    ASM_OPTIMIZATIONS="ARM"
    ;;
  aarch64*)
    DEFINES="$DEFINES -DCPU_aarch64 -DAARCH64_ASSEMBLY -DOPTIMIZED_FLAGS -DUNALIGNED_PROFITABLE"
    ASM_OPTIMIZATIONS="AArch64"
    ;;
  esac
fi
```

Then add an `#elif defined(CPU_aarch64) && defined(AARCH64_ASSEMBLY)` block in `m68k.h` with aarch64-native flag operations using `adds`/`subs` + `mrs NZCV`.

**C.3 — spcflags uses mutex instead of atomics on ARM.** ✅ **FIXED**

`spcflags.h:79-89` previously wrapped every `SPCFLAGS_SET` / `SPCFLAGS_CLEAR` in `B2_lock_mutex`/`B2_unlock_mutex`. Now replaced with `__atomic_fetch_or` / `__atomic_fetch_and` (GCC builtins) for ARM, AArch64, x86, and x86_64, with the mutex fallback kept for other platforms:

```c
#define SPCFLAGS_SET(m)   __atomic_fetch_or(&regs.spcflags, (m), __ATOMIC_SEQ_CST)
#define SPCFLAGS_CLEAR(m) __atomic_fetch_and(&regs.spcflags, ~(m), __ATOMIC_SEQ_CST)
```

**C.4 — Indirect-call dispatch.**

The CPU loop at `newcpu.cpp:1539` uses `(*cpufunctbl[opcode])(opcode)` — an indirect function call per instruction. On ARM's smaller BTB, this causes branch mispredictions for uncommon opcodes. A computed-goto / threaded-interpreter approach (`goto *dispatch_table[opcode]`) keeps CPU state in registers and eliminates call/return overhead. Measured speedups on ARM: 20–40%.

This is a larger refactoring effort but would be the single biggest performance win for the interpreter.

**C.5 — Per-instruction tick check.**

`newcpu.cpp:1540` calls `cpu_check_ticks()` on every instruction — a decrement + branch. This could be merged into the spcflags check (set `SPCFLAG_DOINT` when the counter expires) to eliminate one branch per instruction.

**C.6 — STOP instruction busy-waits.** ✅ **FIXED**

`newcpu.cpp:1447` — `SleepAndWait()` was previously commented out (`#if 0`). Now re-enabled, yielding CPU via `usleep(1000)` when the 68k executes a STOP instruction (idle loop).

### Recommendations

| ID | Change | Impact | Effort | Status |
|----|--------|--------|--------|--------|
| C.1 | Add ARM to `CPU_CAN_ACCESS_UNALIGNED`, use `__builtin_bswap32` | **Critical** | Low | ✅ Done |
| C.2 | Define `ARM_ASSEMBLY`/`OPTIMIZED_FLAGS` in configure.ac; add aarch64 flags | **High** | Medium | ✅ Done |
| C.3 | Replace spcflags mutex with `__atomic_fetch_or/and` | High | Low | ✅ Done |
| C.4 | Convert to computed-goto dispatch | **Very High** | High | — |
| C.5 | Merge tick check into spcflags test | Medium | Medium | — |
| C.6 | Re-enable `SleepAndWait()` for STOP instruction | Medium | Low | ✅ Done |

**Files changed:** `sysdeps.h` (ARM byte-swap + `CPU_CAN_ACCESS_UNALIGNED`), `configure.ac` (ARM/AArch64 defines), `m68k.h` (~200 lines of aarch64 flag assembly), `spcflags.h` (atomic ops), `newcpu.cpp` (STOP sleep).

---

## 3. Video / Display Pipeline

### Pipeline Overview

For each frame, the data flows through up to **7 memory-copy stages**:

```
Mac Framebuffer (the_buffer)
  → [1] memcmp vs the_buffer_copy (dirty detection, up to 3MB read×2)
  → [2] memcpy dirty lines → the_buffer_copy
  → [3] Screen_blit dirty lines → guest_surface (format conversion)
  → [4] SDL_BlitSurface guest→host surface (palette/depth conversion)
  → [5] SDL_UpdateTexture host surface → GPU texture
  → [6] SDL_RenderCopy texture → renderer (always full-screen)
  → [7] Double-buffer: memcpy the_buffer → write_buffer (full 3MB, unconditional)
  → [8] VNC: per-pixel read_surface_pixel + SDL_GetRGB (786K iterations)
```

### Findings

**V.1 — VNC update is inline in the present path and uses per-pixel conversion.** ✅ **FIXED**

Previously, `vnc_server.cpp` ran a nested loop over every pixel in the dirty region synchronously in `present_sdl_video()`, blocking the display output for 10–30 ms on RPi.

Now implemented:
- **Background thread**: VNC pixel conversion and `rfbProcessEvents` run on a dedicated `VNCThread`, decoupled from the display pipeline via condition variable signaling
- **Scanline snapshot**: The main thread copies only the dirty scanlines (fast `memcpy` per row) into a private buffer, then signals the VNC thread
- **Fast-path ARGB8888 conversion**: For 32bpp surfaces with standard XRGB/XBGR masks, pixel conversion uses direct uint32 shift-and-mask instead of `SDL_GetRGB` per pixel
- **Rect merging**: Multiple dirty rects between VNC thread wakeups are merged into a single bounding rect
- Generic slow-path with manual mask extraction for non-32bpp formats (no SDL dependency from VNC thread)

**V.2 — Double-buffer copies entire framebuffer unconditionally every VBL.** ✅ **FIXED**

`video_sdl2.cpp:1968` / `video_sdl2.cpp:2000` — previously:
```cpp
memcpy(write_ptr, the_buffer, the_buffer_size);
```

Now guarded with `memcmp` to skip the copy when the frame hasn't changed:
```cpp
if (memcmp(write_ptr, the_buffer, the_buffer_size) != 0) {
    memcpy(write_ptr, the_buffer, the_buffer_size);
    display_read_buffer.store(write_ptr, std::memory_order_release);
}
```

On idle screens this saves ~180 MB/s of memory bandwidth. On active screens the `memcmp` early-exits at the first difference with negligible overhead.

**V.3 — `SDL_RenderCopy` always copies the full texture.**

`video_sdl2.cpp:1124` passes `NULL, NULL` (full source, full destination) even when only a small rect was updated via `SDL_UpdateTexture`. On KMSDRM, this triggers a full-buffer GPU composite every frame.

Fix: Pass the dirty rect to `SDL_RenderCopy`, or skip `SDL_RenderPresent` entirely when nothing changed.

**V.4 — Dirty detection by byte-comparison scans entire framebuffer.**

Non-VOSF mode (`update_display_static` at `video_sdl2.cpp:2722`) uses line-by-line `memcmp` of the entire framebuffer against a copy — **6 MB of reads** per frame. The bbox variant (`video_sdl2.cpp:2883`) uses 64×64 block comparison but still reads every block.

Fix: Enable VOSF on ARM if the profitability test passes (it may fail — see V.5). Alternatively, use NEON-optimized comparison or block checksums to fast-skip clean regions.

**V.5 — VOSF may fail profitability test on ARM.**

`video_vosf.h:241-273` benchmarks SIGSEGV delivery cost. On ARM, the kernel signal path is slower than x86, so VOSF may be automatically rejected. When VOSF is off, the emulator falls back to the expensive memcmp scanning.

**V.6 — 8bpp palette conversion every frame.**

At 8bpp, every frame goes through `SDL_BlitSurface` which does per-pixel palette lookup (8→32 bit expansion). SDL's generic blitter is not NEON-optimized.

Fix: Pre-expand the palette on palette change. Maintain a 32bpp shadow surface that only needs updating when `SDL_SetPaletteColors` is called, then `SDL_UpdateTexture` directly from it.

### Recommendations

| ID | Change | Impact | Effort | Status |
|----|--------|--------|--------|--------|
| V.1 | Move VNC to background thread; use bulk memcpy for ARGB surfaces | **Critical** | Medium | ✅ Done |
| V.2 | Conditional double-buffer copy (only when dirty) | High | Low | ✅ Done |
| V.3 | Skip present when no dirty rects | Medium | Low | — |
| V.4 | NEON-optimized memcmp or block checksums for dirty detection | Medium | Medium | — |
| V.5 | Tune VOSF profitability threshold for ARM | Low | Low | — |
| V.6 | Pre-expand 8bpp palette on change instead of per-frame conversion | Medium | Medium | — |

**Files changed:** `video_sdl2.cpp` (memcmp guard in both `VideoInterrupt` paths, removed empty-rect VNC call), `vnc_server.cpp` (complete rewrite: background thread, scanline snapshot, fast-path ARGB conversion), `vnc_server.h` (added `VNCServerProcessEvents` declaration).

---

## 4. Audio Subsystem

### Findings

**A.1 — Blocking semaphore in SDL audio callback.** ✅ **FIXED**

Previously, the SDL audio callback triggered an emulation interrupt and **blocked** on `SDL_SemWait` until the emulator produced data. This caused buffer underruns and audible clicks/pops under CPU load.

Now replaced with a **lock-free single-producer single-consumer ring buffer**:
- The SDL callback reads pre-filled data from the ring buffer without blocking
- `AudioInterrupt()` (called on the emulation thread) writes new audio data into the ring
- Ring size is 4× the block size (power of 2), providing ~4 blocks of buffering
- Uses `__atomic_store_n` with `__ATOMIC_RELEASE` for lock-free producer/consumer synchronization
- Fast path: at full volume, direct `ring_read` into the output stream (no intermediate copy)
- Graceful underrun: plays silence when the ring is empty (no stall)

**A.2 — Default buffer size is 4096 frames (~93 ms latency).** ✅ **FIXED**

Reduced default from `4096` to `2048` frames (~46 ms at 44.1 kHz). With the ring buffer, smaller buffers are safe since the callback never blocks.

**A.3 — Unnecessary intermediate copy.** ✅ **FIXED**

The old code did `memcpy` → `memset` → `SDL_MixAudio` (three full-buffer operations per callback). The new ring buffer design eliminates the intermediate `audio_mix_buf` entirely. At full volume, a single `ring_read` directly into the output stream replaces all three operations.

### Recommendations

| ID | Change | Impact | Effort | Status |
|----|--------|--------|--------|--------|
| A.1 | Replace blocking semaphore with lock-free ring buffer | **Critical** | Medium | ✅ Done |
| A.2 | Reduce default buffer to 1024–2048 frames | Medium | Low | ✅ Done |
| A.3 | Fast-path: direct memcpy when volume is 100% | Low | Low | ✅ Done |

**Files changed:** `audio_sdl.cpp` (complete rewrite of audio pipeline: ring buffer, non-blocking callback, 2048-frame default, fast-path volume).

---

## 5. Disk I/O & Filesystem

### Findings

**D.1 — Every disk read/write is `lseek` + `read`/`write`.** ✅ **FIXED**

`sys_unix.cpp` — previously used two system calls per I/O operation:
```cpp
lseek(fh->fd, offset + fh->start_byte, SEEK_SET);
return read(fh->fd, buffer, length);
```

Now uses `pread()`/`pwrite()` which does both in a single atomic syscall:
```cpp
ssize_t result = pread(fh->fd, buffer, length, offset + fh->start_byte);
return result < 0 ? 0 : result;
```

**D.2 — No application-level disk cache.**

`disk.cpp:313-337` passes every `DiskPrime()` straight through to the OS. No read-ahead, no block cache, no write coalescing. During boot or app launch (sequential reads), this means thousands of unnecessary syscalls.

**D.3 — ExtFS directory enumeration is O(N²).** ⚠️ **HIGH IMPACT for Finder**

`extfs.cpp:1403-1416`: For indexed directory access (as the Finder does), the code opens the directory, reads entries up to the requested index, then closes it — for **every** index. For a directory with N files, the Finder triggers N calls, each reading 1..N entries = O(N²) total `readdir` calls plus N `opendir`/`closedir` pairs.

For a folder with 100 files: **~5,000 readdir syscalls** and 100 opendir/closedir pairs.

Fix: Cache the full directory listing on first enumeration. Invalidate when directory mtime changes.

**D.4 — No stat() caching in ExtFS.**

Every `fs_get_cat_info`, `fs_get_file_info`, `fs_open` calls `stat()`. For an `ls`-equivalent, that's N `stat` calls on top of the O(N²) readdir.

### Recommendations

| ID | Change | Impact | Effort | Status |
|----|--------|--------|--------|--------|
| D.1 | Replace `lseek`+`read`/`write` with `pread`/`pwrite` | Medium | Low | ✅ Done |
| D.2 | Add LRU read cache (64 KB) in DiskPrime | High | Medium | — |
| D.3 | Cache directory listings in ExtFS | **High** | Medium | — |
| D.4 | Cache stat() results per FSItem | Medium | Low | — |

**Files changed:** `sys_unix.cpp` (`Sys_read`/`Sys_write` now use `pread`/`pwrite`).

---

## 6. Networking

### Findings

**N.1 — Ethernet receive uses 20 ms `select()` timeout.**

`ether_unix.cpp:1044-1049`: The packet receive thread polls with a 20 ms timeout, causing up to 20 ms latency per packet and 50 idle wakeups/sec.

**N.2 — Slirp thread polls with 10 ms timeout.**

`ether_unix.cpp:968-1004`: The slirp thread loops with a 10 ms `select()` timeout — 100 idle wakeups/sec even with no network traffic.

**N.3 — Per-packet interrupt acknowledgement blocks receive thread.**

`ether_unix.cpp:1063-1064`: After signaling a packet interrupt, the receive thread blocks on `sem_wait(&int_ack)` until the emulation thread processes it. This serializes all packet processing.

### Recommendations

| ID | Change | Impact | Effort |
|----|--------|--------|--------|
| N.1 | Use `poll()` or `epoll` with pipe-based wakeup | Medium | Low |
| N.2 | Adaptive slirp timeout (100 ms idle, 10 ms active) | Low | Low |
| N.3 | Batch packet processing with a queue | Low | Medium |

---

## 7. Timing & Threading

### Findings

**T.1 — Uses `CLOCK_REALTIME` instead of `CLOCK_MONOTONIC`.**

`timer_unix.cpp:107-108`: Timing uses `clock_gettime(CLOCK_REALTIME)`, which is affected by NTP adjustments. `CLOCK_MONOTONIC` is the correct choice for interval timing.

**T.2 — Timer thread uses signal-based suspend/resume.**

`timer.cpp:390-393`: `pthread_kill(SIGSUSPEND)` + `sem_wait` for every `PrimeTime()`/`RmvTime()` call. Each operation costs ~2–5 µs on ARM from signal delivery overhead.

Fix: Use `pthread_cond_timedwait` instead.

**T.3 — Two unsynchronized 60 Hz loops.**

The redraw thread runs dirty detection at 60 Hz. The VBL/VideoInterrupt calls `present_sdl_video()` at a separate 60 Hz cadence. These are unsynchronized — can double-present or present stale data.

Fix: Merge into a single coordinated pipeline, or use a condition variable to signal "new frame ready."

### Recommendations

| ID | Change | Impact | Effort |
|----|--------|--------|--------|
| T.1 | Switch to `CLOCK_MONOTONIC` | Low | Low |
| T.2 | Replace signal-based timer suspend with condvar | Medium | Medium |
| T.3 | Unify refresh architecture into single pipeline | Medium | High |

---

## Master Recommendation Table

Sorted by estimated impact on Raspberry Pi performance:

| Rank | ID | Subsystem | Change | Impact | Effort | Status |
|------|-----|-----------|--------|--------|--------|--------|
| 1 | C.1 | CPU/Memory | **ARM byte-swap: add to `CPU_CAN_ACCESS_UNALIGNED`, use `__builtin_bswap32`** | ~15–25% | Low | ✅ Done |
| 2 | C.2 | CPU/Flags | **Enable `OPTIMIZED_FLAGS` + `ARM_ASSEMBLY` in configure.ac; add aarch64 flag asm** | ~10–20% | Medium | ✅ Done |
| 3 | C.4 | CPU/Dispatch | Convert to computed-goto threaded interpreter | ~20–40% | High | — |
| 4 | B.3 | Build | Enable LTO (`-flto=auto`) | ~5–15% | Low | ✅ Done |
| 5 | V.1 | Video/VNC | Move VNC to background thread; bulk memcpy instead of per-pixel | ~10–30 ms/frame | Medium | ✅ Done |
| 6 | A.1 | Audio | Replace blocking semaphore with lock-free ring buffer | Eliminates pops | Medium | ✅ Done |
| 7 | C.3 | CPU/spcflags | Replace mutex with `__atomic_fetch_or`/`and` | ~2–5% | Low | ✅ Done |
| 8 | B.1+B.2 | Build | `-O3 -march=armv8-a -mtune=cortex-a72` | ~3–8% | Low | ✅ Done |
| 9 | V.2 | Video | Conditional double-buffer copy (skip when clean) | ~180 MB/s saved | Low | ✅ Done |
| 10 | D.3 | ExtFS | Cache directory listings (fix O(N²) readdir) | Finder 5–10× faster | Medium | — |
| 11 | B.4 | Build | Drop PIE + stack-protector from Debian hardening | ~5–10% | Low | ✅ Done |
| 12 | C.6 | CPU | Re-enable `SleepAndWait()` for STOP idle | CPU usage drops | Low | ✅ Done |
| 13 | D.1 | Disk | `pread`/`pwrite` instead of `lseek`+`read`/`write` | ~50% fewer syscalls | Low | ✅ Done |
| 14 | V.3 | Video | Skip `SDL_RenderPresent` when nothing changed | ~5 ms/frame idle | Low | — |
| 15 | D.2 | Disk | Add 64 KB LRU read cache | Faster boot/launch | Medium | — |
| 16 | B.5 | Build | `-fno-exceptions -fno-rtti` globally | ~1–2% | Low | ✅ Done |
| 17 | A.2 | Audio | Reduce default buffer to 1024–2048 frames | 50 ms latency drop | Low | ✅ Done |
| 18 | V.6 | Video | Pre-expand 8bpp palette on change | ~2–3 ms/frame @ 8bpp | Medium | — |
| 19 | N.1 | Network | Use `poll()`/`epoll` for ethernet receive | 20 ms→instant latency | Low | — |
| 20 | C.5 | CPU | Merge tick check into spcflags test | ~1% | Medium | — |
| 21 | T.2 | Timer | Replace signal-based timer with condvar | Fewer signals | Medium | — |
| 22 | T.3 | Video/Timer | Unify two 60 Hz loops into one | Frame consistency | High | — |
| 23 | V.4 | Video | NEON-optimized dirty detection | ~1–2 ms/frame | Medium | — |
| 24 | N.2 | Network | Adaptive slirp timeout | Fewer idle wakeups | Low | — |
| 25 | T.1 | Timer | `CLOCK_MONOTONIC` | Correctness | Low | — |
| 26 | A.3 | Audio | Skip intermediate copy at 100% volume | ~0.1 ms/callback | Low | ✅ Done |
| 27 | D.4 | ExtFS | Cache stat() results | Fewer syscalls | Low | — |

**Summary: 14 of 27 recommendations implemented.**

### Quick Wins — ALL IMPLEMENTED ✅

1. ✅ **C.1** — ARM byte-swap in `sysdeps.h` — `__builtin_bswap32`/`__builtin_bswap16`
2. ✅ **B.3** — LTO enabled (`-flto=auto`) in configure.ac, CI, and Dockerfiles
3. ✅ **C.3** — Atomic spcflags via `__atomic_fetch_or`/`__atomic_fetch_and`
4. ✅ **B.1+B.2** — `-O3 -march=armv8-a/-march=armv7-a` in configure.ac, CI, Dockerfiles
5. ✅ **V.2** — Double-buffer memcpy guarded with memcmp dirty check

### Additional Low-Effort Fixes — ALL IMPLEMENTED ✅

6. ✅ **C.2** — ARM/aarch64 flag optimizations (`configure.ac` defines + ~200 lines aarch64 asm in `m68k.h`)
7. ✅ **B.4** — Debian hardening reduced to `+format,+fortify,+relro,-pie,-stackprotector`
8. ✅ **B.5** — Global `-fno-rtti` for all GCC C++ builds
9. ✅ **C.6** — `SleepAndWait()` re-enabled for STOP instruction idle
10. ✅ **D.1** — `pread`/`pwrite` replacing `lseek`+`read`/`write` in `sys_unix.cpp`

### Medium-Effort Fixes — IMPLEMENTED ✅

11. ✅ **V.1** — VNC moved to background thread with scanline snapshot + fast-path ARGB conversion
12. ✅ **A.1** — Lock-free ring buffer replacing blocking semaphore in audio callback
13. ✅ **A.2** — Default audio buffer reduced from 4096 to 2048 frames (93→46 ms latency)
14. ✅ **A.3** — Direct ring_read at full volume (eliminates intermediate copy)

### Remaining Larger Projects (Worth planning)

1. **C.4** — Computed-goto dispatch (touches gencpu.c + newcpu.cpp, ~20–40% speedup)
2. **D.3** — ExtFS directory cache (new data structure + invalidation logic)
3. **V.3** — Skip `SDL_RenderPresent` when nothing changed

### Files Modified

| File | Changes |
|------|--------|
| `BasiliskII/src/Unix/sysdeps.h` | ARM byte-swap + `CPU_CAN_ACCESS_UNALIGNED` |
| `BasiliskII/src/Unix/configure.ac` | ARM/AArch64 CPU detection, optimization defines, `-O3`, `-flto=auto`, `-fno-rtti` |
| `BasiliskII/src/uae_cpu_2026/m68k.h` | ~200 lines aarch64 flag assembly |
| `BasiliskII/src/uae_cpu_2026/spcflags.h` | Atomic `SPCFLAGS_SET`/`SPCFLAGS_CLEAR` |
| `BasiliskII/src/uae_cpu_2026/newcpu.cpp` | Re-enabled `SleepAndWait()` for STOP |
| `BasiliskII/src/SDL/video_sdl2.cpp` | memcmp guard on double-buffer memcpy; removed empty-rect VNC call |
| `BasiliskII/src/SDL/vnc_server.cpp` | Background thread, scanline snapshot, fast-path ARGB conversion |
| `BasiliskII/src/SDL/vnc_server.h` | Added `VNCServerProcessEvents` declaration |
| `BasiliskII/src/SDL/audio_sdl.cpp` | Lock-free ring buffer, non-blocking callback, 2048-frame default |
| `BasiliskII/src/Unix/sys_unix.cpp` | `pread`/`pwrite` in `Sys_read`/`Sys_write` |
| `BasiliskII/debian/rules` | Reduced Debian hardening flags |
| `.github/workflows/build-deb-rpi.yml` | `-march`, `-flto=auto` for arm64+armhf CI jobs |
| `BasiliskII/docker/Dockerfile` | `-march=armv8-a`, `-flto=auto` |
| `BasiliskII/docker/Dockerfile.armhf` | `-march=armv7-a`, `-flto=auto` |
