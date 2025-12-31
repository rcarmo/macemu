# ARM JIT Branch - Fit/Gap Analysis

This document tracks the development status, known issues, and actionable items for the `feature/arm-jit` branch.

## Current Status

**Build**: ✅ Compiles successfully via GitHub Actions (ARM32 cross-compilation on Debian 12)
**Runtime**: ⚠️ Runs but has display corruption issues

## Known Issues

### 1. Screen Corruption (High Priority)

**Symptom**: Bitmap corruption visible on screen, significantly worse at lower bit depths (1/2/4/8-bit modes).

**Observations**:

- 32-bit color depth shows minimal/no corruption
- 16-bit shows moderate corruption
- 8-bit and below shows severe corruption
- The corruption pattern suggests issues with pixel format conversion or pitch calculations

**Root Cause Candidates**:

| Area                                      | Likelihood | Notes                                                                                                                                   |
| ----------------------------------------- | ---------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Screen_blit format conversion             | HIGH       | Mac is big-endian, ARM is little-endian. The blitters in `video_blit.cpp` may not handle all depth/format combinations correctly on ARM |
| Pitch mismatch in update_display_static   | MEDIUM     | The `update_display_static()` and `update_display_static_bbox()` functions have separate code paths for low bit depths vs 8+ bits       |
| SDL_UpdateTexture vs guest_surface format | MEDIUM     | Recent change from `SDL_LockTexture` to `SDL_UpdateTexture` may have format assumptions                                                 |
| JIT memory byte-swap operations           | LOW        | ARM JIT uses `REV`/`REV16`/`REVSH` instructions for byte swapping - these appear correct                                                |
| Texture pixel format mismatch             | MEDIUM     | Texture is BGRA8888, but guest surfaces vary by depth                                                                                   |

---

## Fit Analysis: What Works

### ARM JIT Compiler

- ✅ Successfully ported from ARAnyM
- ✅ ARM32 codegen with `REV` instructions for byte swapping
- ✅ Direct addressing mode enabled
- ✅ Signal handling configured for ARM cross-compilation
- ⚠️ **Integer-only JIT** — FPU operations use interpreted IEEE emulation (see [Future Work](#future-work-fpu-jit))

### SDL2 Video Backend

- ✅ KMSDRM support with OpenGL ES 2.0
- ✅ Window creation and texture rendering
- ✅ Basic frame refresh loop
- ✅ Mouse capture support (with evdev fallback)

### Input Handling

- ✅ evdev fallback for KMSDRM (when SDL capture unavailable)
- ✅ Keyboard input via SDL
- ✅ Mouse motion events

---

## Gap Analysis: Known Deficiencies

### Display Pipeline Issues

#### Gap 1: Low Bit Depth Pixel Expansion

**Location**: [video_sdl2.cpp](BasiliskII/src/SDL/video_sdl2.cpp#L927-L967), [video_blit.cpp](BasiliskII/src/CrossPlatform/video_blit.cpp)

**Problem**: 1/2/4-bit Mac depths expand to 8-bit SDL surfaces, then blit to 32-bit textures. The expansion and palette application path may have endianness issues.

**Code path**:

```
Mac framebuffer (1/2/4/8-bit) → guest_surface (8-bit paletted)
    → SDL_BlitSurface → host_surface (32-bit BGRA)
    → SDL_UpdateTexture → GPU texture
```

**Investigation needed**:

- Verify `Blit_Expand_*_To_8()` functions handle ARM little-endian correctly
- Check palette application in `update_palette()`
- Confirm SDL_BlitSurface color conversion is correct

#### Gap 2: 16-bit Color Pixel Format

**Location**: [video_sdl2.cpp#L944-L946](BasiliskII/src/SDL/video_sdl2.cpp#L944-L946)

**Problem**: Mac 16-bit is RGB555 big-endian, SDL surface is RGB565. The `Screen_blit` function selection may be incorrect.

**Current code**:

```cpp
case VIDEO_DEPTH_16BIT:
    guest_surface = SDL_CreateRGBSurface(0, width, height, 16, 0xf800, 0x07e0, 0x001f, 0);
```

**Issue**: Creates RGB565, but Mac uses RGB555. The blitter `Blit_RGB565_NBO` is selected, but source data is RGB555.

#### Gap 3: VOSF Disabled on ARM

**Location**: [configure.ac#L1503](BasiliskII/src/Unix/configure.ac#L1503)

**Problem**: VOSF (Video On SEGV Fault) is disabled for ARM, meaning the fallback `update_display_static` path is used. This path has different behavior than VOSF.

**Implication**: Cannot use dirty-page tracking; must compare entire framebuffer each frame.

#### Gap 4: Direct Addressing without VOSF

**Location**: [configure.ac#L1505](BasiliskII/src/Unix/configure.ac#L1505)

**Problem**: Direct addressing is required for JIT, but normally requires VOSF. ARM is special-cased to allow direct addressing without VOSF, but this may affect video buffer handling.

---

## Actionable Issues

### High Priority

1. **[BUG]** Add diagnostic mode to dump pixel data before/after Screen_blit

   - Location: `update_display_static_bbox()` in video_sdl2.cpp
   - Action: Add `B2_DUMP_PIXELS` env var to write raw bytes to file for analysis

2. **[BUG]** Verify 16-bit format conversion

   - Location: video_blit.cpp `Screen_blitter_init()`
   - Action: Check if RGB555→RGB565 conversion is being applied correctly
   - Test: Force `Blit_RGB555_NBO` and compare output

3. **[BUG]** Test with raw memcpy for low bit depths

   - Location: video_sdl2.cpp `update_display_static()`
   - Action: Bypass Screen_blit and use direct memcpy to isolate issue
   - Existing debug: `B2_RAW_16BIT` env var exists for 16-bit

4. **[BUG]** Verify palette application path
   - Location: video_sdl2.cpp `update_palette()`
   - Action: Log palette entries and verify SDL palette is set correctly

### Medium Priority

5. **[FEATURE]** Add comprehensive video debug logging

   - Existing: `B2_DEBUG_VIDEO` env var
   - Action: Extend to log pixel format at each stage of pipeline

6. **[INVESTIGATE]** Compare master branch video path

   - The master branch uses the same video_sdl2.cpp but without ARM JIT
   - Test if corruption occurs with `--disable-jit-compiler`

7. **[INVESTIGATE]** Test with software renderer

   - Bypass OpenGL ES entirely
   - Use `SDL_HINT_RENDER_DRIVER=software`

8. **[REFACTOR]** Consider reverting SDL_LockTexture change
   - Recent commit 3b448b3c changed from `SDL_LockTexture` to `SDL_UpdateTexture`
   - May have introduced format assumptions

### Low Priority

9. **[CLEANUP]** Remove dead debug code from present_sdl_video()

   - Commit 3b448b3c removed some debug logging
   - Some g\_\* debug variables remain unused

10. **[DOCS]** Document build requirements and test procedure
    - Target hardware: Raspberry Pi 3B, 1GB RAM, 640x480 display
    - ROM: Quadra 800 (Model ID 35, ROM_VERSION_32)

---

## Debug Environment Variables

| Variable         | Purpose                            |
| ---------------- | ---------------------------------- |
| `B2_DEBUG_VIDEO` | Enable video pipeline logging      |
| `B2_DEBUG_INPUT` | Enable evdev input logging         |
| `B2_RAW_16BIT`   | Bypass Screen_blit for 16-bit mode |
| `B2_EVDEV_MOUSE` | Override evdev mouse device path   |

---

## Build Configuration

Current ARM32 JIT build flags:

```
--enable-sdl-video --enable-sdl-audio --enable-jit-compiler
--enable-addressing=direct --enable-fpe=ieee --disable-vosf
--disable-gtk --without-mon --without-x --without-esd
--disable-nls --with-sdl2
```

---

## Historical Notes

### Old Manual Build (Pre-ARM JIT)

The original build used a vendored SDL2 with specific configuration:

```bash
wget https://www.libsdl.org/release/SDL2-2.32.8.tar.gz
tar -zxvf SDL2-2.32.8.tar.gz
cd SDL2-2.32.8 && ./configure --disable-video-opengl --disable-video-x11 \
    --disable-pulseaudio --disable-esd --disable-video-wayland && make -j4

cd macemu/BasiliskII/src/Unix && NO_CONFIGURE=1 ./autogen.sh && \
./configure --enable-sdl-audio --enable-sdl-framework --enable-sdl-video \
    --disable-vosf --without-mon --without-esd --without-gtk \
    --disable-jit-compiler --disable-nls
```

Note: This old build **disabled JIT** and used a custom SDL2 without OpenGL.

---

## Future Work: FPU JIT

The current ARM JIT only accelerates integer 68k operations. Floating-point instructions (FADD, FMUL, FDIV, FSQRT, etc.) fall back to the interpreted IEEE FPU emulator (`fpu/fpu_ieee.cpp`).

### Why No ARM FPU JIT?

The ARAnyM project (source of this JIT) only implemented FPU JIT for x86/x86-64 using x87 stack-based instructions. The ARM architecture requires a completely different approach:

| Aspect | x86 FPU JIT | ARM FPU JIT (needed) |
|--------|-------------|----------------------|
| **Register model** | x87 stack (ST0-ST7) | VFP/NEON registers (D0-D31) |
| **Precision** | 80-bit extended | 64-bit double max |
| **Rounding modes** | x87 control word | FPSCR register |
| **Code generator** | `compemu_fpp.cpp` exists | Would need new `codegen_arm_fpu.cpp` |

### Implementation Notes

A future FPU JIT for ARM would require:

1. **New codegen file** (`codegen_arm_fpu.cpp`) with VFP/NEON instruction emission
2. **Register allocator extension** to manage D0-D31 float registers
3. **68881/68882 semantics mapping** to VFP operations
4. **Precision handling** — 68k uses 80-bit extended; ARM VFP is 64-bit double
5. **Exception flag mapping** between 68k and ARM FPSCR

### Performance Impact

For Mac applications with heavy FPU use (CAD, spreadsheets, QuickDraw GX), the interpreted FPU is a bottleneck. JIT-compiled integer code runs at near-native speed, but FPU operations remain ~10-50× slower.

**Priority**: Medium-Low (most classic Mac apps are integer-heavy)

---

## Related Branches

- `master`: UAE CPU interpreter (stable, no JIT on ARM)
- `feature/unicorn-cpu`: Unicorn Engine backend (QEMU TCG JIT)
- `feature/arm-jit`: ARM32 JIT (current focus) ← **this branch**
