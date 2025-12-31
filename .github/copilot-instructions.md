This project is a port of the BasiliskII Mac emulator to the Raspberry Pi, targeting OpenGL ES 2 on KMSDRM SDL with JIT support for ARM 32 or 64 (depending on branch).

## Branches

- **master**: Stable branch with UAE CPU (interpreted, JIT on x86 only)
- **feature/unicorn-cpu**: Unicorn Engine backend (QEMU TCG JIT)
- **feature/arm-jit**: ARM32 JIT implementation (standalone) - **current focus**


## Build & Deploy

All builds **MUST** go through GitHub Actions for ARM cross-compilation and deployment to real Raspberry Pi hardware. Do not assume local builds work on target.

### Build Requirements

- GitHub Actions workflow for ARM64/ARMhf cross-compilation
- SDL2 with KMSDRM backend (not X11)
- OpenGL ES 2.0 renderer

## Testing Configuration

Testing uses a **Quadra 800 ROM** (Model ID 35):
- ROM version: `ROM_VERSION_32` (0x067c) - 32-bit clean, 1MB
- This is the most complex ROM type supported by BasiliskII

The testing hardware is a Raspberry Pi 3B with 1GB RAM, running Raspberry Pi OS (64-bit) based on Debian 12 Bookworm with KMSDRM and OpenGL ES 2.0 support and a Waveshare LCD (640x480). The target has multi-arch (ARM32/ARM64) support and `armhf` builds run directly on the OS.

## Key Technical Notes

- **Endianness**: Mac is big-endian; `ReadMacInt*`/`WriteMacInt*` handle byte swapping
- **Detailed fit/gap analysis**: See `BRANCH_GAPS.md`