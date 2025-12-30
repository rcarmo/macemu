# Unicorn CPU Backend for BasiliskII

This directory contains a prototype CPU backend for BasiliskII using the
[Unicorn Engine](https://www.unicorn-engine.org/), a lightweight multi-platform,
multi-architecture CPU emulator framework based on QEMU's TCG (Tiny Code Generator).

## Why Unicorn?

The existing BasiliskII CPU backends have limitations:
- **uae_cpu**: Interpreted, slow on all platforms
- **uae_cpu_2021 with JIT**: Fast, but JIT only available for x86/x64 and ARM32

Unicorn provides:
- JIT-accelerated emulation on **all** supported host architectures
- Native support for x86, x64, ARM, ARM64, MIPS, and more
- No need to maintain separate JIT backends per architecture
- Well-tested QEMU TCG codebase

## Status

**PROTOTYPE** - This is an experimental implementation.

### Implemented
- Basic CPU initialization (Init680x0/Exit680x0)
- Memory mapping (RAM, ROM, frame buffer)
- EMUL_OP trap handling for BasiliskII patches
- Execute68k/Execute68kTrap for nested calls
- Basic interrupt support structure

### TODO
- A-line trap handling (Mac OS toolbox calls)
- F-line trap handling (FPU instructions)
- Full interrupt injection
- FPU emulation integration
- Performance optimization
- Testing with actual Mac OS ROMs

## Building

### Prerequisites

Install Unicorn Engine:

```bash
# macOS
brew install unicorn

# Debian/Ubuntu
sudo apt install libunicorn-dev

# From source
git clone https://github.com/unicorn-engine/unicorn.git
cd unicorn
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

### Compile BasiliskII with Unicorn

```bash
cd BasiliskII/src/Unix
./autogen.sh
./configure --enable-unicorn-cpu
make
```

## Architecture

```
+------------------+
|   BasiliskII     |
|   (main_unix)    |
+--------+---------+
         |
         v
+------------------+
| cpu_emulation.h  |  <- Standard BasiliskII CPU interface
+--------+---------+
         |
         v
+------------------+
| unicorn_glue.cpp |  <- Unicorn integration layer
+--------+---------+
         |
         v
+------------------+
|  Unicorn Engine  |  <- QEMU TCG based JIT
+------------------+
         |
         v
+------------------+
|  Host CPU (ARM64,|
|  x86_64, etc.)   |
+------------------+
```

## How It Works

1. **Memory Mapping**: RAM and ROM are mapped directly into Unicorn's address space
   using `uc_mem_map_ptr()`, allowing zero-copy access.

2. **EMUL_OP Detection**: A code hook monitors executed instructions looking for
   the special 0x71XX opcodes that BasiliskII uses for emulation callbacks.

3. **Trap Handling**: A-line traps (0xAXXX) trigger Mac OS toolbox calls, handled
   via Unicorn's interrupt hook mechanism.

4. **Execute68k**: Nested 68k code execution (used by EMUL_OP handlers) pushes a
   special return address on the stack and runs until that address is reached.

## Performance Considerations

Unicorn's TCG JIT should provide performance between:
- Faster than UAE interpreter (5-10x typical)
- Slower than hand-tuned native JIT (UAE's x86 JIT is ~2x faster)
- Comparable to other TCG-based emulators

The main advantage is **portability** - the same code works on ARM64, RISC-V,
and any other platform Unicorn supports.

## References

- [Unicorn Engine Documentation](https://www.unicorn-engine.org/docs/)
- [Unicorn API Reference](https://www.unicorn-engine.org/docs/api.html)
- [QEMU TCG](https://wiki.qemu.org/Documentation/TCG)
- [BasiliskII](https://basilisk.cebix.net/)
