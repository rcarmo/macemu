# macemu-jit - ARM64 JITs for Macintosh Emulators

![icon](icon-256.png)

## Raspberry Pi Builds

This fork provides experimental pre-built packages and Docker images optimized for Raspberry Pi, using SDL2 with framebuffer/KMS display (no X11 or desktop environment required). Raspberry Pi packages are built with the available JIT backends enabled.

### Pre-built .deb Packages

Download from [GitHub Releases](https://github.com/rcarmo/macemu/releases) or build from source.

#### Install from release:
```bash
# 68K Macs
wget https://github.com/rcarmo/macemu/releases/latest/download/basiliskii-sdl_<version>_arm64.deb
sudo dpkg -i basiliskii-sdl_<version>_arm64.deb

# PowerPC Macs
wget https://github.com/rcarmo/macemu/releases/latest/download/sheepshaver-sdl_<version>_arm64.deb
sudo dpkg -i sheepshaver-sdl_<version>_arm64.deb
```

#### Build from source on Raspberry Pi:
```bash
# Install dependencies
sudo apt-get install build-essential autoconf automake wget

# Build SDL2 (optimized for Pi, no X11/Wayland)
wget https://www.libsdl.org/release/SDL2-2.32.8.tar.gz
tar -zxvf SDL2-2.32.8.tar.gz
cd SDL2-2.32.8
./configure --disable-video-opengl --disable-video-x11 --disable-pulseaudio --disable-esd --disable-video-wayland
make -j4 && sudo make install
cd ..

# Build BasiliskII
cd macemu/BasiliskII/src/Unix
NO_CONFIGURE=1 ./autogen.sh
ac_cv_have_asm_extended_signals=yes ./configure \
            --enable-sdl-audio --enable-sdl-framework --enable-sdl-video \
            --enable-vosf --enable-addressing=direct \
            --without-mon --without-esd --without-gtk \
            --enable-jit-compiler --enable-aarch64-jit-experimental --disable-nls
CPATH=$CPATH:/usr/local/include/SDL2 make -j4
sudo make install
```

### Docker Containers

Docker images are available for running BasiliskII and SheepShaver in privileged containers with direct hardware access.

#### BasiliskII quick start:
```bash
cd BasiliskII/docker
mkdir -p data
cp /path/to/mac.rom data/rom
cp /path/to/disk.img data/hd.img
cp data/basiliskii_prefs.example data/basiliskii_prefs
# Edit data/basiliskii_prefs as needed

docker compose up -d
```

#### SheepShaver quick start:
```bash
cd SheepShaver/docker
mkdir -p data
cp /path/to/powermac.rom data/rom
cp /path/to/disk.img data/hd.img
cp data/sheepshaver_prefs.example data/sheepshaver_prefs
# Edit data/sheepshaver_prefs as needed

docker compose up -d
```

#### Pull pre-built images:
```bash
docker pull ghcr.io/rcarmo/basiliskii-sdl:latest
docker pull ghcr.io/rcarmo/sheepshaver-sdl:latest
```

The containers require privileged mode for access to:
- `/dev/fb0` - Framebuffer
- `/dev/dri` - KMS/DRM video
- `/dev/input` - Keyboard/mouse
- `/dev/snd` - Audio

See [BasiliskII/docker/README.md](BasiliskII/docker/README.md) and [SheepShaver/docker/README.md](SheepShaver/docker/README.md) for detailed configuration options.

### GitHub Actions CI

This repository includes automated builds:
- **`.github/workflows/build-deb-rpi.yml`** - Builds `basiliskii-sdl` and `sheepshaver-sdl` `.deb` packages for ARM64 and ARMhf
- **`.github/workflows/docker-rpi.yml`** - Builds and pushes BasiliskII and SheepShaver SDL images to GHCR

Packages are automatically uploaded to GitHub Releases when a version tag is pushed.

---

## Supported Platforms

#### BasiliskII
```
macOS     x86_64 JIT / arm64 non-JIT
Linux x86 x86_64 JIT
Linux arm64      JIT (boots Mac OS — see below)
MinGW x86        JIT
```
#### SheepShaver
```
macOS     x86_64 JIT / arm64 non-JIT
Linux x86 x86_64 JIT / arm64 JIT (boots Mac OS)
MinGW x86        JIT
```

---

## How To Build

These builds need SDL2.0.14+ framework/library installed.

https://www.libsdl.org

### BasiliskII

#### macOS
preparation:

Download gmp-6.2.1.tar.xz from https://gmplib.org.
```
$ cd ~/Downloads
$ tar xf gmp-6.2.1.tar.xz
$ cd gmp-6.2.1
$ ./configure --disable-shared
$ make
$ make check
$ sudo make install
```
Download mpfr-4.2.0.tar.xz from https://www.mpfr.org.
```
$ cd ~/Downloads
$ tar xf mpfr-4.2.0.tar.xz
$ cd mpfr-4.2.0
$ ./configure --disable-shared
$ make
$ make check
$ sudo make install
```
On an Intel Mac, the libraries should be cross-built.  
Change the `configure` command for both GMP and MPFR as follows, and ignore the `make check` command:
```
$ CFLAGS="-arch arm64" CXXFLAGS="$CFLAGS" ./configure -host=aarch64-apple-darwin --disable-shared 
```
(from https://github.com/kanjitalk755/macemu/pull/96)

about changing Deployment Target:  
If you build with an older version of Xcode, you can change Deployment Target to the minimum it supports or 10.7, whichever is greater.

build:
```
$ cd macemu/BasiliskII/src/MacOSX
$ xcodebuild build -project BasiliskII.xcodeproj -configuration Release
```
or same as Linux

#### Linux
preparation (arm64 only): Install GMP and MPFR.
```
$ cd macemu/BasiliskII/src/Unix
$ ./autogen.sh
$ make
```

#### Linux AArch64 with JIT (experimental)

This fork includes an experimental AArch64 JIT backend. The JIT translates
68k instructions to native ARM64 code at runtime for significantly faster
emulation.

**Prerequisites:**
```bash
sudo apt install build-essential autoconf automake libsdl2-dev \
  libmpfr-dev libgmp-dev libvncserver-dev libpng-dev
```

**Build:**
```bash
cd macemu/BasiliskII/src/Unix
ac_cv_have_asm_extended_signals=yes ./configure --enable-aarch64-jit-experimental
make -j$(nproc)
```

The build produces `BasiliskII` in `src/Unix/`.

**Key build notes:**
- LTO (`-flto=auto`) is intentionally disabled on AArch64 — it strips JIT
  gate checks that the compiler determines are "dead code" but are actually
  needed at runtime. Non-AArch64 ARM/RPi packaging can still use LTO where the
  backend is not affected by those AArch64 JIT gate checks.
- The default JIT optimization level is L2 (native ARM64 codegen). Set
  `B2_JIT_MAX_OPTLEV=1` to fall back to interpreter-only JIT dispatch.
- Headless ROM proof harnesses intentionally use a small 8MB RAM footprint for
  deterministic stress. Desktop/VNC QA should use 64MB (`ramsize 67108864`) and
  `jitcachesize 131072`; 32768KB runs showed repeated hard translation-cache
  flushes under the full-JIT ROM/headless workload.

**Running:**
```bash
./BasiliskII --config /path/to/prefs
```

**Useful environment variables:**

| Variable | Default | Description |
|---|---|---|
| `B2_JIT_MAX_OPTLEV` | `2` | Max JIT optimization level (0=interpreter, 1=JIT dispatch, 2=native codegen) |
| `B2_JIT_ENABLE_STABLE_DIRECT_EDGES` | `0` | Opt-in profiled ROM-only direct-edge promotion experiment |
| `B2_JIT_STABLE_DIRECT_ROM_ONLY` | `1` on AArch64 | Restrict stable direct-edge promotion to ROM-to-ROM edges |
| `B2_JIT_MANAGED_IRQ` | `0` | Enable managed IRQ delivery model (recommended: `1`) |

**VNC server:**

Add to your prefs file for remote access:
```
vncserver true
vncport 5900
```

#### AArch64 JIT Status

The AArch64 JIT backend is under active development.

**BasiliskII (68K):**
- ✅ Full-JIT optlev=2 is the default ARM64 path after the 2026-06-13 strict preserved-log validation.
- ✅ Strict 300s ROM/steady-state soak reached `DC[64460000] pc=00156f94` with no `JIT_FALLBACK`, `SEGV_SKIP`, `JITBLOCKVERIFY`, `op=8c4c`, or `bad_pcp` markers.
- ✅ Boots to Mac OS Finder desktop at JIT optlev=1 (interpreter dispatch)
- ✅ Boots to Mac OS Finder desktop at JIT optlev=2 (native ARM64 codegen)
- ✅ Speedometer 4.02 Graphics benchmark runs (score: 210.368 vs Mac Classic = 1.0)
- ✅ VNC server with correct coordinate mapping
- ✅ Managed IRQ delivery for stable interrupt handling
- ✅ 301-vector opcode equivalence test suite, score=100
- ✅ Mid-block branch side-exit fix (`daea9c94`) — both branch outcomes previously took side-exit path

**SheepShaver (PPC):**
- ✅ **Mac OS boots to "Welcome to Mac OS" with JIT** (JIT is default; use `SS_USE_JIT=0` to force interpreter mode)
- ✅ **Mac OS boots to desktop** in interpreter mode (VNC on port 5999)
- ✅ **209/209** opcode test vectors pass (score=100)
- ✅ **1800/1825 ROM blocks pass** (98.6%) — headless ROM harness, 10K-block scan
- ✅ **285+ PPC opcodes** inlined as native ARM64 (integer, FPU, AltiVec/NEON, CR, branches)
- ✅ **~737 MIPS** on the tight `addi+bdnz` loop (intra-block CBNZ, Orange Pi 6 Plus)
- ✅ Full FPU: double+single arithmetic, fused multiply-add, FPSCR rounding mode sync
- ✅ VNC keyboard + mouse input for remote control
- ✅ Active JIT phases: hash+chaining block cache, fast dispatch, compile-time chaining, runtime back-patching, PPC64/rld correctness
- ⚠️ Lazy CR0 and register-allocation scaffolding are present but currently disabled pending proof-driven revalidation
- ✅ ROM/opcode audits have fixed critical JIT bugs including `bcl`/`bclrl`, fallback-only terminators, privileged/trap fallback masking, XER struct layout, and AArch64 temp clobbers
- ✅ Signal handler crash dumps fixed (stack overflow + missing arg + register shift)
- ✅ Unix layer hardened: slirp pipe framing, XPRAM I/O, `strdup` null check, 17 bounds fixes
- See [JIT-STATUS.md](JIT-STATUS.md), [BasiliskII/qa/README.md](BasiliskII/qa/README.md),
[qa/README.md](qa/README.md), and [SheepShaver/AARCH64_JIT_PLAN.md](SheepShaver/AARCH64_JIT_PLAN.md) for details

### End-to-end QA and reporting

The repository now has a layered QA scaffold for BasiliskII and SheepShaver:

- BasiliskII matrix and run wrapper: `BasiliskII/qa/`
- Shared emulator-neutral VNC/Gherkin stories: `qa/tests/vnc/`
- Per-emulator VNC profiles: `qa/tests/vnc/profiles/basiliskii.json` and `qa/tests/vnc/profiles/sheepshaver.json`
- Deterministic screenshot checks for CI: PNG dimensions/blank detection, SHA/aHash, optional Tesseract OCR, optional OpenCV template matching
- PDF report generation from run artifacts via `qa/tests/vnc/tools/generate-pdf-report.mjs`

The intended validation ladder is: opcode/vector preflight → ROM smoke → VNC desktop reachability → deterministic screenshot assertions → hardware/network/audio coverage → Markdown/PDF evidence reports. The default VNC driver is still `noop`, so CI can validate story parsing and report generation before a real VNC capture/input backend is wired in.

**Bugs fixed in BasiliskII JIT (this fork):**
1. IRQ deliverability bug — latching pending interrupts while masked
2. `HAVE_GET_WORD_UNSWAPPED` extraction mismatch in compiled handlers
3. Interpreter fallback dispatch byte-order bug (`cpufunctbl` indexing)
4. Flag liveness metadata byte-order bug (`prop[]` indexing)
5. L2 compiled handler dispatch byte-order bug (`comptbl[]` indexing)
6. LTO stripping JIT gate checks
7. VNC mouse coordinate scaling with SDL logical size
8. DBRA multi-iteration loop termination (block tracer following backward branches)
9. DBRA/DBcc CCR leakage through block chaining
10. `flags_to_stack` carry inversion when flags already valid
11. Mid-block branch side-exit: both branch outcomes executed side-exit path, corrupting guest PC
12. Stable ROM JIT edge profiling: ROM blocks bypassed the recompile/profiling countdown

#### MinGW32/MSYS2
preparation:
```
$ pacman -S base-devel mingw-w64-i686-toolchain autoconf automake mingw-w64-i686-SDL2
```
note: MinGW32 dropped GTK2 package.
See msys2/MINGW-packages#24490

build (from a mingw32.exe prompt):
```
$ cd macemu/BasiliskII/src/Windows
$ ../Unix/autogen.sh
$ make
```

### SheepShaver

#### AArch64 (with JIT)
```bash
cd macemu/SheepShaver/src/Unix
./autogen.sh
./configure --enable-sdl-video --enable-sdl-audio --enable-jit
make -j12
# AArch64 builds wire in the PPC JIT automatically when --enable-jit is used.
# Requires: sudo sysctl -w vm.mmap_min_addr=0
```

#### macOS
about changing Deployment Target: see BasiliskII
```
$ cd macemu/SheepShaver/src/MacOSX
$ xcodebuild build -project SheepShaver_Xcode8.xcodeproj -configuration Release
```
or same as Linux

#### Linux
```
$ cd macemu/SheepShaver/src/Unix
$ ./autogen.sh
$ make
```
For Raspberry Pi:
https://github.com/vaccinemedia/macemu

#### MinGW32/MSYS2
preparation: same as BasiliskII  
  
build (from a mingw32.exe prompt):
```
$ cd macemu/SheepShaver
$ make links
$ cd src/Windows
$ ../Unix/autogen.sh
$ make
```

---

## Recommended key bindings for GNOME
https://github.com/kanjitalk755/macemu/blob/master/SheepShaver/doc/Linux/gnome_keybindings.txt

(from https://github.com/kanjitalk755/macemu/issues/59)
