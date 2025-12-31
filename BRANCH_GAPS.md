# Unicorn CPU Backend - Fit/Gap Analysis

This document compares the Unicorn CPU backend (`feature/unicorn-cpu`) against the UAE non-JIT interpreter for emulation correctness. Items are prioritized by impact on boot and runtime behavior.

---

## 🔴 Critical Gaps (Blocking or High Risk)

### 1. ROM Base Address Mismatch
| | UAE (Reference) | Unicorn (Current) |
|-|-----------------|-------------------|
| **ROM Base** | `0x40800000` (fixed for ROM_VERSION_32) | Dynamically placed after RAM |

**Impact**: ROM code may use absolute addresses; mismatch could cause crashes or incorrect memory access.

**Action**: Modify `Init680x0()` in `unicorn_glue.cpp` to use fixed ROM addresses matching UAE's `basilisk_glue.cpp` logic per ROM version.

**Files**: `unicorn_glue.cpp` lines 440-460, reference `uae_cpu/basilisk_glue.cpp` lines 78-95

---

### 2. VBR (Vector Base Register) Not Tracked
| | UAE | Unicorn |
|-|-----|---------|
| **VBR** | Dynamically tracked via `regs.vbr` | Static `vbr = 0` |

**Impact**: Any ROM or system software that relocates the exception vector table will fail.

**Action**: Read VBR from Unicorn's M68K state (`UC_M68K_REG_VBR` if available) in `take_exception()` and `deliver_interrupt()`.

**Files**: `unicorn_glue.cpp` - `take_exception()`, check Unicorn M68K register list

---

### 3. Dynamic Dummy Memory Mapping
| | UAE | Unicorn |
|-|-----|---------|
| **Unmapped Access** | `dummy_bank` returns 0, no new mappings | `hook_mem_invalid` maps 64KB regions on-demand |

**Impact**: Creates up to 16MB of spurious mappings. Masks real bugs, wastes memory, may cause address aliasing issues.

**Action**: 
1. Audit which addresses trigger dummy mappings during boot
2. Pre-map required regions (like UAE does) based on findings
3. Remove or limit dynamic mapping to fail-safe only

**Files**: `unicorn_glue.cpp` - `hook_mem_invalid()`, compare with `uae_cpu/memory.cpp` - `memory_init()`

---

### 4. Extreme Performance Degradation
| | UAE Non-JIT | Unicorn (Current) |
|-|-------------|-------------------|
| **Speed** | Usable on Pi 3B | Extremely slow, nearly unusable, never boots to a working display |
| **Cause** | Interpreted but optimized | Likely hook overhead or JIT not engaging |

**Impact**: Emulation is too slow for practical use. Defeats the purpose of using Unicorn's TCG JIT.

**Action**:
1. Fix ROM base and VBR issues first
2. Reduce hook frequency - current `hook_mem_invalid` may be firing excessively
3. Check if chunked execution (`CHUNK_SIZE = 100000`) is appropriate or causing JIT thrashing
4. Compare instruction throughput with UAE interpreter as baseline

**Diagnostic steps**:
```c
// Add to Start680x0() after main loop:
printf("Chunks: %llu, Exceptions: %llu, Ratio: %.2f\n", 
       total_chunks, total_exceptions, 
       (double)total_exceptions / total_chunks);
```
High exception/chunk ratio indicates excessive trapping killing performance.

**Files**: `unicorn_glue.cpp` - `Start680x0()`, `hook_mem_invalid()`, `hook_intr()`

---

## 🟡 Medium Gaps (Functional but Incorrect)

### 4. FPU Integration Incomplete
| | UAE | Unicorn |
|-|-----|---------|
| **FPU Type** | Respects `FPUType` preference, full 68881/68882 | M68040 model has FPU, but preference ignored |
| **F-line traps** | Full FPU instruction decode | Basic exception forwarding |

**Impact**: FPU-heavy software may behave differently; `FPUType=0` (no FPU) not honored.

**Action**:
1. Check if Unicorn M68040 FPU can be disabled
2. Ensure D2 register FPU flag at boot matches `FPUType` setting
3. Test with FPU-dependent software

**Files**: `unicorn_glue.cpp` - `Init680x0()`, `Start680x0()` register setup

---

### 5. MOVEM Instruction Workaround
| | UAE | Unicorn |
|-|-----|---------|
| **MOVEM** | Native support | Requires `hook_code` workaround |

**Impact**: Performance penalty; potential edge cases in register save/restore.

**Action**: 
1. Verify Unicorn version - newer versions may have fixed this
2. If still needed, audit workaround for correctness with all addressing modes
3. Consider upgrading Unicorn library

**Files**: `unicorn_glue.cpp` - check for MOVEM handling code

---

### 6. Bus/Address Error Handling
| | UAE | Unicorn |
|-|-----|---------|
| **Bus Error** | SIGSEGV → proper 68k exception frame | `hook_mem_invalid` → dummy mapping or stop |
| **Address Error** | SIGSEGV → proper 68k exception frame | Same as above |

**Impact**: Software that intentionally triggers bus errors (memory sizing, etc.) won't work correctly.

**Action**: Instead of mapping dummy memory, push proper 68k exception frame and vector to handler.

**Files**: `unicorn_glue.cpp` - `hook_mem_invalid()`, `take_exception()`

---

## 🟢 Verified Working

| Feature | Notes |
|---------|-------|
| RAM mapping at 0x0 | ✅ Both use DIRECT_ADDRESSING |
| Frame buffer at 0xa0000000 | ✅ Matches UAE |
| EMUL_OP (0x71xx) traps | ✅ Illegal instruction hook working |
| A-line trap dispatch | ✅ ROM vector table used |
| 60Hz timer interrupt | ✅ Autovector delivery working |
| Boot entry point | ✅ `ROMBaseMac + 0x2a` |
| Low memory globals | ✅ Mapped within RAM region |
| ReadMacInt/WriteMacInt | ✅ Byte-swap correct |

---

## ❓ Untested / Unknown

| Feature | Risk | Notes |
|---------|------|-------|
| 24-bit addressing mode | Medium | Older ROMs (Plus, SE, Classic) not tested |
| Multiple ROM versions | Medium | Only Quadra 800 ROM tested |
| NMI (level 7 interrupt) | Low | `TriggerNMI()` implemented but untested |

---

## Testing Checklist

For Quadra 800 ROM (Model ID 35, `ROM_VERSION_32`):

- [ ] Boot to "Welcome to Macintosh"
- [ ] Boot completes to Finder
- [ ] Mouse/keyboard input works
- [ ] Disk image mounts correctly  
- [ ] Application launches (e.g., SimpleText)
- [ ] FPU test application runs correctly
- [ ] Clean shutdown via Special → Shut Down

---

## Reference: Memory Layout

```
UAE Non-JIT (ROM_VERSION_32):
0x00000000 - RAM (up to RAMSize)
0x40800000 - ROM (1MB)
0xa0000000 - Frame buffer

Unicorn (current, needs fixing):
0x00000000 - RAM
RAMSize    - ROM (should be 0x40800000)
0x50F00000 - Dummy I/O (128KB)
0xa0000000 - Frame buffer  
0xFFC00000 - High memory for stack probing (4MB)
```
