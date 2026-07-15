#ifndef ARM64_BRANCH_PATCH_H
#define ARM64_BRANCH_PATCH_H

#include <stdint.h>

enum arm64_branch_patch_status {
	ARM64_BRANCH_PATCH_OK = 0,
	ARM64_BRANCH_PATCH_UNALIGNED,
	ARM64_BRANCH_PATCH_B_RANGE,
	ARM64_BRANCH_PATCH_TB_RANGE,
	ARM64_BRANCH_PATCH_CB_RANGE,
	ARM64_BRANCH_PATCH_BCOND_RANGE,
	ARM64_BRANCH_PATCH_UNSUPPORTED,
};

/* Pure instruction patching contract shared by the runtime write boundary and
   the direct conformance probe. byte_offset is relative to the instruction
   address; patched is written only on success. */
static inline arm64_branch_patch_status arm64_patch_branch_instruction(
	uint32_t instruction, int64_t byte_offset, uint32_t *patched)
{
	if (byte_offset % 4 != 0)
		return ARM64_BRANCH_PATCH_UNALIGNED;
	const int64_t off = byte_offset / 4;

	if ((instruction & 0xfc000000) == 0x14000000) {
		if (off > 0x1ffffff || off < -0x2000000)
			return ARM64_BRANCH_PATCH_B_RANGE;
		*patched = (instruction & 0xfc000000) | ((uint32_t)off & 0x03ffffff);
	} else if ((instruction & 0x7e000000) == 0x36000000) {
		if (off > 0x1fff || off < -0x2000)
			return ARM64_BRANCH_PATCH_TB_RANGE;
		*patched = (instruction & 0xfff8001f) | (((uint32_t)off & 0x3fff) << 5);
	} else if ((instruction & 0x7e000000) == 0x34000000) {
		if (off > 0x3ffff || off < -0x40000)
			return ARM64_BRANCH_PATCH_CB_RANGE;
		*patched = (instruction & 0xff00001f) | (((uint32_t)off & 0x7ffff) << 5);
	} else if ((instruction & 0xff000010) == 0x54000000) {
		if (off > 0x3ffff || off < -0x40000)
			return ARM64_BRANCH_PATCH_BCOND_RANGE;
		*patched = (instruction & 0xff00001f) | (((uint32_t)off & 0x7ffff) << 5);
	} else {
		return ARM64_BRANCH_PATCH_UNSUPPORTED;
	}
	return ARM64_BRANCH_PATCH_OK;
}

#endif
