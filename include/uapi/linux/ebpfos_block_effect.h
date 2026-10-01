/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_EBPFOS_BLOCK_EFFECT_H
#define _UAPI_LINUX_EBPFOS_BLOCK_EFFECT_H

#include <linux/types.h>

struct ebpfos_block_segment {
	__u64 byte_offset;
	__u32 bytes;
	__u32 opf;
};

#endif
