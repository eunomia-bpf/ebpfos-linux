/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_H
#define _LINUX_EBPFOS_H

#include <linux/bits.h>
#include <linux/types.h>

#define EBPFOS_COMPONENT_CALL_ABI_ID 0x454243414c4c0001ULL
#define EBPFOS_COMPONENT_CALL_ABI_VERSION 1U
#define EBPFOS_COMPONENT_CALL_INPUT_SIZE 128U
#define EBPFOS_COMPONENT_CALL_OUTPUT_SIZE 128U
#define EBPFOS_CAP_KPROG_TERMINAL_ROOT BIT_ULL(4)
#define EBPFOS_EFFECT_KPROG_TERMINAL_WAIT BIT_ULL(7)

struct ebpfos_component_call_frame {
	u32 version;
	u32 flags;
	u64 method_id;
	u64 object_id;
	u64 epoch;
	u32 input_size;
	u32 output_capacity;
	u8 input[EBPFOS_COMPONENT_CALL_INPUT_SIZE];
	s32 status;
	u32 output_size;
	u8 output[EBPFOS_COMPONENT_CALL_OUTPUT_SIZE];
};

#define EBPFOS_COMPONENT_CALL_CONTEXT_SIZE \
	((u32)sizeof(struct ebpfos_component_call_frame))


#endif /* _LINUX_EBPFOS_H */
