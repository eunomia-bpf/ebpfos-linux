/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _EBPFOS_STEP_SCOPE_H
#define _EBPFOS_STEP_SCOPE_H
#include <linux/types.h>
/* Explicit continuation state owned by one verified component invocation.
	* The component runtime must retain it and re-enter on the same CPU. */
struct ebpfos_step_scope {
	bool valid, pending;
	u32 size;
	u8 state[64];
};
int ebpfos_step_read(const struct ebpfos_step_scope *scope, void *dst, u32 size);
int ebpfos_step_save(struct ebpfos_step_scope *scope, const void *src, u32 size);
#endif
