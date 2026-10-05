/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_ENTRY_H
#define _LINUX_EBPFOS_ENTRY_H

#include <linux/types.h>

struct ebpfos_executor_root_slot;

/*
 * C entry to a published, non-sleepable component. The context layout is the
 * one checked by the stock verifier for the loaded program. Native-signature
 * lowering belongs to the compiler; this API does not reinterpret arguments,
 * marshal objects, or manufacture pointer authority.
 *
 * Cache the stable slot, never its program address. Each call observes one
 * complete published epoch and holds it through return. On a closed gate or
 * missing role no program executes: the caller can take its native fallback.
 * A successful call returns zero, separately from the program's u32 result.
 */
int ebpfos_component_call_slot(struct ebpfos_executor_root_slot *slot, u64 role,
			       const void *context, u32 *result);

/*
 * A running component already holds its root's RCU epoch across imports. A
 * typed native import bridge may borrow that hold; it must last through this
 * call's return. Gate checks, rebinding and exact invocation accounting are
 * unchanged. The stock program callbacks still own their execution context.
 */
int ebpfos_component_call_slot_rcu(struct ebpfos_executor_root_slot *slot, u64 role,
				   const void *context, u32 *result);

#endif
