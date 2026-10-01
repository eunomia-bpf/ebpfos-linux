/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_IRQ_ROUTE_H
#define _LINUX_EBPFOS_IRQ_ROUTE_H

#include <linux/types.h>

struct ebpfos_component_irq_frame;

/* The caller handles -EAGAIN when migration has closed this handle's gate. */
int ebpfos_irq_route_call(u64 handle, u64 role,
	const struct ebpfos_component_irq_frame *frame,
	u64 *epoch, u32 *provider_id, u32 *status);

#endif
