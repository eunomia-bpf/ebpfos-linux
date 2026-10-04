// SPDX-License-Identifier: GPL-2.0-only
/* Non-sleepable dispatch through the per-handle executor-root bundle. */
#include <linux/bpf.h>
#include <linux/ebpfos.h>
#include <linux/ebpfos_irq_route.h>
#include <linux/errno.h>
#include <linux/filter.h>
#include <linux/module.h>
#include "irq_route_dispatch.h"

int ebpfos_irq_route_call_slot(struct ebpfos_executor_root_slot *slot, u64 role,
	const struct ebpfos_component_irq_frame *frame,
	u64 *epoch, u32 *provider_id, u32 *status)
{
	return ebpfos_irq_route_call_slot_inner(slot, role, frame, epoch,
					      provider_id, status);
}
EXPORT_SYMBOL_GPL(ebpfos_irq_route_call_slot);

int ebpfos_irq_route_call(u64 handle, u64 role,
	const struct ebpfos_component_irq_frame *frame,
	u64 *epoch, u32 *provider_id, u32 *status)
{
	if (!handle)
		return -EINVAL;
	return ebpfos_irq_route_call_slot(ebpfos_executor_root_lookup(handle),
		role, frame, epoch, provider_id, status);
}
EXPORT_SYMBOL_GPL(ebpfos_irq_route_call);
