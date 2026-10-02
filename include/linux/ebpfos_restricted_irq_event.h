/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_RESTRICTED_IRQ_EVENT_H
#define _LINUX_EBPFOS_RESTRICTED_IRQ_EVENT_H
#include <linux/interrupt.h>
#include <linux/spinlock_types.h>
#include <linux/wait.h>

void ebpfos_restricted_irq_event_register(void *key, void *owner);
void ebpfos_restricted_irq_event_unregister(void *owner);
void ebpfos_restricted_irq_wake(void *data, void *route_key,
		void (*native)(void *), wait_queue_head_t *waitqueue);
irqreturn_t ebpfos_restricted_irq_event(
	int irq, void *data, void *route_key, irq_handler_t native, spinlock_t *lock,
	unsigned long *counter, wait_queue_head_t *waitqueue,
	struct fasync_struct **async, void __iomem *status, u32 mask,
	unsigned int flags, unsigned int shared_mask,
	unsigned int mode_mask, unsigned int mode_value);
#endif
