/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_RESTRICTED_WORK_H
#define _LINUX_EBPFOS_RESTRICTED_WORK_H

#include <linux/workqueue.h>

struct device;
typedef struct spinlock spinlock_t;

typedef void (*ebpfos_work_native_t)(void *queue);

void ebpfos_restricted_work_register(void *queue, void *owner);
void ebpfos_restricted_work_unregister(void *owner);
void ebpfos_restricted_work(void *queue, ebpfos_work_native_t native,
			   struct work_struct *work,
			   struct workqueue_struct *workqueue, u64 scalar);
void ebpfos_restricted_pm_work(void *queue, ebpfos_work_native_t native,
		spinlock_t *stop_lock, bool *stop, spinlock_t *wakeup_lock,
		u32 *wakeup_mask, bool *processing, struct device *device,
		struct work_struct *work, struct workqueue_struct *workqueue,
		u32 mask_bit);
#endif
