/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_RESTRICTED_WORK_H
#define _LINUX_EBPFOS_RESTRICTED_WORK_H

#include <linux/workqueue.h>

typedef void (*ebpfos_work_native_t)(void *queue);

void ebpfos_restricted_work_register(void *queue, void *owner);
void ebpfos_restricted_work_unregister(void *owner);
void ebpfos_restricted_work(void *queue, ebpfos_work_native_t native,
			   struct work_struct *work);
#endif
