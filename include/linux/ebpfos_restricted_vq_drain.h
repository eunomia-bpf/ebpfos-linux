/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_RESTRICTED_VQ_DRAIN_H
#define _LINUX_EBPFOS_RESTRICTED_VQ_DRAIN_H

#include <linux/types.h>

struct virtqueue;
struct spinlock;
typedef struct spinlock spinlock_t;

void ebpfos_restricted_vq_drain_register(struct virtqueue *vq,
		spinlock_t *lock, void *owner, unsigned int completion_offset);
void ebpfos_restricted_vq_drain_unregister(void *owner);
void ebpfos_restricted_vq_drain(struct virtqueue *vq,
		void (*native)(struct virtqueue *vq));
#endif
