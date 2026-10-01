/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_RESTRICTED_NAPI_H
#define _LINUX_EBPFOS_RESTRICTED_NAPI_H

#include <linux/netdevice.h>
#include <linux/virtio.h>

#define EBPFOS_NAPI_DISABLE_ALWAYS 1U
#define EBPFOS_NAPI_REQUIRE_WEIGHT 2U

void ebpfos_restricted_napi_register(struct virtqueue *queue, void *owner);
void ebpfos_restricted_napi_unregister(void *owner);
void ebpfos_restricted_napi(struct virtqueue *queue,
			    void (*native)(struct virtqueue *),
			    struct napi_struct *napi, u16 *calls,
			    unsigned int flags);
#endif
