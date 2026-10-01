/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_EBPFOS_FOPS_ROUTE_H
#define _UAPI_LINUX_EBPFOS_FOPS_ROUTE_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct ebpfos_fops_route_request {
	__s32 fd;
	__u32 flags;
	__u64 handle;
	__u64 role;
	__u64 linux_entries;
};

#define EBPFOS_FOPS_ROUTE_IOC_ATTACH \
	_IOW('E', 0x70, struct ebpfos_fops_route_request)
#define EBPFOS_FOPS_ROUTE_IOC_QUIESCE \
	_IOW('E', 0x71, struct ebpfos_fops_route_request)
#define EBPFOS_FOPS_ROUTE_IOC_SWITCH \
	_IOW('E', 0x72, struct ebpfos_fops_route_request)
#define EBPFOS_FOPS_ROUTE_IOC_RESUME \
	_IOW('E', 0x73, struct ebpfos_fops_route_request)
#define EBPFOS_FOPS_ROUTE_IOC_STATS \
	_IOWR('E', 0x74, struct ebpfos_fops_route_request)
#define EBPFOS_FOPS_ROUTE_IOC_DETACH \
	_IOW('E', 0x75, struct ebpfos_fops_route_request)

#define EBPFOS_FOPS_ROUTE_F_COMPONENT 1U
#define EBPFOS_FOPS_ROUTE_F_EXTENDED 2U
#define EBPFOS_FOPS_ROUTE_F_WAIT_BRIDGE 4U

#endif
