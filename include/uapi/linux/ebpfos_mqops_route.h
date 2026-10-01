/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_EBPFOS_MQOPS_ROUTE_H
#define _UAPI_LINUX_EBPFOS_MQOPS_ROUTE_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct ebpfos_mqops_route_request {
	__s32 fd;
	__u32 flags;
	__u64 handle;
	__u64 role;
	__u64 linux_entries;
	__u64 component_entries;
	__u64 faults;
};

#define EBPFOS_MQOPS_ROUTE_IOC_ATTACH _IOW('E', 0x86, struct ebpfos_mqops_route_request)
#define EBPFOS_MQOPS_ROUTE_IOC_QUIESCE _IOW('E', 0x87, struct ebpfos_mqops_route_request)
#define EBPFOS_MQOPS_ROUTE_IOC_SWITCH _IOW('E', 0x88, struct ebpfos_mqops_route_request)
#define EBPFOS_MQOPS_ROUTE_IOC_RESUME _IOW('E', 0x89, struct ebpfos_mqops_route_request)
#define EBPFOS_MQOPS_ROUTE_IOC_STATS _IOWR('E', 0x8a, struct ebpfos_mqops_route_request)
#define EBPFOS_MQOPS_ROUTE_IOC_DETACH _IOW('E', 0x8b, struct ebpfos_mqops_route_request)
#define EBPFOS_MQOPS_ROUTE_F_COMPONENT 1U

#endif
