/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_EBPFOS_BOPS_ROUTE_H
#define _UAPI_LINUX_EBPFOS_BOPS_ROUTE_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct ebpfos_bops_route_request {
	__s32 fd;
	__u32 flags;
	__u64 handle;
	__u64 role;
	__u64 linux_entries;
};

#define EBPFOS_BOPS_ROUTE_IOC_ATTACH _IOW('E', 0x76, struct ebpfos_bops_route_request)
#define EBPFOS_BOPS_ROUTE_IOC_QUIESCE _IOW('E', 0x77, struct ebpfos_bops_route_request)
#define EBPFOS_BOPS_ROUTE_IOC_SWITCH _IOW('E', 0x78, struct ebpfos_bops_route_request)
#define EBPFOS_BOPS_ROUTE_IOC_RESUME _IOW('E', 0x79, struct ebpfos_bops_route_request)
#define EBPFOS_BOPS_ROUTE_IOC_STATS _IOWR('E', 0x7a, struct ebpfos_bops_route_request)
#define EBPFOS_BOPS_ROUTE_IOC_DETACH _IOW('E', 0x7b, struct ebpfos_bops_route_request)
#define EBPFOS_BOPS_ROUTE_F_COMPONENT 1U

#endif
