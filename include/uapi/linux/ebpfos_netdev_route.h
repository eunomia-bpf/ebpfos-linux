/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_EBPFOS_NETDEV_ROUTE_H
#define _UAPI_LINUX_EBPFOS_NETDEV_ROUTE_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct ebpfos_netdev_route_request {
	__s32 ifindex;
	__u32 flags;
	__u64 handle;
	__u64 role;
	__u64 linux_entries;
	__u64 component_entries;
	__u64 faults;
	__u64 method_entries[7]; /* 1..6 correspond to generated method IDs. */
};

#define EBPFOS_NETDEV_ROUTE_IOC_ATTACH _IOW('E', 0x80, struct ebpfos_netdev_route_request)
#define EBPFOS_NETDEV_ROUTE_IOC_QUIESCE _IOW('E', 0x81, struct ebpfos_netdev_route_request)
#define EBPFOS_NETDEV_ROUTE_IOC_SWITCH _IOW('E', 0x82, struct ebpfos_netdev_route_request)
#define EBPFOS_NETDEV_ROUTE_IOC_RESUME _IOW('E', 0x83, struct ebpfos_netdev_route_request)
#define EBPFOS_NETDEV_ROUTE_IOC_STATS _IOWR('E', 0x84, struct ebpfos_netdev_route_request)
#define EBPFOS_NETDEV_ROUTE_IOC_DETACH _IOW('E', 0x85, struct ebpfos_netdev_route_request)
#define EBPFOS_NETDEV_ROUTE_F_COMPONENT 1U

#endif
