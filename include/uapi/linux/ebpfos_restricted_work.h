/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_EBPFOS_RESTRICTED_WORK_H
#define _UAPI_LINUX_EBPFOS_RESTRICTED_WORK_H
#include <linux/ioctl.h>
#include <linux/types.h>

struct ebpfos_restricted_work_request {
	__u64 id;
	__s32 prog_fd;
	__u32 active;
	__u64 native_entries;
	__u64 component_entries;
	__u64 hardirq_entries;
	__u64 faults;
};

#define EBPFOS_RESTRICTED_WORK_NEXT _IOWR('E', 0xd0, struct ebpfos_restricted_work_request)
#define EBPFOS_RESTRICTED_WORK_ATTACH _IOW('E', 0xd1, struct ebpfos_restricted_work_request)
#define EBPFOS_RESTRICTED_WORK_SWITCH _IOW('E', 0xd2, struct ebpfos_restricted_work_request)
#define EBPFOS_RESTRICTED_WORK_STATS _IOWR('E', 0xd3, struct ebpfos_restricted_work_request)
#define EBPFOS_RESTRICTED_WORK_DETACH _IOW('E', 0xd4, struct ebpfos_restricted_work_request)
#endif
