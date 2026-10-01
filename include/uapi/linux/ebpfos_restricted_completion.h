/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_EBPFOS_RESTRICTED_COMPLETION_H
#define _UAPI_LINUX_EBPFOS_RESTRICTED_COMPLETION_H
#include <linux/ioctl.h>
#include <linux/types.h>

struct ebpfos_restricted_completion_request {
	__u64 id;
	__s32 prog_fd;
	__u32 active;
	__u64 native_entries;
	__u64 component_entries;
	__u64 hardirq_entries;
	__u64 faults;
};

#define EBPFOS_RESTRICTED_COMPLETION_NEXT _IOWR('E', 0xc0, struct ebpfos_restricted_completion_request)
#define EBPFOS_RESTRICTED_COMPLETION_ATTACH _IOW('E', 0xc1, struct ebpfos_restricted_completion_request)
#define EBPFOS_RESTRICTED_COMPLETION_SWITCH _IOW('E', 0xc2, struct ebpfos_restricted_completion_request)
#define EBPFOS_RESTRICTED_COMPLETION_STATS _IOWR('E', 0xc3, struct ebpfos_restricted_completion_request)
#define EBPFOS_RESTRICTED_COMPLETION_DETACH _IOW('E', 0xc4, struct ebpfos_restricted_completion_request)
#endif
