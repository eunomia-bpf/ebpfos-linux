/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_EBPFOS_RESTRICTED_NAPI_H
#define _UAPI_LINUX_EBPFOS_RESTRICTED_NAPI_H
#include <linux/ioctl.h>
#include <linux/types.h>

struct ebpfos_restricted_napi_request {
	__u64 id;
	__s32 prog_fd;
	__u32 active;
	__u64 native_entries;
	__u64 component_entries;
	__u64 hardirq_entries;
	__u64 faults;
};

#define EBPFOS_RESTRICTED_NAPI_NEXT _IOWR('E', 0xd5, struct ebpfos_restricted_napi_request)
#define EBPFOS_RESTRICTED_NAPI_ATTACH _IOW('E', 0xd6, struct ebpfos_restricted_napi_request)
#define EBPFOS_RESTRICTED_NAPI_SWITCH _IOW('E', 0xd7, struct ebpfos_restricted_napi_request)
#define EBPFOS_RESTRICTED_NAPI_STATS _IOWR('E', 0xd8, struct ebpfos_restricted_napi_request)
#define EBPFOS_RESTRICTED_NAPI_DETACH _IOW('E', 0xd9, struct ebpfos_restricted_napi_request)
#endif
