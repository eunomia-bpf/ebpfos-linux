/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_EBPFOS_RESTRICTED_BLOCK_H
#define _UAPI_LINUX_EBPFOS_RESTRICTED_BLOCK_H
#include <linux/ioctl.h>
#include <linux/types.h>

struct ebpfos_restricted_block_request {
	__s32 fd;
	__s32 softirq_prog_fd;
	__s32 timer_prog_fd;
	__u32 status_offset;
	__u32 active;
	__u64 native_entries;
	__u64 softirq_entries;
	__u64 timer_entries;
	__u64 softirq_context_entries;
	__u64 hardirq_context_entries;
	__u64 faults;
};

#define EBPFOS_RESTRICTED_BLOCK_ATTACH _IOW('E', 0xa0, struct ebpfos_restricted_block_request)
#define EBPFOS_RESTRICTED_BLOCK_SWITCH _IOW('E', 0xa1, struct ebpfos_restricted_block_request)
#define EBPFOS_RESTRICTED_BLOCK_STATS _IOWR('E', 0xa2, struct ebpfos_restricted_block_request)
#define EBPFOS_RESTRICTED_BLOCK_DETACH _IOW('E', 0xa3, struct ebpfos_restricted_block_request)
#endif
