/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_EBPFOS_RESTRICTED_IRQ_EVENT_H
#define _UAPI_LINUX_EBPFOS_RESTRICTED_IRQ_EVENT_H
#include <linux/ioctl.h>
#include <linux/types.h>

struct ebpfos_restricted_irq_event_request {
	__s32 fd;
	__s32 prog_fd;
	__u32 active;
	__u32 reserved;
	__u64 native_entries;
	__u64 component_entries;
	__u64 hardirq_entries;
	__u64 faults;
};

#define EBPFOS_RESTRICTED_IRQ_EVENT_ATTACH _IOW('E', 0xb0, struct ebpfos_restricted_irq_event_request)
#define EBPFOS_RESTRICTED_IRQ_EVENT_SWITCH _IOW('E', 0xb1, struct ebpfos_restricted_irq_event_request)
#define EBPFOS_RESTRICTED_IRQ_EVENT_STATS _IOWR('E', 0xb2, struct ebpfos_restricted_irq_event_request)
#define EBPFOS_RESTRICTED_IRQ_EVENT_DETACH _IOW('E', 0xb3, struct ebpfos_restricted_irq_event_request)
#endif
