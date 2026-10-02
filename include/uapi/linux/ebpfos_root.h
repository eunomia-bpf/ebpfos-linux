/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_EBPFOS_ROOT_H
#define _UAPI_LINUX_EBPFOS_ROOT_H

#include <linux/ebpfos.h>

#define EBPFOS_ROOT_MAX_ROLES 64U

struct ebpfos_ioc_root_role {
	__s32 admission_fd;
	__u32 reserved;
	__u64 role_type;
};

struct ebpfos_ioc_root_publish {
	/* Retained wire slot; the ioctl command fixes the request size. */
	__u32 version;
	__u32 flags;
	__u64 object_id;
	__u64 expected_epoch;
	__u64 target_epoch;
	__u32 role_count;
	__u32 reserved;
	struct ebpfos_ioc_root_role roles[EBPFOS_ROOT_MAX_ROLES];
};

#define EBPFOS_IOC_ROOT_PUBLISH \
	_IOW(EBPFOS_IOC_MAGIC, 0x3b, struct ebpfos_ioc_root_publish)

#endif
