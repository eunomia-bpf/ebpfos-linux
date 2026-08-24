/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_EBPFOS_RUNTIME_H
#define _UAPI_EBPFOS_RUNTIME_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define EBPFOS_RUNTIME_ROOT_ABI_VERSION 1U
#define EBPFOS_RUNTIME_ROOT_MAX_SLOTS 16U
#define EBPFOS_RUNTIME_ROOT_CONTEXT_SIZE 304U
#define EBPFOS_RUNTIME_ROOT_TAG_SIZE 8U
#define EBPFOS_RUNTIME_ROOT_DIGEST_SIZE 32U
#define EBPFOS_RUNTIME_ROOT_IOC_MAGIC 0xe8

struct ebpfos_runtime_root_slot {
	__u64 slot_id;
	__s32 prog_fd;
	__u32 flags;
	__u8 program_tag[EBPFOS_RUNTIME_ROOT_TAG_SIZE];
	__u8 image_digest[EBPFOS_RUNTIME_ROOT_DIGEST_SIZE];
};

struct ebpfos_runtime_root_publish {
	__u32 version;
	__u32 flags;
	__u64 expected_epoch;
	__u64 target_epoch;
	__u32 slot_count;
	__u32 reserved;
	struct ebpfos_runtime_root_slot slots[EBPFOS_RUNTIME_ROOT_MAX_SLOTS];
};

struct ebpfos_runtime_root_call {
	__u32 version;
	__u32 flags;
	__u64 slot_id;
	__u64 expected_epoch;
	__u64 observed_epoch;
	__u32 provider_prog_id;
	__u32 provider_status;
	__u32 context_size;
	__u32 reserved;
	__u8 context[EBPFOS_RUNTIME_ROOT_CONTEXT_SIZE];
};

struct ebpfos_runtime_root_slot_snapshot {
	__u64 slot_id;
	__u32 prog_id;
	__u32 reserved;
	__u8 program_tag[EBPFOS_RUNTIME_ROOT_TAG_SIZE];
	__u8 image_digest[EBPFOS_RUNTIME_ROOT_DIGEST_SIZE];
};

struct ebpfos_runtime_root_snapshot {
	__u32 version;
	__u32 flags;
	__u64 epoch;
	__u32 slot_count;
	__u32 reserved;
	struct ebpfos_runtime_root_slot_snapshot
		slots[EBPFOS_RUNTIME_ROOT_MAX_SLOTS];
};

#define EBPFOS_RUNTIME_ROOT_IOC_PUBLISH \
	_IOW(EBPFOS_RUNTIME_ROOT_IOC_MAGIC, 0x01, \
	     struct ebpfos_runtime_root_publish)
#define EBPFOS_RUNTIME_ROOT_IOC_CALL \
	_IOWR(EBPFOS_RUNTIME_ROOT_IOC_MAGIC, 0x02, \
	      struct ebpfos_runtime_root_call)
#define EBPFOS_RUNTIME_ROOT_IOC_READ \
	_IOR(EBPFOS_RUNTIME_ROOT_IOC_MAGIC, 0x03, \
	     struct ebpfos_runtime_root_snapshot)

#endif /* _UAPI_EBPFOS_RUNTIME_H */
