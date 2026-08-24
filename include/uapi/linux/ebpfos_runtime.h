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

#define EBPFOS_RUNTIME_SYSCALL_ACTION_NONE 0U
#define EBPFOS_RUNTIME_SYSCALL_ACTION_COMMIT_STAGED 1U
#define EBPFOS_RUNTIME_SYSCALL_ACTION_ROLLBACK_ROOT 2U

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

struct ebpfos_runtime_syscall_root {
	__u32 version;
	__u32 flags;
	__u64 expected_epoch;
	__u64 syscall_slot_id;
	__u64 observer_slot_id;
	__u64 installer_slot_id;
	__u64 old_lstar;
	__u64 target_lstar;
	__u64 syscall_calls;
	__u64 unknown_syscalls;
	__u64 graph_commits;
	__u32 cpus_observed;
	__u32 cpus_written;
	__u32 active;
	__u32 reserved;
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
#define EBPFOS_RUNTIME_ROOT_IOC_STAGE \
	_IOW(EBPFOS_RUNTIME_ROOT_IOC_MAGIC, 0x04, \
	     struct ebpfos_runtime_root_publish)
#define EBPFOS_RUNTIME_ROOT_IOC_SYSCALL_INSTALL \
	_IOWR(EBPFOS_RUNTIME_ROOT_IOC_MAGIC, 0x05, \
	      struct ebpfos_runtime_syscall_root)
#define EBPFOS_RUNTIME_ROOT_IOC_SYSCALL_READ \
	_IOR(EBPFOS_RUNTIME_ROOT_IOC_MAGIC, 0x06, \
	     struct ebpfos_runtime_syscall_root)

#endif /* _UAPI_EBPFOS_RUNTIME_H */
