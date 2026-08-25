/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_EBPFOS_RUNTIME_H
#define _UAPI_EBPFOS_RUNTIME_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define EBPFOS_RUNTIME_ROOT_ABI_VERSION 10U
#define EBPFOS_RUNTIME_ROOT_MAX_SLOTS 20U
#define EBPFOS_RUNTIME_ROOT_CONTEXT_SIZE 304U
#define EBPFOS_RUNTIME_ROOT_TAG_SIZE 8U
#define EBPFOS_RUNTIME_ROOT_DIGEST_SIZE 32U
#define EBPFOS_RUNTIME_ROOT_IOC_MAGIC 0xe8
#define EBPFOS_RUNTIME_PROCESS_MAX_TASKS 4U
#define EBPFOS_RUNTIME_SUCCESSOR_CPUS 4U

#define EBPFOS_RUNTIME_SYSCALL_ACTION_NONE 0U
#define EBPFOS_RUNTIME_SYSCALL_ACTION_COMMIT_STAGED 1U
#define EBPFOS_RUNTIME_SYSCALL_ACTION_ROLLBACK_ROOT 2U
#define EBPFOS_RUNTIME_SYSCALL_ACTION_ROLLBACK_IRQ_ROOT 3U
#define EBPFOS_RUNTIME_SYSCALL_ACTION_INSTALL_IRQ_ROOT 4U
#define EBPFOS_RUNTIME_SYSCALL_ACTION_REARM_IRQ_ROOT 5U
#define EBPFOS_RUNTIME_SYSCALL_ACTION_INSTALL_PROCESS_ROOT 6U
#define EBPFOS_RUNTIME_SYSCALL_ACTION_ROLLBACK_PROCESS_ROOT 7U
#define EBPFOS_RUNTIME_SYSCALL_ACTION_INSTALL_DEVICE_ROOT 8U
#define EBPFOS_RUNTIME_SYSCALL_ACTION_EMIT_DEVICE_BYTE 9U
#define EBPFOS_RUNTIME_SYSCALL_ACTION_ROLLBACK_DEVICE_ROOT 10U

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

struct ebpfos_runtime_irq_root {
	__u32 version;
	__u32 flags;
	__u64 expected_epoch;
	__u64 observer_slot_id;
	__u64 installer_slot_id;
	__u64 handler_slot_id;
	__u64 portal_broadcast_slot_id;
	__u64 routing_observer_slot_id;
	__u64 routing_installer_slot_id;
	__u64 pulse_observer_slot_id;
	__u64 pulse_installer_slot_id;
	__u64 routing_old;
	__u64 routing_target;
	__u64 pulse_resting;
	__u64 pulse_armed;
	__u64 old_idtr;
	__u64 target_idtr;
	__u64 handler_entry;
	__u8 target_table_sha256[EBPFOS_RUNTIME_ROOT_DIGEST_SIZE];
	__u8 entry_descriptor_sha256[EBPFOS_RUNTIME_ROOT_DIGEST_SIZE];
	__u64 dispatches;
	__u64 dispatch_errors;
	__u64 pulse_rearms;
	__u64 portal_broadcasts;
	__u64 portal_dispatches;
	__u64 portal_generation;
	__u64 first_dispatch_epoch;
	__u64 last_dispatch_epoch;
	__u32 cpus_observed;
	__u32 cpus_written;
	__u32 machine_cpus_observed;
	__u32 machine_cpus_written;
	__u32 vector;
	__u32 gate_dpl;
	__u32 first_dispatch_prog_id;
	__u32 last_dispatch_prog_id;
	__u32 active;
	__u32 first_vector;
	__u32 last_vector;
	__u32 vector_count;
	__u32 donor_external_gates;
	__u32 portal_vector;
	__u32 portal_errors;
	__u32 reserved;
};

struct ebpfos_runtime_process_root {
	__u32 version;
	__u32 flags;
	__u64 expected_epoch;
	__u64 process_slot_id;
	__u64 mmu_observer_slot_id;
	__u64 mmu_reloader_slot_id;
	__u64 task_object_id;
	__u64 task_start_boottime;
	__u64 mm_object_id;
	__u64 address_space_object_id;
	__u64 mmu_root_physical;
	__u64 returns;
	__u64 return_errors;
	__u64 syscall_returns;
	__u64 irq_returns;
	__u64 mmu_observations;
	__u64 mmu_reloads;
	__u64 mmu_errors;
	__u64 mmu_first_epoch;
	__u64 mmu_last_epoch;
	__u64 mmu_native_fallbacks;
	__u64 first_return_epoch;
	__u64 last_return_epoch;
	__u64 native_fallbacks;
	__u64 state_mutations;
	__u64 task_set_digest;
	__u64 address_space_set_digest;
	__u64 mmu_root_set_digest;
	__u64 task_enrollments;
	__u64 cpu_mask;
	__u64 scheduler_decisions;
	__u64 scheduler_context_switch_growth;
	__u64 scheduler_cpu_owner_digest;
	__u64 scheduler_native_fallbacks;
	__u32 task_pid;
	__u32 task_tgid;
	__u32 first_return_prog_id;
	__u32 last_return_prog_id;
	__u32 mmu_observer_prog_id;
	__u32 mmu_reloader_prog_id;
	__u32 active;
	__u32 task_count;
	__u32 mm_count;
	__u32 max_tasks;
	__u32 cpus_observed;
	__u32 scheduler_cpu_claims;
	__u32 reserved;
};

struct ebpfos_runtime_device_root {
	__u32 version;
	__u32 flags;
	__u64 expected_epoch;
	__u64 device_slot_id;
	__u64 device_object_id;
	__u64 writes;
	__u64 write_errors;
	__u64 first_write_epoch;
	__u64 last_write_epoch;
	__u64 native_fallbacks;
	__u64 dma_operations;
	__u32 io_port;
	__u32 first_write_prog_id;
	__u32 last_write_prog_id;
	__u32 active;
	__u32 reserved;
};

struct ebpfos_runtime_successor_stage {
	__u32 version;
	__u32 flags;
	__u64 user_address;
	__u64 image_bytes;
	__u64 physical_base;
	__u64 virtual_base;
	__u64 cr3;
	__u64 idtr;
	__u64 lstar;
	__u64 cpu_root;
	__u64 cpu_stacks[EBPFOS_RUNTIME_SUCCESSOR_CPUS];
	__u64 cpu_contexts[EBPFOS_RUNTIME_SUCCESSOR_CPUS];
	__u8 image_sha256[EBPFOS_RUNTIME_ROOT_DIGEST_SIZE];
	__u64 mapped_pages;
	__u32 idt_vectors;
	__u32 cpus;
	__u32 staged;
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
#define EBPFOS_RUNTIME_ROOT_IOC_IRQ_INSTALL \
	_IOWR(EBPFOS_RUNTIME_ROOT_IOC_MAGIC, 0x07, \
	      struct ebpfos_runtime_irq_root)
#define EBPFOS_RUNTIME_ROOT_IOC_IRQ_READ \
	_IOR(EBPFOS_RUNTIME_ROOT_IOC_MAGIC, 0x08, \
	     struct ebpfos_runtime_irq_root)
#define EBPFOS_RUNTIME_ROOT_IOC_PROCESS_READ \
	_IOR(EBPFOS_RUNTIME_ROOT_IOC_MAGIC, 0x09, \
	     struct ebpfos_runtime_process_root)
#define EBPFOS_RUNTIME_ROOT_IOC_DEVICE_READ \
	_IOR(EBPFOS_RUNTIME_ROOT_IOC_MAGIC, 0x0a, \
	     struct ebpfos_runtime_device_root)
#define EBPFOS_RUNTIME_ROOT_IOC_SUCCESSOR_STAGE \
	_IOWR(EBPFOS_RUNTIME_ROOT_IOC_MAGIC, 0x0b, \
	      struct ebpfos_runtime_successor_stage)

#endif /* _UAPI_EBPFOS_RUNTIME_H */
