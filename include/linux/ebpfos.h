/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_H
#define _LINUX_EBPFOS_H

#include <linux/bits.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/types.h>
#include <uapi/linux/ebpfos.h>

/* Internal experiment uses; do not freeze these into the UAPI yet. */
#define EBPFOS_COMPONENT_USE_SPLIT_READER 6U
#define EBPFOS_COMPONENT_USE_SPLIT_WRITER 7U
#define EBPFOS_COMPONENT_USE_SPLIT_V2_READER 8U
#define EBPFOS_COMPONENT_USE_SPLIT_V2_WRITER 9U
#define EBPFOS_COMPONENT_SPLIT_TRANSITION_ID 0x201ULL
#define EBPFOS_COMPONENT_SPLIT_V2_TRANSITION_ID 0x202ULL
#define EBPFOS_FILE_SPLIT_V2_KEY_SIZE 4U
#define EBPFOS_FILE_SPLIT_V2_VALUE_SIZE 2080U
#define EBPFOS_FILE_SPLIT_V2_MAX_ENTRIES 16386U

/*
 * Kernel-private experiment ABI.  The split publication model is not frozen
 * into uapi/linux/ebpfos.h until authority views survive the KVM gates.
 */
struct ebpfos_file_split_publish {
	__s32 file_fd;
	__s32 reader_admission_fd;
	__s32 writer_admission_fd;
	__u32 flags;
	__u64 expected_route_id;
	__u64 expected_provider_id;
	__u64 expected_epoch;
	__u8 expected_active_content_digest[32];
	__u64 route_id;
	__u64 implementation_provider_id;
	__u64 graph_epoch;
	__u64 publish_frontier;
	__u64 reader_provider_id;
	__u64 writer_provider_id;
	__u64 transition_id;
	__u64 reader_grant_id;
	__u64 writer_grant_id;
	__u32 graph_shape;
	__u32 reader_state;
	__u32 writer_state;
	__u32 reserved0;
	__u32 reader_prog_id;
	__u32 reader_map_id;
	__u32 writer_prog_id;
	__u32 writer_map_id;
	__u8 reader_content_digest[32];
	__u8 writer_content_digest[32];
};

#define EBPFOS_IOC_FILE_SPLIT_PUBLISH_EXPERIMENTAL \
	_IOWR(EBPFOS_IOC_MAGIC, 0x38, \
	      struct ebpfos_file_split_publish)

#define EBPFOS_FILE_SPLIT_CONTROL_STATUS 0U
#define EBPFOS_FILE_SPLIT_CONTROL_ARM_REPLAY_FAULT 1U
#define EBPFOS_FILE_SPLIT_CONTROL_REPAIR_READER 2U
#define EBPFOS_FILE_SPLIT_CONTROL_RETIRE_LINEAGE 3U
#define EBPFOS_FILE_SPLIT_CONTROL_F_CORRUPT_IMPORT BIT(0)

struct ebpfos_file_split_control {
	__s32 file_fd;
	__u32 operation;
	__u32 flags;
	__u32 reserved0;
	__u64 expected_route_id;
	__u64 expected_graph_epoch;
	__u64 expected_reader_frontier;
	__u64 expected_writer_frontier;
	__u64 route_id;
	__u64 graph_epoch;
	__u64 reader_frontier;
	__u64 writer_frontier;
	__u64 pending_sequence;
	__u64 pending_file_cookie;
	__u64 pending_visible_before;
	__u64 pending_visible_after;
	__u64 pending_size;
	__u64 pending_digest;
	__u64 visible_size;
	__u64 repaired_bytes;
	__u64 lineage_provider_id;
	__u64 lineage_acquires;
	__u64 lineage_acquires_at_retire;
	__u32 route_state;
	__u32 admission_gate;
	__u32 repair_pending;
	__u32 replay_fault_armed;
	__u32 lineage_prog_id;
	__u32 lineage_map_id;
	__u32 lineage_retired;
	__u32 reserved1;
	__u64 reader_provider_id;
	__u64 writer_provider_id;
	__u64 read_calls;
	__u64 write_calls;
	__u64 read_bytes;
	__u64 write_bytes;
	__u64 reader_dispatches;
	__u64 writer_dispatches;
	__u64 retired_reader_dispatches;
	__u64 retired_writer_dispatches;
	__u64 hot_publications;
	__u64 publish_frontier;
	__u32 reader_prog_id;
	__u32 reader_map_id;
	__u32 writer_prog_id;
	__u32 writer_map_id;
	__u32 acquired_calls;
	__u32 last_publish_drained_calls;
};

#define EBPFOS_IOC_FILE_SPLIT_CONTROL_EXPERIMENTAL \
	_IOWR(EBPFOS_IOC_MAGIC, 0x39, \
	      struct ebpfos_file_split_control)

#define EBPFOS_FILE_CHECKPOINT_MAGIC "EBPFSCP1"
#define EBPFOS_FILE_CHECKPOINT_FORMAT_V1 1U
#define EBPFOS_FILE_CHECKPOINT_SEAL 1U
#define EBPFOS_FILE_CHECKPOINT_RESTORE 2U
#define EBPFOS_FILE_CHECKPOINT_F_FAIL_AFTER_READER_IMPORT BIT(0)
#define EBPFOS_FILE_CHECKPOINT_F_FAIL_AFTER_REPLY_COPYOUT BIT(1)
#define EBPFOS_FILE_CHECKPOINT_F_ALL \
	(EBPFOS_FILE_CHECKPOINT_F_FAIL_AFTER_READER_IMPORT | \
	 EBPFOS_FILE_CHECKPOINT_F_FAIL_AFTER_REPLY_COPYOUT)

/*
 * Canonical little-endian record copied after its separately addressed image.
 * This remains a kernel-private experiment ABI until cold restore passes KVM.
 */
struct ebpfos_file_checkpoint_manifest_v1 {
	__u8 magic[8];
	__le16 format_version;
	__le16 manifest_size;
	__le64 checkpoint_id;
	__le64 route_id;
	__le64 source_graph_epoch;
	__le64 restore_generation;
	__le64 provider_lineage_id;
	__le64 schema_hash;
	__le64 transition_id;
	__le64 frontier;
	__le64 visible_size;
	__le64 last_sequence;
	__le64 lineage_acquires_at_retire;
	__le64 lineage_policy_generation;
	__u8 lineage_policy_digest[32];
	__u8 lineage_content_digest[32];
	__u8 reader_content_digest[32];
	__u8 writer_content_digest[32];
	__u8 image_sha256[32];
	__u8 record_sha256[32];
} __packed;

struct ebpfos_file_checkpoint {
	__s32 file_fd;
	__s32 reader_admission_fd;
	__s32 writer_admission_fd;
	__u32 operation;
	__u32 flags;
	__u32 reserved0;
	__u64 expected_route_id;
	__u64 expected_graph_epoch;
	__u64 expected_frontier;
	__u64 expected_visible_size;
	__u64 expected_lineage_acquires_at_retire;
	__aligned_u64 image;
	__u64 image_capacity;
	struct ebpfos_file_checkpoint_manifest_v1 manifest;
	__u64 reader_provider_id;
	__u64 writer_provider_id;
	__u32 reader_prog_id;
	__u32 reader_map_id;
	__u32 writer_prog_id;
	__u32 writer_map_id;
	__u32 route_state;
	__u32 admission_gate;
	__u32 checkpointed;
	__u32 reserved1;
	__u64 graph_epoch;
	__u64 restore_generation;
};

#define EBPFOS_IOC_FILE_CHECKPOINT_EXPERIMENTAL \
	_IOWR(EBPFOS_IOC_MAGIC, 0x3a, struct ebpfos_file_checkpoint)

/* Read-only correspondence check for a sealed adapter and fresh targets. */
struct ebpfos_state_adapter_target_pair {
	__s32 adapter_fd;
	__s32 reader_admission_fd;
	__s32 writer_admission_fd;
	__u32 flags;
	__u32 reader_state;
	__u32 writer_state;
	__u64 reader_grant_id;
	__u64 writer_grant_id;
	__u32 reader_prog_id;
	__u32 reader_map_id;
	__u32 writer_prog_id;
	__u32 writer_map_id;
	__u8 adapter_content_digest[32];
	__u8 reader_content_digest[32];
	__u8 writer_content_digest[32];
};

#define EBPFOS_IOC_STATE_ADAPTER_TARGET_PAIR_EXPERIMENTAL \
	_IOWR(EBPFOS_IOC_MAGIC, 0x3d, \
	      struct ebpfos_state_adapter_target_pair)

#define EBPFOS_FILE_SPLIT_CONVERT_F_FAIL_AFTER_READER_CHUNK BIT(0)
#define EBPFOS_FILE_SPLIT_CONVERT_F_FAIL_AFTER_WRITER_CHUNK BIT(1)
#define EBPFOS_FILE_SPLIT_CONVERT_F_ALL \
	(EBPFOS_FILE_SPLIT_CONVERT_F_FAIL_AFTER_READER_CHUNK | \
	 EBPFOS_FILE_SPLIT_CONVERT_F_FAIL_AFTER_WRITER_CHUNK)

/*
 * Execute one sealed adapter into private target maps.  Success stages, but
 * does not consume, either grant and cannot publish a graph.
 */
struct ebpfos_file_split_private_convert {
	__s32 file_fd;
	__s32 adapter_fd;
	__s32 reader_admission_fd;
	__s32 writer_admission_fd;
	__u32 flags;
	__u32 reader_state;
	__u32 writer_state;
	__u32 adapter_state;
	__u32 graph_shape;
	__u32 reserved0;
	__u64 expected_route_id;
	__u64 expected_graph_epoch;
	__u64 expected_frontier;
	__u64 expected_visible_size;
	__u64 route_id;
	__u64 graph_epoch;
	__u64 target_epoch;
	__u64 frontier;
	__u64 visible_size;
	__u64 reader_grant_id;
	__u64 writer_grant_id;
	__u32 source_reader_prog_id;
	__u32 source_reader_map_id;
	__u32 source_writer_prog_id;
	__u32 source_writer_map_id;
	__u32 reader_prog_id;
	__u32 reader_map_id;
	__u32 writer_prog_id;
	__u32 writer_map_id;
	__u64 source_schema;
	__u64 target_schema;
	__u64 alpha_size;
	__u64 alpha_sequence;
	__u8 alpha_sha256[32];
	__u8 adapter_content_digest[32];
};

#define EBPFOS_IOC_FILE_SPLIT_PRIVATE_CONVERT_EXPERIMENTAL \
	_IOWR(EBPFOS_IOC_MAGIC, 0x3e, \
	      struct ebpfos_file_split_private_convert)

#define EBPFOS_FILE_SPLIT_HOT_PUBLISH_F_FAIL_BEFORE_COMMIT BIT(0)
#define EBPFOS_FILE_SPLIT_HOT_PUBLISH_F_ALL \
	EBPFOS_FILE_SPLIT_HOT_PUBLISH_F_FAIL_BEFORE_COMMIT

/*
 * Input-only hot publication transaction.  The kernel refreshes the staged
 * pair and checks both Alpha images before the sole graph linearization point;
 * no fallible user copy follows a successful commit.
 */
struct ebpfos_file_split_hot_publish {
	__s32 file_fd;
	__s32 adapter_fd;
	__s32 reader_admission_fd;
	__s32 writer_admission_fd;
	__u32 flags;
	__u32 reserved0;
	__u64 expected_route_id;
	__u64 expected_graph_epoch;
	__u64 minimum_frontier;
	__u64 minimum_visible_size;
	__u64 expected_target_epoch;
	__u32 expected_source_reader_prog_id;
	__u32 expected_source_reader_map_id;
	__u32 expected_source_writer_prog_id;
	__u32 expected_source_writer_map_id;
	__u64 expected_reader_grant_id;
	__u64 expected_writer_grant_id;
	__u32 expected_reader_prog_id;
	__u32 expected_reader_map_id;
	__u32 expected_writer_prog_id;
	__u32 expected_writer_map_id;
	__u8 expected_adapter_content_digest[32];
	__u8 expected_source_reader_content_digest[32];
	__u8 expected_source_writer_content_digest[32];
	__u8 expected_reader_content_digest[32];
	__u8 expected_writer_content_digest[32];
};

#define EBPFOS_IOC_FILE_SPLIT_HOT_PUBLISH_EXPERIMENTAL \
	_IOW(EBPFOS_IOC_MAGIC, 0x3f, \
	     struct ebpfos_file_split_hot_publish)

/*
 * Kernel-private generated KOperation experiment ABI.  PREPARE publishes no
 * operation: its fallible reply is copied before the transaction is staged.
 * EXECUTE is input-only, so no user copy can fail after native execution.
 */
#define EBPFOS_KOPERATION_ABI_VERSION 1U
#define EBPFOS_KOPERATION_PAGE_TABLE_READ_CR3_ROOT 1U

#define EBPFOS_KOPERATION_STATUS_STAGED 1U
#define EBPFOS_KOPERATION_STATUS_COMPLETE 2U
#define EBPFOS_KOPERATION_STATUS_BURNED 3U

struct ebpfos_koperation_prepare {
	__u32 version;
	__u32 operation_id;
	__u32 flags;
	__u32 reserved0;
	__u64 transaction_id;
	__u64 staged_shadow;
	__u8 semantic_sha256[32];
	__u8 proof_template_sha256[32];
	__u8 native_sha256[32];
	__u8 equivalence_sha256[32];
	__u64 attempts;
	__u64 commits;
	__u64 rejects;
};

struct ebpfos_koperation_execute {
	__u32 version;
	__u32 operation_id;
	__s32 proof_prog_fd;
	__u32 flags;
	__u64 transaction_id;
	__u64 expected_shadow;
};

struct ebpfos_koperation_result {
	__u32 version;
	__u32 operation_id;
	__u32 status;
	__s32 error;
	__u64 transaction_id;
	__u64 staged_shadow;
	__u64 native_result;
	__u8 semantic_sha256[32];
	__u8 proof_program_sha256[32];
	__u8 native_sha256[32];
	__u8 equivalence_sha256[32];
	__u64 attempts;
	__u64 commits;
	__u64 rejects;
};

#define EBPFOS_IOC_KOPERATION_PREPARE_EXPERIMENTAL \
	_IOWR(EBPFOS_IOC_MAGIC, 0x40, struct ebpfos_koperation_prepare)
#define EBPFOS_IOC_KOPERATION_EXECUTE_EXPERIMENTAL \
	_IOW(EBPFOS_IOC_MAGIC, 0x41, struct ebpfos_koperation_execute)
#define EBPFOS_IOC_KOPERATION_RESULT_EXPERIMENTAL \
	_IOR(EBPFOS_IOC_MAGIC, 0x42, struct ebpfos_koperation_result)

struct file;
struct inode;
struct iov_iter;
struct kiocb;
struct bpf_map;
struct bpf_prog;
struct ebpfos_admission;
struct ebpfos_binding;
struct ebpfos_prog_identity;
struct ebpfos_state_adapter;

struct ebpfos_admission_restore_pair {
	struct ebpfos_admission *reader;
	struct ebpfos_admission *writer;
	u64 predecessor_policy_generation;
	const u8 *predecessor_policy_digest;
	const u8 *predecessor_content_digest;
	const u8 *reader_content_digest;
	const u8 *writer_content_digest;
};

typedef ssize_t (*ebpfos_file_iter_fn)(struct kiocb *iocb,
				       struct iov_iter *iter);

#ifdef CONFIG_EBPFOS
/* Legacy graph dispatch; typed struct_ops call it only as a fallback. */
u32 ebpfos_run_hook(enum ebpfos_hook_id hook, const u64 *args, u32 nr_args);
bool ebpfos_hook_enabled(enum ebpfos_hook_id hook);
long ebpfos_policy_activate_ioctl(void __user *argp);
long ebpfos_policy_status_ioctl(void __user *argp);
long ebpfos_admission_seal_ioctl(void __user *argp);
long ebpfos_admission_info_ioctl(void __user *argp);
long ebpfos_state_adapter_seal_ioctl(void __user *argp);
long ebpfos_state_adapter_info_ioctl(void __user *argp);
long ebpfos_state_adapter_target_pair_ioctl(void __user *argp);
struct ebpfos_state_adapter *
ebpfos_state_adapter_get_from_fd(int fd, struct file **file_out);
const u8 *ebpfos_state_adapter_content_digest(
	const struct ebpfos_state_adapter *adapter);
u64 ebpfos_state_adapter_source_schema(
	const struct ebpfos_state_adapter *adapter);
u64 ebpfos_state_adapter_target_schema(
	const struct ebpfos_state_adapter *adapter);
int ebpfos_state_adapter_claim_target_pair_locked(
	const struct ebpfos_state_adapter *adapter,
	const struct ebpfos_binding *source_reader,
	const struct ebpfos_binding *source_writer,
	struct ebpfos_admission *reader, struct ebpfos_admission *writer,
	struct ebpfos_admission_identity_v1 *reader_identity,
	struct ebpfos_admission_identity_v1 *writer_identity);
int ebpfos_state_adapter_validate_target_pair_locked(
	const struct ebpfos_state_adapter *adapter,
	const struct ebpfos_binding *source_reader,
	const struct ebpfos_binding *source_writer,
	struct ebpfos_admission *reader, struct ebpfos_admission *writer,
	struct ebpfos_admission_identity_v1 *reader_identity,
	struct ebpfos_admission_identity_v1 *writer_identity);

/* The admission gate is outermost to every subsystem route/object lock. */
void ebpfos_admission_gate_lock(void);
void ebpfos_admission_gate_unlock(void);
bool ebpfos_policy_enforcing(void);
bool ebpfos_policy_enforcing_locked(void);
int ebpfos_policy_identity_validate_locked(
	u64 generation, const u8 realm_id[16],
	const u8 policy_digest[32], const u8 host_policy_digest[32],
	u32 required_flags);
int ebpfos_state_adapter_verify_signature(
	const struct ebpfos_state_adapter_record_v1 *record,
	const void *signature, size_t signature_size);
int ebpfos_legacy_mutation_check_locked(void);
int ebpfos_legacy_binding_add_locked(void);
void ebpfos_legacy_binding_del_locked(void);
/* Mark every managed file route DRAINING and wake its admission waiters. */
int ebpfos_file_policy_rotate_locked(void);

struct ebpfos_admission *ebpfos_admission_get_from_fd(int fd);
/* Final put may acquire the admission gate; callers must not hold it. */
void ebpfos_admission_put(struct ebpfos_admission *admission);
int ebpfos_admission_claim_locked(struct ebpfos_admission *admission,
				  const struct ebpfos_binding *predecessor,
				  u32 expected_use);
int ebpfos_admission_claim_pair_locked(struct ebpfos_admission *e3,
				       struct ebpfos_admission *e4,
				       const struct ebpfos_binding *predecessor);
int ebpfos_admission_claim_sibling_pair_locked(struct ebpfos_admission *reader,
					       struct ebpfos_admission *writer,
					       const struct ebpfos_binding *predecessor);
int ebpfos_admission_claim_validated_pair_locked(
	struct ebpfos_admission *first, struct ebpfos_admission *second);
int
ebpfos_admission_restore_claim_locked(struct ebpfos_admission_restore_pair *pair);
int
ebpfos_admission_restore_validate_locked(struct ebpfos_admission_restore_pair *pair);
int ebpfos_admission_publish_validate_locked(
	struct ebpfos_admission *admission,
	const struct ebpfos_binding *predecessor, bool recovery);
int ebpfos_admission_consume_locked(struct ebpfos_admission *admission,
				    bool recovery);
int ebpfos_admission_consume_pair_locked(struct ebpfos_admission *first,
					 struct ebpfos_admission *second);
int ebpfos_admission_recovery_e3_consume_locked(
	struct ebpfos_admission *e3, struct ebpfos_admission *e4);
void ebpfos_admission_burn_locked(struct ebpfos_admission *admission);
void ebpfos_admission_burn_pair_locked(struct ebpfos_admission *first,
				       struct ebpfos_admission *second);
u32 ebpfos_admission_state_locked(struct ebpfos_admission *admission);
void ebpfos_admission_fill_identity_locked(
	struct ebpfos_admission *admission,
	struct ebpfos_admission_identity_v1 *identity);
struct ebpfos_binding *ebpfos_admission_binding_get(
	struct ebpfos_admission *admission);

int ebpfos_native_binding_create_locked(struct ebpfos_binding **binding);
struct ebpfos_binding *ebpfos_binding_get(struct ebpfos_binding *binding);
void ebpfos_binding_put(struct ebpfos_binding *binding);
int ebpfos_binding_acquire_current_locked(struct ebpfos_binding *binding);
bool ebpfos_binding_content_matches(const struct ebpfos_binding *binding,
				    const u8 digest[32]);
u64 ebpfos_binding_policy_generation(const struct ebpfos_binding *binding);
u64 ebpfos_binding_runtime_schema(const struct ebpfos_binding *binding);
u32 ebpfos_binding_use(const struct ebpfos_binding *binding);
u32 ebpfos_binding_kind(const struct ebpfos_binding *binding);
const u8 *ebpfos_binding_content_digest(const struct ebpfos_binding *binding);
const struct ebpfos_component_desc_v1 *
ebpfos_binding_descriptor(const struct ebpfos_binding *binding);
struct bpf_prog *ebpfos_binding_prog(const struct ebpfos_binding *binding);
struct bpf_map *ebpfos_binding_map(const struct ebpfos_binding *binding);
void ebpfos_binding_fill_identity(const struct ebpfos_binding *binding,
				  struct ebpfos_admission_identity_v1 *identity);
void ebpfos_prog_identity_put(struct ebpfos_prog_identity *identity);

long ebpfos_object_create_ioctl(void __user *argp);
long ebpfos_file_enroll_ioctl(void __user *argp);
long ebpfos_file_status_ioctl(void __user *argp);
long ebpfos_file_replace_begin_ioctl(void __user *argp, void **txn_slot);
long ebpfos_file_replace_begin_v2_ioctl(void __user *argp, void **txn_slot);
long ebpfos_file_replace_catchup_ioctl(void __user *argp, void **txn_slot);
long ebpfos_file_replace_commit_ioctl(void __user *argp, void **txn_slot);
long ebpfos_file_replace_abort_ioctl(void __user *argp, void **txn_slot);
long ebpfos_file_replace_status_ioctl(void __user *argp, void **txn_slot);
long ebpfos_file_recovery_begin_ioctl(void __user *argp, void **txn_slot);
long ebpfos_file_recovery_begin_v2_ioctl(void __user *argp, void **txn_slot);
long ebpfos_file_recovery_arm_ioctl(void __user *argp, void **txn_slot);
long ebpfos_file_recovery_arm_v2_ioctl(void __user *argp, void **txn_slot);
long ebpfos_file_recovery_abort_ioctl(void __user *argp, void **txn_slot);
long ebpfos_file_recovery_status_ioctl(void __user *argp);
long ebpfos_file_recovery_retire_ioctl(void __user *argp);
long ebpfos_file_admission_status_ioctl(void __user *argp);
long ebpfos_file_split_publish_experimental_ioctl(void __user *argp);
long ebpfos_file_split_control_experimental_ioctl(void __user *argp);
long ebpfos_file_checkpoint_experimental_ioctl(void __user *argp);
long ebpfos_file_split_private_convert_experimental_ioctl(void __user *argp);
long ebpfos_file_split_hot_publish_experimental_ioctl(void __user *argp);
void ebpfos_file_replace_release(void **txn_slot);
#ifdef CONFIG_EBPFOS_KOPERATION
long ebpfos_koperation_prepare_ioctl(void __user *argp, void **txn_slot);
long ebpfos_koperation_execute_ioctl(void __user *argp, void **txn_slot);
long ebpfos_koperation_result_ioctl(void __user *argp, void **txn_slot);
void ebpfos_koperation_release(void **txn_slot);
#else
static inline long ebpfos_koperation_prepare_ioctl(void __user *argp,
						    void **txn_slot)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_koperation_execute_ioctl(void __user *argp,
						    void **txn_slot)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_koperation_result_ioctl(void __user *argp,
						   void **txn_slot)
{
	return -EOPNOTSUPP;
}

static inline void ebpfos_koperation_release(void **txn_slot)
{
}
#endif
void ebpfos_inode_route_init(struct inode *inode);
void ebpfos_inode_route_destroy(struct inode *inode);
bool ebpfos_inode_reject_managed(struct inode *inode);
bool ebpfos_inode_visible_size(struct inode *inode, loff_t *size);
ssize_t ebpfos_file_read_iter(struct kiocb *iocb, struct iov_iter *to,
			      ebpfos_file_iter_fn native_read);
ssize_t ebpfos_file_write_iter(struct kiocb *iocb, struct iov_iter *from,
			       ebpfos_file_iter_fn native_write);

#ifdef CONFIG_TMPFS
bool ebpfos_shmem_file_supported(struct file *file);
ssize_t ebpfos_shmem_native_read(struct file *file, void *buffer,
				 size_t size, loff_t offset);
ssize_t ebpfos_shmem_native_snapshot(struct file *file, void *buffer,
				     size_t size);
#endif
#else
static inline u32 ebpfos_run_hook(enum ebpfos_hook_id hook,
				  const u64 *args, u32 nr_args)
{
	return EBPFOS_ACTION(EBPFOS_VERDICT_CONTINUE, 0);
}

static inline bool ebpfos_hook_enabled(enum ebpfos_hook_id hook)
{
	return false;
}

static inline long ebpfos_policy_activate_ioctl(void __user *argp)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_policy_status_ioctl(void __user *argp)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_admission_seal_ioctl(void __user *argp)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_admission_info_ioctl(void __user *argp)
{
	return -EOPNOTSUPP;
}

static inline void ebpfos_admission_gate_lock(void)
{
}

static inline void ebpfos_admission_gate_unlock(void)
{
}

static inline bool ebpfos_policy_enforcing(void)
{
	return false;
}

static inline bool ebpfos_policy_enforcing_locked(void)
{
	return false;
}

static inline int ebpfos_legacy_mutation_check_locked(void)
{
	return 0;
}

static inline int ebpfos_legacy_binding_add_locked(void)
{
	return 0;
}

static inline void ebpfos_legacy_binding_del_locked(void)
{
}

static inline int ebpfos_file_policy_rotate_locked(void)
{
	return -EOPNOTSUPP;
}

static inline struct ebpfos_admission *ebpfos_admission_get_from_fd(int fd)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static inline void ebpfos_admission_put(struct ebpfos_admission *admission)
{
}

static inline int
ebpfos_admission_claim_locked(struct ebpfos_admission *admission,
			      const struct ebpfos_binding *predecessor,
			      u32 expected_use)
{
	return -EOPNOTSUPP;
}

static inline int
ebpfos_admission_claim_pair_locked(struct ebpfos_admission *e3,
				   struct ebpfos_admission *e4,
				   const struct ebpfos_binding *predecessor)
{
	return -EOPNOTSUPP;
}

static inline int
ebpfos_admission_claim_sibling_pair_locked(struct ebpfos_admission *reader,
					   struct ebpfos_admission *writer,
					   const struct ebpfos_binding *predecessor)
{
	return -EOPNOTSUPP;
}

static inline int ebpfos_admission_claim_validated_pair_locked(
	struct ebpfos_admission *first, struct ebpfos_admission *second)
{
	return -EOPNOTSUPP;
}

static inline int
ebpfos_admission_restore_claim_locked(struct ebpfos_admission_restore_pair *pair)
{
	return -EOPNOTSUPP;
}

static inline int
ebpfos_admission_restore_validate_locked(struct ebpfos_admission_restore_pair *pair)
{
	return -EOPNOTSUPP;
}

static inline int ebpfos_admission_publish_validate_locked(
	struct ebpfos_admission *admission,
	const struct ebpfos_binding *predecessor, bool recovery)
{
	return -EOPNOTSUPP;
}

static inline int
ebpfos_admission_consume_locked(struct ebpfos_admission *admission,
				bool recovery)
{
	return -EOPNOTSUPP;
}

static inline int
ebpfos_admission_consume_pair_locked(struct ebpfos_admission *first,
				     struct ebpfos_admission *second)
{
	return -EOPNOTSUPP;
}

static inline int ebpfos_admission_recovery_e3_consume_locked(
	struct ebpfos_admission *e3, struct ebpfos_admission *e4)
{
	return -EOPNOTSUPP;
}

static inline void
ebpfos_admission_burn_locked(struct ebpfos_admission *admission)
{
}

static inline void ebpfos_admission_burn_pair_locked(
	struct ebpfos_admission *first, struct ebpfos_admission *second)
{
}

static inline u32
ebpfos_admission_state_locked(struct ebpfos_admission *admission)
{
	return EBPFOS_ADMISSION_NONE;
}

static inline void ebpfos_admission_fill_identity_locked(
	struct ebpfos_admission *admission,
	struct ebpfos_admission_identity_v1 *identity)
{
}

static inline struct ebpfos_binding *
ebpfos_admission_binding_get(struct ebpfos_admission *admission)
{
	return NULL;
}

static inline int
ebpfos_native_binding_create_locked(struct ebpfos_binding **binding)
{
	return -EOPNOTSUPP;
}

static inline struct ebpfos_binding *
ebpfos_binding_get(struct ebpfos_binding *binding)
{
	return NULL;
}

static inline void ebpfos_binding_put(struct ebpfos_binding *binding)
{
}

static inline int
ebpfos_binding_acquire_current_locked(struct ebpfos_binding *binding)
{
	return -EOPNOTSUPP;
}

static inline bool
ebpfos_binding_content_matches(const struct ebpfos_binding *binding,
			       const u8 digest[32])
{
	return false;
}

static inline u64
ebpfos_binding_policy_generation(const struct ebpfos_binding *binding)
{
	return 0;
}

static inline u64
ebpfos_binding_runtime_schema(const struct ebpfos_binding *binding)
{
	return 0;
}

static inline u32 ebpfos_binding_use(const struct ebpfos_binding *binding)
{
	return 0;
}

static inline u32 ebpfos_binding_kind(const struct ebpfos_binding *binding)
{
	return 0;
}

static inline const u8 *
ebpfos_binding_content_digest(const struct ebpfos_binding *binding)
{
	return NULL;
}

static inline const struct ebpfos_component_desc_v1 *
ebpfos_binding_descriptor(const struct ebpfos_binding *binding)
{
	return NULL;
}

static inline struct bpf_prog *
ebpfos_binding_prog(const struct ebpfos_binding *binding)
{
	return NULL;
}

static inline struct bpf_map *
ebpfos_binding_map(const struct ebpfos_binding *binding)
{
	return NULL;
}

static inline void ebpfos_binding_fill_identity(
	const struct ebpfos_binding *binding,
	struct ebpfos_admission_identity_v1 *identity)
{
}

static inline void
ebpfos_prog_identity_put(struct ebpfos_prog_identity *identity)
{
}

static inline long ebpfos_object_create_ioctl(void __user *argp)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_file_enroll_ioctl(void __user *argp)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_file_status_ioctl(void __user *argp)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_file_replace_begin_ioctl(void __user *argp,
						   void **txn_slot)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_file_replace_begin_v2_ioctl(void __user *argp,
						      void **txn_slot)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_file_replace_catchup_ioctl(void __user *argp,
						     void **txn_slot)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_file_replace_commit_ioctl(void __user *argp,
						    void **txn_slot)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_file_replace_abort_ioctl(void __user *argp,
						   void **txn_slot)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_file_replace_status_ioctl(void __user *argp,
						    void **txn_slot)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_file_recovery_begin_ioctl(void __user *argp,
						    void **txn_slot)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_file_recovery_begin_v2_ioctl(void __user *argp,
						       void **txn_slot)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_file_recovery_arm_ioctl(void __user *argp,
						  void **txn_slot)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_file_recovery_arm_v2_ioctl(void __user *argp,
						     void **txn_slot)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_file_recovery_abort_ioctl(void __user *argp,
						    void **txn_slot)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_file_recovery_status_ioctl(void __user *argp)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_file_recovery_retire_ioctl(void __user *argp)
{
	return -EOPNOTSUPP;
}

static inline long ebpfos_file_admission_status_ioctl(void __user *argp)
{
	return -EOPNOTSUPP;
}

static inline long
ebpfos_file_split_publish_experimental_ioctl(void __user *argp)
{
	return -EOPNOTSUPP;
}

static inline long
ebpfos_file_split_control_experimental_ioctl(void __user *argp)
{
	return -EOPNOTSUPP;
}

static inline long
ebpfos_file_checkpoint_experimental_ioctl(void __user *argp)
{
	return -EOPNOTSUPP;
}

static inline void ebpfos_file_replace_release(void **txn_slot)
{
}

static inline void ebpfos_inode_route_init(struct inode *inode)
{
}

static inline void ebpfos_inode_route_destroy(struct inode *inode)
{
}

static inline bool ebpfos_inode_reject_managed(struct inode *inode)
{
	return false;
}

static inline bool ebpfos_inode_visible_size(struct inode *inode, loff_t *size)
{
	return false;
}

static inline ssize_t
ebpfos_file_read_iter(struct kiocb *iocb, struct iov_iter *to,
		      ebpfos_file_iter_fn native_read)
{
	return native_read(iocb, to);
}

static inline ssize_t
ebpfos_file_write_iter(struct kiocb *iocb, struct iov_iter *from,
		       ebpfos_file_iter_fn native_write)
{
	return native_write(iocb, from);
}
#endif

static inline bool ebpfos_action_is(u32 action, enum ebpfos_verdict verdict)
{
	return EBPFOS_ACTION_VERDICT(action) == verdict;
}

static inline int ebpfos_action_error(u32 action)
{
	u32 error = EBPFOS_ACTION_PAYLOAD(action);

	return error ? -(int)error : -EPERM;
}
#endif
