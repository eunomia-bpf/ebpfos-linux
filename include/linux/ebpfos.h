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
#define EBPFOS_COMPONENT_SPLIT_TRANSITION_ID 0x201ULL

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
	__u32 route_state;
	__u32 admission_gate;
	__u32 repair_pending;
	__u32 replay_fault_armed;
};

#define EBPFOS_IOC_FILE_SPLIT_CONTROL_EXPERIMENTAL \
	_IOWR(EBPFOS_IOC_MAGIC, 0x39, \
	      struct ebpfos_file_split_control)

struct file;
struct inode;
struct iov_iter;
struct kiocb;
struct bpf_map;
struct bpf_prog;
struct ebpfos_admission;
struct ebpfos_binding;
struct ebpfos_prog_identity;

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

/* The admission gate is outermost to every subsystem route/object lock. */
void ebpfos_admission_gate_lock(void);
void ebpfos_admission_gate_unlock(void);
bool ebpfos_policy_enforcing(void);
bool ebpfos_policy_enforcing_locked(void);
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
void ebpfos_file_replace_release(void **txn_slot);
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
