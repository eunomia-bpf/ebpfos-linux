/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_H
#define _LINUX_EBPFOS_H

#include <linux/errno.h>
#include <linux/types.h>
#include <uapi/linux/ebpfos.h>

struct file;
struct inode;
struct iov_iter;
struct kiocb;

typedef ssize_t (*ebpfos_file_iter_fn)(struct kiocb *iocb,
				       struct iov_iter *iter);

#ifdef CONFIG_EBPFOS
/* Public dispatch selects typed struct_ops first and raw graph as fallback. */
u32 ebpfos_run_hook(enum ebpfos_hook_id hook, const u64 *args, u32 nr_args);
u32 ebpfos_run_raw_hook(enum ebpfos_hook_id hook, const u64 *args, u32 nr_args);
bool ebpfos_hook_enabled(enum ebpfos_hook_id hook);
long ebpfos_object_create_ioctl(void __user *argp);
long ebpfos_file_enroll_ioctl(void __user *argp);
long ebpfos_file_status_ioctl(void __user *argp);
long ebpfos_file_replace_begin_ioctl(void __user *argp, void **txn_slot);
long ebpfos_file_replace_catchup_ioctl(void __user *argp, void **txn_slot);
long ebpfos_file_replace_commit_ioctl(void __user *argp, void **txn_slot);
long ebpfos_file_replace_abort_ioctl(void __user *argp, void **txn_slot);
long ebpfos_file_replace_status_ioctl(void __user *argp, void **txn_slot);
long ebpfos_file_recovery_begin_ioctl(void __user *argp, void **txn_slot);
long ebpfos_file_recovery_arm_ioctl(void __user *argp, void **txn_slot);
long ebpfos_file_recovery_abort_ioctl(void __user *argp, void **txn_slot);
long ebpfos_file_recovery_status_ioctl(void __user *argp);
long ebpfos_file_recovery_retire_ioctl(void __user *argp);
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

static inline u32 ebpfos_run_raw_hook(enum ebpfos_hook_id hook,
				      const u64 *args, u32 nr_args)
{
	return EBPFOS_ACTION(EBPFOS_VERDICT_CONTINUE, 0);
}

static inline bool ebpfos_hook_enabled(enum ebpfos_hook_id hook)
{
	return false;
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

static inline long ebpfos_file_recovery_arm_ioctl(void __user *argp,
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
