// SPDX-License-Identifier: GPL-2.0-only
#include <linux/ebpfos.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

struct ebpfos_file {
	/* Serializes the one file-replacement transaction owned by this FD. */
	struct mutex file_txn_lock;
	void *file_txn;
	/* Independent generated KOperation proof/native transaction. */
	struct mutex koperation_txn_lock;
	void *koperation_txn;
};

/* Retiring the legacy hook fields does not change the version query wire. */
static_assert(sizeof(struct ebpfos_ioc_version) == 8);

static int ebpfos_open(struct inode *inode, struct file *file)
{
	struct ebpfos_file *state;

	state = kzalloc_obj(*state, GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	mutex_init(&state->file_txn_lock);
	mutex_init(&state->koperation_txn_lock);
	file->private_data = state;
	return 0;
}

static int ebpfos_release(struct inode *inode, struct file *file)
{
	struct ebpfos_file *state = file->private_data;

	if (state) {
		ebpfos_file_replace_release(&state->file_txn);
		ebpfos_koperation_release(&state->koperation_txn);
		mutex_destroy(&state->koperation_txn_lock);
		mutex_destroy(&state->file_txn_lock);
		kfree(state);
	}
	return 0;
}

static long ebpfos_ioctl_version(void __user *argp)
{
	struct ebpfos_ioc_version version = {
		.uapi_version = EBPFOS_UAPI_VERSION,
		.feature_flags = 0,
	};

	return copy_to_user(argp, &version, sizeof(version)) ? -EFAULT : 0;
}

static long ebpfos_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ebpfos_file *state = file->private_data;
	void __user *argp = (void __user *)arg;
	long result;

	switch (cmd) {
	case EBPFOS_IOC_VERSION:
		return ebpfos_ioctl_version(argp);
	case EBPFOS_IOC_POLICY_ACTIVATE:
		return ebpfos_policy_activate_ioctl(argp);
	case EBPFOS_IOC_POLICY_STATUS:
		return ebpfos_policy_status_ioctl(argp);
	case EBPFOS_IOC_ADMISSION_SEAL:
		return ebpfos_admission_seal_ioctl(argp);
	case EBPFOS_IOC_ADMISSION_INFO:
		return ebpfos_admission_info_ioctl(argp);
	case EBPFOS_IOC_ADMISSION_RUNTIME_INFO:
		return ebpfos_admission_runtime_info_ioctl(argp);
	case EBPFOS_IOC_STATE_ADAPTER_SEAL:
		return ebpfos_state_adapter_seal_ioctl(argp);
	case EBPFOS_IOC_STATE_ADAPTER_INFO:
		return ebpfos_state_adapter_info_ioctl(argp);
	case EBPFOS_IOC_STATE_ADAPTER_TARGET_PAIR_EXPERIMENTAL:
		return ebpfos_state_adapter_target_pair_ioctl(argp);
	case EBPFOS_IOC_FILE_SPLIT_PRIVATE_CONVERT_EXPERIMENTAL:
		return ebpfos_file_split_private_convert_experimental_ioctl(argp);
	case EBPFOS_IOC_FILE_SPLIT_HOT_PUBLISH_EXPERIMENTAL:
		return ebpfos_file_split_hot_publish_experimental_ioctl(argp);
	case EBPFOS_IOC_OBJECT_CREATE:
		return ebpfos_object_create_ioctl(argp);
	case EBPFOS_IOC_FILE_ENROLL:
		return ebpfos_file_enroll_ioctl(argp);
	case EBPFOS_IOC_FILE_STATUS:
		return ebpfos_file_status_ioctl(argp);
	case EBPFOS_IOC_FILE_REPLACE_BEGIN:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_replace_begin_ioctl(argp,
							 &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_REPLACE_CATCHUP:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_replace_catchup_ioctl(argp,
							   &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_REPLACE_COMMIT:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_replace_commit_ioctl(argp,
							  &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_REPLACE_ABORT:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_replace_abort_ioctl(argp,
							 &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_REPLACE_STATUS:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_replace_status_ioctl(argp,
							  &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_RECOVERY_BEGIN:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_recovery_begin_ioctl(argp,
							  &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_RECOVERY_ARM:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_recovery_arm_ioctl(argp,
							&state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_RECOVERY_ABORT:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_recovery_abort_ioctl(argp,
							  &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_RECOVERY_STATUS:
		return ebpfos_file_recovery_status_ioctl(argp);
	case EBPFOS_IOC_FILE_RECOVERY_RETIRE:
		return ebpfos_file_recovery_retire_ioctl(argp);
	case EBPFOS_IOC_FILE_REPLACE_BEGIN_V2:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_replace_begin_v2_ioctl(argp,
							    &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_RECOVERY_BEGIN_V2:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_recovery_begin_v2_ioctl(
			argp, &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_RECOVERY_ARM_V2:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_recovery_arm_v2_ioctl(argp,
							   &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_ADMISSION_STATUS:
		return ebpfos_file_admission_status_ioctl(argp);
	case EBPFOS_IOC_FILE_SPLIT_PUBLISH_EXPERIMENTAL:
		return ebpfos_file_split_publish_experimental_ioctl(argp);
	case EBPFOS_IOC_FILE_SPLIT_CONTROL_EXPERIMENTAL:
		return ebpfos_file_split_control_experimental_ioctl(argp);
	case EBPFOS_IOC_FILE_CHECKPOINT_EXPERIMENTAL:
		return ebpfos_file_checkpoint_experimental_ioctl(argp);
	case EBPFOS_IOC_KOPERATION_PREPARE_EXPERIMENTAL:
		mutex_lock(&state->koperation_txn_lock);
		result = ebpfos_koperation_prepare_ioctl(
			argp, &state->koperation_txn);
		mutex_unlock(&state->koperation_txn_lock);
		return result;
	case EBPFOS_IOC_KOPERATION_EXECUTE_EXPERIMENTAL:
		mutex_lock(&state->koperation_txn_lock);
		result = ebpfos_koperation_execute_ioctl(
			argp, &state->koperation_txn);
		mutex_unlock(&state->koperation_txn_lock);
		return result;
	case EBPFOS_IOC_KOPERATION_RESULT_EXPERIMENTAL:
		mutex_lock(&state->koperation_txn_lock);
		result = ebpfos_koperation_result_ioctl(
			argp, &state->koperation_txn);
		mutex_unlock(&state->koperation_txn_lock);
		return result;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations ebpfos_fops = {
	.owner = THIS_MODULE,
	.open = ebpfos_open,
	.release = ebpfos_release,
	.unlocked_ioctl = ebpfos_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = ebpfos_ioctl,
#endif
	.llseek = noop_llseek,
};

static struct miscdevice ebpfos_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ebpfos",
	.fops = &ebpfos_fops,
	.mode = 0600,
};

static int __init ebpfos_init(void)
{
	int error;

	error = misc_register(&ebpfos_miscdev);
	if (error)
		return error;
	pr_info("ebpfos: component control nucleus ready\n");
	return 0;
}
subsys_initcall(ebpfos_init);

MODULE_DESCRIPTION("eBPFOS transactional eBPF component graph");
MODULE_AUTHOR("eunomia-bpf community");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.2");
