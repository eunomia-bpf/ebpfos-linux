// SPDX-License-Identifier: GPL-2.0-only
#include <linux/ebpfos.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

struct ebpfos_control {
	/* Independent generated KOperation proof/native transaction. */
	struct mutex koperation_txn_lock;
	void *koperation_txn;
};

/* Retiring the legacy hook fields does not change the version query wire. */
static_assert(sizeof(struct ebpfos_ioc_version) == 8);

static int ebpfos_open(struct inode *inode, struct file *file)
{
	struct ebpfos_control *state;

	state = kzalloc_obj(*state, GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	mutex_init(&state->koperation_txn_lock);
	file->private_data = state;
	return 0;
}

static int ebpfos_release(struct inode *inode, struct file *file)
{
	struct ebpfos_control *state = file->private_data;

	if (state) {
		ebpfos_koperation_release(&state->koperation_txn);
		mutex_destroy(&state->koperation_txn_lock);
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
	struct ebpfos_control *state = file->private_data;
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
