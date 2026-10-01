// SPDX-License-Identifier: GPL-2.0-only
#include <linux/ebpfos.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/uaccess.h>

/* Retiring the legacy hook fields does not change the version query wire. */
static_assert(sizeof(struct ebpfos_ioc_version) == 8);

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
	void __user *argp = (void __user *)arg;

	(void)file;

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
	default:
		return -ENOTTY;
	}
}

static const struct file_operations ebpfos_fops = {
	.owner = THIS_MODULE,
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
