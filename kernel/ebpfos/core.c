// SPDX-License-Identifier: GPL-2.0-only
#include <linux/ebpfos.h>
#include <uapi/linux/ebpfos_root.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

struct ebpfos_control_session {
	struct mutex lock;
	u64 quiesced_object;
};

static int ebpfos_open(struct inode *inode, struct file *file)
{
	struct ebpfos_control_session *session;

	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session)
		return -ENOMEM;
	mutex_init(&session->lock);
	file->private_data = session;
	return 0;
}

static int ebpfos_release(struct inode *inode, struct file *file)
{
	struct ebpfos_control_session *session = file->private_data;

	if (session->quiesced_object)
		ebpfos_executor_root_resume(session->quiesced_object);
	kfree(session);
	return 0;
}

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
	struct ebpfos_control_session *session = file->private_data;
	struct ebpfos_ioc_root_quiesce request;
	long error;

	switch (cmd) {
	case EBPFOS_IOC_VERSION:
		return ebpfos_ioctl_version(argp);
	case EBPFOS_IOC_ADMISSION_SEAL:
		return ebpfos_admission_seal_ioctl(argp);
	case EBPFOS_IOC_ADMISSION_INFO:
		return ebpfos_admission_info_ioctl(argp);
	case EBPFOS_IOC_ADMISSION_RUNTIME_INFO:
		return ebpfos_admission_runtime_info_ioctl(argp);
	case EBPFOS_IOC_ROOT_QUIESCE:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (copy_from_user(&request, argp, sizeof(request)))
			return -EFAULT;
		mutex_lock(&session->lock);
		if (session->quiesced_object) {
			error = -EBUSY;
		} else {
			error = ebpfos_executor_root_quiesce(
				request.object_id, request.expected_epoch);
			if (!error)
				session->quiesced_object = request.object_id;
		}
		mutex_unlock(&session->lock);
		return error;
	case EBPFOS_IOC_ROOT_RESUME:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		mutex_lock(&session->lock);
		if (!session->quiesced_object) {
			error = -EINVAL;
		} else {
			ebpfos_executor_root_resume(session->quiesced_object);
			session->quiesced_object = 0;
			error = 0;
		}
		mutex_unlock(&session->lock);
		return error;
	case EBPFOS_IOC_ROOT_PUBLISH:
		return ebpfos_executor_root_publish_ioctl(argp);
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
