// SPDX-License-Identifier: GPL-2.0-only
/* Generated file_operations boundary. No pipe-specific hook is used here. */
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/ebpfos_fops_route.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/wait.h>
#include <uapi/linux/ebpfos_fops_route.h>

#include "fops-route-generated.h"
#include "component_graph.h"

struct ebpfos_fops_route {
	const struct file_operations *original;
	struct file_operations routed;
	atomic_t active;
	wait_queue_head_t drained;
	struct ebpfos_component_gate gate;
	atomic64_t linux_entries;
	bool component;
	u64 handle;
	u64 role;
};

static DEFINE_MUTEX(ebpfos_fops_route_lock);

static ssize_t ebpfos_fops_linux_iter(struct ebpfos_fops_route *route,
				     struct kiocb *iocb,
				     struct iov_iter *iter, u32 method)
{
	atomic64_inc(&route->linux_entries);
	switch (method) {
#define EBPFOS_LINUX_ITER(name, method_id) \
	case method_id: \
		return route->original->name(iocb, iter);
	EBPFOS_FOPS_ROUTE_METHODS(EBPFOS_LINUX_ITER)
#undef EBPFOS_LINUX_ITER
	default:
		return -EOPNOTSUPP;
	}
}

static ssize_t ebpfos_fops_route_iter(struct kiocb *iocb,
				     struct iov_iter *iter, u32 method)
{
	struct file *file = iocb->ki_filp;
	struct ebpfos_fops_route *route = READ_ONCE(file->f_ebpfos_route);
	struct ebpfos_fops_route_frame frame;
	size_t before, after;
	u64 epoch = 0;
	u32 provider_id = 0, provider_status = 0;
	int error;

	if (!route)
		return -ESTALE;
	atomic_inc(&route->active);
	ebpfos_component_gate_enter(&route->gate);
	if (!READ_ONCE(route->component)) {
		ssize_t result = ebpfos_fops_linux_iter(route, iocb,
						iter, method);

		ebpfos_component_gate_exit(&route->gate);
		if (atomic_dec_and_test(&route->active))
			wake_up_all(&route->drained);
		return result;
	}
	before = iov_iter_count(iter);
	frame = (struct ebpfos_fops_route_frame) {
		.version = EBPFOS_FOPS_ROUTE_FRAME_VERSION,
		.method = method,
		.handle = route->handle,
		.requested = before,
	};
	error = ebpfos_fops_route_call(route->handle, route->role, &frame,
				      &epoch, &provider_id, &provider_status);
	after = iov_iter_count(iter);
	/* A provider cannot claim bytes it did not copy through the terminal
	 * effect. This also rejects a status-only placeholder. */
	if (!error && (provider_status || frame.result > (s64)before ||
		(frame.result >= 0 && (s64)(before - after) != frame.result) ||
		(frame.result < 0 && before != after)))
		error = -EPROTO;
	ebpfos_component_gate_exit(&route->gate);
	if (atomic_dec_and_test(&route->active))
		wake_up_all(&route->drained);
	return error ? error : frame.result;
}

#define EBPFOS_DEFINE_ITER(name, method_id) \
static ssize_t ebpfos_fops_route_##name(struct kiocb *iocb, \
					struct iov_iter *iter) \
{ \
	return ebpfos_fops_route_iter(iocb, iter, method_id); \
}
EBPFOS_FOPS_ROUTE_METHODS(EBPFOS_DEFINE_ITER)
#undef EBPFOS_DEFINE_ITER

static int ebpfos_fops_route_release(struct inode *inode, struct file *file)
{
	struct ebpfos_fops_route *route = file->f_ebpfos_route;
	const struct file_operations *original = route->original;
	int result = 0;

	WARN_ON_ONCE(atomic_read(&route->active));
	WRITE_ONCE(file->f_op, original);
	WRITE_ONCE(file->f_ebpfos_route, NULL);
	if (original->release)
		result = original->release(inode, file);
	kfree(route);
	return result;
}

int ebpfos_fops_route_attach(struct file *file, u64 handle, u64 role)
{
	struct ebpfos_fops_route *route;
	int error = 0;

	if (!file || !handle || !role)
		return -EINVAL;
	route = kzalloc(sizeof(*route), GFP_KERNEL);
	if (!route)
		return -ENOMEM;
	mutex_lock(&ebpfos_fops_route_lock);
	if (file->f_op &&
	    (file->f_op->read_iter == ebpfos_fops_route_read_iter ||
	     file->f_op->write_iter == ebpfos_fops_route_write_iter)) {
		error = -EBUSY;
		goto out;
	}
	route->original = READ_ONCE(file->f_op);
	if (!route->original || (!route->original->read_iter &&
				 !route->original->write_iter)) {
		error = -EOPNOTSUPP;
		goto out;
	}
	route->routed = *route->original;
#define EBPFOS_INSTALL_ITER(name, method_id) \
	if (route->original->name) \
		route->routed.name = ebpfos_fops_route_##name;
	EBPFOS_FOPS_ROUTE_METHODS(EBPFOS_INSTALL_ITER)
#undef EBPFOS_INSTALL_ITER
	route->routed.release = ebpfos_fops_route_release;
	route->handle = handle;
	route->role = role;
	atomic_set(&route->active, 0);
	init_waitqueue_head(&route->drained);
	ebpfos_component_gate_init(&route->gate);
	atomic64_set(&route->linux_entries, 0);
	WRITE_ONCE(file->f_ebpfos_route, route);
	smp_wmb();
	WRITE_ONCE(file->f_op, &route->routed);
out:
	mutex_unlock(&ebpfos_fops_route_lock);
	if (error)
		kfree(route);
	return error;
}

int ebpfos_fops_route_detach(struct file *file)
{
	struct ebpfos_fops_route *route;

	if (!file)
		return -EINVAL;
	mutex_lock(&ebpfos_fops_route_lock);
	if (!file->f_op ||
	    (file->f_op->read_iter != ebpfos_fops_route_read_iter &&
	     file->f_op->write_iter != ebpfos_fops_route_write_iter)) {
		mutex_unlock(&ebpfos_fops_route_lock);
		return -ENOENT;
	}
	route = file->f_ebpfos_route;
	/* Caller has closed the generic gate, so no new VFS entry can cache
	 * the routed table. Existing routed calls finish before restoration. */
	wait_event(route->drained, !atomic_read(&route->active));
	WRITE_ONCE(file->f_op, route->original);
	WRITE_ONCE(file->f_ebpfos_route, NULL);
	mutex_unlock(&ebpfos_fops_route_lock);
	kfree(route);
	return 0;
}

static struct ebpfos_fops_route *ebpfos_fops_route_get(struct file *file)
{
	if (!file || !file->f_op ||
	    (file->f_op->read_iter != ebpfos_fops_route_read_iter &&
	     file->f_op->write_iter != ebpfos_fops_route_write_iter))
		return NULL;
	return file->f_ebpfos_route;
}

int ebpfos_fops_route_quiesce(struct file *file)
{
	struct ebpfos_fops_route *route = ebpfos_fops_route_get(file);

	return route ? ebpfos_component_gate_engage(&route->gate) : -ENOENT;
}

int ebpfos_fops_route_switch(struct file *file, bool component)
{
	struct ebpfos_fops_route *route = ebpfos_fops_route_get(file);

	if (!route)
		return -ENOENT;
	if (!READ_ONCE(route->gate.draining))
		return -EBUSY;
	WRITE_ONCE(route->component, component);
	return 0;
}

void ebpfos_fops_route_resume(struct file *file)
{
	struct ebpfos_fops_route *route = ebpfos_fops_route_get(file);

	if (route)
		ebpfos_component_gate_abort(&route->gate);
}

u64 ebpfos_fops_route_linux_entries(struct file *file)
{
	struct ebpfos_fops_route *route = ebpfos_fops_route_get(file);

	return route ? atomic64_read(&route->linux_entries) : 0;
}

static long ebpfos_fops_route_ioctl(struct file *control,
				   unsigned int command, unsigned long argument)
{
	struct ebpfos_fops_route_request request;
	struct file *target;
	long result;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, (void __user *)argument, sizeof(request)))
		return -EFAULT;
	if (request.flags & ~EBPFOS_FOPS_ROUTE_F_COMPONENT)
		return -EINVAL;
	target = fget(request.fd);
	if (!target)
		return -EBADF;
	switch (command) {
	case EBPFOS_FOPS_ROUTE_IOC_ATTACH:
		result = ebpfos_fops_route_attach(target, request.handle,
						  request.role);
		break;
	case EBPFOS_FOPS_ROUTE_IOC_QUIESCE:
		result = ebpfos_fops_route_quiesce(target);
		break;
	case EBPFOS_FOPS_ROUTE_IOC_SWITCH:
		result = ebpfos_fops_route_switch(target,
				request.flags & EBPFOS_FOPS_ROUTE_F_COMPONENT);
		break;
	case EBPFOS_FOPS_ROUTE_IOC_RESUME:
		ebpfos_fops_route_resume(target);
		result = 0;
		break;
	case EBPFOS_FOPS_ROUTE_IOC_STATS:
		request.linux_entries =
			ebpfos_fops_route_linux_entries(target);
		result = copy_to_user((void __user *)argument, &request,
					      sizeof(request)) ? -EFAULT : 0;
		break;
	case EBPFOS_FOPS_ROUTE_IOC_DETACH:
		result = ebpfos_fops_route_detach(target);
		break;
	default:
		result = -ENOTTY;
	}
	fput(target);
	return result;
}

static const struct file_operations ebpfos_fops_route_control_ops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ebpfos_fops_route_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_ptr_ioctl,
#endif
};

static struct miscdevice ebpfos_fops_route_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ebpfos-route",
	.fops = &ebpfos_fops_route_control_ops,
};

static int __init ebpfos_fops_route_init(void)
{
	return misc_register(&ebpfos_fops_route_device);
}
device_initcall(ebpfos_fops_route_init);
