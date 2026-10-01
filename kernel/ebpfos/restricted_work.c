// SPDX-License-Identifier: GPL-2.0-only
/* Generic non-sleepable callback effect: schedule an owner's work item. */
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/ebpfos_restricted_work.h>
#include <linux/err.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <uapi/linux/ebpfos_restricted_work.h>

struct work_route {
	struct list_head node;
	void *queue;
	void *owner;
	u64 id;
	struct bpf_prog *prog;
	bool active;
	atomic64_t native_entries;
	atomic64_t component_entries;
	atomic64_t hardirq_entries;
	atomic64_t faults;
};

static LIST_HEAD(work_routes);
static DEFINE_MUTEX(work_routes_lock);
static atomic64_t work_next_id = ATOMIC64_INIT(0);

static struct work_route *route_for_queue(void *queue)
{
	struct work_route *route;

	list_for_each_entry_rcu(route, &work_routes, node)
		if (route->queue == queue)
			return route;
	return NULL;
}

static struct work_route *route_for_id(u64 id)
{
	struct work_route *route;

	list_for_each_entry(route, &work_routes, node)
		if (route->id == id)
			return route;
	return NULL;
}

void ebpfos_restricted_work_register(void *queue, void *owner)
{
	struct work_route *route, *existing;

	if (IS_ERR_OR_NULL(queue) || !owner)
		return;
	route = kzalloc(sizeof(*route), GFP_KERNEL);
	if (!route)
		return;
	route->queue = queue;
	route->owner = owner;
	route->id = atomic64_inc_return(&work_next_id);
	mutex_lock(&work_routes_lock);
	list_for_each_entry(existing, &work_routes, node)
		if (existing->queue == queue) {
			mutex_unlock(&work_routes_lock);
			kfree(route);
			return;
		}
	list_add_rcu(&route->node, &work_routes);
	mutex_unlock(&work_routes_lock);
}
EXPORT_SYMBOL_GPL(ebpfos_restricted_work_register);

void ebpfos_restricted_work_unregister(void *owner)
{
	struct work_route *route, *next;

	mutex_lock(&work_routes_lock);
	list_for_each_entry_safe(route, next, &work_routes, node) {
		if (route->owner != owner)
			continue;
		list_del_rcu(&route->node);
		synchronize_rcu();
		if (route->prog)
			bpf_prog_put(route->prog);
		kfree(route);
	}
	mutex_unlock(&work_routes_lock);
}
EXPORT_SYMBOL_GPL(ebpfos_restricted_work_unregister);

void ebpfos_restricted_work(void *queue, ebpfos_work_native_t native,
			   struct work_struct *work,
			   struct workqueue_struct *workqueue, u64 scalar)
{
	struct { u64 args[1]; } context = { .args = { scalar } };
	struct work_route *route;
	u32 result;

	rcu_read_lock();
	route = route_for_queue(queue);
	if (!route || !READ_ONCE(route->active) || !READ_ONCE(route->prog))
		goto native;
	result = bpf_prog_run(route->prog, &context);
	if (result > 1) {
		atomic64_inc(&route->faults);
		WRITE_ONCE(route->active, false);
		goto native;
	}
	atomic64_inc(&route->component_entries);
	if (in_hardirq())
		atomic64_inc(&route->hardirq_entries);
	if (result)
		queue_work_on(WORK_CPU_UNBOUND, workqueue, work);
	goto out;
native:
	if (route)
		atomic64_inc(&route->native_entries);
	native(queue);
out:
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(ebpfos_restricted_work);

static long work_ioctl(struct file *file, unsigned int command,
		       unsigned long argument)
{
	struct ebpfos_restricted_work_request request;
	struct work_route *route;
	struct bpf_prog *prog = NULL;
	long result = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, (void __user *)argument, sizeof(request)))
		return -EFAULT;
	if (command == EBPFOS_RESTRICTED_WORK_ATTACH) {
		prog = bpf_prog_get_type(request.prog_fd,
					 BPF_PROG_TYPE_RAW_TRACEPOINT);
		if (IS_ERR(prog))
			return PTR_ERR(prog);
	}
	mutex_lock(&work_routes_lock);
	if (command == EBPFOS_RESTRICTED_WORK_NEXT) {
		u64 next_id = U64_MAX;

		list_for_each_entry(route, &work_routes, node)
			if (route->id > request.id && route->id < next_id)
				next_id = route->id;
		if (next_id == U64_MAX) {
			result = -ENOENT;
			goto out;
		}
		request.id = next_id;
		result = copy_to_user((void __user *)argument, &request,
				      sizeof(request)) ? -EFAULT : 0;
		goto out;
	}
	route = route_for_id(request.id);
	if (!route) {
		result = -ENOENT;
		goto out;
	}
	switch (command) {
	case EBPFOS_RESTRICTED_WORK_ATTACH:
		if (route->prog) {
			result = -EBUSY;
			break;
		}
		WRITE_ONCE(route->prog, prog);
		prog = NULL;
		break;
	case EBPFOS_RESTRICTED_WORK_SWITCH:
		if (request.active && !route->prog) {
			result = -EINVAL;
			break;
		}
		WRITE_ONCE(route->active, !!request.active);
		synchronize_rcu();
		break;
	case EBPFOS_RESTRICTED_WORK_STATS:
		request.native_entries = atomic64_read(&route->native_entries);
		request.component_entries = atomic64_read(&route->component_entries);
		request.hardirq_entries = atomic64_read(&route->hardirq_entries);
		request.faults = atomic64_read(&route->faults);
		request.active = READ_ONCE(route->active);
		result = copy_to_user((void __user *)argument, &request,
				      sizeof(request)) ? -EFAULT : 0;
		break;
	case EBPFOS_RESTRICTED_WORK_DETACH:
		WRITE_ONCE(route->active, false);
		synchronize_rcu();
		if (route->prog) {
			bpf_prog_put(route->prog);
			WRITE_ONCE(route->prog, NULL);
		}
		break;
	default:
		result = -ENOTTY;
	}
out:
	mutex_unlock(&work_routes_lock);
	if (prog)
		bpf_prog_put(prog);
	return result;
}

static const struct file_operations work_ops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = work_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_ptr_ioctl,
#endif
};
static struct miscdevice work_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ebpfos-restricted-work",
	.fops = &work_ops,
};

static int __init restricted_work_init(void)
{
	return misc_register(&work_device);
}
device_initcall(restricted_work_init);
