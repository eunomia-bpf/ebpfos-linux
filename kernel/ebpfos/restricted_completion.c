// SPDX-License-Identifier: GPL-2.0-only
/* Generic non-sleepable consume, publish-length and complete effect. */
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/ebpfos_restricted_completion.h>
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
#include <uapi/linux/ebpfos_restricted_completion.h>

struct completion_route {
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

static LIST_HEAD(completion_routes);
static DEFINE_MUTEX(completion_routes_lock);
static atomic64_t completion_next_id = ATOMIC64_INIT(0);

static struct completion_route *route_for_queue(void *queue)
{
	struct completion_route *route;

	list_for_each_entry_rcu(route, &completion_routes, node)
		if (route->queue == queue)
			return route;
	return NULL;
}

static struct completion_route *route_for_id(u64 id)
{
	struct completion_route *route;

	list_for_each_entry(route, &completion_routes, node)
		if (route->id == id)
			return route;
	return NULL;
}

void ebpfos_restricted_completion_register(void *queue, void *owner)
{
	struct completion_route *route, *existing;

	if (IS_ERR_OR_NULL(queue) || !owner)
		return;
	route = kzalloc(sizeof(*route), GFP_KERNEL);
	if (!route)
		return;
	route->queue = queue;
	route->owner = owner;
	route->id = atomic64_inc_return(&completion_next_id);
	mutex_lock(&completion_routes_lock);
	list_for_each_entry(existing, &completion_routes, node)
		if (existing->queue == queue) {
			mutex_unlock(&completion_routes_lock);
			kfree(route);
			return;
		}
	list_add_rcu(&route->node, &completion_routes);
	mutex_unlock(&completion_routes_lock);
}
EXPORT_SYMBOL_GPL(ebpfos_restricted_completion_register);

void ebpfos_restricted_completion_unregister(void *owner)
{
	struct completion_route *route, *next;

	mutex_lock(&completion_routes_lock);
	list_for_each_entry_safe(route, next, &completion_routes, node) {
		if (route->owner != owner)
			continue;
		list_del_rcu(&route->node);
		synchronize_rcu();
		if (route->prog)
			bpf_prog_put(route->prog);
		kfree(route);
	}
	mutex_unlock(&completion_routes_lock);
}
EXPORT_SYMBOL_GPL(ebpfos_restricted_completion_unregister);

void ebpfos_restricted_completion(
	void *queue, ebpfos_completion_native_t native,
	ebpfos_completion_consume_t consume, unsigned int *published,
	struct completion *done)
{
	struct { u64 args[2]; } context;
	struct completion_route *route;
	unsigned int len = 0;
	void *buffer;
	u32 result;

	rcu_read_lock();
	route = route_for_queue(queue);
	if (!route || !READ_ONCE(route->active) || !READ_ONCE(route->prog)) {
		if (route)
			atomic64_inc(&route->native_entries);
		native(queue);
		goto out;
	}
	buffer = consume(queue, &len);
	context.args[0] = !!buffer;
	context.args[1] = len;
	result = bpf_prog_run(route->prog, &context);
	if (result != !!buffer) {
		atomic64_inc(&route->faults);
		atomic64_inc(&route->native_entries);
		WRITE_ONCE(route->active, false);
	} else {
		atomic64_inc(&route->component_entries);
		if (in_hardirq())
			atomic64_inc(&route->hardirq_entries);
	}
	/* A consumed buffer cannot be replayed through native(queue). */
	if (buffer) {
		smp_store_release(published, len);
		complete(done);
	}
out:
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(ebpfos_restricted_completion);

static long completion_ioctl(struct file *file, unsigned int command,
			     unsigned long argument)
{
	struct ebpfos_restricted_completion_request request;
	struct completion_route *route;
	struct bpf_prog *prog = NULL;
	long result = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, (void __user *)argument, sizeof(request)))
		return -EFAULT;
	if (command == EBPFOS_RESTRICTED_COMPLETION_ATTACH) {
		prog = bpf_prog_get_type(request.prog_fd,
					 BPF_PROG_TYPE_RAW_TRACEPOINT);
		if (IS_ERR(prog))
			return PTR_ERR(prog);
	}
	mutex_lock(&completion_routes_lock);
	if (command == EBPFOS_RESTRICTED_COMPLETION_NEXT) {
		u64 next_id = U64_MAX;

		list_for_each_entry(route, &completion_routes, node)
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
	case EBPFOS_RESTRICTED_COMPLETION_ATTACH:
		if (route->prog) {
			result = -EBUSY;
			break;
		}
		WRITE_ONCE(route->prog, prog);
		prog = NULL;
		break;
	case EBPFOS_RESTRICTED_COMPLETION_SWITCH:
		if (request.active && !route->prog) {
			result = -EINVAL;
			break;
		}
		WRITE_ONCE(route->active, !!request.active);
		synchronize_rcu();
		break;
	case EBPFOS_RESTRICTED_COMPLETION_STATS:
		request.native_entries = atomic64_read(&route->native_entries);
		request.component_entries = atomic64_read(&route->component_entries);
		request.hardirq_entries = atomic64_read(&route->hardirq_entries);
		request.faults = atomic64_read(&route->faults);
		request.active = READ_ONCE(route->active);
		result = copy_to_user((void __user *)argument, &request,
				      sizeof(request)) ? -EFAULT : 0;
		break;
	case EBPFOS_RESTRICTED_COMPLETION_DETACH:
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
	mutex_unlock(&completion_routes_lock);
	if (prog)
		bpf_prog_put(prog);
	return result;
}

static const struct file_operations completion_ops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = completion_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_ptr_ioctl,
#endif
};
static struct miscdevice completion_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ebpfos-restricted-completion",
	.fops = &completion_ops,
};

static int __init restricted_completion_init(void)
{
	return misc_register(&completion_device);
}
device_initcall(restricted_completion_init);
