// SPDX-License-Identifier: GPL-2.0-only
/* Generic non-sleepable virtqueue callback effect: increment and schedule NAPI. */
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/ebpfos_restricted_napi.h>
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
#include <uapi/linux/ebpfos_restricted_napi.h>

struct napi_route {
	struct list_head node;
	struct virtqueue *queue;
	void *owner;
	u64 id;
	struct bpf_prog *prog;
	bool active;
	atomic64_t native_entries;
	atomic64_t component_entries;
	atomic64_t hardirq_entries;
	atomic64_t faults;
};

static LIST_HEAD(napi_routes);
static DEFINE_MUTEX(napi_routes_lock);
static atomic64_t napi_next_id = ATOMIC64_INIT(0);

static struct napi_route *route_for_queue(struct virtqueue *queue)
{
	struct napi_route *route;

	list_for_each_entry_rcu(route, &napi_routes, node)
		if (route->queue == queue)
			return route;
	return NULL;
}

static struct napi_route *route_for_id(u64 id)
{
	struct napi_route *route;

	list_for_each_entry(route, &napi_routes, node)
		if (route->id == id)
			return route;
	return NULL;
}

void ebpfos_restricted_napi_register(struct virtqueue *queue, void *owner)
{
	struct napi_route *route, *existing;

	if (IS_ERR_OR_NULL(queue) || !owner)
		return;
	route = kzalloc(sizeof(*route), GFP_KERNEL);
	if (!route)
		return;
	route->queue = queue;
	route->owner = owner;
	route->id = atomic64_inc_return(&napi_next_id);
	mutex_lock(&napi_routes_lock);
	list_for_each_entry(existing, &napi_routes, node)
		if (existing->queue == queue) {
			mutex_unlock(&napi_routes_lock);
			kfree(route);
			return;
		}
	list_add_rcu(&route->node, &napi_routes);
	mutex_unlock(&napi_routes_lock);
}
EXPORT_SYMBOL_GPL(ebpfos_restricted_napi_register);

void ebpfos_restricted_napi_unregister(void *owner)
{
	struct napi_route *route, *next;

	mutex_lock(&napi_routes_lock);
	list_for_each_entry_safe(route, next, &napi_routes, node) {
		if (route->owner != owner)
			continue;
		list_del_rcu(&route->node);
		synchronize_rcu();
		if (route->prog)
			bpf_prog_put(route->prog);
		kfree(route);
	}
	mutex_unlock(&napi_routes_lock);
}
EXPORT_SYMBOL_GPL(ebpfos_restricted_napi_unregister);

void ebpfos_restricted_napi(struct virtqueue *queue,
			    void (*native)(struct virtqueue *),
			    struct napi_struct *napi, u16 *calls)
{
	struct { u64 args[1]; } context = {
		.args = { !napi_is_scheduled(napi) &&
			  !napi_disable_pending(napi) }
	};
	struct napi_route *route;
	u32 result;

	rcu_read_lock();
	route = route_for_queue(queue);
	if (!route || !READ_ONCE(route->active) || !READ_ONCE(route->prog))
		goto native;
	result = bpf_prog_run(route->prog, &context);
	if (result != 1) {
		atomic64_inc(&route->faults);
		WRITE_ONCE(route->active, false);
		goto native;
	}
	(*calls)++;
	if (napi_schedule_prep(napi)) {
		virtqueue_disable_cb(queue);
		__napi_schedule(napi);
	}
	atomic64_inc(&route->component_entries);
	if (in_hardirq())
		atomic64_inc(&route->hardirq_entries);
	goto out;
native:
	if (route)
		atomic64_inc(&route->native_entries);
	native(queue);
out:
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(ebpfos_restricted_napi);

static long napi_ioctl(struct file *file, unsigned int command,
		       unsigned long argument)
{
	struct ebpfos_restricted_napi_request request;
	struct napi_route *route;
	struct bpf_prog *prog = NULL;
	long result = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, (void __user *)argument, sizeof(request)))
		return -EFAULT;
	if (command == EBPFOS_RESTRICTED_NAPI_ATTACH) {
		prog = bpf_prog_get_type(request.prog_fd,
					 BPF_PROG_TYPE_RAW_TRACEPOINT);
		if (IS_ERR(prog))
			return PTR_ERR(prog);
	}
	mutex_lock(&napi_routes_lock);
	if (command == EBPFOS_RESTRICTED_NAPI_NEXT) {
		u64 next_id = U64_MAX;

		list_for_each_entry(route, &napi_routes, node)
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
	case EBPFOS_RESTRICTED_NAPI_ATTACH:
		if (route->prog) {
			result = -EBUSY;
			break;
		}
		WRITE_ONCE(route->prog, prog);
		prog = NULL;
		break;
	case EBPFOS_RESTRICTED_NAPI_SWITCH:
		if (request.active && !route->prog) {
			result = -EINVAL;
			break;
		}
		WRITE_ONCE(route->active, !!request.active);
		synchronize_rcu();
		break;
	case EBPFOS_RESTRICTED_NAPI_STATS:
		request.native_entries = atomic64_read(&route->native_entries);
		request.component_entries = atomic64_read(&route->component_entries);
		request.hardirq_entries = atomic64_read(&route->hardirq_entries);
		request.faults = atomic64_read(&route->faults);
		request.active = READ_ONCE(route->active);
		result = copy_to_user((void __user *)argument, &request,
				      sizeof(request)) ? -EFAULT : 0;
		break;
	case EBPFOS_RESTRICTED_NAPI_DETACH:
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
	mutex_unlock(&napi_routes_lock);
	if (prog)
		bpf_prog_put(prog);
	return result;
}

static const struct file_operations napi_ops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = napi_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_ptr_ioctl,
#endif
};
static struct miscdevice napi_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ebpfos-restricted-napi",
	.fops = &napi_ops,
};

static int __init restricted_napi_init(void)
{
	return misc_register(&napi_device);
}
device_initcall(restricted_napi_init);
