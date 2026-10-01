// SPDX-License-Identifier: GPL-2.0-only
/* Generic non-sleepable IRQ event: counter update, waiter and async wake. */
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/ebpfos_restricted_irq_event.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/rculist.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <uapi/linux/ebpfos_restricted_irq_event.h>

struct irq_event_route {
	struct list_head node;
	void *data;
	struct file *target;
	struct bpf_prog *prog;
	bool active;
	atomic64_t native_entries;
	atomic64_t component_entries;
	atomic64_t hardirq_entries;
	atomic64_t faults;
};

static LIST_HEAD(irq_event_routes);
static DEFINE_MUTEX(irq_event_lock);

static struct irq_event_route *route_for(void *data)
{
	struct irq_event_route *route;

	list_for_each_entry_rcu(route, &irq_event_routes, node)
		if (route->data == data)
			return route;
	return NULL;
}

static struct irq_event_route *route_for_locked(void *data)
{
	struct irq_event_route *route;

	list_for_each_entry(route, &irq_event_routes, node)
		if (route->data == data)
			return route;
	return NULL;
}

irqreturn_t ebpfos_restricted_irq_event(
	int irq, void *data, irq_handler_t native, spinlock_t *lock,
	unsigned long *counter, wait_queue_head_t *waitqueue,
	struct fasync_struct **async, void __iomem *status, u32 mask,
	unsigned int flags, unsigned int shared_mask,
	unsigned int mode_mask, unsigned int mode_value)
{
	struct { u64 args[2]; } context = { .args = { READ_ONCE(*counter), 0 } };
	struct irq_event_route *route;
	u32 result;
	irqreturn_t answer;

	rcu_read_lock();
	route = route_for(data);
	if (!route || !READ_ONCE(route->active) ||
	    (flags & mode_mask) != mode_value)
		goto native;
	if (flags & shared_mask)
		context.args[1] = !!(readl(status) & mask);
	result = bpf_prog_run(route->prog, &context);
	if (result == IRQ_NONE || result == IRQ_HANDLED) {
		if (result == IRQ_HANDLED &&
		    (flags & shared_mask) && !context.args[1])
			goto fault;
		if (result == IRQ_HANDLED) {
			spin_lock(lock);
			(*counter)++;
			if (flags & shared_mask)
				writel(mask, status);
			spin_unlock(lock);
			wake_up_interruptible(waitqueue);
			kill_fasync(async, SIGIO, POLL_IN);
		}
		atomic64_inc(&route->component_entries);
		if (in_hardirq())
			atomic64_inc(&route->hardirq_entries);
		answer = result;
		goto out;
	}
fault:
	atomic64_inc(&route->faults);
	WRITE_ONCE(route->active, false);
native:
	if (route)
		atomic64_inc(&route->native_entries);
	answer = native(irq, data);
out:
	rcu_read_unlock();
	return answer;
}
EXPORT_SYMBOL_GPL(ebpfos_restricted_irq_event);

static long control_ioctl(struct file *control, unsigned int command,
			  unsigned long argument)
{
	struct ebpfos_restricted_irq_event_request request;
	struct irq_event_route *route, *found = NULL;
	struct file *target;
	long result = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, (void __user *)argument, sizeof(request)))
		return -EFAULT;
	target = fget(request.fd);
	if (!target)
		return -EBADF;
	if (!target->private_data) {
		result = -EINVAL;
		goto out;
	}
	if (command == EBPFOS_RESTRICTED_IRQ_EVENT_ATTACH) {
		route = kzalloc(sizeof(*route), GFP_KERNEL);
		if (!route) {
			result = -ENOMEM;
			goto out;
		}
		route->prog = bpf_prog_get_type(request.prog_fd,
					     BPF_PROG_TYPE_RAW_TRACEPOINT);
		if (IS_ERR(route->prog)) {
			result = PTR_ERR(route->prog);
			kfree(route);
			goto out;
		}
		route->data = target->private_data;
		get_file(target);
		route->target = target;
		mutex_lock(&irq_event_lock);
		if (route_for_locked(route->data)) {
			result = -EBUSY;
			mutex_unlock(&irq_event_lock);
			bpf_prog_put(route->prog);
			fput(route->target);
			kfree(route);
			goto out;
		}
		list_add_rcu(&route->node, &irq_event_routes);
		mutex_unlock(&irq_event_lock);
		goto out;
	}
	mutex_lock(&irq_event_lock);
	found = route_for_locked(target->private_data);
	if (!found) {
		result = -ENOENT;
		goto unlock;
	}
	switch (command) {
	case EBPFOS_RESTRICTED_IRQ_EVENT_SWITCH:
		WRITE_ONCE(found->active, !!request.active);
		synchronize_rcu();
		break;
	case EBPFOS_RESTRICTED_IRQ_EVENT_STATS:
		request.native_entries = atomic64_read(&found->native_entries);
		request.component_entries = atomic64_read(&found->component_entries);
		request.hardirq_entries = atomic64_read(&found->hardirq_entries);
		request.faults = atomic64_read(&found->faults);
		request.active = READ_ONCE(found->active);
		result = copy_to_user((void __user *)argument, &request,
				      sizeof(request)) ? -EFAULT : 0;
		break;
	case EBPFOS_RESTRICTED_IRQ_EVENT_DETACH:
		list_del_rcu(&found->node);
		synchronize_rcu();
		bpf_prog_put(found->prog);
		fput(found->target);
		kfree(found);
		break;
	default:
		result = -ENOTTY;
	}
unlock:
	mutex_unlock(&irq_event_lock);
out:
	fput(target);
	return result;
}

static const struct file_operations control_ops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = control_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_ptr_ioctl,
#endif
};
static struct miscdevice control_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ebpfos-restricted-irq-event",
	.fops = &control_ops,
};

static int __init restricted_irq_event_init(void)
{
	return misc_register(&control_device);
}
device_initcall(restricted_irq_event_init);
