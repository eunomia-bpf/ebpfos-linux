// SPDX-License-Identifier: GPL-2.0-only
/* Non-sleepable request completion route; one program per callback context. */
#include <linux/atomic.h>
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/ebpfos_restricted_block.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <uapi/linux/ebpfos_restricted_block.h>

#include "restricted-block-route-generated.h"

struct ebpfos_restricted_block_route {
	const struct blk_mq_ops *original;
	struct blk_mq_ops routed;
	struct module *owner;
	struct bpf_prog *softirq_prog;
	struct bpf_prog *timer_prog;
	struct bpf_prog *queue_timer_prog;
	u32 status_offset;
	bool active;
	atomic64_t native_entries;
	atomic64_t softirq_entries;
	atomic64_t timer_entries;
	atomic64_t softirq_context_entries;
	atomic64_t hardirq_context_entries;
	atomic64_t faults;
	atomic64_t queue_timer_entries;
	atomic64_t queue_timer_hardirq_entries;
};

static DEFINE_MUTEX(ebpfos_restricted_block_lock);

static struct ebpfos_restricted_block_route *route_for(struct request_queue *q);

static u32 run_restricted(struct bpf_prog *prog, blk_status_t status)
{
	struct { u64 args[1]; } context = { .args = { status } };

	return bpf_prog_run(prog, &context);
}

static u32 run_queue_timer(struct bpf_prog *prog, unsigned int rate,
			   unsigned long current_bytes)
{
	struct { u64 args[2]; } context = { .args = { rate, current_bytes } };

	return bpf_prog_run(prog, &context);
}

static void ebpfos_restricted_block_complete(struct request *rq)
{
	struct ebpfos_restricted_block_route *route = route_for(rq->q);
	struct bpf_prog *prog = route->softirq_prog;
	blk_status_t status;
	u32 result;

	if (!READ_ONCE(route->active))
		goto native;
	if (!prog)
		goto fault;
	status = *(u8 *)((u8 *)blk_mq_rq_to_pdu(rq) + route->status_offset);
	result = run_restricted(prog, status);
	if (result && result <= 256) {
		atomic64_inc(&route->softirq_entries);
		if (in_serving_softirq())
			atomic64_inc(&route->softirq_context_entries);
		blk_mq_end_request(rq, result - 1);
		return;
	}
fault:
	atomic64_inc(&route->faults);
	WRITE_ONCE(route->active, false);
native:
	atomic64_inc(&route->native_entries);
	route->original->complete(rq);
}

enum hrtimer_restart ebpfos_restricted_block_timer(
	struct request *rq, struct hrtimer *timer,
	enum hrtimer_restart (*native)(struct hrtimer *), blk_status_t status)
{
	struct ebpfos_restricted_block_route *route = route_for(rq->q);
	u32 result;

	if (!route || !READ_ONCE(route->active))
		goto native;
	if (!route->timer_prog)
		goto fault;
	result = run_restricted(route->timer_prog, status);
	if ((result & 0xff) && !(result & ~0x1ff) &&
	    (result >> 8) <= HRTIMER_RESTART) {
		atomic64_inc(&route->timer_entries);
		if (in_hardirq())
			atomic64_inc(&route->hardirq_context_entries);
		blk_mq_end_request(rq, (result & 0xff) - 1);
		return result >> 8;
	}
fault:
	atomic64_inc(&route->faults);
	WRITE_ONCE(route->active, false);
native:
	if (route)
		atomic64_inc(&route->native_entries);
	return native(timer);
}
EXPORT_SYMBOL_GPL(ebpfos_restricted_block_timer);

enum hrtimer_restart ebpfos_restricted_block_queue_timer(
	struct request_queue *q, struct hrtimer *timer,
	enum hrtimer_restart (*native)(struct hrtimer *),
	atomic_long_t *counter, unsigned int rate, ktime_t interval)
{
	struct ebpfos_restricted_block_route *route = route_for(q);
	u32 result;

	if (!route || !READ_ONCE(route->active))
		goto native;
	if (!route->queue_timer_prog)
		goto fault;
	result = run_queue_timer(route->queue_timer_prog, rate,
				 atomic_long_read(counter));
	if (result == 0) {
		atomic64_inc(&route->queue_timer_entries);
		if (in_hardirq())
			atomic64_inc(&route->queue_timer_hardirq_entries);
		return HRTIMER_NORESTART;
	}
	if (result != U32_MAX && (result & 3) == 1) {
		atomic_long_set(counter, result >> 2);
		blk_mq_start_stopped_hw_queues(q, true);
		hrtimer_forward(timer, hrtimer_cb_get_time(timer), interval);
		atomic64_inc(&route->queue_timer_entries);
		if (in_hardirq())
			atomic64_inc(&route->queue_timer_hardirq_entries);
		return HRTIMER_RESTART;
	}
fault:
	atomic64_inc(&route->faults);
	WRITE_ONCE(route->active, false);
native:
	if (route)
		atomic64_inc(&route->native_entries);
	return native(timer);
}
EXPORT_SYMBOL_GPL(ebpfos_restricted_block_queue_timer);

static struct ebpfos_restricted_block_route *route_for(struct request_queue *q)
{
	const struct blk_mq_ops *ops = READ_ONCE(q->mq_ops);

	if (!ops || ops->complete != ebpfos_restricted_block_complete)
		return NULL;
	return container_of(ops, struct ebpfos_restricted_block_route, routed);
}

static int attach(struct gendisk *disk,
		  const struct ebpfos_restricted_block_request *request)
{
	struct request_queue *q = disk->queue;
	struct ebpfos_restricted_block_route *route;
	unsigned int memflags;
	int error = 0;

	if (request->status_offset >= q->tag_set->cmd_size)
		return -EINVAL;
	route = kzalloc(sizeof(*route), GFP_KERNEL);
	if (!route)
		return -ENOMEM;
	if (request->softirq_prog_fd >= 0) {
		route->softirq_prog = bpf_prog_get_type(request->softirq_prog_fd,
						 BPF_PROG_TYPE_RAW_TRACEPOINT);
		if (IS_ERR(route->softirq_prog)) {
			error = PTR_ERR(route->softirq_prog);
			route->softirq_prog = NULL;
			goto free;
		}
	}
	if (request->timer_prog_fd >= 0) {
		route->timer_prog = bpf_prog_get_type(request->timer_prog_fd,
					       BPF_PROG_TYPE_RAW_TRACEPOINT);
		if (IS_ERR(route->timer_prog)) {
			error = PTR_ERR(route->timer_prog);
			route->timer_prog = NULL;
			goto free;
		}
	}
	if (request->queue_timer_enabled) {
		route->queue_timer_prog = bpf_prog_get_type(
			request->queue_timer_prog_fd,
			BPF_PROG_TYPE_RAW_TRACEPOINT);
		if (IS_ERR(route->queue_timer_prog)) {
			error = PTR_ERR(route->queue_timer_prog);
			route->queue_timer_prog = NULL;
			goto free;
		}
	}
	mutex_lock(&ebpfos_restricted_block_lock);
	memflags = blk_mq_freeze_queue(q);
	if (route_for(q)) {
		error = -EBUSY;
		goto unlock;
	}
	route->original = READ_ONCE(q->mq_ops);
	if (!route->original || !route->original->complete) {
		error = -EOPNOTSUPP;
		goto unlock;
	}
	route->owner = disk->fops->owner;
	if (!try_module_get(route->owner)) {
		error = -ENODEV;
		goto unlock;
	}
	route->routed = *route->original;
#define EBPFOS_INSTALL_RESTRICTED(name, method_id) \
	route->routed.name = ebpfos_restricted_block_##name;
	EBPFOS_RESTRICTED_BLOCK_METHODS(EBPFOS_INSTALL_RESTRICTED)
#undef EBPFOS_INSTALL_RESTRICTED
	route->status_offset = request->status_offset;
	WRITE_ONCE(q->mq_ops, &route->routed);
unlock:
	blk_mq_unfreeze_queue(q, memflags);
	mutex_unlock(&ebpfos_restricted_block_lock);
	if (!error)
		return 0;
free:
	if (route->timer_prog)
		bpf_prog_put(route->timer_prog);
	if (route->queue_timer_prog)
		bpf_prog_put(route->queue_timer_prog);
	if (route->softirq_prog)
		bpf_prog_put(route->softirq_prog);
	kfree(route);
	return error;
}

static long control_ioctl(struct file *control, unsigned int command,
			  unsigned long argument)
{
	struct ebpfos_restricted_block_request request;
	struct ebpfos_restricted_block_route *route;
	struct request_queue *q;
	struct file *target;
	long result = 0;
	unsigned int memflags;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, (void __user *)argument, sizeof(request)))
		return -EFAULT;
	target = fget(request.fd);
	if (!target)
		return -EBADF;
	if (!S_ISBLK(file_inode(target)->i_mode)) {
		result = -ENOTBLK;
		goto out;
	}
	q = file_bdev(target)->bd_disk->queue;
	if (command == EBPFOS_RESTRICTED_BLOCK_ATTACH) {
		result = attach(file_bdev(target)->bd_disk, &request);
		goto out;
	}
	mutex_lock(&ebpfos_restricted_block_lock);
	route = route_for(q);
	if (!route) {
		result = -ENOENT;
		goto unlock;
	}
	switch (command) {
	case EBPFOS_RESTRICTED_BLOCK_SWITCH:
		memflags = blk_mq_freeze_queue(q);
		WRITE_ONCE(route->active, !!request.active);
		blk_mq_unfreeze_queue(q, memflags);
		break;
	case EBPFOS_RESTRICTED_BLOCK_STATS:
		request.native_entries = atomic64_read(&route->native_entries);
		request.softirq_entries = atomic64_read(&route->softirq_entries);
		request.timer_entries = atomic64_read(&route->timer_entries);
		request.softirq_context_entries =
			atomic64_read(&route->softirq_context_entries);
		request.hardirq_context_entries =
			atomic64_read(&route->hardirq_context_entries);
		request.faults = atomic64_read(&route->faults);
		request.queue_timer_entries = atomic64_read(&route->queue_timer_entries);
		request.queue_timer_hardirq_entries =
			atomic64_read(&route->queue_timer_hardirq_entries);
		request.active = READ_ONCE(route->active);
		result = copy_to_user((void __user *)argument, &request,
				      sizeof(request)) ? -EFAULT : 0;
		break;
	case EBPFOS_RESTRICTED_BLOCK_DETACH:
		memflags = blk_mq_freeze_queue(q);
		WRITE_ONCE(q->mq_ops, route->original);
		blk_mq_unfreeze_queue(q, memflags);
		module_put(route->owner);
		if (route->timer_prog)
			bpf_prog_put(route->timer_prog);
		if (route->queue_timer_prog)
			bpf_prog_put(route->queue_timer_prog);
		if (route->softirq_prog)
			bpf_prog_put(route->softirq_prog);
		kfree(route);
		break;
	default:
		result = -ENOTTY;
	}
unlock:
	mutex_unlock(&ebpfos_restricted_block_lock);
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
	.name = "ebpfos-restricted-block",
	.fops = &control_ops,
};

static int __init restricted_block_init(void)
{
	return misc_register(&control_device);
}
device_initcall(restricted_block_init);
