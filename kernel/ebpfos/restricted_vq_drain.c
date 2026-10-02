// SPDX-License-Identifier: GPL-2.0-only
/* Non-sleepable virtqueue drain and per-buffer completion effect. */
#include <linux/bpf.h>
#ifdef CONFIG_BLOCK
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#endif
#include <linux/capability.h>
#include <linux/completion.h>
#include <linux/ebpfos_restricted_vq_drain.h>
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
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/virtio.h>
#include <linux/workqueue.h>
#include <uapi/linux/ebpfos_restricted_vq_drain.h>

enum drain_delivery {
	DRAIN_COMPLETE,
	DRAIN_BLOCK_REQUEST,
	DRAIN_WORK,
};

struct drain_route {
	struct list_head node;
	struct virtqueue *vq;
	spinlock_t *lock;
	void *owner;
	u64 id;
	u32 completion_offset;
	enum drain_delivery delivery;
	bool *stop;
	u32 work_offset;
	struct workqueue_struct *workqueue;
	struct bpf_prog *prog;
	bool active;
	atomic64_t native_entries;
	atomic64_t component_entries;
	atomic64_t hardirq_entries;
	atomic64_t faults;
};

static LIST_HEAD(drain_routes);
static DEFINE_MUTEX(drain_routes_lock);
static atomic64_t drain_next_id = ATOMIC64_INIT(0);

static struct drain_route *route_for_queue(struct virtqueue *vq)
{
	struct drain_route *route;

	list_for_each_entry_rcu(route, &drain_routes, node)
		if (route->vq == vq)
			return route;
	return NULL;
}

static struct drain_route *route_for_id(u64 id)
{
	struct drain_route *route;

	list_for_each_entry(route, &drain_routes, node)
		if (route->id == id)
			return route;
	return NULL;
}

static void register_route(struct virtqueue *vq, spinlock_t *lock,
		void *owner, enum drain_delivery delivery,
		unsigned int completion_offset, bool *stop,
		unsigned int work_offset, struct workqueue_struct *workqueue)
{
	struct drain_route *route, *existing;

	if (IS_ERR_OR_NULL(vq) || !lock || !owner)
		return;
	route = kzalloc(sizeof(*route), GFP_KERNEL);
	if (!route)
		return;
	route->vq = vq;
	route->lock = lock;
	route->owner = owner;
	route->completion_offset = completion_offset;
	route->delivery = delivery;
	route->stop = stop;
	route->work_offset = work_offset;
	route->workqueue = workqueue;
	route->id = atomic64_inc_return(&drain_next_id);
	mutex_lock(&drain_routes_lock);
	list_for_each_entry(existing, &drain_routes, node)
		if (existing->vq == vq) {
			mutex_unlock(&drain_routes_lock);
			kfree(route);
			return;
		}
	list_add_rcu(&route->node, &drain_routes);
	mutex_unlock(&drain_routes_lock);
}

void ebpfos_restricted_vq_drain_register(struct virtqueue *vq,
		spinlock_t *lock, void *owner, unsigned int completion_offset)
{
	register_route(vq, lock, owner, DRAIN_COMPLETE,
		       completion_offset, NULL, 0, NULL);
}
EXPORT_SYMBOL_GPL(ebpfos_restricted_vq_drain_register);

#ifdef CONFIG_BLOCK
void ebpfos_restricted_vq_drain_register_block(struct virtqueue *vq,
		spinlock_t *lock, void *owner)
{
	register_route(vq, lock, owner, DRAIN_BLOCK_REQUEST, 0, NULL, 0, NULL);
}
EXPORT_SYMBOL_GPL(ebpfos_restricted_vq_drain_register_block);
#endif

void ebpfos_restricted_vq_drain_register_work(struct virtqueue *vq,
		spinlock_t *lock, void *owner, bool *stop,
		unsigned int work_offset, struct workqueue_struct *workqueue)
{
	if (!stop || !workqueue)
		return;
	register_route(vq, lock, owner, DRAIN_WORK,
		       0, stop, work_offset, workqueue);
}
EXPORT_SYMBOL_GPL(ebpfos_restricted_vq_drain_register_work);

void ebpfos_restricted_vq_drain_unregister(void *owner)
{
	struct drain_route *route, *next;

	mutex_lock(&drain_routes_lock);
	list_for_each_entry_safe(route, next, &drain_routes, node) {
		if (route->owner != owner)
			continue;
		list_del_rcu(&route->node);
		synchronize_rcu();
		if (route->prog)
			bpf_prog_put(route->prog);
		kfree(route);
	}
	mutex_unlock(&drain_routes_lock);
}
EXPORT_SYMBOL_GPL(ebpfos_restricted_vq_drain_unregister);

void ebpfos_restricted_vq_drain(struct virtqueue *vq,
		void (*native)(struct virtqueue *vq))
{
	struct drain_route *route;
	unsigned long flags;
	unsigned int len;
	void *buffer;
	bool fault = false;
#ifdef CONFIG_BLOCK
	struct request_queue *stopped_queue = NULL;
#endif

	rcu_read_lock();
	route = route_for_queue(vq);
	if (!route || !READ_ONCE(route->active) || !READ_ONCE(route->prog)) {
		if (route)
			atomic64_inc(&route->native_entries);
		native(vq);
		goto out;
	}
	spin_lock_irqsave(route->lock, flags);
	do {
		virtqueue_disable_cb(vq);
		while ((buffer = virtqueue_get_buf(vq, &len))) {
			struct completion *done = NULL;
			struct { u64 args[3]; } context = {
				.args = { 1, 0, 0 },
			};
#ifdef CONFIG_BLOCK
			struct request *request = NULL;

			if (route->delivery == DRAIN_BLOCK_REQUEST) {
				request = blk_mq_rq_from_pdu(buffer);
				stopped_queue = request->q;
			} else
#endif
			if (route->delivery == DRAIN_WORK) {
				context.args[1] = READ_ONCE(*route->stop);
			} else {
				done = *(struct completion **)
					((char *)buffer + route->completion_offset);
				context.args[1] = !!done;
			}

			if (bpf_prog_run(route->prog, &context) != 1) {
				atomic64_inc(&route->faults);
				WRITE_ONCE(route->active, false);
				fault = true;
			} else {
				atomic64_inc(&route->component_entries);
				if (in_hardirq())
					atomic64_inc(&route->hardirq_entries);
			}
			/* The consumed buffer cannot be replayed by native(vq). */
#ifdef CONFIG_BLOCK
			if (request) {
				if (!blk_should_fake_timeout(stopped_queue))
					blk_mq_complete_request(request);
			} else
#endif
			if (route->delivery == DRAIN_WORK) {
				if (!context.args[1])
					queue_work_on(WORK_CPU_UNBOUND,
						route->workqueue,
						(struct work_struct *)((char *)buffer +
							route->work_offset));
			} else if (done)
				complete(done);
			if (fault)
				break;
		}
		if (fault)
			break;
	} while (!virtqueue_enable_cb(vq));
#ifdef CONFIG_BLOCK
	if (stopped_queue)
		blk_mq_start_stopped_hw_queues(stopped_queue, true);
#endif
	spin_unlock_irqrestore(route->lock, flags);
	if (fault) {
		atomic64_inc(&route->native_entries);
		native(vq);
	}
out:
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(ebpfos_restricted_vq_drain);

static long drain_ioctl(struct file *file, unsigned int command,
			unsigned long argument)
{
	struct ebpfos_restricted_vq_drain_request request;
	struct drain_route *route;
	struct bpf_prog *prog = NULL;
	long result = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, (void __user *)argument, sizeof(request)))
		return -EFAULT;
	if (command == EBPFOS_RESTRICTED_VQ_DRAIN_ATTACH) {
		prog = bpf_prog_get_type(request.prog_fd,
					 BPF_PROG_TYPE_RAW_TRACEPOINT);
		if (IS_ERR(prog))
			return PTR_ERR(prog);
	}
	mutex_lock(&drain_routes_lock);
	if (command == EBPFOS_RESTRICTED_VQ_DRAIN_NEXT) {
		u64 next_id = U64_MAX;

		list_for_each_entry(route, &drain_routes, node)
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
	case EBPFOS_RESTRICTED_VQ_DRAIN_ATTACH:
		if (route->prog) {
			result = -EBUSY;
			break;
		}
		WRITE_ONCE(route->prog, prog);
		prog = NULL;
		break;
	case EBPFOS_RESTRICTED_VQ_DRAIN_SWITCH:
		if (request.active && !route->prog) {
			result = -EINVAL;
			break;
		}
		WRITE_ONCE(route->active, !!request.active);
		synchronize_rcu();
		break;
	case EBPFOS_RESTRICTED_VQ_DRAIN_STATS:
		request.native_entries = atomic64_read(&route->native_entries);
		request.component_entries = atomic64_read(&route->component_entries);
		request.hardirq_entries = atomic64_read(&route->hardirq_entries);
		request.faults = atomic64_read(&route->faults);
		request.active = READ_ONCE(route->active);
		result = copy_to_user((void __user *)argument, &request,
				      sizeof(request)) ? -EFAULT : 0;
		break;
	case EBPFOS_RESTRICTED_VQ_DRAIN_DETACH:
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
	mutex_unlock(&drain_routes_lock);
	if (prog)
		bpf_prog_put(prog);
	return result;
}

static const struct file_operations drain_ops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = drain_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_ptr_ioctl,
#endif
};
static struct miscdevice drain_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ebpfos-restricted-vq-drain",
	.fops = &drain_ops,
};

static int __init restricted_vq_drain_init(void)
{
	return misc_register(&drain_device);
}
device_initcall(restricted_vq_drain_init);
