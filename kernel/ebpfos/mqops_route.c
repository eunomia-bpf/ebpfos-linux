// SPDX-License-Identifier: GPL-2.0-only
/* Generic blk_mq_ops request route, scoped to one request_queue. */
#include <linux/atomic.h>
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/capability.h>
#include <linux/ebpfos.h>
#include <linux/ebpfos_fops_route.h>
#include <linux/ebpfos_services.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <uapi/linux/ebpfos_mqops_route.h>

#include "mqops-route-generated.h"
#include "component_graph.h"

struct ebpfos_mqops_route {
	const struct blk_mq_ops *original;
	struct blk_mq_ops routed;
	struct module *owner;
	struct ebpfos_component_gate gate;
	atomic64_t linux_entries;
	atomic64_t component_entries;
	atomic64_t faults;
	bool component;
	u64 handle;
	u64 role;
};

struct ebpfos_mqops_input {
	u64 sector;
	u32 bytes;
	u32 opf;
	u32 last;
};

static DEFINE_MUTEX(ebpfos_mqops_route_lock);

static blk_status_t ebpfos_mqops_route_queue_rq(struct blk_mq_hw_ctx *hctx,
					const struct blk_mq_queue_data *bd)
{
	struct ebpfos_mqops_route *route = container_of(
		READ_ONCE(hctx->queue->mq_ops), struct ebpfos_mqops_route, routed);
	struct ebpfos_component_call_frame frame = {};
	struct ebpfos_mqops_input input;
	blk_status_t status;
	u64 epoch = 0;
	u32 provider_id = 0, provider_status = 0;
	int error;

	ebpfos_component_gate_enter(&route->gate);
	if (!READ_ONCE(route->component) || hctx->type != HCTX_TYPE_DEFAULT) {
		atomic64_inc(&route->linux_entries);
		status = route->original->queue_rq(hctx, bd);
		goto out;
	}
	input.sector = blk_rq_pos(bd->rq);
	input.bytes = blk_rq_bytes(bd->rq);
	input.opf = bd->rq->cmd_flags;
	input.last = bd->last;
	frame.version = EBPFOS_COMPONENT_CALL_ABI_VERSION;
	frame.method_id = 1;
	frame.object_id = route->handle;
	frame.input_size = sizeof(input);
	memcpy(frame.input, &input, sizeof(input));
	error = ebpfos_fops_route_call(route->handle, route->role, &frame,
				      &epoch, &provider_id, &provider_status);
	if (error || provider_status || frame.status || frame.output_size) {
		atomic64_inc(&route->faults);
		WRITE_ONCE(route->component, false);
		atomic64_inc(&route->linux_entries);
		status = route->original->queue_rq(hctx, bd);
		goto out;
	}
	blk_mq_start_request(bd->rq);
	blk_mq_end_request(bd->rq, BLK_STS_OK);
	atomic64_inc(&route->component_entries);
	status = BLK_STS_OK;
out:
	ebpfos_component_gate_exit(&route->gate);
	return status;
}

static struct ebpfos_mqops_route *ebpfos_mqops_route_get(struct request_queue *q)
{
	const struct blk_mq_ops *ops = READ_ONCE(q->mq_ops);

	if (!ops || ops->queue_rq != ebpfos_mqops_route_queue_rq)
		return NULL;
	return container_of(ops, struct ebpfos_mqops_route, routed);
}

static int ebpfos_mqops_route_attach(struct gendisk *disk, u64 handle, u64 role)
{
	struct request_queue *q = disk->queue;
	struct ebpfos_mqops_route *route;
	unsigned int memflags;
	int error;

	if (!handle || !role)
		return -EINVAL;
	route = kzalloc(sizeof(*route), GFP_KERNEL);
	if (!route)
		return -ENOMEM;
	error = ebpfos_effect_handle_get(handle);
	if (error)
		goto free;
	mutex_lock(&ebpfos_mqops_route_lock);
	memflags = blk_mq_freeze_queue(q);
	if (ebpfos_mqops_route_get(q)) {
		error = -EBUSY;
		goto unlock;
	}
	route->original = READ_ONCE(q->mq_ops);
	if (!route->original || !route->original->queue_rq ||
	    route->original->get_budget || route->original->put_budget ||
	    route->original->commit_rqs) {
		error = -EOPNOTSUPP;
		goto unlock;
	}
	route->owner = disk->fops->owner;
	if (!try_module_get(route->owner)) {
		error = -ENODEV;
		goto unlock;
	}
	route->routed = *route->original;
#define EBPFOS_INSTALL_MQOPS(name, method_id) \
	route->routed.name = ebpfos_mqops_route_##name;
	EBPFOS_MQOPS_ROUTE_METHODS(EBPFOS_INSTALL_MQOPS)
#undef EBPFOS_INSTALL_MQOPS
	/* Route every request through queue_rq, including driver batches. */
	route->routed.queue_rqs = NULL;
	route->handle = handle;
	route->role = role;
	ebpfos_component_gate_init(&route->gate);
	WRITE_ONCE(q->mq_ops, &route->routed);
unlock:
	blk_mq_unfreeze_queue(q, memflags);
	mutex_unlock(&ebpfos_mqops_route_lock);
	if (!error)
		return 0;
	ebpfos_effect_handle_put(handle);
free:
	kfree(route);
	return error;
}

static int ebpfos_mqops_route_detach(struct gendisk *disk)
{
	struct request_queue *q = disk->queue;
	struct ebpfos_mqops_route *route;
	unsigned int memflags;

	mutex_lock(&ebpfos_mqops_route_lock);
	route = ebpfos_mqops_route_get(q);
	if (!route) {
		mutex_unlock(&ebpfos_mqops_route_lock);
		return -ENOENT;
	}
	ebpfos_component_gate_abort(&route->gate);
	memflags = blk_mq_freeze_queue(q);
	WRITE_ONCE(q->mq_ops, route->original);
	blk_mq_unfreeze_queue(q, memflags);
	mutex_unlock(&ebpfos_mqops_route_lock);
	module_put(route->owner);
	ebpfos_effect_handle_put(route->handle);
	kfree(route);
	return 0;
}

static long ebpfos_mqops_route_ioctl(struct file *control,
				    unsigned int command, unsigned long argument)
{
	struct ebpfos_mqops_route_request request;
	struct ebpfos_mqops_route *route;
	struct gendisk *disk;
	struct file *target;
	long result = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, (void __user *)argument, sizeof(request)))
		return -EFAULT;
	if (request.flags & ~EBPFOS_MQOPS_ROUTE_F_COMPONENT)
		return -EINVAL;
	target = fget(request.fd);
	if (!target)
		return -EBADF;
	if (!S_ISBLK(file_inode(target)->i_mode)) {
		result = -ENOTBLK;
		goto out;
	}
	disk = file_bdev(target)->bd_disk;
	if (command == EBPFOS_MQOPS_ROUTE_IOC_ATTACH) {
		result = ebpfos_mqops_route_attach(disk, request.handle,
					   request.role);
		goto out;
	}
	if (command == EBPFOS_MQOPS_ROUTE_IOC_DETACH) {
		result = ebpfos_mqops_route_detach(disk);
		goto out;
	}
	mutex_lock(&ebpfos_mqops_route_lock);
	route = ebpfos_mqops_route_get(disk->queue);
	if (!route) {
		result = -ENOENT;
		goto unlock;
	}
	switch (command) {
	case EBPFOS_MQOPS_ROUTE_IOC_QUIESCE:
		result = ebpfos_component_gate_engage(&route->gate);
		break;
	case EBPFOS_MQOPS_ROUTE_IOC_SWITCH:
		if (!READ_ONCE(route->gate.draining))
			result = -EINVAL;
		else
			WRITE_ONCE(route->component,
				request.flags & EBPFOS_MQOPS_ROUTE_F_COMPONENT);
		break;
	case EBPFOS_MQOPS_ROUTE_IOC_RESUME:
		ebpfos_component_gate_abort(&route->gate);
		break;
	case EBPFOS_MQOPS_ROUTE_IOC_STATS:
		request.linux_entries = atomic64_read(&route->linux_entries);
		request.component_entries = atomic64_read(&route->component_entries);
		request.faults = atomic64_read(&route->faults);
		result = copy_to_user((void __user *)argument, &request,
				      sizeof(request)) ? -EFAULT : 0;
		break;
	default:
		result = -ENOTTY;
	}
unlock:
	mutex_unlock(&ebpfos_mqops_route_lock);
out:
	fput(target);
	return result;
}

static const struct file_operations ebpfos_mqops_route_control_ops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ebpfos_mqops_route_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_ptr_ioctl,
#endif
};

static struct miscdevice ebpfos_mqops_route_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ebpfos-mq-route",
	.fops = &ebpfos_mqops_route_control_ops,
};

static int __init ebpfos_mqops_route_init(void)
{
	return misc_register(&ebpfos_mqops_route_device);
}
device_initcall(ebpfos_mqops_route_init);
