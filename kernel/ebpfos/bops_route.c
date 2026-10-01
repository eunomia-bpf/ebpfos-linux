// SPDX-License-Identifier: GPL-2.0-only
/* Generic block_device_operations route; the disk's module owns registration. */
#include <linux/atomic.h>
#include <linux/bio.h>
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/capability.h>
#include <linux/ebpfos.h>
#include <linux/ebpfos_fops_route.h>
#include <linux/ebpfos_services.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <uapi/linux/ebpfos_bops_route.h>

#include "bops-route-generated.h"
#include "component_graph.h"

struct ebpfos_bops_route {
	const struct block_device_operations *original;
	struct block_device_operations routed;
	struct ebpfos_component_gate gate;
	atomic64_t linux_entries;
	bool component;
	u64 handle;
	u64 role;
};

struct ebpfos_bops_input {
	u64 sector;
	u32 bytes;
	u32 opf;
};

static DEFINE_MUTEX(ebpfos_bops_route_lock);

static void ebpfos_bops_route_submit_bio(struct bio *bio)
{
	struct gendisk *disk = bio->bi_bdev->bd_disk;
	const struct block_device_operations *ops = READ_ONCE(disk->fops);
	struct ebpfos_bops_route *route =
		container_of(ops, struct ebpfos_bops_route, routed);
	struct ebpfos_component_call_frame frame = {};
	struct ebpfos_bops_input input;
	struct ebpfos_effect_scope *scope;
	u64 epoch = 0;
	u32 provider_id = 0, provider_status = 0;
	int error;

	ebpfos_component_gate_enter(&route->gate);
	if (!READ_ONCE(route->component)) {
		atomic64_inc(&route->linux_entries);
		route->original->submit_bio(bio);
		goto out;
	}
	input.sector = bio->bi_iter.bi_sector;
	input.bytes = bio->bi_iter.bi_size;
	input.opf = bio->bi_opf;
	frame.version = EBPFOS_COMPONENT_CALL_ABI_VERSION;
	frame.method_id = 1;
	frame.object_id = route->handle;
	frame.input_size = sizeof(input);
	memcpy(frame.input, &input, sizeof(input));
	scope = ebpfos_effect_scope_enter_bio(route->handle, bio);
	if (IS_ERR(scope)) {
		error = PTR_ERR(scope);
		goto fail;
	}
	error = ebpfos_fops_route_call(route->handle, route->role, &frame,
				      &epoch, &provider_id, &provider_status);
	if (ebpfos_effect_scope_exit(scope) && !error)
		error = -EPROTO;
	if (!error && (provider_status || frame.status || frame.output_size ||
		       (!bio_no_advance_iter(bio) && bio->bi_iter.bi_size)))
		error = -EPROTO;
	if (error)
		goto fail;
	bio_endio(bio);
	goto out;
fail:
	bio->bi_status = BLK_STS_IOERR;
	bio_endio(bio);
out:
	ebpfos_component_gate_exit(&route->gate);
}

static struct ebpfos_bops_route *ebpfos_bops_route_get(struct gendisk *disk)
{
	const struct block_device_operations *ops = READ_ONCE(disk->fops);

	if (!ops || ops->submit_bio != ebpfos_bops_route_submit_bio)
		return NULL;
	return container_of(ops, struct ebpfos_bops_route, routed);
}

static int ebpfos_bops_route_attach(struct gendisk *disk, u64 handle, u64 role)
{
	struct ebpfos_bops_route *route;
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
	mutex_lock(&ebpfos_bops_route_lock);
	memflags = blk_mq_freeze_queue(disk->queue);
	if (ebpfos_bops_route_get(disk)) {
		error = -EBUSY;
		goto unlock;
	}
	route->original = READ_ONCE(disk->fops);
	if (!route->original || !route->original->submit_bio) {
		error = -EOPNOTSUPP;
		goto unlock;
	}
	if (!try_module_get(route->original->owner)) {
		error = -ENODEV;
		goto unlock;
	}
	route->routed = *route->original;
#define EBPFOS_INSTALL_BOPS(name, method_id) \
	route->routed.name = ebpfos_bops_route_##name;
	EBPFOS_BOPS_ROUTE_METHODS(EBPFOS_INSTALL_BOPS)
#undef EBPFOS_INSTALL_BOPS
	route->handle = handle;
	route->role = role;
	ebpfos_component_gate_init(&route->gate);
	atomic64_set(&route->linux_entries, 0);
	WRITE_ONCE(disk->fops, &route->routed);
unlock:
	blk_mq_unfreeze_queue(disk->queue, memflags);
	mutex_unlock(&ebpfos_bops_route_lock);
	if (!error)
		return 0;
	ebpfos_effect_handle_put(handle);
free:
	kfree(route);
	return error;
}

static int ebpfos_bops_route_detach(struct gendisk *disk)
{
	struct ebpfos_bops_route *route;
	unsigned int memflags;

	mutex_lock(&ebpfos_bops_route_lock);
	route = ebpfos_bops_route_get(disk);
	if (!route) {
		mutex_unlock(&ebpfos_bops_route_lock);
		return -ENOENT;
	}
	ebpfos_component_gate_abort(&route->gate);
	memflags = blk_mq_freeze_queue(disk->queue);
	WRITE_ONCE(disk->fops, route->original);
	blk_mq_unfreeze_queue(disk->queue, memflags);
	mutex_unlock(&ebpfos_bops_route_lock);
	module_put(route->original->owner);
	ebpfos_effect_handle_put(route->handle);
	kfree(route);
	return 0;
}

static long ebpfos_bops_route_ioctl(struct file *control,
				   unsigned int command, unsigned long argument)
{
	struct ebpfos_bops_route_request request;
	struct ebpfos_bops_route *route;
	struct gendisk *disk;
	struct file *target;
	long result = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, (void __user *)argument, sizeof(request)))
		return -EFAULT;
	if (request.flags & ~EBPFOS_BOPS_ROUTE_F_COMPONENT)
		return -EINVAL;
	target = fget(request.fd);
	if (!target)
		return -EBADF;
	if (!S_ISBLK(file_inode(target)->i_mode)) {
		result = -ENOTBLK;
		goto out;
	}
	disk = file_bdev(target)->bd_disk;
	if (command == EBPFOS_BOPS_ROUTE_IOC_ATTACH) {
		result = ebpfos_bops_route_attach(disk, request.handle,
					 request.role);
		goto out;
	}
	if (command == EBPFOS_BOPS_ROUTE_IOC_DETACH) {
		result = ebpfos_bops_route_detach(disk);
		goto out;
	}
	mutex_lock(&ebpfos_bops_route_lock);
	route = ebpfos_bops_route_get(disk);
	if (!route) {
		result = -ENOENT;
		goto unlock;
	}
	switch (command) {
	case EBPFOS_BOPS_ROUTE_IOC_QUIESCE:
		result = ebpfos_component_gate_engage(&route->gate);
		break;
	case EBPFOS_BOPS_ROUTE_IOC_SWITCH:
		if (!READ_ONCE(route->gate.draining))
			result = -EINVAL;
		else
			WRITE_ONCE(route->component,
				request.flags & EBPFOS_BOPS_ROUTE_F_COMPONENT);
		break;
	case EBPFOS_BOPS_ROUTE_IOC_RESUME:
		ebpfos_component_gate_abort(&route->gate);
		break;
	case EBPFOS_BOPS_ROUTE_IOC_STATS:
		request.linux_entries = atomic64_read(&route->linux_entries);
		result = copy_to_user((void __user *)argument, &request,
				      sizeof(request)) ? -EFAULT : 0;
		break;
	default:
		result = -ENOTTY;
	}
unlock:
	mutex_unlock(&ebpfos_bops_route_lock);
out:
	fput(target);
	return result;
}

static const struct file_operations ebpfos_bops_route_control_ops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ebpfos_bops_route_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_ptr_ioctl,
#endif
};

static struct miscdevice ebpfos_bops_route_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ebpfos-block-route",
	.fops = &ebpfos_bops_route_control_ops,
};

static int __init ebpfos_bops_route_init(void)
{
	return misc_register(&ebpfos_bops_route_device);
}
device_initcall(ebpfos_bops_route_init);
