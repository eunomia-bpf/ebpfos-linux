// SPDX-License-Identifier: GPL-2.0-only
/* Generated file_operations boundary. No pipe-specific hook is used here. */
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/ebpfos.h>
#include <linux/ebpfos_fops_route.h>
#include <linux/ebpfos_services.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/limits.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/wait.h>
#include <uapi/linux/ebpfos_fops_route.h>

#include "fops-route-generated.h"
#include "component_graph.h"

enum ebpfos_fops_method {
#define EBPFOS_FOPS_METHOD_ID(name, id) EBPFOS_FOPS_METHOD_##name = id,
	EBPFOS_FOPS_ROUTE_ITER_METHODS(EBPFOS_FOPS_METHOD_ID)
	EBPFOS_FOPS_ROUTE_WRITE_METHODS(EBPFOS_FOPS_METHOD_ID)
	EBPFOS_FOPS_ROUTE_POLL_METHODS(EBPFOS_FOPS_METHOD_ID)
	EBPFOS_FOPS_ROUTE_RELEASE_METHODS(EBPFOS_FOPS_METHOD_ID)
	EBPFOS_FOPS_ROUTE_READ_METHODS(EBPFOS_FOPS_METHOD_ID)
	EBPFOS_FOPS_ROUTE_LLSEEK_METHODS(EBPFOS_FOPS_METHOD_ID)
#undef EBPFOS_FOPS_METHOD_ID
};

struct ebpfos_fops_route {
	const struct file_operations *original;
	struct file_operations routed;
	atomic_t active;
	wait_queue_head_t drained;
	struct ebpfos_component_gate gate;
	atomic64_t linux_entries;
	bool component;
	bool extended;
	u64 handle;
	u64 role;
	struct ebpfos_effect_wait_ref *wait;
	poll_table bridge_poll;
	struct list_head bridges;
	int bridge_error;
};

struct ebpfos_fops_bridge {
	struct list_head link;
	wait_queue_head_t *head;
	wait_queue_entry_t entry;
	struct ebpfos_fops_route *route;
};

static DEFINE_MUTEX(ebpfos_fops_route_lock);

static int ebpfos_fops_bridge_wake(wait_queue_entry_t *entry,
				   unsigned int mode, int sync, void *key)
{
	struct ebpfos_fops_bridge *bridge = entry->private;

	ebpfos_effect_wait_ref_wake(bridge->route->wait,
				   EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP);
	return 1;
}

static void ebpfos_fops_bridge_poll(struct file *file,
				    wait_queue_head_t *head, poll_table *table)
{
	struct ebpfos_fops_route *route =
		container_of(table, struct ebpfos_fops_route, bridge_poll);
	struct ebpfos_fops_bridge *bridge;

	list_for_each_entry(bridge, &route->bridges, link)
		if (bridge->head == head)
			return;
	if (route->bridge_error)
		return;
	bridge = kzalloc_obj(*bridge);
	if (!bridge) {
		route->bridge_error = -ENOMEM;
		return;
	}
	bridge->route = route;
	bridge->head = head;
	init_waitqueue_func_entry(&bridge->entry, ebpfos_fops_bridge_wake);
	bridge->entry.private = bridge;
	add_wait_queue(head, &bridge->entry);
	list_add(&bridge->link, &route->bridges);
}

static void ebpfos_fops_bridge_cleanup(struct ebpfos_fops_route *route)
{
	struct ebpfos_fops_bridge *bridge, *next;

	list_for_each_entry_safe(bridge, next, &route->bridges, link) {
		remove_wait_queue(bridge->head, &bridge->entry);
		list_del(&bridge->link);
		kfree(bridge);
	}
	ebpfos_effect_wait_ref_put(route->wait);
	route->wait = NULL;
}

static int ebpfos_fops_route_invoke(struct ebpfos_fops_route *route,
				    struct file *file, struct iov_iter *iter,
				    poll_table *table,
				    struct ebpfos_component_call_frame *frame)
{
	struct ebpfos_effect_scope *scope;
	u64 epoch = 0;
	u32 provider_id = 0, provider_status = 0;
	int error;

	scope = ebpfos_effect_scope_enter(route->handle, file, iter, table);
	if (IS_ERR(scope))
		return PTR_ERR(scope);
	ebpfos_effect_scope_set_nowait(scope, route->wait &&
					    (frame->flags & 1U));
	error = ebpfos_fops_route_call(route->handle, route->role, frame,
				      &epoch, &provider_id, &provider_status);
	if (ebpfos_effect_scope_exit(scope) && !error)
		error = -EPROTO;
	if (!error && provider_status)
		error = -EPROTO;
	return error;
}

/* An absent binding has not entered a provider, so native retry is safe. */
static bool ebpfos_fops_route_fallback(struct ebpfos_fops_route *route,
				       int error)
{
	if (error != -ENOENT)
		return false;
	WRITE_ONCE(route->component, false);
	return true;
}

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
	struct ebpfos_component_call_frame frame = {};
	size_t before, after;
	u64 consumed, seen;
	ssize_t result;
	unsigned int flags;
	bool waitable;
	int error;

	if (!route)
		return -ESTALE;
	waitable = route->wait && !(file->f_flags & O_NONBLOCK) &&
		   !(iocb->ki_flags & IOCB_NOWAIT);
	atomic_inc(&route->active);
	for (;;) {
		before = iov_iter_count(iter);
		seen = waitable ? ebpfos_effect_wait_ref_sequence(route->wait) : 0;
		ebpfos_component_gate_enter(&route->gate);
		if (!READ_ONCE(route->component) ||
		    before > EBPFOS_FOPS_ROUTE_COMPONENT_IO_MAX) {
			flags = iocb->ki_flags;
			if (waitable)
				iocb->ki_flags |= IOCB_NOWAIT;
			result = ebpfos_fops_linux_iter(route, iocb, iter, method);
			iocb->ki_flags = flags;
		} else {
			memset(&frame, 0, sizeof(frame));
			consumed = 0;
			frame.version = EBPFOS_COMPONENT_CALL_ABI_VERSION;
			frame.method_id = method;
			frame.object_id = route->handle;
			frame.flags = waitable || file->f_flags & O_NONBLOCK ? 1 : 0;
			frame.output_capacity = sizeof(consumed);
			memcpy(frame.input, &before, sizeof(before));
			frame.input_size = sizeof(before);
			error = ebpfos_fops_route_invoke(route, file, iter, NULL,
						  &frame);
			if (ebpfos_fops_route_fallback(route, error)) {
				flags = iocb->ki_flags;
				if (waitable)
					iocb->ki_flags |= IOCB_NOWAIT;
				result = ebpfos_fops_linux_iter(route, iocb, iter,
							       method);
				iocb->ki_flags = flags;
				goto iter_done;
			}
			after = iov_iter_count(iter);
			if (!error && frame.output_size != sizeof(consumed))
				error = -EPROTO;
			if (!error) {
				memcpy(&consumed, frame.output, sizeof(consumed));
				if (frame.status || consumed > before ||
				    before - after != consumed)
					error = frame.status < 0 && before == after ?
						frame.status : -EPROTO;
			}
			result = error ? error : consumed;
		}
iter_done:
		ebpfos_component_gate_exit(&route->gate);
		if (!waitable || result != -EAGAIN)
			break;
		if (iov_iter_count(iter) != before) {
			result = -EPROTO;
			break;
		}
		error = ebpfos_effect_wait_ref_wait(route->wait, seen);
		if (error) {
			result = error;
			break;
		}
	}
	if (atomic_dec_and_test(&route->active))
		wake_up_all(&route->drained);
	return result;
}

#define EBPFOS_DEFINE_ITER(name, method_id) \
static ssize_t ebpfos_fops_route_##name(struct kiocb *iocb, \
					struct iov_iter *iter) \
{ \
	return ebpfos_fops_route_iter(iocb, iter, method_id); \
}
EBPFOS_FOPS_ROUTE_METHODS(EBPFOS_DEFINE_ITER)
#undef EBPFOS_DEFINE_ITER

static ssize_t ebpfos_fops_route_write(struct file *file,
				       const char __user *buf, size_t count,
				       loff_t *ppos)
{
	struct ebpfos_fops_route *route = READ_ONCE(file->f_ebpfos_route);
	struct ebpfos_component_call_frame frame = {};
	u64 user_addr = (unsigned long)buf;
	u64 consumed, position = ppos ? *ppos : 0;
	ssize_t result;
	int error;

	if (!route)
		return -ESTALE;
	atomic_inc(&route->active);
	ebpfos_component_gate_enter(&route->gate);
	if (!READ_ONCE(route->component) ||
	    count > EBPFOS_FOPS_ROUTE_COMPONENT_IO_MAX) {
		atomic64_inc(&route->linux_entries);
		result = route->original->write(file, buf, count, ppos);
		goto out;
	}
	frame.version = EBPFOS_COMPONENT_CALL_ABI_VERSION;
	frame.method_id = EBPFOS_FOPS_METHOD_write;
	frame.object_id = route->handle;
	frame.flags = file->f_flags & O_NONBLOCK ? 1 : 0;
	frame.input_size = sizeof(count) + sizeof(user_addr) + sizeof(position);
	frame.output_capacity = sizeof(consumed) + sizeof(position);
	memcpy(frame.input, &count, sizeof(count));
	memcpy(frame.input + sizeof(count), &user_addr, sizeof(user_addr));
	memcpy(frame.input + sizeof(count) + sizeof(user_addr), &position,
	       sizeof(position));
	error = ebpfos_fops_route_invoke(route, file, NULL, NULL, &frame);
	if (ebpfos_fops_route_fallback(route, error)) {
		atomic64_inc(&route->linux_entries);
		result = route->original->write(file, buf, count, ppos);
		goto out;
	}
	if (!error && frame.status < 0)
		error = frame.status;
	if (!error && (frame.status > 0 ||
	    frame.output_size != sizeof(consumed) + sizeof(position)))
		error = -EPROTO;
	if (!error) {
		memcpy(&consumed, frame.output, sizeof(consumed));
		memcpy(&position, frame.output + sizeof(consumed),
		       sizeof(position));
		if (consumed > count || consumed > SSIZE_MAX)
			error = -EPROTO;
		else {
			if (ppos)
				*ppos = position;
			result = consumed;
		}
	}
	if (error)
		result = error;
out:
	ebpfos_component_gate_exit(&route->gate);
	if (atomic_dec_and_test(&route->active))
		wake_up_all(&route->drained);
	return result;
}

static ssize_t ebpfos_fops_route_read(struct file *file, char __user *buf,
				      size_t count, loff_t *ppos)
{
	struct ebpfos_fops_route *route = READ_ONCE(file->f_ebpfos_route);
	struct ebpfos_component_call_frame frame = {};
	u64 user_addr = (unsigned long)buf;
	u64 consumed, position = ppos ? *ppos : 0;
	ssize_t result;
	int error;

	if (!route)
		return -ESTALE;
	atomic_inc(&route->active);
	ebpfos_component_gate_enter(&route->gate);
	if (!READ_ONCE(route->component) ||
	    count > EBPFOS_FOPS_ROUTE_COMPONENT_IO_MAX) {
		atomic64_inc(&route->linux_entries);
		result = route->original->read(file, buf, count, ppos);
		goto out;
	}
	frame.version = EBPFOS_COMPONENT_CALL_ABI_VERSION;
	frame.method_id = EBPFOS_FOPS_METHOD_read;
	frame.object_id = route->handle;
	frame.flags = file->f_flags & O_NONBLOCK ? 1 : 0;
	frame.input_size = sizeof(count) + sizeof(user_addr) + sizeof(position);
	frame.output_capacity = sizeof(consumed) + sizeof(position);
	memcpy(frame.input, &count, sizeof(count));
	memcpy(frame.input + sizeof(count), &user_addr, sizeof(user_addr));
	memcpy(frame.input + sizeof(count) + sizeof(user_addr), &position,
	       sizeof(position));
	error = ebpfos_fops_route_invoke(route, file, NULL, NULL, &frame);
	if (ebpfos_fops_route_fallback(route, error)) {
		atomic64_inc(&route->linux_entries);
		result = route->original->read(file, buf, count, ppos);
		goto out;
	}
	if (!error && frame.status < 0)
		error = frame.status;
	if (!error && (frame.status > 0 ||
	    frame.output_size != sizeof(consumed) + sizeof(position)))
		error = -EPROTO;
	if (!error) {
		memcpy(&consumed, frame.output, sizeof(consumed));
		memcpy(&position, frame.output + sizeof(consumed),
		       sizeof(position));
		if (consumed > count || consumed > SSIZE_MAX)
			error = -EPROTO;
		else {
			if (ppos)
				*ppos = position;
			result = consumed;
		}
	}
	if (error)
		result = error;
out:
	ebpfos_component_gate_exit(&route->gate);
	if (atomic_dec_and_test(&route->active))
		wake_up_all(&route->drained);
	return result;
}

static loff_t ebpfos_fops_route_llseek(struct file *file, loff_t offset,
				       int whence)
{
	struct ebpfos_fops_route *route = READ_ONCE(file->f_ebpfos_route);
	struct ebpfos_component_call_frame frame = {};
	loff_t result;
	int error;

	if (!route)
		return -ESTALE;
	atomic_inc(&route->active);
	ebpfos_component_gate_enter(&route->gate);
	if (!READ_ONCE(route->component)) {
		atomic64_inc(&route->linux_entries);
		result = route->original->llseek(file, offset, whence);
		goto out;
	}
	frame.version = EBPFOS_COMPONENT_CALL_ABI_VERSION;
	frame.method_id = EBPFOS_FOPS_METHOD_llseek;
	frame.object_id = route->handle;
	frame.input_size = sizeof(offset) + sizeof(whence);
	frame.output_capacity = sizeof(result);
	memcpy(frame.input, &offset, sizeof(offset));
	memcpy(frame.input + sizeof(offset), &whence, sizeof(whence));
	error = ebpfos_fops_route_invoke(route, file, NULL, NULL, &frame);
	if (ebpfos_fops_route_fallback(route, error)) {
		atomic64_inc(&route->linux_entries);
		result = route->original->llseek(file, offset, whence);
		goto out;
	}
	if (!error && frame.status < 0)
		error = frame.status;
	if (!error && (frame.status > 0 ||
	    frame.output_size != sizeof(result)))
		error = -EPROTO;
	if (!error) {
		memcpy(&result, frame.output, sizeof(result));
		file->f_pos = result;
	} else {
		result = error;
	}
out:
	ebpfos_component_gate_exit(&route->gate);
	if (atomic_dec_and_test(&route->active))
		wake_up_all(&route->drained);
	return result;
}

static __poll_t ebpfos_fops_route_poll(struct file *file, poll_table *table)
{
	struct ebpfos_fops_route *route = READ_ONCE(file->f_ebpfos_route);
	struct ebpfos_component_call_frame frame = {};
	__poll_t mask = EPOLLERR;
	int error;

	if (!route)
		return EPOLLERR;
	atomic_inc(&route->active);
	ebpfos_component_gate_enter(&route->gate);
	if (!READ_ONCE(route->component)) {
		atomic64_inc(&route->linux_entries);
		mask = route->original->poll(file, table);
		goto out;
	}
	frame.version = EBPFOS_COMPONENT_CALL_ABI_VERSION;
	frame.method_id = EBPFOS_FOPS_METHOD_poll;
	frame.object_id = route->handle;
	frame.output_capacity = sizeof(mask);
	error = ebpfos_fops_route_invoke(route, file, NULL, table, &frame);
	if (ebpfos_fops_route_fallback(route, error)) {
		atomic64_inc(&route->linux_entries);
		mask = route->original->poll(file, table);
	} else if (!error && !frame.status && frame.output_size == sizeof(mask)) {
		memcpy(&mask, frame.output, sizeof(mask));
	}
out:
	ebpfos_component_gate_exit(&route->gate);
	if (atomic_dec_and_test(&route->active))
		wake_up_all(&route->drained);
	return mask;
}

static int ebpfos_fops_route_release(struct inode *inode, struct file *file)
{
	struct ebpfos_fops_route *route = file->f_ebpfos_route;
	const struct file_operations *original = route->original;
	struct ebpfos_component_call_frame frame = {};
	int result = 0;

	WARN_ON_ONCE(atomic_read(&route->active));
	ebpfos_component_gate_enter(&route->gate);
	ebpfos_fops_bridge_cleanup(route);
	if (route->extended && original->release &&
	    READ_ONCE(route->component)) {
		frame.version = EBPFOS_COMPONENT_CALL_ABI_VERSION;
		frame.method_id = EBPFOS_FOPS_METHOD_release;
		frame.object_id = route->handle;
		result = ebpfos_fops_route_invoke(route, file, NULL, NULL,
					  &frame);
		if (ebpfos_fops_route_fallback(route, result))
			goto native;
		if (!result && frame.output_size)
			result = -EPROTO;
		if (!result)
			result = frame.status;
		goto done;
	}
native:
	if (original->release) {
		WRITE_ONCE(file->f_op, original);
		WRITE_ONCE(file->f_ebpfos_route, NULL);
		atomic64_inc(&route->linux_entries);
		result = original->release(inode, file);
	}
done:
	WRITE_ONCE(file->f_op, original);
	WRITE_ONCE(file->f_ebpfos_route, NULL);
	ebpfos_component_gate_exit(&route->gate);
	ebpfos_effect_handle_put(route->handle);
	kfree(route);
	return result;
}

static int ebpfos_fops_route_attach_flags(struct file *file, u64 handle,
					  u64 role, bool extended,
					  bool wait_bridge)
{
	struct ebpfos_fops_route *route;
	int error = 0;

	if (!file || !handle)
		return -EINVAL;
	route = kzalloc(sizeof(*route), GFP_KERNEL);
	if (!route)
		return -ENOMEM;
	INIT_LIST_HEAD(&route->bridges);
	error = ebpfos_effect_handle_get(handle);
	if (error) {
		kfree(route);
		return error;
	}
	mutex_lock(&ebpfos_fops_route_lock);
	if (file->f_op && file->f_op->release == ebpfos_fops_route_release) {
		error = -EBUSY;
		goto out;
	}
	route->original = READ_ONCE(file->f_op);
	if (!route->original || (!route->original->read_iter &&
				 !route->original->write_iter &&
				 !(extended && (route->original->write ||
						 route->original->poll ||
						 route->original->read ||
						 route->original->llseek)))) {
		error = -EOPNOTSUPP;
		goto out;
	}
	if (wait_bridge) {
		if (!(file->f_mode & FMODE_NOWAIT) ||
		    !route->original->poll ||
		    (!route->original->read_iter &&
		     !route->original->write_iter)) {
			error = -EOPNOTSUPP;
			goto out;
		}
		route->wait = ebpfos_effect_wait_ref_get(handle, 0);
		if (IS_ERR(route->wait)) {
			error = PTR_ERR(route->wait);
			route->wait = NULL;
			goto out;
		}
		init_poll_funcptr(&route->bridge_poll,
				  ebpfos_fops_bridge_poll);
		route->original->poll(file, &route->bridge_poll);
		if (route->bridge_error || list_empty(&route->bridges)) {
			error = route->bridge_error ?: -EOPNOTSUPP;
			goto out;
		}
	}
	route->routed = *route->original;
#define EBPFOS_INSTALL_ITER(name, method_id) \
	if (route->original->name) \
		route->routed.name = ebpfos_fops_route_##name;
	EBPFOS_FOPS_ROUTE_METHODS(EBPFOS_INSTALL_ITER)
#undef EBPFOS_INSTALL_ITER
	if (extended && route->original->write)
		route->routed.write = ebpfos_fops_route_write;
	if (extended && route->original->read)
		route->routed.read = ebpfos_fops_route_read;
	if (extended && route->original->llseek)
		route->routed.llseek = ebpfos_fops_route_llseek;
	if (extended && route->original->poll)
		route->routed.poll = ebpfos_fops_route_poll;
	route->routed.release = ebpfos_fops_route_release;
	route->extended = extended;
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
	if (error) {
		ebpfos_fops_bridge_cleanup(route);
		kfree(route);
	}
	if (error)
		ebpfos_effect_handle_put(handle);
	return error;
}

int ebpfos_fops_route_attach(struct file *file, u64 handle, u64 role)
{
	return ebpfos_fops_route_attach_flags(file, handle, role, false, false);
}

int ebpfos_fops_route_detach(struct file *file)
{
	struct ebpfos_fops_route *route;

	if (!file)
		return -EINVAL;
	mutex_lock(&ebpfos_fops_route_lock);
	if (!file->f_op || file->f_op->release != ebpfos_fops_route_release) {
		mutex_unlock(&ebpfos_fops_route_lock);
		return -ENOENT;
	}
	route = file->f_ebpfos_route;
	/* Caller excludes new VFS acquisition. Existing routed calls finish
	 * before restoration. */
	wait_event(route->drained, !atomic_read(&route->active));
	ebpfos_fops_bridge_cleanup(route);
	WRITE_ONCE(file->f_op, route->original);
	WRITE_ONCE(file->f_ebpfos_route, NULL);
	mutex_unlock(&ebpfos_fops_route_lock);
	ebpfos_effect_handle_put(route->handle);
	kfree(route);
	return 0;
}

static struct ebpfos_fops_route *ebpfos_fops_route_get(struct file *file)
{
	if (!file || !file->f_op ||
	    file->f_op->release != ebpfos_fops_route_release)
		return NULL;
	return file->f_ebpfos_route;
}

int ebpfos_fops_route_quiesce(struct file *file)
{
	struct ebpfos_fops_route *route;
	int error;

	mutex_lock(&ebpfos_fops_route_lock);
	route = ebpfos_fops_route_get(file);
	error = route ? ebpfos_component_gate_engage(&route->gate) : -ENOENT;
	mutex_unlock(&ebpfos_fops_route_lock);
	return error;
}

int ebpfos_fops_route_switch(struct file *file, bool component)
{
	struct ebpfos_fops_route *route;
	int error = 0;

	mutex_lock(&ebpfos_fops_route_lock);
	route = ebpfos_fops_route_get(file);
	if (!route)
		error = -ENOENT;
	else if (!READ_ONCE(route->gate.draining))
		error = -EBUSY;
	else
		WRITE_ONCE(route->component, component);
	mutex_unlock(&ebpfos_fops_route_lock);
	return error;
}

void ebpfos_fops_route_resume(struct file *file)
{
	struct ebpfos_fops_route *route;

	mutex_lock(&ebpfos_fops_route_lock);
	route = ebpfos_fops_route_get(file);
	if (route) {
		ebpfos_component_gate_abort(&route->gate);
		if (route->wait)
				ebpfos_effect_wait_ref_wake(route->wait,
					 EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP);
	}
	mutex_unlock(&ebpfos_fops_route_lock);
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
	if ((command == EBPFOS_FOPS_ROUTE_IOC_ATTACH &&
	     request.flags & ~(EBPFOS_FOPS_ROUTE_F_EXTENDED |
			       EBPFOS_FOPS_ROUTE_F_WAIT_BRIDGE)) ||
	    (command != EBPFOS_FOPS_ROUTE_IOC_ATTACH &&
	     request.flags & ~EBPFOS_FOPS_ROUTE_F_COMPONENT))
		return -EINVAL;
	target = fget(request.fd);
	if (!target)
		return -EBADF;
	switch (command) {
	case EBPFOS_FOPS_ROUTE_IOC_ATTACH:
		result = ebpfos_fops_route_attach_flags(target, request.handle,
						request.role,
						request.flags &
						EBPFOS_FOPS_ROUTE_F_EXTENDED,
						request.flags &
						EBPFOS_FOPS_ROUTE_F_WAIT_BRIDGE);
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
