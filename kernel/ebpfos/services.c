// SPDX-License-Identifier: GPL-2.0-only
/* Generic effects for a sleepable component call on a native object handle. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/bio.h>
#include <linux/ebpfos_services.h>
#include <linux/err.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/net_tstamp.h>
#include <linux/netdevice.h>
#include <linux/poll.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/uio.h>
#include <linux/wait.h>
#include <linux/xarray.h>
#include <uapi/linux/ebpfos_block_effect.h>
#if IS_ENABLED(CONFIG_KUNIT)
#include <kunit/test.h>
#endif

#define EBPFOS_EFFECT_WAIT_SLOTS 8
#define EBPFOS_EFFECT_IRQ_SLOTS 8
#define EBPFOS_EFFECT_COPY_MAX 256

struct ebpfos_effect_wait {
	wait_queue_head_t queue;
	atomic64_t sequence;
};

struct ebpfos_effect_object {
	refcount_t pins;
	atomic_t logical_refs;
	struct mutex lock;
	raw_spinlock_t irq_locks[EBPFOS_EFFECT_IRQ_SLOTS];
	struct mutex block_pages_lock;
	struct xarray block_pages;
	struct fasync_struct *fasync;
	struct ebpfos_effect_wait wait[EBPFOS_EFFECT_WAIT_SLOTS];
};

struct ebpfos_effect_task {
	struct ebpfos_effect_scope *top;
};

struct ebpfos_effect_scope {
	u64 handle;
	struct ebpfos_effect_object *object;
	struct ebpfos_effect_task *task;
	struct ebpfos_effect_scope *previous;
	struct file *file;
	struct iov_iter *iter;
	struct poll_table_struct *poll;
	struct bio *bio;
	struct bvec_iter bio_iter;
	u64 bio_bytes;
	struct net_device *netdev;
	struct sk_buff *skb;
	u32 net_stats_bytes;
	bool net_stats_pending;
	bool net_timestamp_pending;
	size_t copied_from_iter;
	bool locked;
};

/* tty_ioctl is retained in the generic route's copied file_operations. */
extern long tty_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

static DEFINE_XARRAY(ebpfos_effect_objects);
static DEFINE_MUTEX(ebpfos_effect_objects_lock);
static DEFINE_XARRAY(ebpfos_effect_tasks);

static void ebpfos_effect_object_destroy(struct ebpfos_effect_object *object)
{
	struct page *page;
	unsigned long index;
	int i;

	xa_for_each(&object->block_pages, index, page)
		__free_page(page);
	xa_destroy(&object->block_pages);
	for (i = 0; i < EBPFOS_EFFECT_WAIT_SLOTS; i++)
		wake_up_pollfree(&object->wait[i].queue);
	synchronize_rcu();
	kfree(object);
}

static struct ebpfos_effect_object *ebpfos_effect_object_get(u64 handle)
{
	struct ebpfos_effect_object *object;
	int error, i;

	if (!handle)
		return ERR_PTR(-EINVAL);
	mutex_lock(&ebpfos_effect_objects_lock);
	object = xa_load(&ebpfos_effect_objects, handle);
	if (object) {
		refcount_inc(&object->pins);
		goto out;
	}
	object = kzalloc_obj(*object);
	if (!object) {
		object = ERR_PTR(-ENOMEM);
		goto out;
	}
	refcount_set(&object->pins, 1);
	atomic_set(&object->logical_refs, 1);
	mutex_init(&object->lock);
	for (i = 0; i < EBPFOS_EFFECT_IRQ_SLOTS; i++)
		raw_spin_lock_init(&object->irq_locks[i]);
	mutex_init(&object->block_pages_lock);
	xa_init(&object->block_pages);
	for (i = 0; i < EBPFOS_EFFECT_WAIT_SLOTS; i++) {
		init_waitqueue_head(&object->wait[i].queue);
		atomic64_set(&object->wait[i].sequence, 0);
	}
	error = xa_insert(&ebpfos_effect_objects, handle, object, GFP_KERNEL);
	if (error) {
		kfree(object);
		object = ERR_PTR(error);
	}
out:
	mutex_unlock(&ebpfos_effect_objects_lock);
	return object;
}

static struct ebpfos_effect_object *ebpfos_effect_object_lookup(u64 handle)
{
	struct ebpfos_effect_object *object;

	mutex_lock(&ebpfos_effect_objects_lock);
	object = xa_load(&ebpfos_effect_objects, handle);
	if (object)
		refcount_inc(&object->pins);
	mutex_unlock(&ebpfos_effect_objects_lock);
	return object;
}

static void ebpfos_effect_object_put(u64 handle,
				     struct ebpfos_effect_object *object)
{
	bool last;

	mutex_lock(&ebpfos_effect_objects_lock);
	last = refcount_dec_and_test(&object->pins);
	if (last)
		xa_erase(&ebpfos_effect_objects, handle);
	mutex_unlock(&ebpfos_effect_objects_lock);
	if (last)
		ebpfos_effect_object_destroy(object);
}

int ebpfos_effect_handle_get(u64 handle)
{
	struct ebpfos_effect_object *object = ebpfos_effect_object_get(handle);

	return IS_ERR(object) ? PTR_ERR(object) : 0;
}

void ebpfos_effect_handle_put(u64 handle)
{
	struct ebpfos_effect_object *object;
	bool last = false;

	mutex_lock(&ebpfos_effect_objects_lock);
	object = xa_load(&ebpfos_effect_objects, handle);
	if (object) {
		last = refcount_dec_and_test(&object->pins);
		if (last)
			xa_erase(&ebpfos_effect_objects, handle);
	}
	mutex_unlock(&ebpfos_effect_objects_lock);
	if (last)
		ebpfos_effect_object_destroy(object);
}

struct ebpfos_effect_scope *ebpfos_effect_scope_enter(u64 handle,
						      struct file *file,
						      struct iov_iter *iter,
						      struct poll_table_struct *table)
{
	struct ebpfos_effect_scope *scope;
	struct ebpfos_effect_task *task;
	int error;

	scope = kzalloc_obj(*scope);
	if (!scope)
		return ERR_PTR(-ENOMEM);
	scope->object = ebpfos_effect_object_lookup(handle);
	if (!scope->object) {
		error = -ENOENT;
		goto out_free_scope;
	}
	task = xa_load(&ebpfos_effect_tasks, (unsigned long)current);
	if (task && task->top && task->top->handle == handle &&
	    task->top->locked) {
		error = -EDEADLK;
		goto out_put;
	}
	if (!task) {
		task = kzalloc_obj(*task);
		if (!task) {
			error = -ENOMEM;
			goto out_put;
		}
		error = xa_insert(&ebpfos_effect_tasks, (unsigned long)current,
				  task, GFP_KERNEL);
		if (error) {
			kfree(task);
			goto out_put;
		}
	}
	scope->handle = handle;
	scope->task = task;
	scope->previous = task->top;
	scope->file = file;
	scope->iter = iter;
	scope->poll = table;
	task->top = scope;
	return scope;
out_put:
	ebpfos_effect_object_put(handle, scope->object);
out_free_scope:
	kfree(scope);
	return ERR_PTR(error);
}

struct ebpfos_effect_scope *ebpfos_effect_scope_enter_bio(u64 handle,
						   struct bio *bio)
{
	struct ebpfos_effect_scope *scope;

	if (!bio)
		return ERR_PTR(-EINVAL);
	scope = ebpfos_effect_scope_enter(handle, NULL, NULL, NULL);
	if (!IS_ERR(scope)) {
		scope->bio = bio;
		scope->bio_iter = bio->bi_iter;
	}
	return scope;
}

int ebpfos_effect_scope_exit(struct ebpfos_effect_scope *scope)
{
	struct ebpfos_effect_task *task;
	int error = 0;

	if (IS_ERR_OR_NULL(scope))
		return -EINVAL;
	task = scope->task;
	if (task->top != scope)
		return -EINVAL;
	if (scope->locked) {
		mutex_unlock(&scope->object->lock);
		error = -EPROTO;
	}
	if (scope->bio) {
		scope->bio_iter.bi_sector = scope->bio->bi_iter.bi_sector +
			(scope->bio_bytes >> SECTOR_SHIFT);
		scope->bio->bi_iter = scope->bio_iter;
	}
	task->top = scope->previous;
	if (!task->top) {
		xa_erase(&ebpfos_effect_tasks, (unsigned long)current);
		kfree(task);
	}
	ebpfos_effect_object_put(scope->handle, scope->object);
	kfree(scope);
	return error;
}

struct ebpfos_effect_scope *ebpfos_effect_net_scope_enter(u64 handle,
						 struct net_device *dev,
						 struct sk_buff *skb)
{
	struct ebpfos_effect_scope *scope;

	if (!dev || !skb)
		return ERR_PTR(-EINVAL);
	scope = ebpfos_effect_scope_enter(handle, NULL, NULL, NULL);
	if (IS_ERR(scope))
		return scope;
	scope->netdev = dev;
	scope->skb = skb;
	return scope;
}

bool ebpfos_effect_net_skb_pending(struct ebpfos_effect_scope *scope)
{
	return !IS_ERR_OR_NULL(scope) && scope->skb;
}

static struct ebpfos_effect_scope *ebpfos_effect_current(u64 handle)
{
	struct ebpfos_effect_task *task;

	task = xa_load(&ebpfos_effect_tasks, (unsigned long)current);
	if (!task || !task->top || task->top->handle != handle)
		return NULL;
	return task->top;
}

void ebpfos_effect_poll(u64 handle, u32 slot, struct file *file,
			struct poll_table_struct *table)
{
	struct ebpfos_effect_object *object;

	if (slot >= EBPFOS_EFFECT_WAIT_SLOTS)
		return;
	object = ebpfos_effect_object_lookup(handle);
	if (!object)
		return;
	poll_wait(file, &object->wait[slot].queue, table);
	ebpfos_effect_object_put(handle, object);
}

int ebpfos_effect_fasync(u64 handle, int fd, struct file *file, int on)
{
	struct ebpfos_effect_object *object;
	int error;

	object = ebpfos_effect_object_lookup(handle);
	if (!object)
		return -ENOENT;
	error = fasync_helper(fd, file, on, &object->fasync);
	ebpfos_effect_object_put(handle, object);
	return error;
}

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_ebpfos_effect_lock(u64 handle)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);

	if (!scope)
		return -EPERM;
	if (scope->locked)
		return -EDEADLK;
	mutex_lock(&scope->object->lock);
	scope->locked = true;
	return 0;
}

__bpf_kfunc int bpf_ebpfos_effect_unlock(u64 handle)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);

	if (!scope || !scope->locked)
		return -EPERM;
	scope->locked = false;
	mutex_unlock(&scope->object->lock);
	return 0;
}

/* The IRQ lock never spans BPF instructions or sleepable helper calls. */
__bpf_kfunc u64 bpf_ebpfos_effect_irq_cmpxchg(u64 handle, u32 kind,
					       u64 *value, u64 expected, u64 desired)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);
	unsigned long flags;
	u64 observed;

	if (!scope || kind >= EBPFOS_EFFECT_IRQ_SLOTS || !value)
		return U64_MAX;
	raw_spin_lock_irqsave(&scope->object->irq_locks[kind], flags);
	observed = READ_ONCE(*value);
	if (observed == expected)
		WRITE_ONCE(*value, desired);
	raw_spin_unlock_irqrestore(&scope->object->irq_locks[kind], flags);
	return observed;
}

__bpf_kfunc s64 bpf_ebpfos_effect_sequence(u64 handle, u32 slot)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);

	if (!scope || slot >= EBPFOS_EFFECT_WAIT_SLOTS)
		return -EINVAL;
	return atomic64_read(&scope->object->wait[slot].sequence);
}

__bpf_kfunc int bpf_ebpfos_effect_wait(u64 handle, u32 slot, u64 seen)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);
	struct ebpfos_effect_wait *wait;

	if (!scope || slot >= EBPFOS_EFFECT_WAIT_SLOTS)
		return -EINVAL;
	if (scope->locked)
		return -EDEADLK;
	wait = &scope->object->wait[slot];
	return wait_event_interruptible(wait->queue,
			atomic64_read(&wait->sequence) != seen);
}

/* Enter with the object lock held; return with it held even on a signal. */
__bpf_kfunc int bpf_ebpfos_effect_wait_locked(u64 handle, u32 slot)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);
	struct ebpfos_effect_wait *wait;
	u64 seen;
	int ret;

	if (!scope || !scope->locked || slot >= EBPFOS_EFFECT_WAIT_SLOTS)
		return -EINVAL;
	wait = &scope->object->wait[slot];
	seen = atomic64_read(&wait->sequence);
	scope->locked = false;
	mutex_unlock(&scope->object->lock);
	ret = wait_event_interruptible(wait->queue,
			atomic64_read(&wait->sequence) != seen);
	mutex_lock(&scope->object->lock);
	scope->locked = true;
	return ret;
}

__bpf_kfunc int bpf_ebpfos_effect_wake(u64 handle, u32 slot, u32 mask)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);
	struct ebpfos_effect_wait *wait;

	if (!scope || slot >= EBPFOS_EFFECT_WAIT_SLOTS)
		return -EINVAL;
	wait = &scope->object->wait[slot];
	atomic64_inc(&wait->sequence);
	wake_up_interruptible_poll(&wait->queue, mask);
	return 0;
}

__bpf_kfunc int bpf_ebpfos_effect_poll(u64 handle, u32 slot)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);

	if (!scope || !scope->file || !scope->poll ||
	    slot >= EBPFOS_EFFECT_WAIT_SLOTS)
		return -EINVAL;
	poll_wait(scope->file, &scope->object->wait[slot].queue, scope->poll);
	return 0;
}

__bpf_kfunc long bpf_ebpfos_effect_copy_from_iter(u64 handle,
					   void *dst, u32 dst__sz)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);
	long copied;

	if (!scope || !scope->iter || !dst || !dst__sz ||
	    dst__sz > EBPFOS_EFFECT_COPY_MAX)
		return -EINVAL;
	copied = copy_from_iter(dst, dst__sz, scope->iter);
	scope->copied_from_iter += copied;
	return copied;
}

__bpf_kfunc int bpf_ebpfos_effect_iter_revert(u64 handle, u32 count)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);

	if (!scope || !scope->iter || count > scope->copied_from_iter)
		return -EINVAL;
	iov_iter_revert(scope->iter, count);
	scope->copied_from_iter -= count;
	return 0;
}

__bpf_kfunc long bpf_ebpfos_effect_tty_emit(u64 handle, const void *src,
					     u32 src__sz, u32 flags)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);
	struct tty_file_private *private;
	struct tty_struct *tty;
	long written;

	if (!scope || !scope->file || !src || !src__sz ||
	    src__sz > EBPFOS_EFFECT_COPY_MAX || flags & ~1U ||
	    scope->file->f_op->unlocked_ioctl != tty_ioctl)
		return -EINVAL;
	private = scope->file->private_data;
	if (!private || !private->tty)
		return -EIO;
	tty = private->tty;
	if (!tty->ops || !tty->ops->write || tty_io_error(tty))
		return -EIO;
	if (!mutex_trylock(&tty->atomic_write_lock)) {
		if (flags & 1U)
			return -EAGAIN;
		if (mutex_lock_interruptible(&tty->atomic_write_lock))
			return -ERESTARTSYS;
	}
	written = tty->ops->write(tty, src, src__sz);
	mutex_unlock(&tty->atomic_write_lock);
	wake_up_interruptible_poll(&tty->write_wait, EPOLLOUT);
	return written;
}

__bpf_kfunc long bpf_ebpfos_effect_copy_to_iter(u64 handle,
						 const void *src, u32 src__sz)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);

	if (!scope || !scope->iter || !src || !src__sz ||
	    src__sz > EBPFOS_EFFECT_COPY_MAX)
		return -EINVAL;
	return copy_to_iter(src, src__sz, scope->iter);
}

__bpf_kfunc int bpf_ebpfos_effect_bio_peek(u64 handle, void *out,
					     u32 out__sz)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);
	struct ebpfos_block_segment segment;
	struct bio_vec bv;

	if (!scope || !scope->bio || !out || out__sz != sizeof(segment))
		return -EINVAL;
	if (!scope->bio_iter.bi_size)
		return 0;
	if (bio_no_advance_iter(scope->bio))
		return -EOPNOTSUPP;
	bv = bio_iter_iovec(scope->bio, scope->bio_iter);
	segment.byte_offset = ((u64)scope->bio->bi_iter.bi_sector <<
			       SECTOR_SHIFT) + scope->bio_bytes;
	segment.bytes = min_t(u32, bv.bv_len, EBPFOS_EFFECT_COPY_MAX);
	segment.bytes = min_t(u32, segment.bytes,
				 PAGE_SIZE - (segment.byte_offset & (PAGE_SIZE - 1)));
	segment.opf = scope->bio->bi_opf;
	memcpy(out, &segment, sizeof(segment));
	return 1;
}

static long ebpfos_effect_bio_copy(u64 handle, void *buffer, u32 bytes,
				   bool to_bio)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);
	struct bio_vec bv;
	void *mapped;

	if (!scope || !scope->bio || !buffer || !bytes ||
	    bytes > EBPFOS_EFFECT_COPY_MAX || bytes > scope->bio_iter.bi_size)
		return -EINVAL;
	if (bio_no_advance_iter(scope->bio))
		return -EOPNOTSUPP;
	bv = bio_iter_iovec(scope->bio, scope->bio_iter);
	if (bytes > bv.bv_len)
		return -EINVAL;
	mapped = bvec_kmap_local(&bv);
	if (to_bio)
		memcpy(mapped, buffer, bytes);
	else
		memcpy(buffer, mapped, bytes);
	kunmap_local(mapped);
	bvec_iter_advance_single(scope->bio->bi_io_vec, &scope->bio_iter, bytes);
	scope->bio_bytes += bytes;
	return bytes;
}

__bpf_kfunc long bpf_ebpfos_effect_bio_read(u64 handle,
					     void *dst, u32 dst__sz)
{
	return ebpfos_effect_bio_copy(handle, dst, dst__sz, false);
}

__bpf_kfunc long bpf_ebpfos_effect_bio_write(u64 handle,
					      const void *src, u32 src__sz)
{
	return ebpfos_effect_bio_copy(handle, (void *)src, src__sz, true);
}

static long ebpfos_effect_block_copy(u64 handle, u64 offset, void *buffer,
				     u32 bytes, bool write)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);
	struct ebpfos_effect_object *object;
	struct page *page;
	void *mapped;
	u64 bio_base;
	u64 index = offset >> PAGE_SHIFT;
	u32 within = offset & (PAGE_SIZE - 1);
	int error = 0;

	if (!scope || !scope->bio || !buffer || !bytes ||
	    bytes > EBPFOS_EFFECT_COPY_MAX || bytes > PAGE_SIZE - within ||
	    index > ULONG_MAX)
		return -EINVAL;
	bio_base = (u64)scope->bio->bi_iter.bi_sector << SECTOR_SHIFT;
	if (offset < bio_base || offset - bio_base > scope->bio->bi_iter.bi_size ||
	    bytes > scope->bio->bi_iter.bi_size - (offset - bio_base))
		return -EINVAL;
	object = scope->object;
	mutex_lock(&object->block_pages_lock);
	page = xa_load(&object->block_pages, index);
	if (!page && write) {
		page = alloc_page(GFP_NOIO | __GFP_ZERO | __GFP_HIGHMEM);
		if (!page) {
			error = -ENOMEM;
			goto out;
		}
		error = xa_insert(&object->block_pages, index, page, GFP_NOIO);
		if (error) {
			__free_page(page);
			goto out;
		}
	}
	if (!page) {
		memset(buffer, 0, bytes);
		goto out;
	}
	mapped = kmap_local_page(page);
	if (write)
		memcpy(mapped + within, buffer, bytes);
	else
		memcpy(buffer, mapped + within, bytes);
	kunmap_local(mapped);
out:
	mutex_unlock(&object->block_pages_lock);
	return error ?: bytes;
}

__bpf_kfunc long bpf_ebpfos_effect_block_read(u64 handle, u64 offset,
					       void *dst, u32 dst__sz)
{
	return ebpfos_effect_block_copy(handle, offset, dst, dst__sz, false);
}

__bpf_kfunc long bpf_ebpfos_effect_block_write(u64 handle, u64 offset,
						const void *src, u32 src__sz)
{
	return ebpfos_effect_block_copy(handle, offset, (void *)src, src__sz,
						true);
}

__bpf_kfunc u64 bpf_ebpfos_effect_current_handle(void)
{
	struct ebpfos_effect_task *task;

	task = xa_load(&ebpfos_effect_tasks, (unsigned long)current);
	return task && task->top ? task->top->handle : 0;
}

__bpf_kfunc u32 bpf_ebpfos_effect_file_flags(u64 handle)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);

	return scope && scope->file ? READ_ONCE(scope->file->f_flags) : 0;
}

__bpf_kfunc bool bpf_ebpfos_effect_access_ok(u64 handle, u64 user_addr,
					       u32 size)
{
	return ebpfos_effect_current(handle) &&
		access_ok((const void __user *)(unsigned long)user_addr, size);
}

__bpf_kfunc unsigned long bpf_ebpfos_effect_copy_from_user(u64 handle,
					void *dst, u32 dst__sz, u64 user_addr)
{
	if (!ebpfos_effect_current(handle) || !dst || !dst__sz ||
	    dst__sz > EBPFOS_EFFECT_COPY_MAX)
		return dst__sz;
	return copy_from_user(dst, (const void __user *)(unsigned long)user_addr,
			      dst__sz);
}

__bpf_kfunc unsigned long bpf_ebpfos_effect_copy_to_user(u64 handle,
					   u64 user_addr, const void *src,
					   u32 src__sz)
{
	if (!ebpfos_effect_current(handle) || !src || !src__sz ||
	    src__sz > EBPFOS_EFFECT_COPY_MAX)
		return src__sz;
	return copy_to_user((void __user *)(unsigned long)user_addr, src,
			    src__sz);
}

__bpf_kfunc int bpf_ebpfos_effect_signal_pending(u64 handle)
{
	return ebpfos_effect_current(handle) ? signal_pending(current) : -EPERM;
}

__bpf_kfunc int bpf_ebpfos_effect_signal(u64 handle, int signal)
{
	if (!ebpfos_effect_current(handle) || !valid_signal(signal))
		return -EINVAL;
	return send_sig(signal, current, 0);
}

__bpf_kfunc int bpf_ebpfos_effect_fasync(u64 handle, int signal, int band)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);

	if (!scope || !valid_signal(signal))
		return -EINVAL;
	kill_fasync(&scope->object->fasync, signal, band);
	return 0;
}

__bpf_kfunc int bpf_ebpfos_effect_ref_get(u64 handle)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);
	int refs;

	if (!scope)
		return -EPERM;
	refs = atomic_read(&scope->object->logical_refs);
	do {
		if (refs <= 0)
			return -ESTALE;
		if (refs == INT_MAX)
			return -EOVERFLOW;
	} while (!atomic_try_cmpxchg(&scope->object->logical_refs,
				      &refs, refs + 1));
	return 0;
}

__bpf_kfunc int bpf_ebpfos_effect_ref_put(u64 handle)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);
	int refs;

	if (!scope)
		return -EPERM;
	refs = atomic_read(&scope->object->logical_refs);
	do {
		if (refs <= 0)
			return -EINVAL;
	} while (!atomic_try_cmpxchg(&scope->object->logical_refs,
				      &refs, refs - 1));
	return refs - 1;
}

/* A routed network call owns the skb until the terminal consume effect. */
__bpf_kfunc s64 bpf_ebpfos_effect_net_skb_len(u64 handle)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);

	return scope && scope->skb ? scope->skb->len : -EPERM;
}

__bpf_kfunc int bpf_ebpfos_effect_net_lstats_add(u64 handle, u32 bytes)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);

	if (!scope || !scope->netdev || !scope->skb ||
	    bytes != scope->skb->len || scope->net_stats_pending)
		return -EINVAL;
	scope->net_stats_bytes = bytes;
	scope->net_stats_pending = true;
	return 0;
}

__bpf_kfunc int bpf_ebpfos_effect_net_tx_timestamp(u64 handle)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);

	if (!scope || !scope->skb || scope->net_timestamp_pending)
		return -EINVAL;
	scope->net_timestamp_pending = true;
	return 0;
}

__bpf_kfunc int bpf_ebpfos_effect_net_consume_skb(u64 handle)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);
	struct sk_buff *skb;

	if (!scope || !scope->netdev || !scope->skb)
		return -EPERM;
	skb = scope->skb;
	scope->skb = NULL;
	if (scope->net_stats_pending)
		dev_lstats_add(scope->netdev, scope->net_stats_bytes);
	if (scope->net_timestamp_pending)
		skb_tx_timestamp(skb);
	dev_kfree_skb(skb);
	return 0;
}

__bpf_kfunc int bpf_ebpfos_effect_net_tx_complete(u64 handle)
{
	struct ebpfos_effect_scope *scope = ebpfos_effect_current(handle);

	if (!scope || !scope->netdev || !scope->skb)
		return -EPERM;
	scope->net_stats_pending = true;
	scope->net_stats_bytes = scope->skb->len;
	scope->net_timestamp_pending = true;
	return bpf_ebpfos_effect_net_consume_skb(handle);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(ebpfos_l1_services)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_lock, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_unlock, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_irq_cmpxchg, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_sequence, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_wait, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_wait_locked, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_wake, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_poll, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_copy_from_iter, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_iter_revert, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_tty_emit, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_copy_to_iter, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_bio_peek, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_bio_read, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_bio_write, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_block_read, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_block_write, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_current_handle, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_file_flags, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_access_ok, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_copy_from_user, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_copy_to_user, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_signal_pending, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_signal, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_fasync, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_ref_get, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_ref_put, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_net_skb_len, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_net_lstats_add, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_net_tx_timestamp, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_net_consume_skb, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_net_tx_complete, KF_SLEEPABLE)
BTF_KFUNCS_END(ebpfos_l1_services)

bool ebpfos_effect_kfunc_allowed(u32 btf_id)
{
	return btf_id_set8_contains(&ebpfos_l1_services, btf_id);
}

static int ebpfos_effect_kfunc_filter(const struct bpf_prog *prog, u32 id)
{
	if (!ebpfos_effect_kfunc_allowed(id))
		return 0;
	return !prog || !prog->aux || !prog->aux->ebpfos_component ||
	       prog->type != BPF_PROG_TYPE_SYSCALL || !prog->sleepable;
}

static const struct btf_kfunc_id_set ebpfos_effect_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &ebpfos_l1_services,
	.filter = ebpfos_effect_kfunc_filter,
};

static int __init ebpfos_effect_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					 &ebpfos_effect_kfunc_set);
}
late_initcall(ebpfos_effect_init);

#if IS_ENABLED(CONFIG_KUNIT)
static void ebpfos_effect_scope_test(struct kunit *test)
{
	struct ebpfos_effect_scope *scope, *nested;
	s64 sequence;
	u64 irq_counter = 3;

	KUNIT_EXPECT_TRUE(test, ebpfos_effect_kfunc_allowed(
			ebpfos_l1_services.pairs[0].id));
	KUNIT_EXPECT_FALSE(test, ebpfos_effect_kfunc_allowed(0));
	KUNIT_ASSERT_EQ(test, ebpfos_effect_handle_get(0xeffec7), 0);
	KUNIT_ASSERT_EQ(test, ebpfos_effect_handle_get(0xeffec9), 0);
	scope = ebpfos_effect_scope_enter(0xeffec7, NULL, NULL, NULL);
	KUNIT_ASSERT_FALSE(test, IS_ERR(scope));
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_irq_cmpxchg(
		0xeffec9, 0, &irq_counter, 3, 4), U64_MAX);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_irq_cmpxchg(
		0xeffec7, EBPFOS_EFFECT_IRQ_SLOTS, &irq_counter, 3, 4),
		U64_MAX);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_irq_cmpxchg(
		0xeffec7, 0, &irq_counter, 3, 4), 3ULL);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_irq_cmpxchg(
		0xeffec7, 0, &irq_counter, 3, 5), 4ULL);
	KUNIT_EXPECT_EQ(test, irq_counter, 4ULL);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_lock(0xeffec9), -EPERM);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_lock(0xeffec7), 0);
	nested = ebpfos_effect_scope_enter(0xeffec7, NULL, NULL, NULL);
	KUNIT_ASSERT_TRUE(test, IS_ERR(nested));
	KUNIT_EXPECT_EQ(test, PTR_ERR(nested), (long)-EDEADLK);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_unlock(0xeffec7), 0);
	sequence = bpf_ebpfos_effect_sequence(0xeffec7, 0);
	KUNIT_EXPECT_EQ(test, sequence, 0LL);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_wake(0xeffec7, 0, EPOLLIN), 0);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_wait(0xeffec7, 0, sequence), 0);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_ref_get(0xeffec7), 0);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_ref_put(0xeffec7), 1);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_ref_put(0xeffec7), 0);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_ref_put(0xeffec7), -EINVAL);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_ref_get(0xeffec7), -ESTALE);
	KUNIT_EXPECT_EQ(test, ebpfos_effect_scope_exit(scope), 0);
	scope = ebpfos_effect_scope_enter(0xeffec7, NULL, NULL, NULL);
	KUNIT_ASSERT_FALSE(test, IS_ERR(scope));
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_lock(0xeffec7), 0);
	KUNIT_EXPECT_EQ(test, ebpfos_effect_scope_exit(scope), -EPROTO);
	ebpfos_effect_handle_put(0xeffec7);
	ebpfos_effect_handle_put(0xeffec9);
}

static void ebpfos_effect_copy_test(struct kunit *test)
{
	char source[] = "abcd", destination[sizeof(source)] = {};
	char buffer[sizeof(source)] = {};
	struct kvec vector = { .iov_base = source, .iov_len = 4 };
	struct ebpfos_effect_scope *scope;
	struct iov_iter iter;

	KUNIT_ASSERT_EQ(test, ebpfos_effect_handle_get(0xeffec8), 0);
	iov_iter_kvec(&iter, ITER_SOURCE, &vector, 1, 4);
	scope = ebpfos_effect_scope_enter(0xeffec8, NULL, &iter, NULL);
	KUNIT_ASSERT_FALSE(test, IS_ERR(scope));
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_copy_from_iter(0xeffec8,
							  buffer, 4), 4L);
	KUNIT_EXPECT_MEMEQ(test, buffer, source, 4);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_iter_revert(0xeffec8, 5),
			-EINVAL);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_iter_revert(0xeffec8, 2), 0);
	KUNIT_EXPECT_EQ(test, iov_iter_count(&iter), 2UL);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_tty_emit(0xeffec8,
							buffer, 4, 0), -EINVAL);
	KUNIT_EXPECT_EQ(test, ebpfos_effect_scope_exit(scope), 0);
	vector.iov_base = destination;
	iov_iter_kvec(&iter, ITER_DEST, &vector, 1, 4);
	scope = ebpfos_effect_scope_enter(0xeffec8, NULL, &iter, NULL);
	KUNIT_ASSERT_FALSE(test, IS_ERR(scope));
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_copy_to_iter(0xeffec8,
							buffer, 4), 4L);
	KUNIT_EXPECT_MEMEQ(test, destination, source, 4);
	KUNIT_EXPECT_EQ(test, ebpfos_effect_scope_exit(scope), 0);
	ebpfos_effect_handle_put(0xeffec8);
}

static void ebpfos_effect_bio_test(struct kunit *test)
{
	struct ebpfos_block_segment segment;
	struct ebpfos_effect_scope *scope;
	struct bio_vec vector;
	struct bio bio;
	struct page *page;
	char buffer[EBPFOS_EFFECT_COPY_MAX];

	page = alloc_page(GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, page);
	memset(page_address(page), 0x5a, PAGE_SIZE);
	bio_init(&bio, NULL, &vector, 1, REQ_OP_WRITE);
	__bio_add_page(&bio, page, 512, 0);
	bio.bi_iter.bi_sector = 8;
	KUNIT_ASSERT_EQ(test, ebpfos_effect_handle_get(0xeffecb), 0);
	scope = ebpfos_effect_scope_enter_bio(0xeffecb, &bio);
	KUNIT_ASSERT_FALSE(test, IS_ERR(scope));
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_bio_peek(0xeffecb,
					&segment, sizeof(segment)), 1);
	KUNIT_EXPECT_EQ(test, segment.byte_offset, 4096ULL);
	KUNIT_EXPECT_EQ(test, segment.bytes, 256U);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_block_read(0xeffecb, 4096,
							 buffer, sizeof(buffer)), 256L);
	KUNIT_EXPECT_EQ(test, buffer[0], 0);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_bio_read(0xeffecb,
							  buffer, sizeof(buffer)), 256L);
	KUNIT_EXPECT_EQ(test, buffer[0], 'Z');
	KUNIT_EXPECT_EQ(test, buffer[255], 'Z');
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_block_write(0xeffecb, 4096,
							  buffer, sizeof(buffer)), 256L);
	memset(buffer, 0, sizeof(buffer));
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_block_read(0xeffecb, 4096,
							 buffer, sizeof(buffer)), 256L);
	KUNIT_EXPECT_EQ(test, buffer[255], 'Z');
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_block_read(0xeffecb, 4096 - 128,
							 buffer, sizeof(buffer)), -EINVAL);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_block_read(0xeffecb, 4608,
							 buffer, 8), -EINVAL);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_bio_peek(0xeffecb,
					&segment, sizeof(segment)), 1);
	KUNIT_EXPECT_EQ(test, segment.byte_offset, 4352ULL);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_bio_read(0xeffecb,
					buffer, sizeof(buffer)), 256L);
	KUNIT_EXPECT_EQ(test, bpf_ebpfos_effect_bio_peek(0xeffecb,
					&segment, sizeof(segment)), 0);
	KUNIT_EXPECT_EQ(test, ebpfos_effect_scope_exit(scope), 0);
	KUNIT_EXPECT_EQ(test, bio.bi_iter.bi_sector, 9ULL);
	KUNIT_EXPECT_EQ(test, bio.bi_iter.bi_size, 0U);
	bio_uninit(&bio);
	__free_page(page);
	ebpfos_effect_handle_put(0xeffecb);
}

static struct kunit_case ebpfos_effect_cases[] = {
	KUNIT_CASE(ebpfos_effect_scope_test),
	KUNIT_CASE(ebpfos_effect_copy_test),
	KUNIT_CASE(ebpfos_effect_bio_test),
	{}
};

static struct kunit_suite ebpfos_effect_suite = {
	.name = "ebpfos-effect-services",
	.test_cases = ebpfos_effect_cases,
};

kunit_test_suite(ebpfos_effect_suite);
#endif
