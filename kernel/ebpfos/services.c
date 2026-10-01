// SPDX-License-Identifier: GPL-2.0-only
/* Generic effects for a sleepable component call on a native object handle. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/ebpfos_services.h>
#include <linux/err.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/wait.h>
#include <linux/xarray.h>
#if IS_ENABLED(CONFIG_KUNIT)
#include <kunit/test.h>
#endif

#define EBPFOS_EFFECT_WAIT_SLOTS 8
#define EBPFOS_EFFECT_COPY_MAX 256

struct ebpfos_effect_wait {
	wait_queue_head_t queue;
	atomic64_t sequence;
};

struct ebpfos_effect_object {
	refcount_t pins;
	atomic_t logical_refs;
	struct mutex lock;
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
	bool locked;
};

static DEFINE_XARRAY(ebpfos_effect_objects);
static DEFINE_MUTEX(ebpfos_effect_objects_lock);
static DEFINE_XARRAY(ebpfos_effect_tasks);

static void ebpfos_effect_object_destroy(struct ebpfos_effect_object *object)
{
	int i;

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
	task->top = scope->previous;
	if (!task->top) {
		xa_erase(&ebpfos_effect_tasks, (unsigned long)current);
		kfree(task);
	}
	ebpfos_effect_object_put(scope->handle, scope->object);
	kfree(scope);
	return error;
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

	if (!scope || !scope->iter || !dst || !dst__sz ||
	    dst__sz > EBPFOS_EFFECT_COPY_MAX)
		return -EINVAL;
	return copy_from_iter(dst, dst__sz, scope->iter);
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

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(ebpfos_effect_kfunc_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_lock, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_unlock, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_sequence, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_wait, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_wake, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_poll, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_copy_from_iter, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_copy_to_iter, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_signal_pending, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_signal, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_fasync, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_ref_get, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_ref_put, KF_SLEEPABLE)
BTF_KFUNCS_END(ebpfos_effect_kfunc_ids)

bool ebpfos_effect_kfunc_allowed(u32 btf_id)
{
	return btf_id_set8_contains(&ebpfos_effect_kfunc_ids, btf_id);
}

static int ebpfos_effect_kfunc_filter(const struct bpf_prog *prog, u32 id)
{
	return !prog || !prog->aux || !prog->aux->ebpfos_component ||
	       prog->type != BPF_PROG_TYPE_SYSCALL || !prog->sleepable;
}

static const struct btf_kfunc_id_set ebpfos_effect_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &ebpfos_effect_kfunc_ids,
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

	KUNIT_EXPECT_TRUE(test, ebpfos_effect_kfunc_allowed(
			ebpfos_effect_kfunc_ids.pairs[0].id));
	KUNIT_EXPECT_FALSE(test, ebpfos_effect_kfunc_allowed(0));
	KUNIT_ASSERT_EQ(test, ebpfos_effect_handle_get(0xeffec7), 0);
	KUNIT_ASSERT_EQ(test, ebpfos_effect_handle_get(0xeffec9), 0);
	scope = ebpfos_effect_scope_enter(0xeffec7, NULL, NULL, NULL);
	KUNIT_ASSERT_FALSE(test, IS_ERR(scope));
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

static struct kunit_case ebpfos_effect_cases[] = {
	KUNIT_CASE(ebpfos_effect_scope_test),
	KUNIT_CASE(ebpfos_effect_copy_test),
	{}
};

static struct kunit_suite ebpfos_effect_suite = {
	.name = "ebpfos-effect-services",
	.test_cases = ebpfos_effect_cases,
};

kunit_test_suite(ebpfos_effect_suite);
#endif
