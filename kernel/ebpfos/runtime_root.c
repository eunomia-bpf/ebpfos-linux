// SPDX-License-Identifier: GPL-2.0-only
/* Policy-free target runtime root/epoch publication and dispatch primitive. */
#include <linux/bpf.h>
#include <linux/ebpfos_runtime.h>
#include <linux/err.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

struct ebpfos_runtime_slot {
	u64 slot_id;
	struct bpf_prog *prog;
	u8 program_tag[EBPFOS_RUNTIME_ROOT_TAG_SIZE];
	u8 image_digest[EBPFOS_RUNTIME_ROOT_DIGEST_SIZE];
};

struct ebpfos_runtime_bundle {
	struct rcu_head rcu;
	struct work_struct retire_work;
	refcount_t references;
	u64 epoch;
	u32 slot_count;
	struct ebpfos_runtime_slot slots[];
};

struct ebpfos_runtime_root {
	spinlock_t lock;
	struct ebpfos_runtime_bundle __rcu *active;
};

static struct ebpfos_runtime_root ebpfos_runtime_root = {
	.lock = __SPIN_LOCK_UNLOCKED(ebpfos_runtime_root.lock),
};

static bool ebpfos_runtime_nonzero(const u8 *value, size_t size)
{
	return memchr_inv(value, 0, size) != NULL;
}

static void ebpfos_runtime_bundle_release(struct ebpfos_runtime_bundle *bundle)
{
	u32 index;

	if (!refcount_dec_and_test(&bundle->references))
		return;
	for (index = 0; index < bundle->slot_count; index++)
		bpf_prog_put(bundle->slots[index].prog);
	kfree(bundle);
}

static void ebpfos_runtime_bundle_retire_work(struct work_struct *work)
{
	struct ebpfos_runtime_bundle *bundle = container_of(
		work, struct ebpfos_runtime_bundle, retire_work);

	ebpfos_runtime_bundle_release(bundle);
}

static void ebpfos_runtime_bundle_retire_rcu(struct rcu_head *rcu)
{
	struct ebpfos_runtime_bundle *bundle = container_of(
		rcu, struct ebpfos_runtime_bundle, rcu);

	schedule_work(&bundle->retire_work);
}

static struct ebpfos_runtime_bundle *
ebpfos_runtime_bundle_prepare(const struct ebpfos_runtime_root_publish *request)
{
	struct ebpfos_runtime_bundle *bundle;
	size_t bytes;
	u32 index;

	if (request->version != EBPFOS_RUNTIME_ROOT_ABI_VERSION ||
	    request->flags || request->reserved || !request->slot_count ||
	    request->slot_count > EBPFOS_RUNTIME_ROOT_MAX_SLOTS ||
	    request->target_epoch != request->expected_epoch + 1 ||
	    !request->target_epoch)
		return ERR_PTR(-EINVAL);
	if (check_mul_overflow((size_t)request->slot_count,
			       sizeof(bundle->slots[0]), &bytes) ||
	    check_add_overflow(sizeof(*bundle), bytes, &bytes))
		return ERR_PTR(-EOVERFLOW);
	bundle = kzalloc(bytes, GFP_KERNEL);
	if (!bundle)
		return ERR_PTR(-ENOMEM);
	INIT_WORK(&bundle->retire_work, ebpfos_runtime_bundle_retire_work);
	refcount_set(&bundle->references, 1);
	bundle->epoch = request->target_epoch;
	for (index = 0; index < request->slot_count; index++) {
		const struct ebpfos_runtime_root_slot *source =
			&request->slots[index];
		struct ebpfos_runtime_slot *target = &bundle->slots[index];
		struct bpf_prog *prog;

		if (!source->slot_id || source->prog_fd < 0 || source->flags ||
		    (index && request->slots[index - 1].slot_id >= source->slot_id) ||
		    !ebpfos_runtime_nonzero(source->program_tag,
					    sizeof(source->program_tag)) ||
		    !ebpfos_runtime_nonzero(source->image_digest,
					    sizeof(source->image_digest)))
			goto invalid;
		prog = bpf_prog_get(source->prog_fd);
		if (IS_ERR(prog)) {
			int error = PTR_ERR(prog);

			ebpfos_runtime_bundle_release(bundle);
			return ERR_PTR(error);
		}
		if (prog->type != BPF_PROG_TYPE_SYSCALL || !prog->sleepable ||
		    !prog->jited || !prog->jited_len ||
		    prog->aux->max_ctx_offset > EBPFOS_RUNTIME_ROOT_CONTEXT_SIZE ||
		    memcmp(prog->tag, source->program_tag, BPF_TAG_SIZE)) {
			bpf_prog_put(prog);
			goto invalid;
		}
		target->slot_id = source->slot_id;
		target->prog = prog;
		bundle->slot_count = index + 1;
		memcpy(target->program_tag, source->program_tag,
		       sizeof(target->program_tag));
		memcpy(target->image_digest, source->image_digest,
		       sizeof(target->image_digest));
	}
	return bundle;

invalid:
	ebpfos_runtime_bundle_release(bundle);
	return ERR_PTR(-EPROTO);
}

static long ebpfos_runtime_publish(void __user *argp)
{
	struct ebpfos_runtime_root_publish request;
	struct ebpfos_runtime_bundle *source, *target;
	unsigned long irq_flags;
	u64 active_epoch;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	target = ebpfos_runtime_bundle_prepare(&request);
	if (IS_ERR(target))
		return PTR_ERR(target);
	spin_lock_irqsave(&ebpfos_runtime_root.lock, irq_flags);
	source = rcu_dereference_protected(ebpfos_runtime_root.active,
					   lockdep_is_held(&ebpfos_runtime_root.lock));
	active_epoch = source ? source->epoch : 0;
	if (active_epoch != request.expected_epoch) {
		spin_unlock_irqrestore(&ebpfos_runtime_root.lock, irq_flags);
		ebpfos_runtime_bundle_release(target);
		return -ESTALE;
	}
	/* The single RCU pointer assignment is the root/epoch linearization. */
	rcu_assign_pointer(ebpfos_runtime_root.active, target);
	spin_unlock_irqrestore(&ebpfos_runtime_root.lock, irq_flags);
	if (source)
		call_rcu(&source->rcu, ebpfos_runtime_bundle_retire_rcu);
	return 0;
}

static struct ebpfos_runtime_bundle *ebpfos_runtime_bundle_get(u64 slot_id,
							       u32 *slot_index)
{
	struct ebpfos_runtime_bundle *bundle;
	u32 low, high;

	rcu_read_lock();
	bundle = rcu_dereference(ebpfos_runtime_root.active);
	if (!bundle || !refcount_inc_not_zero(&bundle->references)) {
		bundle = NULL;
		goto out;
	}
	low = 0;
	high = bundle->slot_count;
	while (low < high) {
		u32 middle = low + (high - low) / 2;

		if (bundle->slots[middle].slot_id < slot_id)
			low = middle + 1;
		else
			high = middle;
	}
	if (low == bundle->slot_count || bundle->slots[low].slot_id != slot_id) {
		ebpfos_runtime_bundle_release(bundle);
		bundle = NULL;
		goto out;
	}
	*slot_index = low;
out:
	rcu_read_unlock();
	return bundle;
}

static long ebpfos_runtime_call(void __user *argp)
{
	struct ebpfos_runtime_root_call *call;
	struct ebpfos_runtime_bundle *bundle;
	struct bpf_tramp_run_ctx run_ctx = {};
	struct bpf_prog *prog;
	u64 start;
	u32 slot;
	long result = 0;

	call = memdup_user(argp, sizeof(*call));
	if (IS_ERR(call))
		return PTR_ERR(call);
	if (call->version != EBPFOS_RUNTIME_ROOT_ABI_VERSION || call->flags ||
	    call->reserved || !call->slot_id ||
	    call->context_size != EBPFOS_RUNTIME_ROOT_CONTEXT_SIZE) {
		result = -EINVAL;
		goto out;
	}
	bundle = ebpfos_runtime_bundle_get(call->slot_id, &slot);
	if (!bundle) {
		result = -ENOENT;
		goto out;
	}
	if (call->expected_epoch && call->expected_epoch != bundle->epoch) {
		result = -ESTALE;
		goto out_put;
	}
	prog = bundle->slots[slot].prog;
	start = __bpf_prog_enter_sleepable_recur(prog, &run_ctx);
	if (!start) {
		__bpf_prog_exit_sleepable_recur(prog, 0, &run_ctx);
		result = -EBUSY;
		goto out_put;
	}
	call->provider_status = bpf_prog_run(prog, call->context);
	__bpf_prog_exit_sleepable_recur(prog, 0, &run_ctx);
	call->observed_epoch = bundle->epoch;
	call->provider_prog_id = prog->aux->id;
	if (copy_to_user(argp, call, sizeof(*call)))
		result = -EFAULT;
out_put:
	ebpfos_runtime_bundle_release(bundle);
out:
	kfree(call);
	return result;
}

static long ebpfos_runtime_read(void __user *argp)
{
	struct ebpfos_runtime_root_snapshot snapshot = {
		.version = EBPFOS_RUNTIME_ROOT_ABI_VERSION,
	};
	struct ebpfos_runtime_bundle *bundle;
	u32 index;

	rcu_read_lock();
	bundle = rcu_dereference(ebpfos_runtime_root.active);
	if (bundle) {
		snapshot.epoch = bundle->epoch;
		snapshot.slot_count = bundle->slot_count;
		for (index = 0; index < bundle->slot_count; index++) {
			snapshot.slots[index].slot_id = bundle->slots[index].slot_id;
			snapshot.slots[index].prog_id = bundle->slots[index].prog->aux->id;
			memcpy(snapshot.slots[index].program_tag,
			       bundle->slots[index].program_tag,
			       sizeof(snapshot.slots[index].program_tag));
			memcpy(snapshot.slots[index].image_digest,
			       bundle->slots[index].image_digest,
			       sizeof(snapshot.slots[index].image_digest));
		}
	}
	rcu_read_unlock();
	return copy_to_user(argp, &snapshot, sizeof(snapshot)) ? -EFAULT : 0;
}

static long ebpfos_runtime_ioctl(struct file *file, unsigned int command,
				 unsigned long argument)
{
	void __user *argp = (void __user *)argument;

	switch (command) {
	case EBPFOS_RUNTIME_ROOT_IOC_PUBLISH:
		return ebpfos_runtime_publish(argp);
	case EBPFOS_RUNTIME_ROOT_IOC_CALL:
		return ebpfos_runtime_call(argp);
	case EBPFOS_RUNTIME_ROOT_IOC_READ:
		return ebpfos_runtime_read(argp);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations ebpfos_runtime_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ebpfos_runtime_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = ebpfos_runtime_ioctl,
#endif
	.llseek = noop_llseek,
};

static struct miscdevice ebpfos_runtime_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ebpfos-root",
	.fops = &ebpfos_runtime_fops,
	.mode = 0600,
};

static int __init ebpfos_runtime_root_init(void)
{
	int error = misc_register(&ebpfos_runtime_device);

	if (!error)
		pr_info("ebpfos-runtime-root: policy-free RCU epoch executor ready\n");
	return error;
}
subsys_initcall(ebpfos_runtime_root_init);

MODULE_DESCRIPTION("eBPFOS minimal policy-free runtime root executor");
MODULE_LICENSE("GPL");
