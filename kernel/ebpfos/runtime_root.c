// SPDX-License-Identifier: GPL-2.0-only
/* Policy-free target runtime root/epoch publication and dispatch primitive. */
#include <linux/bpf.h>
#include <linux/ebpfos.h>
#include <linux/ebpfos_runtime.h>
#include <linux/entry-common.h>
#include <linux/err.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/ptrace.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/stop_machine.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include <asm/ptrace.h>

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
	struct ebpfos_runtime_bundle *staged;
};

static struct ebpfos_runtime_root ebpfos_runtime_root = {
	.lock = __SPIN_LOCK_UNLOCKED(ebpfos_runtime_root.lock),
};

struct ebpfos_runtime_syscall_state {
	struct mutex lock;
	u64 syscall_slot_id;
	u64 observer_slot_id;
	u64 installer_slot_id;
	u64 epoch;
	u64 old_lstar;
	u64 target_lstar;
	atomic64_t calls;
	atomic64_t unknown;
	atomic64_t graph_commits;
	u32 cpus_observed;
	u32 cpus_written;
	bool active;
};

static struct ebpfos_runtime_syscall_state ebpfos_runtime_syscall = {
	.lock = __MUTEX_INITIALIZER(ebpfos_runtime_syscall.lock),
};

static bool ebpfos_runtime_syscall_active(void)
{
	return smp_load_acquire(&ebpfos_runtime_syscall.active);
}

extern asmlinkage void ebpfos_runtime_syscall_entry(void);
extern asmlinkage void entry_SYSCALL_64(void);
__visible noinstr void ebpfos_runtime_syscall_dispatch(struct pt_regs *regs);

static int ebpfos_runtime_bundle_find(const struct ebpfos_runtime_bundle *bundle,
				      u64 slot_id)
{
	u32 low = 0, high = bundle->slot_count;

	while (low < high) {
		u32 middle = low + (high - low) / 2;

		if (bundle->slots[middle].slot_id < slot_id)
			low = middle + 1;
		else
			high = middle;
	}
	return low < bundle->slot_count && bundle->slots[low].slot_id == slot_id ?
		(int)low : -ENOENT;
}

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
		if (prog->type != BPF_PROG_TYPE_SYSCALL ||
		    !prog->jited || !prog->jited_len ||
		    prog->aux->max_ctx_offset > EBPFOS_RUNTIME_ROOT_CONTEXT_SIZE ||
		    (!prog->sleepable && !prog->aux->ebpfos_component) ||
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
	int syscall_slot;
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
	syscall_slot = ebpfos_runtime_syscall_active() ?
		ebpfos_runtime_bundle_find(target,
					   ebpfos_runtime_syscall.syscall_slot_id) : 0;
	if (active_epoch != request.expected_epoch || syscall_slot < 0 ||
	    ebpfos_runtime_root.staged) {
		spin_unlock_irqrestore(&ebpfos_runtime_root.lock, irq_flags);
		ebpfos_runtime_bundle_release(target);
		return active_epoch != request.expected_epoch ? -ESTALE : -EBUSY;
	}
	/* The single RCU pointer assignment is the root/epoch linearization. */
	rcu_assign_pointer(ebpfos_runtime_root.active, target);
	spin_unlock_irqrestore(&ebpfos_runtime_root.lock, irq_flags);
	if (source)
		call_rcu(&source->rcu, ebpfos_runtime_bundle_retire_rcu);
	return 0;
}

static long ebpfos_runtime_stage(void __user *argp)
{
	struct ebpfos_runtime_root_publish request;
	struct ebpfos_runtime_bundle *active, *target;
	unsigned long irq_flags;
	long result = 0;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	target = ebpfos_runtime_bundle_prepare(&request);
	if (IS_ERR(target))
		return PTR_ERR(target);
	spin_lock_irqsave(&ebpfos_runtime_root.lock, irq_flags);
	active = rcu_dereference_protected(ebpfos_runtime_root.active,
					   lockdep_is_held(&ebpfos_runtime_root.lock));
	if (!active || active->epoch != request.expected_epoch)
		result = -ESTALE;
	else if (ebpfos_runtime_root.staged ||
		 (ebpfos_runtime_syscall_active() &&
		  ebpfos_runtime_bundle_find(target,
				 ebpfos_runtime_syscall.syscall_slot_id) < 0))
		result = -EBUSY;
	else
		ebpfos_runtime_root.staged = target;
	spin_unlock_irqrestore(&ebpfos_runtime_root.lock, irq_flags);
	if (result)
		ebpfos_runtime_bundle_release(target);
	return result;
}

static int ebpfos_runtime_commit_staged(u64 expected_epoch, u64 target_epoch)
{
	struct ebpfos_runtime_bundle *source, *target;
	unsigned long irq_flags;
	int result = 0;

	spin_lock_irqsave(&ebpfos_runtime_root.lock, irq_flags);
	source = rcu_dereference_protected(ebpfos_runtime_root.active,
					   lockdep_is_held(&ebpfos_runtime_root.lock));
	target = ebpfos_runtime_root.staged;
	if (!source || source->epoch != expected_epoch || !target ||
	    target->epoch != target_epoch)
		result = -ESTALE;
	else if (ebpfos_runtime_syscall_active() &&
		 ebpfos_runtime_bundle_find(target,
				 ebpfos_runtime_syscall.syscall_slot_id) < 0)
		result = -EPROTO;
	else {
		ebpfos_runtime_root.staged = NULL;
		rcu_assign_pointer(ebpfos_runtime_root.active, target);
	}
	spin_unlock_irqrestore(&ebpfos_runtime_root.lock, irq_flags);
	if (!result) {
		atomic64_inc(&ebpfos_runtime_syscall.graph_commits);
		call_rcu(&source->rcu, ebpfos_runtime_bundle_retire_rcu);
	}
	return result;
}

static struct ebpfos_runtime_bundle *ebpfos_runtime_bundle_get(u64 slot_id,
							       u32 *slot_index)
{
	struct ebpfos_runtime_bundle *bundle;
	int index;

	rcu_read_lock();
	bundle = rcu_dereference(ebpfos_runtime_root.active);
	if (!bundle || !refcount_inc_not_zero(&bundle->references)) {
		bundle = NULL;
		goto out;
	}
	index = ebpfos_runtime_bundle_find(bundle, slot_id);
	if (index < 0) {
		ebpfos_runtime_bundle_release(bundle);
		bundle = NULL;
		goto out;
	}
	*slot_index = index;
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
	if (!prog->sleepable) {
		result = -EOPNOTSUPP;
		goto out_put;
	}
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

struct ebpfos_runtime_machine_transition {
	struct bpf_prog *prog;
	u64 operand;
	atomic_t error;
	atomic_t executed;
};

static int ebpfos_runtime_machine_run(struct bpf_prog *prog, u64 operand)
{
	struct ebpfos_component_call_frame frame = {
		.version = EBPFOS_COMPONENT_CALL_ABI_VERSION,
		.input_size = sizeof(operand),
		.output_capacity = EBPFOS_COMPONENT_CALL_OUTPUT_SIZE,
	};
	u64 result = 0;

	memcpy(frame.input, &operand, sizeof(operand));
	if (bpf_prog_run(prog, &frame) || frame.status ||
	    frame.output_size != sizeof(result))
		return frame.status ? frame.status : -EREMOTEIO;
	memcpy(&result, frame.output, sizeof(result));
	return result == operand ? 0 : -ESTALE;
}

static int ebpfos_runtime_machine_callback(void *argument)
{
	struct ebpfos_runtime_machine_transition *transition = argument;
	int error;

	error = ebpfos_runtime_machine_run(transition->prog,
					   transition->operand);
	if (error)
		atomic_cmpxchg(&transition->error, 0, error);
	else
		atomic_inc(&transition->executed);
	return 0;
}

static int ebpfos_runtime_machine_all_cpus(struct bpf_prog *prog, u64 operand,
					   u32 *executed)
{
	struct ebpfos_runtime_machine_transition transition = {
		.prog = prog,
		.operand = operand,
		.error = ATOMIC_INIT(0),
		.executed = ATOMIC_INIT(0),
	};
	int error;

	error = stop_machine(ebpfos_runtime_machine_callback, &transition,
			     cpu_online_mask);
	if (!error)
		error = atomic_read(&transition.error);
	*executed = atomic_read(&transition.executed);
	if (!error && *executed != num_online_cpus())
		error = -EREMOTEIO;
	return error;
}

static bool ebpfos_runtime_syscall_program(const struct bpf_prog *prog)
{
	return prog->type == BPF_PROG_TYPE_SYSCALL && !prog->sleepable &&
	       prog->aux->ebpfos_component && !bpf_prog_has_kop_call(prog) &&
	       prog->jited && prog->jited_len;
}

static bool ebpfos_runtime_machine_program(const struct bpf_prog *prog)
{
	return prog->type == BPF_PROG_TYPE_SYSCALL && !prog->sleepable &&
	       prog->aux->ebpfos_component && bpf_prog_has_kop_call(prog) &&
	       prog->jited && prog->jited_len;
}

static int ebpfos_runtime_root_vector(struct ebpfos_runtime_bundle *bundle,
				      u64 expected_root, u64 target_root,
				      u32 *observed, u32 *written)
{
	struct bpf_prog *observer, *installer;
	u32 count;
	int observer_slot, installer_slot, error;

	observer_slot = ebpfos_runtime_bundle_find(
		bundle, ebpfos_runtime_syscall.observer_slot_id);
	installer_slot = ebpfos_runtime_bundle_find(
		bundle, ebpfos_runtime_syscall.installer_slot_id);
	if (observer_slot < 0 || installer_slot < 0)
		return -ENOENT;
	observer = bundle->slots[observer_slot].prog;
	installer = bundle->slots[installer_slot].prog;
	if (!ebpfos_runtime_machine_program(observer) ||
	    !ebpfos_runtime_machine_program(installer))
		return -EPROTO;
	error = ebpfos_runtime_machine_all_cpus(observer, expected_root, &count);
	*observed = count;
	if (error)
		return error;
	error = ebpfos_runtime_machine_all_cpus(installer, target_root, written);
	if (error)
		return error;
	error = ebpfos_runtime_machine_all_cpus(observer, target_root, &count);
	*observed += count;
	return error;
}

static void ebpfos_runtime_syscall_status(
	struct ebpfos_runtime_syscall_root *status)
{
	memset(status, 0, sizeof(*status));
	status->version = EBPFOS_RUNTIME_ROOT_ABI_VERSION;
	mutex_lock(&ebpfos_runtime_syscall.lock);
	status->expected_epoch = READ_ONCE(ebpfos_runtime_syscall.epoch);
	status->syscall_slot_id = READ_ONCE(ebpfos_runtime_syscall.syscall_slot_id);
	status->observer_slot_id = READ_ONCE(ebpfos_runtime_syscall.observer_slot_id);
	status->installer_slot_id = READ_ONCE(ebpfos_runtime_syscall.installer_slot_id);
	status->old_lstar = ebpfos_runtime_syscall.old_lstar;
	status->target_lstar = ebpfos_runtime_syscall.target_lstar;
	status->cpus_observed = ebpfos_runtime_syscall.cpus_observed;
	status->cpus_written = ebpfos_runtime_syscall.cpus_written;
	status->active = ebpfos_runtime_syscall_active();
	mutex_unlock(&ebpfos_runtime_syscall.lock);
	status->syscall_calls = atomic64_read(&ebpfos_runtime_syscall.calls);
	status->unknown_syscalls = atomic64_read(&ebpfos_runtime_syscall.unknown);
	status->graph_commits = atomic64_read(&ebpfos_runtime_syscall.graph_commits);
}

static int ebpfos_runtime_syscall_rollback(
	struct ebpfos_runtime_bundle *bundle, u64 expected_epoch)
{
	u32 observed = 0, written = 0;
	int error;

	mutex_lock(&ebpfos_runtime_syscall.lock);
	if (!ebpfos_runtime_syscall_active() || bundle->epoch != expected_epoch ||
	    READ_ONCE(ebpfos_runtime_syscall.epoch) != expected_epoch) {
		error = -ESTALE;
		goto out;
	}
	error = ebpfos_runtime_root_vector(bundle,
			 ebpfos_runtime_syscall.target_lstar,
			 ebpfos_runtime_syscall.old_lstar, &observed, &written);
	if (!error) {
		ebpfos_runtime_syscall.cpus_observed += observed;
		ebpfos_runtime_syscall.cpus_written += written;
		smp_store_release(&ebpfos_runtime_syscall.active, false);
	}
out:
	mutex_unlock(&ebpfos_runtime_syscall.lock);
	return error;
}

static long ebpfos_runtime_syscall_install(void __user *argp)
{
	struct ebpfos_runtime_syscall_root request;
	struct ebpfos_runtime_bundle *bundle;
	struct bpf_prog *syscall_prog;
	u32 slot, observed = 0, written = 0, rollback_count = 0;
	int error, rollback_error, observer_slot, installer_slot;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.version != EBPFOS_RUNTIME_ROOT_ABI_VERSION || request.flags ||
	    request.reserved || !request.expected_epoch || !request.syscall_slot_id ||
	    !request.observer_slot_id || !request.installer_slot_id)
		return -EINVAL;
	bundle = ebpfos_runtime_bundle_get(request.syscall_slot_id, &slot);
	if (!bundle)
		return -ENOENT;
	if (bundle->epoch != request.expected_epoch) {
		error = -ESTALE;
		goto out_put;
	}
	syscall_prog = bundle->slots[slot].prog;
	observer_slot = ebpfos_runtime_bundle_find(bundle,
						 request.observer_slot_id);
	installer_slot = ebpfos_runtime_bundle_find(bundle,
						  request.installer_slot_id);
	if (!ebpfos_runtime_syscall_program(syscall_prog) || observer_slot < 0 ||
	    installer_slot < 0 ||
	    !ebpfos_runtime_machine_program(bundle->slots[observer_slot].prog) ||
	    !ebpfos_runtime_machine_program(bundle->slots[installer_slot].prog)) {
		error = -EPROTO;
		goto out_put;
	}
	mutex_lock(&ebpfos_runtime_syscall.lock);
	if (ebpfos_runtime_syscall_active()) {
		error = -EBUSY;
		goto out_unlock;
	}
	ebpfos_runtime_syscall.syscall_slot_id = request.syscall_slot_id;
	ebpfos_runtime_syscall.observer_slot_id = request.observer_slot_id;
	ebpfos_runtime_syscall.installer_slot_id = request.installer_slot_id;
	ebpfos_runtime_syscall.epoch = request.expected_epoch;
	ebpfos_runtime_syscall.old_lstar = (u64)entry_SYSCALL_64;
	ebpfos_runtime_syscall.target_lstar =
		(u64)ebpfos_runtime_syscall_entry;
	smp_store_release(&ebpfos_runtime_syscall.active, true);
	error = ebpfos_runtime_root_vector(bundle,
			 ebpfos_runtime_syscall.old_lstar,
			 ebpfos_runtime_syscall.target_lstar, &observed, &written);
	if (error) {
		rollback_error = ebpfos_runtime_machine_all_cpus(
			bundle->slots[installer_slot].prog,
			ebpfos_runtime_syscall.old_lstar, &rollback_count);
		if (!rollback_error)
			smp_store_release(&ebpfos_runtime_syscall.active, false);
		else
			error = rollback_error;
		goto out_unlock;
	}
	ebpfos_runtime_syscall.cpus_observed = observed;
	ebpfos_runtime_syscall.cpus_written = written;
out_unlock:
	if (!error) {
		request.old_lstar = ebpfos_runtime_syscall.old_lstar;
		request.target_lstar = ebpfos_runtime_syscall.target_lstar;
		request.cpus_observed = ebpfos_runtime_syscall.cpus_observed;
		request.cpus_written = ebpfos_runtime_syscall.cpus_written;
		request.active = 1;
		request.syscall_calls = atomic64_read(&ebpfos_runtime_syscall.calls);
		request.unknown_syscalls = atomic64_read(&ebpfos_runtime_syscall.unknown);
		request.graph_commits = atomic64_read(&ebpfos_runtime_syscall.graph_commits);
	}
	mutex_unlock(&ebpfos_runtime_syscall.lock);
	if (!error && copy_to_user(argp, &request, sizeof(request))) {
		error = ebpfos_runtime_syscall_rollback(bundle, request.expected_epoch);
		if (!error)
			error = -EFAULT;
	}
out_put:
	ebpfos_runtime_bundle_release(bundle);
	return error;
}

static long ebpfos_runtime_syscall_read(void __user *argp)
{
	struct ebpfos_runtime_syscall_root status;

	ebpfos_runtime_syscall_status(&status);
	return copy_to_user(argp, &status, sizeof(status)) ? -EFAULT : 0;
}

static long ebpfos_runtime_run_syscall(struct pt_regs *regs)
{
	struct ebpfos_component_call_frame frame = {
		.version = EBPFOS_COMPONENT_CALL_ABI_VERSION,
		.output_capacity = EBPFOS_COMPONENT_CALL_OUTPUT_SIZE,
	};
	struct ebpfos_runtime_bundle *bundle;
	struct bpf_prog *prog;
	u64 arguments[6] = {
		regs->di, regs->si, regs->dx, regs->r10, regs->r8, regs->r9,
	};
	u64 action = EBPFOS_RUNTIME_SYSCALL_ACTION_NONE, target_epoch = 0;
	s64 result = -ENOSYS;
	u32 slot, provider_status;

	bundle = ebpfos_runtime_bundle_get(
		READ_ONCE(ebpfos_runtime_syscall.syscall_slot_id), &slot);
	if (!bundle)
		return -ENOENT;
	prog = bundle->slots[slot].prog;
	if (!ebpfos_runtime_syscall_program(prog)) {
		result = -EPROTO;
		goto out;
	}
	frame.method_id = regs->orig_ax;
	frame.object_id = ebpfos_runtime_syscall.syscall_slot_id;
	frame.epoch = bundle->epoch;
	frame.input_size = sizeof(arguments);
	memcpy(frame.input, arguments, sizeof(arguments));
	provider_status = bpf_prog_run_pin_on_cpu(prog, &frame);
	if (provider_status || frame.status || frame.output_size < sizeof(result)) {
		result = frame.status ? frame.status : -EREMOTEIO;
		goto out;
	}
	memcpy(&result, frame.output, sizeof(result));
	if (frame.output_size >= 2 * sizeof(u64))
		memcpy(&action, frame.output + sizeof(u64), sizeof(action));
	if (frame.output_size >= 3 * sizeof(u64))
		memcpy(&target_epoch, frame.output + 2 * sizeof(u64),
		       sizeof(target_epoch));
	if (action == EBPFOS_RUNTIME_SYSCALL_ACTION_COMMIT_STAGED) {
		int error = ebpfos_runtime_commit_staged(bundle->epoch, target_epoch);

		if (error)
			result = error;
		else
			WRITE_ONCE(ebpfos_runtime_syscall.epoch, target_epoch);
	} else if (action == EBPFOS_RUNTIME_SYSCALL_ACTION_ROLLBACK_ROOT) {
		int error = ebpfos_runtime_syscall_rollback(bundle, target_epoch);

		if (error)
			result = error;
	} else if (action != EBPFOS_RUNTIME_SYSCALL_ACTION_NONE) {
		result = -EPROTO;
	}
out:
	atomic64_inc(&ebpfos_runtime_syscall.calls);
	if (result == -ENOSYS)
		atomic64_inc(&ebpfos_runtime_syscall.unknown);
	ebpfos_runtime_bundle_release(bundle);
	return result;
}

__visible noinstr void ebpfos_runtime_syscall_dispatch(struct pt_regs *regs)
{
	enter_from_user_mode(regs);
	instrumentation_begin();
	local_irq_enable();
	regs->ax = ebpfos_runtime_run_syscall(regs);
	local_irq_disable();
	syscall_exit_to_user_mode_prepare(regs);
	regs->cx = regs->ip;
	regs->r11 = regs->flags;
	instrumentation_end();
	exit_to_user_mode();
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
	case EBPFOS_RUNTIME_ROOT_IOC_STAGE:
		return ebpfos_runtime_stage(argp);
	case EBPFOS_RUNTIME_ROOT_IOC_SYSCALL_INSTALL:
		return ebpfos_runtime_syscall_install(argp);
	case EBPFOS_RUNTIME_ROOT_IOC_SYSCALL_READ:
		return ebpfos_runtime_syscall_read(argp);
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
