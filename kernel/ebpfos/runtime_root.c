// SPDX-License-Identifier: GPL-2.0-only
/* Policy-free target runtime root/epoch publication and dispatch primitive. */
#include <crypto/sha2.h>
#include <linux/bpf.h>
#include <linux/ebpfos.h>
#include <linux/ebpfos_runtime.h>
#include <linux/entry-common.h>
#include <linux/err.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/irq.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/ptrace.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/stop_machine.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include <asm/desc.h>
#include <asm/hw_irq.h>
#include <asm/idtentry.h>
#include <asm/irq_regs.h>
#include <asm/irq_vectors.h>
#include <asm/page.h>
#include <asm/processor-flags.h>
#include <asm/ptrace.h>
#include <asm/thread_info.h>

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

struct ebpfos_runtime_irq_state {
	struct mutex lock;
	u64 observer_slot_id;
	u64 installer_slot_id;
	u64 handler_slot_id;
	u64 routing_observer_slot_id;
	u64 routing_installer_slot_id;
	u64 pulse_observer_slot_id;
	u64 pulse_installer_slot_id;
	u64 routing_old;
	u64 routing_target;
	u64 pulse_resting;
	u64 pulse_armed;
	u64 epoch;
	u64 old_idtr;
	u64 target_idtr;
	u64 handler_entry;
	unsigned long target_table;
	u8 target_table_sha256[SHA256_DIGEST_SIZE];
	atomic64_t dispatches;
	atomic64_t dispatch_errors;
	atomic64_t pulse_rearms;
	atomic64_t first_dispatch_epoch;
	atomic64_t last_dispatch_epoch;
	atomic_t first_dispatch_prog_id;
	atomic_t last_dispatch_prog_id;
	u32 cpus_observed;
	u32 cpus_written;
	u32 machine_cpus_observed;
	u32 machine_cpus_written;
	u32 vector;
	u32 gate_dpl;
	bool active;
};

static struct ebpfos_runtime_irq_state ebpfos_runtime_irq = {
	.lock = __MUTEX_INITIALIZER(ebpfos_runtime_irq.lock),
};

struct ebpfos_runtime_process_state {
	struct mutex lock;
	struct task_struct *task;
	u64 process_slot_id;
	u64 mmu_observer_slot_id;
	u64 mmu_reloader_slot_id;
	u64 epoch;
	u64 task_object_id;
	u64 task_start_boottime;
	u64 mm_object_id;
	u64 address_space_object_id;
	u64 mmu_root_physical;
	atomic64_t returns;
	atomic64_t return_errors;
	atomic64_t syscall_returns;
	atomic64_t irq_returns;
	atomic64_t mmu_observations;
	atomic64_t mmu_reloads;
	atomic64_t mmu_errors;
	atomic64_t mmu_first_epoch;
	atomic64_t mmu_last_epoch;
	atomic64_t mmu_native_fallbacks;
	atomic64_t first_return_epoch;
	atomic64_t last_return_epoch;
	atomic64_t native_fallbacks;
	atomic_t first_return_prog_id;
	atomic_t last_return_prog_id;
	atomic_t mmu_observer_prog_id;
	atomic_t mmu_reloader_prog_id;
	u32 task_pid;
	u32 task_tgid;
	bool active;
};

#define EBPFOS_RUNTIME_PROCESS_RETURN_SYSCALL 1U
#define EBPFOS_RUNTIME_PROCESS_RETURN_IRQ 2U
#define EBPFOS_RUNTIME_PROCESS_CONTINUE_CURRENT 1U

static struct ebpfos_runtime_process_state ebpfos_runtime_process = {
	.lock = __MUTEX_INITIALIZER(ebpfos_runtime_process.lock),
};

struct ebpfos_runtime_device_state {
	struct mutex lock;
	u64 device_slot_id;
	u64 device_object_id;
	u64 epoch;
	atomic64_t writes;
	atomic64_t write_errors;
	atomic64_t first_write_epoch;
	atomic64_t last_write_epoch;
	atomic64_t native_fallbacks;
	atomic64_t dma_operations;
	atomic_t first_write_prog_id;
	atomic_t last_write_prog_id;
	u32 io_port;
	bool active;
};

#define EBPFOS_RUNTIME_DEVICE_UART8250_TX_PORT 0x3f8U

static struct ebpfos_runtime_device_state ebpfos_runtime_device_root = {
	.lock = __MUTEX_INITIALIZER(ebpfos_runtime_device_root.lock),
};

static bool ebpfos_runtime_syscall_active(void)
{
	/* Pairs with the release-store after the root state is initialized. */
	return smp_load_acquire(&ebpfos_runtime_syscall.active);
}

static bool ebpfos_runtime_irq_active(void)
{
	/* Pairs with release-stores after install or exact rollback. */
	return smp_load_acquire(&ebpfos_runtime_irq.active);
}

static bool ebpfos_runtime_process_active(void)
{
	/* Pairs with release-stores after process ownership or rollback. */
	return smp_load_acquire(&ebpfos_runtime_process.active);
}

static bool ebpfos_runtime_device_active(void)
{
	/* Pairs with release-stores after device ownership or exact rollback. */
	return smp_load_acquire(&ebpfos_runtime_device_root.active);
}

static bool ebpfos_runtime_irq_program(const struct bpf_prog *prog)
{
	return prog->type == BPF_PROG_TYPE_SYSCALL && !prog->sleepable &&
	       prog->aux->ebpfos_component && bpf_prog_has_kop_call(prog) &&
	       prog->jited && prog->jited_len;
}

static bool ebpfos_runtime_machine_program(const struct bpf_prog *prog);

static bool ebpfos_runtime_process_program(const struct bpf_prog *prog)
{
	return prog->type == BPF_PROG_TYPE_SYSCALL && !prog->sleepable &&
	       prog->aux->ebpfos_component && !bpf_prog_has_kop_call(prog) &&
	       prog->jited && prog->jited_len;
}

extern asmlinkage void ebpfos_runtime_syscall_entry(void);
extern asmlinkage void entry_SYSCALL_64(void);
extern char ebpfos_runtime_irq_entries_start[];
extern const u8 ebpfos_runtime_irq_entry_descriptor_sha256[SHA256_DIGEST_SIZE];
__visible noinstr void ebpfos_runtime_syscall_dispatch(struct pt_regs *regs);
static int ebpfos_runtime_process_return(u64 operation);

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

static bool
ebpfos_runtime_bundle_has_irq_program(
	const struct ebpfos_runtime_bundle *bundle, u64 slot_id)
{
	int slot = ebpfos_runtime_bundle_find(bundle, slot_id);

	return slot >= 0 && ebpfos_runtime_irq_program(bundle->slots[slot].prog);
}

static bool
ebpfos_runtime_bundle_has_machine_program(
	const struct ebpfos_runtime_bundle *bundle, u64 slot_id)
{
	int slot = ebpfos_runtime_bundle_find(bundle, slot_id);

	return slot >= 0 && ebpfos_runtime_machine_program(bundle->slots[slot].prog);
}

static bool
ebpfos_runtime_bundle_preserves_active_roots(
	const struct ebpfos_runtime_bundle *bundle)
{
	if (ebpfos_runtime_syscall_active() &&
	    ebpfos_runtime_bundle_find(
		bundle, READ_ONCE(ebpfos_runtime_syscall.syscall_slot_id)) < 0)
		return false;
	if (ebpfos_runtime_irq_active() &&
	    (!ebpfos_runtime_bundle_has_irq_program(
		bundle, READ_ONCE(ebpfos_runtime_irq.handler_slot_id)) ||
	     !ebpfos_runtime_bundle_has_machine_program(
		bundle, READ_ONCE(ebpfos_runtime_irq.routing_observer_slot_id)) ||
	     !ebpfos_runtime_bundle_has_machine_program(
		bundle, READ_ONCE(ebpfos_runtime_irq.routing_installer_slot_id)) ||
	     !ebpfos_runtime_bundle_has_machine_program(
		bundle, READ_ONCE(ebpfos_runtime_irq.pulse_observer_slot_id)) ||
	     !ebpfos_runtime_bundle_has_machine_program(
		bundle, READ_ONCE(ebpfos_runtime_irq.pulse_installer_slot_id))))
		return false;
	if (ebpfos_runtime_process_active()) {
		int slot = ebpfos_runtime_bundle_find(
			bundle, READ_ONCE(ebpfos_runtime_process.process_slot_id));

		if (slot < 0 ||
		    !ebpfos_runtime_process_program(bundle->slots[slot].prog) ||
		    !ebpfos_runtime_bundle_has_machine_program(
			bundle,
			READ_ONCE(ebpfos_runtime_process.mmu_observer_slot_id)) ||
		    !ebpfos_runtime_bundle_has_machine_program(
			bundle,
			READ_ONCE(ebpfos_runtime_process.mmu_reloader_slot_id)))
			return false;
	}
	if (ebpfos_runtime_device_active() &&
	    !ebpfos_runtime_bundle_has_machine_program(
		bundle, READ_ONCE(ebpfos_runtime_device_root.device_slot_id)))
		return false;
	return true;
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
	if (active_epoch != request.expected_epoch ||
	    !ebpfos_runtime_bundle_preserves_active_roots(target) ||
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
		 !ebpfos_runtime_bundle_preserves_active_roots(target))
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
	bool process_owned = false;
	int result = 0;

	spin_lock_irqsave(&ebpfos_runtime_root.lock, irq_flags);
	source = rcu_dereference_protected(ebpfos_runtime_root.active,
					   lockdep_is_held(&ebpfos_runtime_root.lock));
	target = ebpfos_runtime_root.staged;
	if (!source || source->epoch != expected_epoch || !target ||
	    target->epoch != target_epoch)
		result = -ESTALE;
	else if (!ebpfos_runtime_bundle_preserves_active_roots(target))
		result = -EPROTO;
	else {
		ebpfos_runtime_root.staged = NULL;
		rcu_assign_pointer(ebpfos_runtime_root.active, target);
		if (ebpfos_runtime_syscall_active())
			WRITE_ONCE(ebpfos_runtime_syscall.epoch, target_epoch);
		if (ebpfos_runtime_irq_active())
			WRITE_ONCE(ebpfos_runtime_irq.epoch, target_epoch);
		if (ebpfos_runtime_process_active()) {
			WRITE_ONCE(ebpfos_runtime_process.epoch, target_epoch);
			process_owned = true;
		}
		if (ebpfos_runtime_device_active())
			WRITE_ONCE(ebpfos_runtime_device_root.epoch, target_epoch);
	}
	spin_unlock_irqrestore(&ebpfos_runtime_root.lock, irq_flags);
	if (!result) {
		atomic64_inc(&ebpfos_runtime_syscall.graph_commits);
		/*
		 * Root replacement is rare and must not depend on the retired
		 * donor timer to advance callbacks.  The expedited grace period
		 * also makes commit return only after every IRQ-side A operation
		 * has linearized wholly before the B epoch.
		 */
		if (process_owned)
			call_rcu(&source->rcu, ebpfos_runtime_bundle_retire_rcu);
		else {
			synchronize_rcu_expedited();
			ebpfos_runtime_bundle_release(source);
		}
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

static void ebpfos_runtime_irq_run(u32 vector)
{
	struct ebpfos_component_call_frame frame = {
		.version = EBPFOS_COMPONENT_CALL_ABI_VERSION,
		.method_id = vector,
		.input_size = sizeof(vector),
		.output_capacity = EBPFOS_COMPONENT_CALL_OUTPUT_SIZE,
	};
	struct ebpfos_runtime_bundle *bundle;
	struct bpf_prog *prog;
	u64 handler_slot_id;
	u64 dispatch_index;
	u32 provider_status;
	int slot;

	if (!ebpfos_runtime_irq_active() ||
	    vector != READ_ONCE(ebpfos_runtime_irq.vector)) {
		atomic64_inc(&ebpfos_runtime_irq.dispatch_errors);
		return;
	}
	handler_slot_id = READ_ONCE(ebpfos_runtime_irq.handler_slot_id);
	rcu_read_lock();
	bundle = rcu_dereference(ebpfos_runtime_root.active);
	if (!bundle)
		goto error;
	slot = ebpfos_runtime_bundle_find(bundle, handler_slot_id);
	if (slot < 0)
		goto error;
	prog = bundle->slots[slot].prog;
	if (!ebpfos_runtime_irq_program(prog))
		goto error;
	frame.object_id = handler_slot_id;
	frame.epoch = bundle->epoch;
	memcpy(frame.input, &vector, sizeof(vector));
	provider_status = bpf_prog_run(prog, &frame);
	if (provider_status || frame.status || frame.output_size != sizeof(u64))
		goto error;
	dispatch_index = atomic64_inc_return(&ebpfos_runtime_irq.dispatches);
	if (dispatch_index == 1) {
		atomic64_set(&ebpfos_runtime_irq.first_dispatch_epoch,
			     bundle->epoch);
		atomic_set(&ebpfos_runtime_irq.first_dispatch_prog_id,
			   prog->aux->id);
	}
	atomic64_set(&ebpfos_runtime_irq.last_dispatch_epoch, bundle->epoch);
	atomic_set(&ebpfos_runtime_irq.last_dispatch_prog_id, prog->aux->id);
	rcu_read_unlock();
	return;

error:
	atomic64_inc(&ebpfos_runtime_irq.dispatch_errors);
	rcu_read_unlock();
}

DECLARE_IDTENTRY_IRQ(X86_TRAP_OTHER, ebpfos_runtime_irq_vector);
static void __ebpfos_runtime_irq_vector(struct pt_regs *regs, u32 vector);

__visible noinstr void ebpfos_runtime_irq_vector(
	struct pt_regs *regs, unsigned long error_code)
{
	irqentry_state_t state = irqentry_enter(regs);
	u32 vector = (u32)(u8)error_code;

	kvm_set_cpu_l1tf_flush_l1d();
	instrumentation_begin();
	run_irq_on_irqstack_cond(__ebpfos_runtime_irq_vector, regs, vector);
	if (user_mode(regs) && ebpfos_runtime_process_active()) {
		ebpfos_runtime_process_return(EBPFOS_RUNTIME_PROCESS_RETURN_IRQ);
		instrumentation_end();
		exit_to_user_mode();
		return;
	}
	instrumentation_end();
	irqentry_exit(regs, state);
}

static noinline void __ebpfos_runtime_irq_vector(
	struct pt_regs *regs, u32 vector)
{
	struct pt_regs *old_regs = set_irq_regs(regs);

	ebpfos_runtime_irq_run(vector);
	set_irq_regs(old_regs);
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
				      u64 observer_slot_id,
				      u64 installer_slot_id,
				      u64 expected_root, u64 target_root,
				      u32 *observed, u32 *written)
{
	struct bpf_prog *observer, *installer;
	u32 count;
	int observer_slot, installer_slot, error;

	observer_slot = ebpfos_runtime_bundle_find(
		bundle, observer_slot_id);
	installer_slot = ebpfos_runtime_bundle_find(
		bundle, installer_slot_id);
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
			 ebpfos_runtime_syscall.observer_slot_id,
			 ebpfos_runtime_syscall.installer_slot_id,
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
			 ebpfos_runtime_syscall.observer_slot_id,
			 ebpfos_runtime_syscall.installer_slot_id,
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

static int ebpfos_runtime_process_activate(
	struct ebpfos_runtime_bundle *bundle, u64 expected_epoch,
	u64 process_slot_id, u64 mmu_observer_slot_id,
	u64 mmu_reloader_slot_id)
{
	struct task_struct *task = current;
	u64 address_space_id, mm_object_id, object_id, root_physical;
	int error = 0, observer_slot, reloader_slot, slot;

	if (!expected_epoch || !process_slot_id || !mmu_observer_slot_id ||
	    !mmu_reloader_slot_id || bundle->epoch != expected_epoch ||
	    !ebpfos_runtime_syscall_active() || !task->mm ||
	    task_pid_nr(task) != task_tgid_nr(task))
		return -EINVAL;
	slot = ebpfos_runtime_bundle_find(bundle, process_slot_id);
	observer_slot = ebpfos_runtime_bundle_find(bundle, mmu_observer_slot_id);
	reloader_slot = ebpfos_runtime_bundle_find(bundle, mmu_reloader_slot_id);
	if (slot < 0 ||
	    !ebpfos_runtime_process_program(bundle->slots[slot].prog) ||
	    observer_slot < 0 || reloader_slot < 0 ||
	    !ebpfos_runtime_machine_program(bundle->slots[observer_slot].prog) ||
	    !ebpfos_runtime_machine_program(bundle->slots[reloader_slot].prog))
		return -EPROTO;
	mutex_lock(&ebpfos_runtime_process.lock);
	if (ebpfos_runtime_process_active()) {
		error = -EBUSY;
		goto out;
	}
	object_id = task->start_boottime ^ ((u64)(u32)task_pid_nr(task) << 32) ^
		    (u32)task_tgid_nr(task);
	if (!object_id)
		object_id = 1;
	mm_object_id = (u64)(unsigned long)task->mm;
	address_space_id = object_id ^ mm_object_id;
	if (!address_space_id)
		address_space_id = 1;
	root_physical = __pa(task->mm->pgd) & CR3_ADDR_MASK;
	if (!root_physical) {
		error = -EPROTO;
		goto out;
	}
	get_task_struct(task);
	ebpfos_runtime_process.task = task;
	ebpfos_runtime_process.process_slot_id = process_slot_id;
	ebpfos_runtime_process.mmu_observer_slot_id = mmu_observer_slot_id;
	ebpfos_runtime_process.mmu_reloader_slot_id = mmu_reloader_slot_id;
	ebpfos_runtime_process.epoch = expected_epoch;
	ebpfos_runtime_process.task_object_id = object_id;
	ebpfos_runtime_process.task_start_boottime = task->start_boottime;
	ebpfos_runtime_process.mm_object_id = mm_object_id;
	ebpfos_runtime_process.address_space_object_id = address_space_id;
	ebpfos_runtime_process.mmu_root_physical = root_physical;
	ebpfos_runtime_process.task_pid = task_pid_nr(task);
	ebpfos_runtime_process.task_tgid = task_tgid_nr(task);
	atomic64_set(&ebpfos_runtime_process.returns, 0);
	atomic64_set(&ebpfos_runtime_process.return_errors, 0);
	atomic64_set(&ebpfos_runtime_process.syscall_returns, 0);
	atomic64_set(&ebpfos_runtime_process.irq_returns, 0);
	atomic64_set(&ebpfos_runtime_process.mmu_observations, 0);
	atomic64_set(&ebpfos_runtime_process.mmu_reloads, 0);
	atomic64_set(&ebpfos_runtime_process.mmu_errors, 0);
	atomic64_set(&ebpfos_runtime_process.mmu_first_epoch, 0);
	atomic64_set(&ebpfos_runtime_process.mmu_last_epoch, 0);
	atomic64_set(&ebpfos_runtime_process.mmu_native_fallbacks, 0);
	atomic64_set(&ebpfos_runtime_process.first_return_epoch, 0);
	atomic64_set(&ebpfos_runtime_process.last_return_epoch, 0);
	atomic64_set(&ebpfos_runtime_process.native_fallbacks, 0);
	atomic_set(&ebpfos_runtime_process.first_return_prog_id, 0);
	atomic_set(&ebpfos_runtime_process.last_return_prog_id, 0);
	atomic_set(&ebpfos_runtime_process.mmu_observer_prog_id, 0);
	atomic_set(&ebpfos_runtime_process.mmu_reloader_prog_id, 0);
	/* Publish the complete stable identity before return-path readers. */
	smp_store_release(&ebpfos_runtime_process.active, true);
out:
	mutex_unlock(&ebpfos_runtime_process.lock);
	return error;
}

static int ebpfos_runtime_process_rollback(
	struct ebpfos_runtime_bundle *bundle, u64 expected_epoch,
	u64 process_slot_id, u64 mmu_observer_slot_id,
	u64 mmu_reloader_slot_id)
{
	struct task_struct *task = NULL;
	int error = 0;

	mutex_lock(&ebpfos_runtime_process.lock);
	if (!ebpfos_runtime_process_active() ||
	    bundle->epoch != expected_epoch ||
	    READ_ONCE(ebpfos_runtime_process.epoch) != expected_epoch ||
	    ebpfos_runtime_process.process_slot_id != process_slot_id ||
	    ebpfos_runtime_process.mmu_observer_slot_id != mmu_observer_slot_id ||
	    ebpfos_runtime_process.mmu_reloader_slot_id != mmu_reloader_slot_id ||
	    ebpfos_runtime_device_active() ||
	    ebpfos_runtime_process.task != current) {
		error = -ESTALE;
		goto out;
	}
	task = ebpfos_runtime_process.task;
	/* Stop return-path readers before dropping the stable task reference. */
	smp_store_release(&ebpfos_runtime_process.active, false);
	ebpfos_runtime_process.task = NULL;
out:
	mutex_unlock(&ebpfos_runtime_process.lock);
	if (task)
		put_task_struct(task);
	return error;
}

static void ebpfos_runtime_process_status(
	struct ebpfos_runtime_process_root *status)
{
	memset(status, 0, sizeof(*status));
	status->version = EBPFOS_RUNTIME_ROOT_ABI_VERSION;
	mutex_lock(&ebpfos_runtime_process.lock);
	status->expected_epoch = READ_ONCE(ebpfos_runtime_process.epoch);
	status->process_slot_id = ebpfos_runtime_process.process_slot_id;
	status->mmu_observer_slot_id =
		ebpfos_runtime_process.mmu_observer_slot_id;
	status->mmu_reloader_slot_id =
		ebpfos_runtime_process.mmu_reloader_slot_id;
	status->task_object_id = ebpfos_runtime_process.task_object_id;
	status->task_start_boottime =
		ebpfos_runtime_process.task_start_boottime;
	status->mm_object_id = ebpfos_runtime_process.mm_object_id;
	status->address_space_object_id =
		ebpfos_runtime_process.address_space_object_id;
	status->mmu_root_physical = ebpfos_runtime_process.mmu_root_physical;
	status->task_pid = ebpfos_runtime_process.task_pid;
	status->task_tgid = ebpfos_runtime_process.task_tgid;
	status->active = ebpfos_runtime_process_active();
	mutex_unlock(&ebpfos_runtime_process.lock);
	status->returns = atomic64_read(&ebpfos_runtime_process.returns);
	status->return_errors =
		atomic64_read(&ebpfos_runtime_process.return_errors);
	status->syscall_returns =
		atomic64_read(&ebpfos_runtime_process.syscall_returns);
	status->irq_returns = atomic64_read(&ebpfos_runtime_process.irq_returns);
	status->mmu_observations =
		atomic64_read(&ebpfos_runtime_process.mmu_observations);
	status->mmu_reloads = atomic64_read(&ebpfos_runtime_process.mmu_reloads);
	status->mmu_errors = atomic64_read(&ebpfos_runtime_process.mmu_errors);
	status->mmu_first_epoch =
		atomic64_read(&ebpfos_runtime_process.mmu_first_epoch);
	status->mmu_last_epoch =
		atomic64_read(&ebpfos_runtime_process.mmu_last_epoch);
	status->mmu_native_fallbacks =
		atomic64_read(&ebpfos_runtime_process.mmu_native_fallbacks);
	status->first_return_epoch =
		atomic64_read(&ebpfos_runtime_process.first_return_epoch);
	status->last_return_epoch =
		atomic64_read(&ebpfos_runtime_process.last_return_epoch);
	status->native_fallbacks =
		atomic64_read(&ebpfos_runtime_process.native_fallbacks);
	status->first_return_prog_id =
		atomic_read(&ebpfos_runtime_process.first_return_prog_id);
	status->last_return_prog_id =
		atomic_read(&ebpfos_runtime_process.last_return_prog_id);
	status->mmu_observer_prog_id =
		atomic_read(&ebpfos_runtime_process.mmu_observer_prog_id);
	status->mmu_reloader_prog_id =
		atomic_read(&ebpfos_runtime_process.mmu_reloader_prog_id);
}

static long ebpfos_runtime_process_read(void __user *argp)
{
	struct ebpfos_runtime_process_root status;

	ebpfos_runtime_process_status(&status);
	return copy_to_user(argp, &status, sizeof(status)) ? -EFAULT : 0;
}

static int ebpfos_runtime_device_activate(
	struct ebpfos_runtime_bundle *bundle, u64 expected_epoch,
	u64 device_slot_id)
{
	int error = 0, slot;

	if (!expected_epoch || !device_slot_id ||
	    bundle->epoch != expected_epoch ||
	    !ebpfos_runtime_syscall_active() ||
	    !ebpfos_runtime_process_active() ||
	    READ_ONCE(ebpfos_runtime_process.task) != current)
		return -EINVAL;
	slot = ebpfos_runtime_bundle_find(bundle, device_slot_id);
	if (slot < 0 ||
	    !ebpfos_runtime_machine_program(bundle->slots[slot].prog))
		return -EPROTO;
	mutex_lock(&ebpfos_runtime_device_root.lock);
	if (ebpfos_runtime_device_active()) {
		error = -EBUSY;
		goto out;
	}
	ebpfos_runtime_device_root.device_slot_id = device_slot_id;
	ebpfos_runtime_device_root.device_object_id = device_slot_id;
	ebpfos_runtime_device_root.epoch = expected_epoch;
	ebpfos_runtime_device_root.io_port =
		EBPFOS_RUNTIME_DEVICE_UART8250_TX_PORT;
	atomic64_set(&ebpfos_runtime_device_root.writes, 0);
	atomic64_set(&ebpfos_runtime_device_root.write_errors, 0);
	atomic64_set(&ebpfos_runtime_device_root.first_write_epoch, 0);
	atomic64_set(&ebpfos_runtime_device_root.last_write_epoch, 0);
	atomic64_set(&ebpfos_runtime_device_root.native_fallbacks, 0);
	atomic64_set(&ebpfos_runtime_device_root.dma_operations, 0);
	atomic_set(&ebpfos_runtime_device_root.first_write_prog_id, 0);
	atomic_set(&ebpfos_runtime_device_root.last_write_prog_id, 0);
	/* Publish the complete fixed PIO authority before write-path readers. */
	smp_store_release(&ebpfos_runtime_device_root.active, true);
out:
	mutex_unlock(&ebpfos_runtime_device_root.lock);
	return error;
}

static int ebpfos_runtime_device_emit(
	struct ebpfos_runtime_bundle *bundle, u64 expected_epoch,
	u64 device_slot_id, u64 byte)
{
	struct ebpfos_component_call_frame frame = {
		.version = EBPFOS_COMPONENT_CALL_ABI_VERSION,
		.method_id = 1,
		.input_size = sizeof(byte),
		.output_capacity = EBPFOS_COMPONENT_CALL_OUTPUT_SIZE,
	};
	struct bpf_prog *prog;
	u64 result = 0, write_index;
	u32 provider_status;
	int error = 0, slot;

	if (byte > U8_MAX)
		return -ERANGE;
	mutex_lock(&ebpfos_runtime_device_root.lock);
	if (!ebpfos_runtime_device_active() ||
	    bundle->epoch != expected_epoch ||
	    ebpfos_runtime_device_root.epoch != expected_epoch ||
	    ebpfos_runtime_device_root.device_slot_id != device_slot_id ||
	    ebpfos_runtime_device_root.io_port !=
		EBPFOS_RUNTIME_DEVICE_UART8250_TX_PORT ||
	    !ebpfos_runtime_process_active() ||
	    READ_ONCE(ebpfos_runtime_process.task) != current) {
		error = -ESTALE;
		goto fault;
	}
	slot = ebpfos_runtime_bundle_find(bundle, device_slot_id);
	if (slot < 0) {
		error = -ENOENT;
		goto fault;
	}
	prog = bundle->slots[slot].prog;
	if (!ebpfos_runtime_machine_program(prog)) {
		error = -EPROTO;
		goto fault;
	}
	frame.object_id = ebpfos_runtime_device_root.device_object_id;
	frame.epoch = bundle->epoch;
	memcpy(frame.input, &byte, sizeof(byte));
	provider_status = bpf_prog_run_pin_on_cpu(prog, &frame);
	if (provider_status || frame.status ||
	    frame.output_size != sizeof(result)) {
		error = frame.status ? frame.status : -EREMOTEIO;
		goto fault;
	}
	memcpy(&result, frame.output, sizeof(result));
	if (result != byte) {
		error = -ESTALE;
		goto fault;
	}
	write_index = atomic64_inc_return(&ebpfos_runtime_device_root.writes);
	if (write_index == 1) {
		atomic64_set(&ebpfos_runtime_device_root.first_write_epoch,
			     bundle->epoch);
		atomic_set(&ebpfos_runtime_device_root.first_write_prog_id,
			   prog->aux->id);
	}
	atomic64_set(&ebpfos_runtime_device_root.last_write_epoch, bundle->epoch);
	atomic_set(&ebpfos_runtime_device_root.last_write_prog_id, prog->aux->id);
	mutex_unlock(&ebpfos_runtime_device_root.lock);
	return 0;

fault:
	atomic64_inc(&ebpfos_runtime_device_root.write_errors);
	mutex_unlock(&ebpfos_runtime_device_root.lock);
	return error;
}

static int ebpfos_runtime_device_rollback(
	struct ebpfos_runtime_bundle *bundle, u64 expected_epoch,
	u64 device_slot_id)
{
	int error = 0, slot;

	mutex_lock(&ebpfos_runtime_device_root.lock);
	slot = ebpfos_runtime_bundle_find(bundle, device_slot_id);
	if (!ebpfos_runtime_device_active() ||
	    bundle->epoch != expected_epoch ||
	    ebpfos_runtime_device_root.epoch != expected_epoch ||
	    ebpfos_runtime_device_root.device_slot_id != device_slot_id ||
	    slot < 0 ||
	    !ebpfos_runtime_machine_program(bundle->slots[slot].prog) ||
	    !ebpfos_runtime_process_active() ||
	    READ_ONCE(ebpfos_runtime_process.task) != current) {
		error = -ESTALE;
		goto out;
	}
	/* The append-only console prefix remains the exact abstract state. */
	smp_store_release(&ebpfos_runtime_device_root.active, false);
out:
	mutex_unlock(&ebpfos_runtime_device_root.lock);
	return error;
}

static void ebpfos_runtime_device_status(
	struct ebpfos_runtime_device_root *status)
{
	memset(status, 0, sizeof(*status));
	status->version = EBPFOS_RUNTIME_ROOT_ABI_VERSION;
	mutex_lock(&ebpfos_runtime_device_root.lock);
	status->expected_epoch = READ_ONCE(ebpfos_runtime_device_root.epoch);
	status->device_slot_id = ebpfos_runtime_device_root.device_slot_id;
	status->device_object_id = ebpfos_runtime_device_root.device_object_id;
	status->io_port = ebpfos_runtime_device_root.io_port;
	status->active = ebpfos_runtime_device_active();
	mutex_unlock(&ebpfos_runtime_device_root.lock);
	status->writes = atomic64_read(&ebpfos_runtime_device_root.writes);
	status->write_errors =
		atomic64_read(&ebpfos_runtime_device_root.write_errors);
	status->first_write_epoch =
		atomic64_read(&ebpfos_runtime_device_root.first_write_epoch);
	status->last_write_epoch =
		atomic64_read(&ebpfos_runtime_device_root.last_write_epoch);
	status->native_fallbacks =
		atomic64_read(&ebpfos_runtime_device_root.native_fallbacks);
	status->dma_operations =
		atomic64_read(&ebpfos_runtime_device_root.dma_operations);
	status->first_write_prog_id =
		atomic_read(&ebpfos_runtime_device_root.first_write_prog_id);
	status->last_write_prog_id =
		atomic_read(&ebpfos_runtime_device_root.last_write_prog_id);
}

static long ebpfos_runtime_device_read(void __user *argp)
{
	struct ebpfos_runtime_device_root status;

	ebpfos_runtime_device_status(&status);
	return copy_to_user(argp, &status, sizeof(status)) ? -EFAULT : 0;
}

static int ebpfos_runtime_process_return(u64 operation)
{
	struct ebpfos_component_call_frame frame = {
		.version = EBPFOS_COMPONENT_CALL_ABI_VERSION,
		.method_id = operation,
		.input_size = 6 * sizeof(u64),
		.output_capacity = EBPFOS_COMPONENT_CALL_OUTPUT_SIZE,
	};
	struct ebpfos_runtime_bundle *bundle;
	struct bpf_prog *observer, *prog, *reloader;
	u64 input[6], action = 0, object_id = 0;
	u64 mmu_index, return_index, root_physical;
	u32 provider_status, slot;
	int error = 0, observer_slot, reloader_slot;

	if (!ebpfos_runtime_process_active())
		return -ENOENT;
	bundle = ebpfos_runtime_bundle_get(
		READ_ONCE(ebpfos_runtime_process.process_slot_id), &slot);
	if (!bundle) {
		error = -ENOENT;
		goto fault;
	}
	prog = bundle->slots[slot].prog;
	observer_slot = ebpfos_runtime_bundle_find(
		bundle, READ_ONCE(ebpfos_runtime_process.mmu_observer_slot_id));
	reloader_slot = ebpfos_runtime_bundle_find(
		bundle, READ_ONCE(ebpfos_runtime_process.mmu_reloader_slot_id));
	root_physical = current->mm ? __pa(current->mm->pgd) & CR3_ADDR_MASK : 0;
	if (!ebpfos_runtime_process_program(prog) ||
	    observer_slot < 0 || reloader_slot < 0 ||
	    !ebpfos_runtime_machine_program(bundle->slots[observer_slot].prog) ||
	    !ebpfos_runtime_machine_program(bundle->slots[reloader_slot].prog) ||
	    bundle->epoch != READ_ONCE(ebpfos_runtime_process.epoch) ||
	    current != READ_ONCE(ebpfos_runtime_process.task) ||
	    task_pid_nr(current) != ebpfos_runtime_process.task_pid ||
	    task_tgid_nr(current) != ebpfos_runtime_process.task_tgid ||
	    current->start_boottime !=
		ebpfos_runtime_process.task_start_boottime ||
	    (u64)(unsigned long)current->mm !=
		ebpfos_runtime_process.mm_object_id ||
	    root_physical != ebpfos_runtime_process.mmu_root_physical) {
		error = -ESTALE;
		goto out;
	}
	observer = bundle->slots[observer_slot].prog;
	reloader = bundle->slots[reloader_slot].prog;
	frame.object_id = ebpfos_runtime_process.task_object_id;
	frame.epoch = bundle->epoch;
	input[0] = frame.object_id;
	input[1] = (u64)(unsigned long)current;
	input[2] = (u64)(unsigned long)current->mm;
	input[3] = ebpfos_runtime_process.task_pid;
	input[4] = ebpfos_runtime_process.task_tgid;
	input[5] = READ_ONCE(current_thread_info()->flags) |
		   READ_ONCE(current_thread_info()->syscall_work);
	memcpy(frame.input, input, sizeof(input));
	provider_status = bpf_prog_run_pin_on_cpu(prog, &frame);
	if (provider_status || frame.status ||
	    frame.output_size != 2 * sizeof(u64)) {
		error = frame.status ? frame.status : -EREMOTEIO;
		goto out;
	}
	memcpy(&action, frame.output, sizeof(action));
	memcpy(&object_id, frame.output + sizeof(u64), sizeof(object_id));
	if (action != EBPFOS_RUNTIME_PROCESS_CONTINUE_CURRENT ||
	    object_id != ebpfos_runtime_process.task_object_id) {
		error = -EPROTO;
		goto out;
	}
	migrate_disable();
	error = ebpfos_runtime_machine_run(observer, root_physical);
	if (!error)
		error = ebpfos_runtime_machine_run(reloader, root_physical);
	migrate_enable();
	if (error) {
		atomic64_inc(&ebpfos_runtime_process.mmu_errors);
		goto out;
	}
	mmu_index = atomic64_inc_return(
		&ebpfos_runtime_process.mmu_observations);
	atomic64_inc(&ebpfos_runtime_process.mmu_reloads);
	if (mmu_index == 1)
		atomic64_set(&ebpfos_runtime_process.mmu_first_epoch,
			     bundle->epoch);
	atomic64_set(&ebpfos_runtime_process.mmu_last_epoch, bundle->epoch);
	atomic_set(&ebpfos_runtime_process.mmu_observer_prog_id,
		   observer->aux->id);
	atomic_set(&ebpfos_runtime_process.mmu_reloader_prog_id,
		   reloader->aux->id);
	return_index = atomic64_inc_return(&ebpfos_runtime_process.returns);
	if (operation == EBPFOS_RUNTIME_PROCESS_RETURN_SYSCALL)
		atomic64_inc(&ebpfos_runtime_process.syscall_returns);
	else if (operation == EBPFOS_RUNTIME_PROCESS_RETURN_IRQ)
		atomic64_inc(&ebpfos_runtime_process.irq_returns);
	else {
		error = -EINVAL;
		goto out;
	}
	if (return_index == 1) {
		atomic64_set(&ebpfos_runtime_process.first_return_epoch,
			     bundle->epoch);
		atomic_set(&ebpfos_runtime_process.first_return_prog_id,
			   prog->aux->id);
	}
	atomic64_set(&ebpfos_runtime_process.last_return_epoch, bundle->epoch);
	atomic_set(&ebpfos_runtime_process.last_return_prog_id, prog->aux->id);
out:
	ebpfos_runtime_bundle_release(bundle);
fault:
	if (error)
		atomic64_inc(&ebpfos_runtime_process.return_errors);
	return error;
}

static void ebpfos_runtime_irq_status(struct ebpfos_runtime_irq_root *status)
{
	memset(status, 0, sizeof(*status));
	status->version = EBPFOS_RUNTIME_ROOT_ABI_VERSION;
	mutex_lock(&ebpfos_runtime_irq.lock);
	status->expected_epoch = ebpfos_runtime_irq.epoch;
	status->observer_slot_id = ebpfos_runtime_irq.observer_slot_id;
	status->installer_slot_id = ebpfos_runtime_irq.installer_slot_id;
	status->handler_slot_id = ebpfos_runtime_irq.handler_slot_id;
	status->routing_observer_slot_id =
		ebpfos_runtime_irq.routing_observer_slot_id;
	status->routing_installer_slot_id =
		ebpfos_runtime_irq.routing_installer_slot_id;
	status->pulse_observer_slot_id = ebpfos_runtime_irq.pulse_observer_slot_id;
	status->pulse_installer_slot_id =
		ebpfos_runtime_irq.pulse_installer_slot_id;
	status->routing_old = ebpfos_runtime_irq.routing_old;
	status->routing_target = ebpfos_runtime_irq.routing_target;
	status->pulse_resting = ebpfos_runtime_irq.pulse_resting;
	status->pulse_armed = ebpfos_runtime_irq.pulse_armed;
	status->old_idtr = ebpfos_runtime_irq.old_idtr;
	status->target_idtr = ebpfos_runtime_irq.target_idtr;
	status->handler_entry = ebpfos_runtime_irq.handler_entry;
	memcpy(status->target_table_sha256,
	       ebpfos_runtime_irq.target_table_sha256,
	       sizeof(status->target_table_sha256));
	memcpy(status->entry_descriptor_sha256,
	       ebpfos_runtime_irq_entry_descriptor_sha256,
	       sizeof(status->entry_descriptor_sha256));
	status->dispatches = atomic64_read(&ebpfos_runtime_irq.dispatches);
	status->dispatch_errors =
		atomic64_read(&ebpfos_runtime_irq.dispatch_errors);
	status->pulse_rearms = atomic64_read(&ebpfos_runtime_irq.pulse_rearms);
	status->first_dispatch_epoch =
		atomic64_read(&ebpfos_runtime_irq.first_dispatch_epoch);
	status->last_dispatch_epoch =
		atomic64_read(&ebpfos_runtime_irq.last_dispatch_epoch);
	status->cpus_observed = ebpfos_runtime_irq.cpus_observed;
	status->cpus_written = ebpfos_runtime_irq.cpus_written;
	status->machine_cpus_observed =
		ebpfos_runtime_irq.machine_cpus_observed;
	status->machine_cpus_written = ebpfos_runtime_irq.machine_cpus_written;
	status->vector = ebpfos_runtime_irq.vector;
	status->gate_dpl = ebpfos_runtime_irq.gate_dpl;
	status->first_dispatch_prog_id =
		atomic_read(&ebpfos_runtime_irq.first_dispatch_prog_id);
	status->last_dispatch_prog_id =
		atomic_read(&ebpfos_runtime_irq.last_dispatch_prog_id);
	status->active = ebpfos_runtime_irq_active();
	mutex_unlock(&ebpfos_runtime_irq.lock);
}

static int ebpfos_runtime_irq_rollback(struct ebpfos_runtime_bundle *bundle,
				       u64 expected_epoch,
				       u64 resume_installer_slot_id,
				       u64 resume_operand)
{
	unsigned long target_table = 0;
	struct bpf_prog *pulse_observer, *pulse_installer, *resume_installer = NULL;
	u32 observed = 0, written = 0, count = 0;
	int error, pulse_observer_slot, pulse_installer_slot, resume_installer_slot;

	mutex_lock(&ebpfos_runtime_irq.lock);
	if (!ebpfos_runtime_irq_active() || bundle->epoch != expected_epoch ||
	    ebpfos_runtime_irq.epoch != expected_epoch) {
		error = -ESTALE;
		goto out;
	}
	pulse_observer_slot = ebpfos_runtime_bundle_find(
		bundle, ebpfos_runtime_irq.pulse_observer_slot_id);
	pulse_installer_slot = ebpfos_runtime_bundle_find(
		bundle, ebpfos_runtime_irq.pulse_installer_slot_id);
	resume_installer_slot = resume_installer_slot_id ?
		ebpfos_runtime_bundle_find(bundle, resume_installer_slot_id) : -1;
	if (pulse_observer_slot < 0 || pulse_installer_slot < 0 ||
	    (resume_installer_slot_id && resume_installer_slot < 0)) {
		error = -ENOENT;
		goto out;
	}
	pulse_observer = bundle->slots[pulse_observer_slot].prog;
	pulse_installer = bundle->slots[pulse_installer_slot].prog;
	if (resume_installer_slot_id)
		resume_installer = bundle->slots[resume_installer_slot].prog;
	if (!ebpfos_runtime_machine_program(pulse_observer) ||
	    !ebpfos_runtime_machine_program(pulse_installer) ||
	    (resume_installer_slot_id &&
	     !ebpfos_runtime_machine_program(resume_installer))) {
		error = -EPROTO;
		goto out;
	}
	error = ebpfos_runtime_machine_all_cpus(
		pulse_observer, ebpfos_runtime_irq.pulse_resting, &count);
	ebpfos_runtime_irq.machine_cpus_observed += count;
	if (error)
		goto out;
	error = ebpfos_runtime_machine_all_cpus(
		pulse_installer, ebpfos_runtime_irq.pulse_resting, &count);
	ebpfos_runtime_irq.machine_cpus_written += count;
	if (error)
		goto out;
	error = ebpfos_runtime_root_vector(bundle,
			 ebpfos_runtime_irq.observer_slot_id,
			 ebpfos_runtime_irq.installer_slot_id,
			 ebpfos_runtime_irq.target_idtr,
			 ebpfos_runtime_irq.old_idtr, &observed, &written);
	ebpfos_runtime_irq.cpus_observed += observed;
	ebpfos_runtime_irq.cpus_written += written;
	if (error)
		goto out;
	error = ebpfos_runtime_root_vector(bundle,
			 ebpfos_runtime_irq.routing_observer_slot_id,
			 ebpfos_runtime_irq.routing_installer_slot_id,
			 ebpfos_runtime_irq.routing_target,
			 ebpfos_runtime_irq.routing_old, &observed, &written);
	ebpfos_runtime_irq.machine_cpus_observed += observed;
	ebpfos_runtime_irq.machine_cpus_written += written;
	if (error)
		goto out;
	/* Publish inactive only after every CPU restored both machine roots. */
	smp_store_release(&ebpfos_runtime_irq.active, false);
	target_table = ebpfos_runtime_irq.target_table;
	ebpfos_runtime_irq.target_table = 0;
	if (resume_installer) {
		error = ebpfos_runtime_machine_all_cpus(
			resume_installer, resume_operand, &count);
		ebpfos_runtime_irq.machine_cpus_written += count;
	}
out:
	mutex_unlock(&ebpfos_runtime_irq.lock);
	if (target_table)
		free_page(target_table);
	return error;
}

static int ebpfos_runtime_irq_activate(struct ebpfos_runtime_bundle *bundle,
				       u64 expected_epoch,
				       u64 observer_slot_id,
				       u64 installer_slot_id,
				       u64 handler_slot_id,
				       u64 routing_observer_slot_id,
				       u64 routing_installer_slot_id,
				       u64 pulse_observer_slot_id,
				       u64 pulse_installer_slot_id,
				       u64 routing_old, u64 routing_target,
				       u64 pulse_resting, u64 pulse_armed,
				       u32 vector, u32 gate_dpl,
				       struct ebpfos_runtime_irq_root *status)
{
	struct desc_ptr old_idtr;
	unsigned long target_table;
	unsigned long handler_entry;
	u32 observed = 0, written = 0, count = 0, rollback_count = 0;
	int error, observer_slot, installer_slot, handler_slot;
	int routing_observer_slot, routing_installer_slot;
	int pulse_observer_slot, pulse_installer_slot, rollback_error;
	bool routing_installed = false, idtr_installed = false;

	if (!expected_epoch || !observer_slot_id || !installer_slot_id ||
	    !handler_slot_id || !routing_observer_slot_id ||
	    !routing_installer_slot_id || !pulse_observer_slot_id ||
	    !pulse_installer_slot_id || routing_old == routing_target ||
	    pulse_resting == pulse_armed || vector < FIRST_EXTERNAL_VECTOR ||
	    vector >= NR_VECTORS || (gate_dpl != 0 && gate_dpl != 3) ||
	    bundle->epoch != expected_epoch)
		return -ESTALE;
	observer_slot = ebpfos_runtime_bundle_find(bundle,
						 observer_slot_id);
	installer_slot = ebpfos_runtime_bundle_find(bundle,
						  installer_slot_id);
	handler_slot = ebpfos_runtime_bundle_find(bundle, handler_slot_id);
	routing_observer_slot = ebpfos_runtime_bundle_find(
		bundle, routing_observer_slot_id);
	routing_installer_slot = ebpfos_runtime_bundle_find(
		bundle, routing_installer_slot_id);
	pulse_observer_slot = ebpfos_runtime_bundle_find(
		bundle, pulse_observer_slot_id);
	pulse_installer_slot = ebpfos_runtime_bundle_find(
		bundle, pulse_installer_slot_id);
	if (observer_slot < 0 || installer_slot < 0 ||
	    handler_slot < 0 || routing_observer_slot < 0 ||
	    routing_installer_slot < 0 || pulse_observer_slot < 0 ||
	    pulse_installer_slot < 0 ||
	    !ebpfos_runtime_machine_program(bundle->slots[observer_slot].prog) ||
	    !ebpfos_runtime_machine_program(bundle->slots[installer_slot].prog) ||
	    !ebpfos_runtime_machine_program(
		bundle->slots[routing_observer_slot].prog) ||
	    !ebpfos_runtime_machine_program(
		bundle->slots[routing_installer_slot].prog) ||
	    !ebpfos_runtime_machine_program(
		bundle->slots[pulse_observer_slot].prog) ||
	    !ebpfos_runtime_machine_program(
		bundle->slots[pulse_installer_slot].prog) ||
	    !ebpfos_runtime_irq_program(bundle->slots[handler_slot].prog))
		return -EPROTO;
	store_idt(&old_idtr);
	if (old_idtr.size != IDT_ENTRIES * sizeof(gate_desc) - 1)
		return -EOPNOTSUPP;
	target_table = get_zeroed_page(GFP_KERNEL);
	if (!target_table)
		return -ENOMEM;
	memcpy((void *)target_table, (const void *)old_idtr.address, PAGE_SIZE);
	handler_entry = (unsigned long)ebpfos_runtime_irq_entries_start +
		IDT_ALIGN * (vector - FIRST_EXTERNAL_VECTOR);
	pack_gate(&((gate_desc *)target_table)[vector], GATE_INTERRUPT,
		  handler_entry, gate_dpl, 0, __KERNEL_CS);
	mutex_lock(&ebpfos_runtime_irq.lock);
	if (ebpfos_runtime_irq.active) {
		error = -EBUSY;
		goto out_free_unlock;
	}
	ebpfos_runtime_irq.observer_slot_id = observer_slot_id;
	ebpfos_runtime_irq.installer_slot_id = installer_slot_id;
	ebpfos_runtime_irq.handler_slot_id = handler_slot_id;
	ebpfos_runtime_irq.routing_observer_slot_id = routing_observer_slot_id;
	ebpfos_runtime_irq.routing_installer_slot_id = routing_installer_slot_id;
	ebpfos_runtime_irq.pulse_observer_slot_id = pulse_observer_slot_id;
	ebpfos_runtime_irq.pulse_installer_slot_id = pulse_installer_slot_id;
	ebpfos_runtime_irq.routing_old = routing_old;
	ebpfos_runtime_irq.routing_target = routing_target;
	ebpfos_runtime_irq.pulse_resting = pulse_resting;
	ebpfos_runtime_irq.pulse_armed = pulse_armed;
	ebpfos_runtime_irq.epoch = expected_epoch;
	ebpfos_runtime_irq.old_idtr = old_idtr.address;
	ebpfos_runtime_irq.target_idtr = target_table;
	ebpfos_runtime_irq.handler_entry = handler_entry;
	ebpfos_runtime_irq.target_table = target_table;
	ebpfos_runtime_irq.vector = vector;
	ebpfos_runtime_irq.gate_dpl = gate_dpl;
	atomic64_set(&ebpfos_runtime_irq.dispatches, 0);
	atomic64_set(&ebpfos_runtime_irq.dispatch_errors, 0);
	atomic64_set(&ebpfos_runtime_irq.pulse_rearms, 0);
	atomic64_set(&ebpfos_runtime_irq.first_dispatch_epoch, 0);
	atomic64_set(&ebpfos_runtime_irq.last_dispatch_epoch, 0);
	atomic_set(&ebpfos_runtime_irq.first_dispatch_prog_id, 0);
	atomic_set(&ebpfos_runtime_irq.last_dispatch_prog_id, 0);
	ebpfos_runtime_irq.machine_cpus_observed = 0;
	ebpfos_runtime_irq.machine_cpus_written = 0;
	sha256((const u8 *)target_table, PAGE_SIZE,
	       ebpfos_runtime_irq.target_table_sha256);
	routing_installed = true;
	error = ebpfos_runtime_root_vector(bundle,
			 routing_observer_slot_id, routing_installer_slot_id,
			 routing_old, routing_target, &observed, &written);
	ebpfos_runtime_irq.machine_cpus_observed += observed;
	ebpfos_runtime_irq.machine_cpus_written += written;
	if (error)
		goto out_restore;
	error = ebpfos_runtime_machine_all_cpus(
		bundle->slots[pulse_observer_slot].prog, pulse_resting, &count);
	ebpfos_runtime_irq.machine_cpus_observed += count;
	if (error)
		goto out_restore;
	idtr_installed = true;
	error = ebpfos_runtime_root_vector(bundle,
			 observer_slot_id, installer_slot_id,
			 old_idtr.address, target_table, &observed, &written);
	ebpfos_runtime_irq.cpus_observed = observed;
	ebpfos_runtime_irq.cpus_written = written;
	if (error)
		goto out_restore;
	/* Publish active before arming any interrupt source. */
	smp_store_release(&ebpfos_runtime_irq.active, true);
	error = ebpfos_runtime_machine_all_cpus(
		bundle->slots[pulse_installer_slot].prog, pulse_armed, &count);
	ebpfos_runtime_irq.machine_cpus_written += count;
	if (error)
		goto out_restore;
	if (status) {
		status->old_idtr = old_idtr.address;
		status->target_idtr = target_table;
		status->handler_entry = handler_entry;
		memcpy(status->target_table_sha256,
		       ebpfos_runtime_irq.target_table_sha256,
		       sizeof(status->target_table_sha256));
		status->cpus_observed = observed;
		status->cpus_written = written;
		status->machine_cpus_observed =
			ebpfos_runtime_irq.machine_cpus_observed;
		status->machine_cpus_written =
			ebpfos_runtime_irq.machine_cpus_written;
		status->vector = vector;
		status->gate_dpl = gate_dpl;
		status->active = 1;
	}
	mutex_unlock(&ebpfos_runtime_irq.lock);
	return 0;

out_restore:
	rollback_error = ebpfos_runtime_machine_all_cpus(
		bundle->slots[pulse_installer_slot].prog, pulse_resting,
		&rollback_count);
	if (!rollback_error && idtr_installed)
		rollback_error = ebpfos_runtime_machine_all_cpus(
			bundle->slots[installer_slot].prog, old_idtr.address,
			&rollback_count);
	if (!rollback_error && routing_installed)
		rollback_error = ebpfos_runtime_machine_all_cpus(
			bundle->slots[routing_installer_slot].prog, routing_old,
			&rollback_count);
	if (rollback_error) {
		/* A partial architectural root retains ownership until recovery. */
		smp_store_release(&ebpfos_runtime_irq.active, true);
		mutex_unlock(&ebpfos_runtime_irq.lock);
		return rollback_error;
	}
	/* Pairs with acquire reads after all partial roots have been restored. */
	smp_store_release(&ebpfos_runtime_irq.active, false);
out_free_unlock:
	ebpfos_runtime_irq.target_table = 0;
	mutex_unlock(&ebpfos_runtime_irq.lock);
	free_page(target_table);
	return error;
}

static int ebpfos_runtime_irq_rearm(struct ebpfos_runtime_bundle *bundle,
				     u64 expected_epoch,
				     u64 pulse_observer_slot_id,
				     u64 pulse_installer_slot_id,
				     u64 pulse_resting, u64 pulse_armed)
{
	struct bpf_prog *observer, *installer;
	u32 count;
	int error, observer_slot, installer_slot;

	mutex_lock(&ebpfos_runtime_irq.lock);
	if (!ebpfos_runtime_irq_active() || bundle->epoch != expected_epoch ||
	    ebpfos_runtime_irq.epoch != expected_epoch ||
	    pulse_observer_slot_id !=
		ebpfos_runtime_irq.pulse_observer_slot_id ||
	    pulse_installer_slot_id !=
		ebpfos_runtime_irq.pulse_installer_slot_id ||
	    pulse_resting != ebpfos_runtime_irq.pulse_resting ||
	    pulse_armed != ebpfos_runtime_irq.pulse_armed) {
		error = -ESTALE;
		goto out;
	}
	observer_slot = ebpfos_runtime_bundle_find(bundle,
						  pulse_observer_slot_id);
	installer_slot = ebpfos_runtime_bundle_find(bundle,
						   pulse_installer_slot_id);
	if (observer_slot < 0 || installer_slot < 0) {
		error = -ENOENT;
		goto out;
	}
	observer = bundle->slots[observer_slot].prog;
	installer = bundle->slots[installer_slot].prog;
	if (!ebpfos_runtime_machine_program(observer) ||
	    !ebpfos_runtime_machine_program(installer)) {
		error = -EPROTO;
		goto out;
	}
	error = ebpfos_runtime_machine_all_cpus(observer, pulse_resting, &count);
	ebpfos_runtime_irq.machine_cpus_observed += count;
	if (error)
		goto out;
	error = ebpfos_runtime_machine_all_cpus(installer, pulse_armed, &count);
	ebpfos_runtime_irq.machine_cpus_written += count;
	if (!error)
		atomic64_inc(&ebpfos_runtime_irq.pulse_rearms);
out:
	mutex_unlock(&ebpfos_runtime_irq.lock);
	return error;
}

static long ebpfos_runtime_irq_install(void __user *argp)
{
	struct ebpfos_runtime_irq_root request;
	struct ebpfos_runtime_bundle *bundle;
	u32 slot;
	int error;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.version != EBPFOS_RUNTIME_ROOT_ABI_VERSION || request.flags ||
	    request.reserved || request.reserved1 || !request.expected_epoch ||
	    !request.observer_slot_id || !request.installer_slot_id ||
	    !request.handler_slot_id || !request.routing_observer_slot_id ||
	    !request.routing_installer_slot_id || !request.pulse_observer_slot_id ||
	    !request.pulse_installer_slot_id)
		return -EINVAL;
	bundle = ebpfos_runtime_bundle_get(request.observer_slot_id, &slot);
	if (!bundle)
		return -ENOENT;
	error = ebpfos_runtime_irq_activate(bundle, request.expected_epoch,
			request.observer_slot_id, request.installer_slot_id,
			request.handler_slot_id, request.routing_observer_slot_id,
			request.routing_installer_slot_id,
			request.pulse_observer_slot_id,
			request.pulse_installer_slot_id, request.routing_old,
			request.routing_target, request.pulse_resting,
			request.pulse_armed, request.vector, request.gate_dpl,
			&request);
	if (!error && copy_to_user(argp, &request, sizeof(request))) {
		error = ebpfos_runtime_irq_rollback(bundle, request.expected_epoch,
						    0, 0);
		if (!error)
			error = -EFAULT;
	}
	ebpfos_runtime_bundle_release(bundle);
	return error;
}

static long ebpfos_runtime_irq_read(void __user *argp)
{
	struct ebpfos_runtime_irq_root status;

	ebpfos_runtime_irq_status(&status);
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
	u64 observer_slot_id = 0, installer_slot_id = 0, handler_slot_id = 0;
	u64 routing_observer_slot_id = 0, routing_installer_slot_id = 0;
	u64 pulse_observer_slot_id = 0, pulse_installer_slot_id = 0;
	u64 routing_old = 0, routing_target = 0;
	u64 pulse_resting = 0, pulse_armed = 0;
	u64 vector = 0, gate_dpl = 0;
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
	if (frame.output_size >= 5 * sizeof(u64)) {
		memcpy(&observer_slot_id, frame.output + 3 * sizeof(u64),
		       sizeof(observer_slot_id));
		memcpy(&installer_slot_id, frame.output + 4 * sizeof(u64),
		       sizeof(installer_slot_id));
	}
	if (frame.output_size >= 8 * sizeof(u64)) {
		memcpy(&handler_slot_id, frame.output + 5 * sizeof(u64),
		       sizeof(handler_slot_id));
		memcpy(&vector, frame.output + 6 * sizeof(u64), sizeof(vector));
		memcpy(&gate_dpl, frame.output + 7 * sizeof(u64),
		       sizeof(gate_dpl));
	}
	if (frame.output_size >= 16 * sizeof(u64)) {
		memcpy(&routing_observer_slot_id,
		       frame.output + 8 * sizeof(u64), sizeof(routing_observer_slot_id));
		memcpy(&routing_installer_slot_id,
		       frame.output + 9 * sizeof(u64), sizeof(routing_installer_slot_id));
		memcpy(&routing_old, frame.output + 10 * sizeof(u64),
		       sizeof(routing_old));
		memcpy(&routing_target, frame.output + 11 * sizeof(u64),
		       sizeof(routing_target));
		memcpy(&pulse_observer_slot_id,
		       frame.output + 12 * sizeof(u64), sizeof(pulse_observer_slot_id));
		memcpy(&pulse_installer_slot_id,
		       frame.output + 13 * sizeof(u64), sizeof(pulse_installer_slot_id));
		memcpy(&pulse_resting, frame.output + 14 * sizeof(u64),
		       sizeof(pulse_resting));
		memcpy(&pulse_armed, frame.output + 15 * sizeof(u64),
		       sizeof(pulse_armed));
	}
	if (action == EBPFOS_RUNTIME_SYSCALL_ACTION_COMMIT_STAGED) {
		int error = ebpfos_runtime_commit_staged(bundle->epoch, target_epoch);

		if (error)
			result = error;
	} else if (action == EBPFOS_RUNTIME_SYSCALL_ACTION_ROLLBACK_ROOT) {
		int error = ebpfos_runtime_syscall_rollback(bundle, target_epoch);

		if (error)
			result = error;
	} else if (action == EBPFOS_RUNTIME_SYSCALL_ACTION_ROLLBACK_IRQ_ROOT) {
		int error = ebpfos_runtime_irq_rollback(bundle, target_epoch,
				observer_slot_id, installer_slot_id);

		if (error)
			result = error;
	} else if (action == EBPFOS_RUNTIME_SYSCALL_ACTION_INSTALL_IRQ_ROOT) {
		int error = ebpfos_runtime_irq_activate(bundle, target_epoch,
				observer_slot_id, installer_slot_id, handler_slot_id,
				routing_observer_slot_id, routing_installer_slot_id,
				pulse_observer_slot_id, pulse_installer_slot_id,
				routing_old, routing_target, pulse_resting, pulse_armed,
				vector, gate_dpl, NULL);

		if (error)
			result = error;
	} else if (action == EBPFOS_RUNTIME_SYSCALL_ACTION_REARM_IRQ_ROOT) {
		int error = ebpfos_runtime_irq_rearm(bundle, target_epoch,
				pulse_observer_slot_id, pulse_installer_slot_id,
				pulse_resting, pulse_armed);

		if (error)
			result = error;
	} else if (action == EBPFOS_RUNTIME_SYSCALL_ACTION_INSTALL_PROCESS_ROOT) {
		int error = ebpfos_runtime_process_activate(
			bundle, target_epoch, observer_slot_id,
			installer_slot_id, handler_slot_id);

		if (error)
			result = error;
	} else if (action == EBPFOS_RUNTIME_SYSCALL_ACTION_ROLLBACK_PROCESS_ROOT) {
		int error = ebpfos_runtime_process_rollback(
			bundle, target_epoch, observer_slot_id,
			installer_slot_id, handler_slot_id);

		if (error)
			result = error;
	} else if (action == EBPFOS_RUNTIME_SYSCALL_ACTION_INSTALL_DEVICE_ROOT) {
		int error = ebpfos_runtime_device_activate(
			bundle, target_epoch, observer_slot_id);

		if (error)
			result = error;
	} else if (action == EBPFOS_RUNTIME_SYSCALL_ACTION_EMIT_DEVICE_BYTE) {
		int error = ebpfos_runtime_device_emit(
			bundle, target_epoch, observer_slot_id, arguments[0]);

		if (error)
			result = error;
	} else if (action == EBPFOS_RUNTIME_SYSCALL_ACTION_ROLLBACK_DEVICE_ROOT) {
		int error = ebpfos_runtime_device_rollback(
			bundle, target_epoch, observer_slot_id);

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
	int process_error;

	enter_from_user_mode(regs);
	instrumentation_begin();
	local_irq_enable();
	regs->ax = ebpfos_runtime_run_syscall(regs);
	if (ebpfos_runtime_process_active()) {
		process_error = ebpfos_runtime_process_return(
			EBPFOS_RUNTIME_PROCESS_RETURN_SYSCALL);
		if (process_error)
			regs->ax = process_error;
		local_irq_disable();
		regs->cx = regs->ip;
		regs->r11 = regs->flags;
		instrumentation_end();
		exit_to_user_mode();
		return;
	}
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
	case EBPFOS_RUNTIME_ROOT_IOC_IRQ_INSTALL:
		return ebpfos_runtime_irq_install(argp);
	case EBPFOS_RUNTIME_ROOT_IOC_IRQ_READ:
		return ebpfos_runtime_irq_read(argp);
	case EBPFOS_RUNTIME_ROOT_IOC_PROCESS_READ:
		return ebpfos_runtime_process_read(argp);
	case EBPFOS_RUNTIME_ROOT_IOC_DEVICE_READ:
		return ebpfos_runtime_device_read(argp);
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
