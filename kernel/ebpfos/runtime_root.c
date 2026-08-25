// SPDX-License-Identifier: GPL-2.0-only
/* Policy-free target runtime root/epoch publication and dispatch primitive. */
#include <crypto/sha2.h>
#include <linux/bpf.h>
#include <linux/cpu.h>
#include <linux/ebpfos.h>
#include <linux/ebpfos_runtime.h>
#include <linux/entry-common.h>
#include <linux/err.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/miscdevice.h>
#include <linux/memblock.h>
#include <linux/mm.h>
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
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include <asm/desc.h>
#include <asm/hw_irq.h>
#include <asm/idtentry.h>
#include <asm/irq_regs.h>
#include <asm/irq_vectors.h>
#include <asm/msr.h>
#include <asm/page.h>
#include <asm/pgtable_types.h>
#include <asm/processor-flags.h>
#include <asm/ptrace.h>
#include <asm/set_memory.h>
#include <asm/special_insns.h>
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
	u64 portal_broadcast_slot_id;
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
	u64 portal_operand;
	u64 portal_generation;
	unsigned long target_table;
	u8 target_table_sha256[SHA256_DIGEST_SIZE];
	atomic64_t dispatches;
	atomic64_t dispatch_errors;
	atomic64_t pulse_rearms;
	atomic64_t portal_broadcasts;
	atomic64_t portal_dispatches;
	atomic64_t first_dispatch_epoch;
	atomic64_t last_dispatch_epoch;
	atomic_t first_dispatch_prog_id;
	atomic_t last_dispatch_prog_id;
	atomic_t portal_operation;
	atomic_t portal_acks;
	atomic_t portal_errors;
	u32 cpus_observed;
	u32 cpus_written;
	u32 machine_cpus_observed;
	u32 machine_cpus_written;
	u32 vector;
	u32 gate_dpl;
	u32 first_vector;
	u32 last_vector;
	u32 vector_count;
	u32 donor_external_gates;
	u32 portal_vector;
	bool active;
};

static struct ebpfos_runtime_irq_state ebpfos_runtime_irq = {
	.lock = __MUTEX_INITIALIZER(ebpfos_runtime_irq.lock),
};

#define EBPFOS_RUNTIME_IRQ_PORTAL_VECTOR 0xf5U
#define EBPFOS_RUNTIME_IRQ_PORTAL_BROADCAST_OPERAND 0xc00f5ULL
#define EBPFOS_RUNTIME_IRQ_PORTAL_RESTORE_IDTR 1U
#define EBPFOS_RUNTIME_IRQ_PORTAL_OBSERVE_PULSE 2U
#define EBPFOS_RUNTIME_IRQ_PORTAL_INSTALL_PULSE 3U
#define EBPFOS_RUNTIME_IRQ_PORTAL_TIMEOUT_NS NSEC_PER_SEC

struct ebpfos_runtime_irq_payload {
	u32 vector;
	u32 portal_operation;
	u64 portal_operand;
	u64 portal_generation;
};

struct ebpfos_runtime_process_task {
	struct task_struct *task;
	u64 task_object_id;
	u64 task_start_boottime;
	u64 mm_object_id;
	u64 address_space_object_id;
	u64 mmu_root_physical;
	u64 context_switch_baseline;
	u32 task_pid;
	u32 task_tgid;
};

struct ebpfos_runtime_process_state {
	struct mutex lock;
	spinlock_t registry_lock;
	struct task_struct *task;
	struct ebpfos_runtime_process_task
		tasks[EBPFOS_RUNTIME_PROCESS_MAX_TASKS];
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
	atomic64_t task_enrollments;
	atomic64_t cpu_mask;
	atomic64_t scheduler_decisions;
	atomic64_t scheduler_native_fallbacks;
	atomic_t first_return_prog_id;
	atomic_t last_return_prog_id;
	atomic_t mmu_observer_prog_id;
	atomic_t mmu_reloader_prog_id;
	u32 task_pid;
	u32 task_tgid;
	u32 task_count;
	u32 mm_count;
	u64 task_set_digest;
	u64 address_space_set_digest;
	u64 mmu_root_set_digest;
	u64 scheduler_context_switch_growth;
	u64 scheduler_cpu_owner_digest;
	u64 cpu_task_objects[EBPFOS_RUNTIME_PROCESS_MAX_TASKS];
	u32 scheduler_cpu_claims;
	atomic_t operations;
	bool active;
};

#define EBPFOS_RUNTIME_PROCESS_RETURN_SYSCALL 1U
#define EBPFOS_RUNTIME_PROCESS_RETURN_IRQ 2U
#define EBPFOS_RUNTIME_PROCESS_CONTINUE_CURRENT 1U

static struct ebpfos_runtime_process_state ebpfos_runtime_process = {
	.lock = __MUTEX_INITIALIZER(ebpfos_runtime_process.lock),
	.registry_lock =
		__SPIN_LOCK_UNLOCKED(ebpfos_runtime_process.registry_lock),
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

struct ebpfos_runtime_successor_state {
	struct mutex lock;
	void *image;
	u64 reserved_bytes;
	u64 transaction_bytes;
	u64 transaction_epoch;
	u8 transaction_sha256[SHA256_DIGEST_SIZE];
	u32 preflight_cpus;
	u32 preflight_cr3_cpus;
	u32 preflight_root_cpus;
	u32 preflight_reverified_cpus;
	u32 preflight_component_cpus;
	bool transaction_admitted;
	bool handoff_preflighted;
	struct ebpfos_runtime_successor_stage descriptor;
};

#define EBPFOS_RUNTIME_SUCCESSOR_MAX_BYTES (64ULL << 20)

static struct ebpfos_runtime_successor_state ebpfos_runtime_successor = {
	.lock = __MUTEX_INITIALIZER(ebpfos_runtime_successor.lock),
};

static phys_addr_t ebpfos_runtime_successor_reserved_base;
static phys_addr_t ebpfos_runtime_successor_reserved_bytes;

static int __init ebpfos_runtime_successor_reserve(char *argument)
{
	char *end;
	phys_addr_t base, bytes;

	if (!argument)
		return -EINVAL;
	bytes = memparse(argument, &end);
	if (*end != '@')
		return -EINVAL;
	base = memparse(end + 1, &end);
	if (*end || !bytes || bytes > EBPFOS_RUNTIME_SUCCESSOR_MAX_BYTES ||
	    !PAGE_ALIGNED(base) || !PAGE_ALIGNED(bytes) ||
	    memblock_reserve(base, bytes))
		return -EINVAL;
	ebpfos_runtime_successor_reserved_base = base;
	ebpfos_runtime_successor_reserved_bytes = bytes;
	return 0;
}
early_param("ebpfos_successor", ebpfos_runtime_successor_reserve);

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
		bundle, READ_ONCE(ebpfos_runtime_irq.installer_slot_id)) ||
	     !ebpfos_runtime_bundle_has_machine_program(
		bundle, READ_ONCE(ebpfos_runtime_irq.portal_broadcast_slot_id)) ||
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
	struct ebpfos_runtime_irq_payload payload = {
		.vector = vector,
	};
	struct ebpfos_component_call_frame frame = {
		.version = EBPFOS_COMPONENT_CALL_ABI_VERSION,
		.method_id = vector,
		.input_size = sizeof(payload),
		.output_capacity = EBPFOS_COMPONENT_CALL_OUTPUT_SIZE,
	};
	struct ebpfos_runtime_bundle *bundle;
	struct bpf_prog *prog;
	u64 handler_slot_id;
	u64 dispatch_index;
	u32 provider_status;
	int slot;

	if (!ebpfos_runtime_irq_active() ||
	    vector < READ_ONCE(ebpfos_runtime_irq.first_vector) ||
	    vector > READ_ONCE(ebpfos_runtime_irq.last_vector)) {
		atomic64_inc(&ebpfos_runtime_irq.dispatch_errors);
		return;
	}
	if (vector == READ_ONCE(ebpfos_runtime_irq.portal_vector)) {
		payload.portal_operation = atomic_read_acquire(
			&ebpfos_runtime_irq.portal_operation);
		if (payload.portal_operation) {
			payload.portal_operand =
				READ_ONCE(ebpfos_runtime_irq.portal_operand);
			payload.portal_generation =
				READ_ONCE(ebpfos_runtime_irq.portal_generation);
		}
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
	memcpy(frame.input, &payload, sizeof(payload));
	provider_status = bpf_prog_run(prog, &frame);
	if (provider_status || frame.status || frame.output_size != sizeof(u64))
		goto error;
	if (payload.portal_operation) {
		if (payload.portal_generation !=
		    READ_ONCE(ebpfos_runtime_irq.portal_generation))
			goto error;
		atomic64_inc(&ebpfos_runtime_irq.portal_dispatches);
		atomic_inc(&ebpfos_runtime_irq.portal_acks);
		rcu_read_unlock();
		return;
	}
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
	if (payload.portal_operation) {
		atomic_inc(&ebpfos_runtime_irq.portal_errors);
		atomic_inc(&ebpfos_runtime_irq.portal_acks);
	} else {
		atomic64_inc(&ebpfos_runtime_irq.dispatch_errors);
	}
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
	struct bpf_prog *second_prog;
	u64 second_operand;
	atomic_t error;
	atomic_t executed;
	atomic_t second_executed;
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
	if (!error && transition->second_prog) {
		error = ebpfos_runtime_machine_run(transition->second_prog,
						   transition->second_operand);
		if (error)
			atomic_cmpxchg(&transition->error, 0, error);
		else
			atomic_inc(&transition->second_executed);
	}
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

static int ebpfos_runtime_machine_pair_all_cpus(
	struct bpf_prog *first_prog, u64 first_operand,
	struct bpf_prog *second_prog, u64 second_operand,
	u32 *first_executed, u32 *second_executed)
{
	struct ebpfos_runtime_machine_transition transition = {
		.prog = first_prog,
		.operand = first_operand,
		.second_prog = second_prog,
		.second_operand = second_operand,
		.error = ATOMIC_INIT(0),
		.executed = ATOMIC_INIT(0),
		.second_executed = ATOMIC_INIT(0),
	};
	int error;

	error = stop_machine(ebpfos_runtime_machine_callback, &transition,
			     cpu_online_mask);
	if (!error)
		error = atomic_read(&transition.error);
	*first_executed = atomic_read(&transition.executed);
	*second_executed = atomic_read(&transition.second_executed);
	if (!error && (*first_executed != num_online_cpus() ||
		       *second_executed != num_online_cpus()))
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

static int ebpfos_runtime_irq_portal_all_cpus(
	struct ebpfos_runtime_bundle *bundle, u64 operation_slot_id, u64 operand,
	u32 portal_operation, u32 *executed)
{
	struct bpf_prog *broadcast_prog, *operation_prog;
	u64 start, generation;
	u32 expected, remote;
	int broadcast_slot, operation_slot, error = 0, errors_before;

	*executed = 0;
	if (portal_operation < EBPFOS_RUNTIME_IRQ_PORTAL_RESTORE_IDTR ||
	    portal_operation > EBPFOS_RUNTIME_IRQ_PORTAL_INSTALL_PULSE)
		return -EINVAL;
	broadcast_slot = ebpfos_runtime_bundle_find(
		bundle, ebpfos_runtime_irq.portal_broadcast_slot_id);
	operation_slot = ebpfos_runtime_bundle_find(bundle, operation_slot_id);
	if (broadcast_slot < 0 || operation_slot < 0)
		return -ENOENT;
	broadcast_prog = bundle->slots[broadcast_slot].prog;
	operation_prog = bundle->slots[operation_slot].prog;
	if (!ebpfos_runtime_machine_program(broadcast_prog) ||
	    !ebpfos_runtime_machine_program(operation_prog))
		return -EPROTO;

	expected = num_online_cpus() - 1;
	generation = ebpfos_runtime_irq.portal_generation + 1;
	if (!generation)
		generation = 1;
	ebpfos_runtime_irq.portal_generation = generation;
	WRITE_ONCE(ebpfos_runtime_irq.portal_operand, operand);
	atomic_set(&ebpfos_runtime_irq.portal_acks, 0);
	errors_before = atomic_read(&ebpfos_runtime_irq.portal_errors);
	atomic_set_release(&ebpfos_runtime_irq.portal_operation,
			   portal_operation);

	preempt_disable();
	error = ebpfos_runtime_machine_run(operation_prog, operand);
	if (!error)
		*executed = 1;
	if (!error && expected) {
		error = ebpfos_runtime_machine_run(
			broadcast_prog,
			EBPFOS_RUNTIME_IRQ_PORTAL_BROADCAST_OPERAND);
		if (!error)
			atomic64_inc(&ebpfos_runtime_irq.portal_broadcasts);
	}
	start = ktime_get_mono_fast_ns();
	while (!error && atomic_read(&ebpfos_runtime_irq.portal_acks) < expected) {
		if (ktime_get_mono_fast_ns() - start >
		    EBPFOS_RUNTIME_IRQ_PORTAL_TIMEOUT_NS) {
			error = -ETIMEDOUT;
			break;
		}
		cpu_relax();
	}
	remote = atomic_read(&ebpfos_runtime_irq.portal_acks);
	*executed += remote;
	if (!error && (remote != expected ||
		       atomic_read(&ebpfos_runtime_irq.portal_errors) !=
		       errors_before))
		error = -EREMOTEIO;
	atomic_set_release(&ebpfos_runtime_irq.portal_operation, 0);
	preempt_enable();
	return error;
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

static u64 ebpfos_runtime_process_task_object(struct task_struct *task)
{
	u64 object_id;

	if (!task)
		return 0;
	object_id = READ_ONCE(task->start_boottime) ^
		    ((u64)(u32)task_pid_nr(task) << 32) ^
		    (u32)task_tgid_nr(task);
	return object_id ?: 1;
}

static u64 ebpfos_runtime_process_digest(u64 value)
{
	value ^= value >> 30;
	value *= 0xbf58476d1ce4e5b9ULL;
	value ^= value >> 27;
	value *= 0x94d049bb133111ebULL;
	value ^= value >> 31;
	return value ?: 1;
}

static u64 ebpfos_runtime_process_context_switches(struct task_struct *task)
{
	return (u64)READ_ONCE(task->nvcsw) +
	       (u64)READ_ONCE(task->nivcsw);
}

static int ebpfos_runtime_process_describe(
	struct task_struct *task, struct ebpfos_runtime_process_task *description)
{
	u64 address_space_id;

	memset(description, 0, sizeof(*description));
	if (!task->mm)
		return -EINVAL;
	description->task = task;
	description->task_object_id = ebpfos_runtime_process_task_object(task);
	description->task_start_boottime = READ_ONCE(task->start_boottime);
	description->mm_object_id = (u64)(unsigned long)task->mm;
	description->task_pid = task_pid_nr(task);
	description->task_tgid = task_tgid_nr(task);
	description->mmu_root_physical =
		__pa(task->mm->pgd) & CR3_ADDR_MASK;
	description->context_switch_baseline =
		ebpfos_runtime_process_context_switches(task);
	address_space_id = description->task_object_id ^
			   description->mm_object_id;
	description->address_space_object_id = address_space_id ?: 1;
	return description->task_start_boottime && description->task_pid &&
	       description->task_tgid && description->mmu_root_physical ? 0 :
		-EPROTO;
}

static int ebpfos_runtime_process_registry_snapshot(
	const struct ebpfos_runtime_process_task *candidate, u32 cpu,
	bool *member, u32 *task_count, u64 *context_switch_baseline,
	u64 *cpu_task_object)
{
	unsigned long irq_flags;
	u32 index;
	int error = 0;

	*member = false;
	*context_switch_baseline = candidate->context_switch_baseline;
	spin_lock_irqsave(&ebpfos_runtime_process.registry_lock, irq_flags);
	*task_count = ebpfos_runtime_process.task_count;
	*cpu_task_object = ebpfos_runtime_process.cpu_task_objects[cpu];
	for (index = 0; index < *task_count; index++) {
		const struct ebpfos_runtime_process_task *entry =
			&ebpfos_runtime_process.tasks[index];

		if (entry->task != candidate->task)
			continue;
		if (entry->task_object_id != candidate->task_object_id ||
		    entry->task_start_boottime !=
			candidate->task_start_boottime ||
		    entry->mm_object_id != candidate->mm_object_id ||
		    entry->address_space_object_id !=
			candidate->address_space_object_id ||
		    entry->mmu_root_physical != candidate->mmu_root_physical ||
		    entry->task_pid != candidate->task_pid ||
		    entry->task_tgid != candidate->task_tgid)
			error = -ESTALE;
		else {
			*member = true;
			*context_switch_baseline = entry->context_switch_baseline;
		}
		break;
	}
	spin_unlock_irqrestore(&ebpfos_runtime_process.registry_lock, irq_flags);
	return error;
}

static int ebpfos_runtime_process_enroll(
	const struct ebpfos_runtime_process_task *candidate)
{
	struct ebpfos_runtime_process_task *entry;
	unsigned long irq_flags;
	bool new_mm = true;
	u32 index;
	int error = 0;

	spin_lock_irqsave(&ebpfos_runtime_process.registry_lock, irq_flags);
	for (index = 0; index < ebpfos_runtime_process.task_count; index++) {
		entry = &ebpfos_runtime_process.tasks[index];
		if (entry->task == candidate->task) {
			if (entry->task_object_id != candidate->task_object_id ||
			    entry->mm_object_id != candidate->mm_object_id ||
			    entry->mmu_root_physical !=
				candidate->mmu_root_physical)
				error = -ESTALE;
			goto out;
		}
		if (entry->mm_object_id == candidate->mm_object_id)
			new_mm = false;
	}
	if (ebpfos_runtime_process.task_count >=
	    EBPFOS_RUNTIME_PROCESS_MAX_TASKS) {
		error = -ENOSPC;
		goto out;
	}
	get_task_struct(candidate->task);
	entry = &ebpfos_runtime_process.tasks[
		ebpfos_runtime_process.task_count++];
	*entry = *candidate;
	if (new_mm)
		ebpfos_runtime_process.mm_count++;
	ebpfos_runtime_process.task_set_digest ^=
		ebpfos_runtime_process_digest(candidate->task_object_id);
	ebpfos_runtime_process.address_space_set_digest ^=
		ebpfos_runtime_process_digest(
			candidate->address_space_object_id);
	ebpfos_runtime_process.mmu_root_set_digest ^=
		ebpfos_runtime_process_digest(candidate->mmu_root_physical);
	atomic64_inc(&ebpfos_runtime_process.task_enrollments);
out:
	spin_unlock_irqrestore(&ebpfos_runtime_process.registry_lock, irq_flags);
	return error;
}

static int ebpfos_runtime_process_claim_cpu(u32 cpu, u64 task_object_id)
{
	unsigned long irq_flags;
	u64 *owner;
	int error = 0;

	spin_lock_irqsave(&ebpfos_runtime_process.registry_lock, irq_flags);
	owner = &ebpfos_runtime_process.cpu_task_objects[cpu];
	if (!*owner) {
		*owner = task_object_id;
		ebpfos_runtime_process.scheduler_cpu_claims++;
		ebpfos_runtime_process.scheduler_cpu_owner_digest ^=
			ebpfos_runtime_process_digest(
				task_object_id ^ ((u64)cpu << 56));
	} else if (*owner != task_object_id) {
		error = -ESTALE;
	}
	spin_unlock_irqrestore(&ebpfos_runtime_process.registry_lock, irq_flags);
	return error;
}

static int ebpfos_runtime_process_activate(
	struct ebpfos_runtime_bundle *bundle, u64 expected_epoch,
	u64 process_slot_id, u64 mmu_observer_slot_id,
	u64 mmu_reloader_slot_id)
{
	struct task_struct *task = current;
	struct ebpfos_runtime_process_task owner;
	int error = 0, observer_slot, reloader_slot, slot;

	if (!expected_epoch || !process_slot_id || !mmu_observer_slot_id ||
	    !mmu_reloader_slot_id || bundle->epoch != expected_epoch ||
	    !ebpfos_runtime_syscall_active() ||
	    ebpfos_runtime_process_describe(task, &owner))
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
	get_task_struct(task);
	memset(ebpfos_runtime_process.tasks, 0,
	       sizeof(ebpfos_runtime_process.tasks));
	memset(ebpfos_runtime_process.cpu_task_objects, 0,
	       sizeof(ebpfos_runtime_process.cpu_task_objects));
	ebpfos_runtime_process.tasks[0] = owner;
	ebpfos_runtime_process.task = task;
	ebpfos_runtime_process.process_slot_id = process_slot_id;
	ebpfos_runtime_process.mmu_observer_slot_id = mmu_observer_slot_id;
	ebpfos_runtime_process.mmu_reloader_slot_id = mmu_reloader_slot_id;
	ebpfos_runtime_process.epoch = expected_epoch;
	ebpfos_runtime_process.task_object_id = owner.task_object_id;
	ebpfos_runtime_process.task_start_boottime = owner.task_start_boottime;
	ebpfos_runtime_process.mm_object_id = owner.mm_object_id;
	ebpfos_runtime_process.address_space_object_id =
		owner.address_space_object_id;
	ebpfos_runtime_process.mmu_root_physical = owner.mmu_root_physical;
	ebpfos_runtime_process.task_pid = owner.task_pid;
	ebpfos_runtime_process.task_tgid = owner.task_tgid;
	ebpfos_runtime_process.task_count = 1;
	ebpfos_runtime_process.mm_count = 1;
	ebpfos_runtime_process.task_set_digest =
		ebpfos_runtime_process_digest(owner.task_object_id);
	ebpfos_runtime_process.address_space_set_digest =
		ebpfos_runtime_process_digest(owner.address_space_object_id);
	ebpfos_runtime_process.mmu_root_set_digest =
		ebpfos_runtime_process_digest(owner.mmu_root_physical);
	ebpfos_runtime_process.scheduler_context_switch_growth = 0;
	ebpfos_runtime_process.scheduler_cpu_owner_digest = 0;
	ebpfos_runtime_process.scheduler_cpu_claims = 0;
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
	atomic64_set(&ebpfos_runtime_process.task_enrollments, 1);
	atomic64_set(&ebpfos_runtime_process.cpu_mask, 0);
	atomic64_set(&ebpfos_runtime_process.scheduler_decisions, 0);
	atomic64_set(&ebpfos_runtime_process.scheduler_native_fallbacks, 0);
	atomic_set(&ebpfos_runtime_process.operations, 0);
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
	struct task_struct *tasks[EBPFOS_RUNTIME_PROCESS_MAX_TASKS] = {};
	unsigned long irq_flags;
	u32 index, task_count = 0;
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
	/* Stop and drain return-path readers before dropping stable references. */
	smp_store_release(&ebpfos_runtime_process.active, false);
	while (atomic_read(&ebpfos_runtime_process.operations))
		cpu_relax();
	spin_lock_irqsave(&ebpfos_runtime_process.registry_lock, irq_flags);
	task_count = ebpfos_runtime_process.task_count;
	for (index = 0; index < task_count; index++) {
		u64 context_switches;

		tasks[index] = ebpfos_runtime_process.tasks[index].task;
		context_switches = tasks[index] ?
			ebpfos_runtime_process_context_switches(tasks[index]) : 0;
		if (context_switches <
		    ebpfos_runtime_process.tasks[index].context_switch_baseline)
			ebpfos_runtime_process.scheduler_context_switch_growth =
				U64_MAX;
		else if (ebpfos_runtime_process.scheduler_context_switch_growth !=
			 U64_MAX)
			ebpfos_runtime_process.scheduler_context_switch_growth +=
				context_switches -
				ebpfos_runtime_process.tasks[index].
					context_switch_baseline;
		ebpfos_runtime_process.tasks[index].task = NULL;
	}
	spin_unlock_irqrestore(&ebpfos_runtime_process.registry_lock, irq_flags);
	ebpfos_runtime_process.task = NULL;
out:
	mutex_unlock(&ebpfos_runtime_process.lock);
	for (index = 0; index < task_count; index++)
		if (tasks[index])
			put_task_struct(tasks[index]);
	return error;
}

static void ebpfos_runtime_process_status(
	struct ebpfos_runtime_process_root *status)
{
	unsigned long irq_flags;

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
	spin_lock_irqsave(&ebpfos_runtime_process.registry_lock, irq_flags);
	status->task_count = ebpfos_runtime_process.task_count;
	status->mm_count = ebpfos_runtime_process.mm_count;
	status->task_set_digest = ebpfos_runtime_process.task_set_digest;
	status->address_space_set_digest =
		ebpfos_runtime_process.address_space_set_digest;
	status->mmu_root_set_digest =
		ebpfos_runtime_process.mmu_root_set_digest;
	status->scheduler_context_switch_growth =
		ebpfos_runtime_process.scheduler_context_switch_growth;
	status->scheduler_cpu_owner_digest =
		ebpfos_runtime_process.scheduler_cpu_owner_digest;
	status->scheduler_cpu_claims =
		ebpfos_runtime_process.scheduler_cpu_claims;
	spin_unlock_irqrestore(&ebpfos_runtime_process.registry_lock, irq_flags);
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
	status->task_enrollments =
		atomic64_read(&ebpfos_runtime_process.task_enrollments);
	status->cpu_mask = atomic64_read(&ebpfos_runtime_process.cpu_mask);
	status->scheduler_decisions =
		atomic64_read(&ebpfos_runtime_process.scheduler_decisions);
	status->scheduler_native_fallbacks = atomic64_read(
		&ebpfos_runtime_process.scheduler_native_fallbacks);
	status->max_tasks = EBPFOS_RUNTIME_PROCESS_MAX_TASKS;
	status->cpus_observed = hweight64(status->cpu_mask);
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
		.input_size = 16 * sizeof(u64),
		.output_capacity = EBPFOS_COMPONENT_CALL_OUTPUT_SIZE,
	};
	struct ebpfos_runtime_process_task candidate;
	struct ebpfos_runtime_bundle *bundle = NULL;
	struct task_struct *group_leader, *real_parent;
	struct bpf_prog *observer, *prog, *reloader;
	u64 action = 0, context_switch_baseline, cpu_task_object;
	u64 group_object_id, input[16], mmu_index, object_id = 0;
	u64 parent_object_id, return_index;
	u32 cpu, provider_status, slot, task_count;
	bool member, migration_disabled = false;
	int error = 0, observer_slot, reloader_slot;

	if (!ebpfos_runtime_process_active())
		return -ENOENT;
	atomic_inc(&ebpfos_runtime_process.operations);
	smp_mb__after_atomic();
	if (!ebpfos_runtime_process_active()) {
		error = -ENOENT;
		goto fault;
	}
	migrate_disable();
	migration_disabled = true;
	cpu = raw_smp_processor_id();
	if (cpu >= EBPFOS_RUNTIME_PROCESS_MAX_TASKS) {
		error = -ERANGE;
		goto fault;
	}
	if (ebpfos_runtime_process_describe(current, &candidate)) {
		error = -ESTALE;
		goto fault;
	}
	error = ebpfos_runtime_process_registry_snapshot(
		&candidate, cpu, &member, &task_count,
		&context_switch_baseline, &cpu_task_object);
	if (error)
		goto fault;
	rcu_read_lock();
	real_parent = rcu_dereference(current->real_parent);
	group_leader = READ_ONCE(current->group_leader);
	parent_object_id = ebpfos_runtime_process_task_object(real_parent);
	group_object_id = ebpfos_runtime_process_task_object(group_leader);
	rcu_read_unlock();
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
	if (!ebpfos_runtime_process_program(prog) ||
	    observer_slot < 0 || reloader_slot < 0 ||
	    !ebpfos_runtime_machine_program(bundle->slots[observer_slot].prog) ||
	    !ebpfos_runtime_machine_program(bundle->slots[reloader_slot].prog) ||
	    bundle->epoch != READ_ONCE(ebpfos_runtime_process.epoch)) {
		error = -ESTALE;
		goto out;
	}
	observer = bundle->slots[observer_slot].prog;
	reloader = bundle->slots[reloader_slot].prog;
	frame.object_id = candidate.task_object_id;
	frame.epoch = bundle->epoch;
	input[0] = frame.object_id;
	input[1] = candidate.mm_object_id;
	input[2] = READ_ONCE(current_thread_info()->flags) |
		   READ_ONCE(current_thread_info()->syscall_work);
	input[3] = candidate.task_start_boottime;
	input[4] = candidate.mmu_root_physical;
	input[5] = READ_ONCE(ebpfos_runtime_process.task_object_id);
	input[6] = parent_object_id;
	input[7] = group_object_id;
	input[8] = member;
	input[9] = task_count;
	input[10] = EBPFOS_RUNTIME_PROCESS_MAX_TASKS;
	input[11] = cpu;
	input[12] = cpu_task_object;
	input[13] = candidate.context_switch_baseline;
	input[14] = context_switch_baseline;
	input[15] = EBPFOS_RUNTIME_PROCESS_MAX_TASKS;
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
	    object_id != candidate.task_object_id) {
		error = -EPROTO;
		goto out;
	}
	if (!member) {
		error = ebpfos_runtime_process_enroll(&candidate);
		if (error)
			goto out;
	}
	error = ebpfos_runtime_process_claim_cpu(cpu,
					 candidate.task_object_id);
	if (error)
		goto out;
	error = ebpfos_runtime_machine_run(observer,
					   candidate.mmu_root_physical);
	if (!error)
		error = ebpfos_runtime_machine_run(reloader,
					  candidate.mmu_root_physical);
	if (!error)
		atomic64_or(BIT_ULL(raw_smp_processor_id()),
			    &ebpfos_runtime_process.cpu_mask);
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
	atomic64_inc(&ebpfos_runtime_process.scheduler_decisions);
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
	if (migration_disabled)
		migrate_enable();
	if (error)
		atomic64_inc(&ebpfos_runtime_process.return_errors);
	atomic_dec(&ebpfos_runtime_process.operations);
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
	status->portal_broadcast_slot_id =
		ebpfos_runtime_irq.portal_broadcast_slot_id;
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
	status->portal_broadcasts =
		atomic64_read(&ebpfos_runtime_irq.portal_broadcasts);
	status->portal_dispatches =
		atomic64_read(&ebpfos_runtime_irq.portal_dispatches);
	status->portal_generation = ebpfos_runtime_irq.portal_generation;
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
	status->first_vector = ebpfos_runtime_irq.first_vector;
	status->last_vector = ebpfos_runtime_irq.last_vector;
	status->vector_count = ebpfos_runtime_irq.vector_count;
	status->donor_external_gates = ebpfos_runtime_irq.donor_external_gates;
	status->portal_vector = ebpfos_runtime_irq.portal_vector;
	status->portal_errors = atomic_read(&ebpfos_runtime_irq.portal_errors);
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
	/* Restore every IDTR through the generated IRQ control portal first. */
	error = ebpfos_runtime_irq_portal_all_cpus(
		bundle, ebpfos_runtime_irq.installer_slot_id,
		ebpfos_runtime_irq.old_idtr,
		EBPFOS_RUNTIME_IRQ_PORTAL_RESTORE_IDTR, &count);
	ebpfos_runtime_irq.cpus_written += count;
	if (error)
		goto out;
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
			       u64 portal_broadcast_slot_id,
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
	u32 entry_vector, generated_gates = 0, donor_external_gates = 0;
	int error, observer_slot, installer_slot, handler_slot;
	int portal_broadcast_slot;
	int routing_observer_slot, routing_installer_slot;
	int pulse_observer_slot, pulse_installer_slot, rollback_error;
	bool routing_installed = false, idtr_installed = false;

	if (!expected_epoch || !observer_slot_id || !installer_slot_id ||
	    !handler_slot_id || !portal_broadcast_slot_id ||
	    !routing_observer_slot_id ||
	    !routing_installer_slot_id || !pulse_observer_slot_id ||
	    !pulse_installer_slot_id || routing_old == routing_target ||
	    pulse_resting == pulse_armed || vector < FIRST_EXTERNAL_VECTOR ||
	    vector >= NR_VECTORS || gate_dpl != 0 ||
	    bundle->epoch != expected_epoch)
		return -ESTALE;
	observer_slot = ebpfos_runtime_bundle_find(bundle,
						 observer_slot_id);
	installer_slot = ebpfos_runtime_bundle_find(bundle,
						  installer_slot_id);
	handler_slot = ebpfos_runtime_bundle_find(bundle, handler_slot_id);
	portal_broadcast_slot = ebpfos_runtime_bundle_find(
		bundle, portal_broadcast_slot_id);
	routing_observer_slot = ebpfos_runtime_bundle_find(
		bundle, routing_observer_slot_id);
	routing_installer_slot = ebpfos_runtime_bundle_find(
		bundle, routing_installer_slot_id);
	pulse_observer_slot = ebpfos_runtime_bundle_find(
		bundle, pulse_observer_slot_id);
	pulse_installer_slot = ebpfos_runtime_bundle_find(
		bundle, pulse_installer_slot_id);
	if (observer_slot < 0 || installer_slot < 0 ||
	    handler_slot < 0 || portal_broadcast_slot < 0 ||
	    routing_observer_slot < 0 ||
	    routing_installer_slot < 0 || pulse_observer_slot < 0 ||
	    pulse_installer_slot < 0 ||
	    !ebpfos_runtime_machine_program(bundle->slots[observer_slot].prog) ||
	    !ebpfos_runtime_machine_program(bundle->slots[installer_slot].prog) ||
	    !ebpfos_runtime_machine_program(
		bundle->slots[portal_broadcast_slot].prog) ||
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
	for (entry_vector = FIRST_EXTERNAL_VECTOR;
	     entry_vector < NR_VECTORS; entry_vector++) {
		handler_entry = (unsigned long)ebpfos_runtime_irq_entries_start +
			IDT_ALIGN * (entry_vector - FIRST_EXTERNAL_VECTOR);
		pack_gate(&((gate_desc *)target_table)[entry_vector],
			  GATE_INTERRUPT, handler_entry, gate_dpl, 0, __KERNEL_CS);
		if (gate_offset(&((gate_desc *)target_table)[entry_vector]) ==
		    handler_entry)
			generated_gates++;
		else
			donor_external_gates++;
	}
	if (generated_gates != NR_VECTORS - FIRST_EXTERNAL_VECTOR ||
	    donor_external_gates) {
		free_page(target_table);
		return -EIO;
	}
	handler_entry = (unsigned long)ebpfos_runtime_irq_entries_start +
		IDT_ALIGN * (vector - FIRST_EXTERNAL_VECTOR);
	mutex_lock(&ebpfos_runtime_irq.lock);
	if (ebpfos_runtime_irq.active) {
		error = -EBUSY;
		goto out_free_unlock;
	}
	ebpfos_runtime_irq.observer_slot_id = observer_slot_id;
	ebpfos_runtime_irq.installer_slot_id = installer_slot_id;
	ebpfos_runtime_irq.handler_slot_id = handler_slot_id;
	ebpfos_runtime_irq.portal_broadcast_slot_id = portal_broadcast_slot_id;
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
	ebpfos_runtime_irq.first_vector = FIRST_EXTERNAL_VECTOR;
	ebpfos_runtime_irq.last_vector = NR_VECTORS - 1;
	ebpfos_runtime_irq.vector_count = generated_gates;
	ebpfos_runtime_irq.donor_external_gates = donor_external_gates;
	ebpfos_runtime_irq.portal_vector = EBPFOS_RUNTIME_IRQ_PORTAL_VECTOR;
	atomic64_set(&ebpfos_runtime_irq.dispatches, 0);
	atomic64_set(&ebpfos_runtime_irq.dispatch_errors, 0);
	atomic64_set(&ebpfos_runtime_irq.pulse_rearms, 0);
	atomic64_set(&ebpfos_runtime_irq.portal_broadcasts, 0);
	atomic64_set(&ebpfos_runtime_irq.portal_dispatches, 0);
	atomic64_set(&ebpfos_runtime_irq.first_dispatch_epoch, 0);
	atomic64_set(&ebpfos_runtime_irq.last_dispatch_epoch, 0);
	atomic_set(&ebpfos_runtime_irq.first_dispatch_prog_id, 0);
	atomic_set(&ebpfos_runtime_irq.last_dispatch_prog_id, 0);
	atomic_set(&ebpfos_runtime_irq.portal_operation, 0);
	atomic_set(&ebpfos_runtime_irq.portal_acks, 0);
	atomic_set(&ebpfos_runtime_irq.portal_errors, 0);
	ebpfos_runtime_irq.portal_generation = 0;
	ebpfos_runtime_irq.machine_cpus_observed = 0;
	ebpfos_runtime_irq.machine_cpus_written = 0;
	ebpfos_runtime_irq.cpus_observed = 0;
	ebpfos_runtime_irq.cpus_written = 0;
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
	written = 0;
	error = ebpfos_runtime_machine_all_cpus(
		bundle->slots[pulse_observer_slot].prog, pulse_resting, &count);
	ebpfos_runtime_irq.machine_cpus_observed += count;
	if (error)
		goto out_restore;
	error = ebpfos_runtime_machine_all_cpus(
		bundle->slots[observer_slot].prog, old_idtr.address, &count);
	ebpfos_runtime_irq.cpus_observed = count;
	if (error)
		goto out_restore;
	/* Every callback installs its generated gate root before arming its pulse. */
	smp_store_release(&ebpfos_runtime_irq.active, true);
	error = ebpfos_runtime_machine_pair_all_cpus(
		bundle->slots[installer_slot].prog, target_table,
		bundle->slots[pulse_installer_slot].prog, pulse_armed,
		&written, &count);
	ebpfos_runtime_irq.cpus_written = written;
	ebpfos_runtime_irq.machine_cpus_written += count;
	idtr_installed = written == num_online_cpus();
	if (error)
		goto out_restore;
	if (status) {
		status->old_idtr = old_idtr.address;
		status->target_idtr = target_table;
		status->handler_entry = handler_entry;
		memcpy(status->target_table_sha256,
		       ebpfos_runtime_irq.target_table_sha256,
		       sizeof(status->target_table_sha256));
		status->cpus_observed = ebpfos_runtime_irq.cpus_observed;
		status->cpus_written = ebpfos_runtime_irq.cpus_written;
		status->machine_cpus_observed =
			ebpfos_runtime_irq.machine_cpus_observed;
		status->machine_cpus_written =
			ebpfos_runtime_irq.machine_cpus_written;
		status->vector = vector;
		status->gate_dpl = gate_dpl;
		status->first_vector = FIRST_EXTERNAL_VECTOR;
		status->last_vector = NR_VECTORS - 1;
		status->vector_count = generated_gates;
		status->donor_external_gates = donor_external_gates;
		status->portal_vector = EBPFOS_RUNTIME_IRQ_PORTAL_VECTOR;
		status->active = 1;
	}
	mutex_unlock(&ebpfos_runtime_irq.lock);
	return 0;

out_restore:
	rollback_error = 0;
	if (idtr_installed)
		rollback_error = ebpfos_runtime_irq_portal_all_cpus(
			bundle, installer_slot_id, old_idtr.address,
			EBPFOS_RUNTIME_IRQ_PORTAL_RESTORE_IDTR,
			&rollback_count);
	else if (written)
		rollback_error = -EREMOTEIO;
	if (!rollback_error)
		smp_store_release(&ebpfos_runtime_irq.active, false);
	if (!rollback_error)
		rollback_error = ebpfos_runtime_machine_all_cpus(
			bundle->slots[pulse_installer_slot].prog, pulse_resting,
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
	u32 count;
	int error;

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
	error = ebpfos_runtime_irq_portal_all_cpus(
		bundle, pulse_observer_slot_id, pulse_resting,
		EBPFOS_RUNTIME_IRQ_PORTAL_OBSERVE_PULSE, &count);
	ebpfos_runtime_irq.machine_cpus_observed += count;
	if (error)
		goto out;
	error = ebpfos_runtime_irq_portal_all_cpus(
		bundle, pulse_installer_slot_id, pulse_armed,
		EBPFOS_RUNTIME_IRQ_PORTAL_INSTALL_PULSE, &count);
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
	    request.first_vector || request.last_vector || request.vector_count ||
	    request.donor_external_gates || request.portal_vector ||
	    request.portal_errors || request.portal_broadcasts ||
	    request.portal_dispatches || request.portal_generation ||
	    request.reserved ||
	    !request.expected_epoch ||
	    !request.observer_slot_id || !request.installer_slot_id ||
	    !request.handler_slot_id || !request.portal_broadcast_slot_id ||
	    !request.routing_observer_slot_id ||
	    !request.routing_installer_slot_id || !request.pulse_observer_slot_id ||
	    !request.pulse_installer_slot_id)
		return -EINVAL;
	bundle = ebpfos_runtime_bundle_get(request.observer_slot_id, &slot);
	if (!bundle)
		return -ENOENT;
	error = ebpfos_runtime_irq_activate(bundle, request.expected_epoch,
			request.observer_slot_id, request.installer_slot_id,
			request.handler_slot_id,
			request.portal_broadcast_slot_id,
			request.routing_observer_slot_id,
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
	u64 vector = 0, portal_broadcast_slot_id = 0;
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
		memcpy(&portal_broadcast_slot_id,
		       frame.output + 7 * sizeof(u64),
		       sizeof(portal_broadcast_slot_id));
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
				portal_broadcast_slot_id,
				routing_observer_slot_id, routing_installer_slot_id,
				pulse_observer_slot_id, pulse_installer_slot_id,
				routing_old, routing_target, pulse_resting, pulse_armed,
				vector, 0, NULL);

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

static void *ebpfos_runtime_successor_physical(
	const struct ebpfos_runtime_successor_stage *request, void *image,
	u64 physical, size_t bytes)
{
	u64 offset;

	if (physical < request->physical_base)
		return NULL;
	offset = physical - request->physical_base;
	if (offset > request->image_bytes ||
	    bytes > request->image_bytes - offset)
		return NULL;
	return (u8 *)image + offset;
}

static int ebpfos_runtime_successor_walk(
	const struct ebpfos_runtime_successor_stage *request, void *image,
	u64 virtual, u64 *leaf)
{
	static const u32 shifts[] = { 39, 30, 21 };
	u64 table = request->cr3 & CR3_ADDR_MASK;
	u64 *entry, value;
	u32 index;

	for (index = 0; index < ARRAY_SIZE(shifts); index++) {
		entry = ebpfos_runtime_successor_physical(
			request, image, table +
			(((virtual >> shifts[index]) & 0x1ff) * sizeof(*entry)),
			sizeof(*entry));
		if (!entry)
			return -ERANGE;
		value = READ_ONCE(*entry);
		if (!(value & _PAGE_PRESENT))
			return -ENOENT;
		if (value & _PAGE_PSE)
			return -EPROTO;
		table = value & PTE_PFN_MASK;
	}
	entry = ebpfos_runtime_successor_physical(
		request, image,
		table + (((virtual >> PAGE_SHIFT) & 0x1ff) * sizeof(*entry)),
		sizeof(*entry));
	if (!entry)
		return -ERANGE;
	value = READ_ONCE(*entry);
	if (!(value & _PAGE_PRESENT))
		return -ENOENT;
	*leaf = value;
	return 0;
}

static int ebpfos_runtime_successor_root_page(
	const struct ebpfos_runtime_successor_stage *request, void *image,
	u64 virtual, bool writable, bool executable)
{
	u64 expected, leaf;
	int error;

	if (virtual < request->virtual_base ||
	    virtual - request->virtual_base >= request->image_bytes)
		return -ERANGE;
	error = ebpfos_runtime_successor_walk(request, image, virtual, &leaf);
	if (error)
		return error;
	expected = request->physical_base +
		((virtual - request->virtual_base) & PAGE_MASK);
	if ((leaf & PTE_PFN_MASK) != expected ||
	    !!(leaf & _PAGE_RW) != writable ||
	    !!(leaf & _PAGE_NX) == executable || leaf & _PAGE_USER)
		return -EPROTO;
	return 0;
}

static int ebpfos_runtime_successor_mapping_page(
	const struct ebpfos_runtime_successor_stage *request, void *image,
	u64 virtual, u64 physical, bool writable, bool executable)
{
	u64 leaf;
	int error;

	error = ebpfos_runtime_successor_walk(request, image, virtual, &leaf);
	if (error)
		return error;
	if ((leaf & PTE_PFN_MASK) != (physical & PAGE_MASK) ||
	    !!(leaf & _PAGE_RW) != writable ||
	    !!(leaf & _PAGE_NX) == executable || leaf & _PAGE_USER)
		return -EPROTO;
	return 0;
}

static void *ebpfos_runtime_successor_virtual(
	const struct ebpfos_runtime_successor_stage *request, void *image,
	u64 virtual, size_t bytes)
{
	u64 offset;

	if (virtual < request->virtual_base)
		return NULL;
	offset = virtual - request->virtual_base;
	if (offset > request->image_bytes || bytes > request->image_bytes - offset)
		return NULL;
	return (u8 *)image + offset;
}

static int ebpfos_runtime_successor_validate(
	struct ebpfos_runtime_successor_stage *request, void *image)
{
	gate_desc *idt;
	u8 handoff_digest[SHA256_DIGEST_SIZE];
	void *handoff;
	u64 end, handoff_end, leaf, mapped = 0, physical_end, virtual;
	u64 idt_physical;
	u32 cpu, vector;
	int error;

	if (check_add_overflow(request->virtual_base,
				 PAGE_ALIGN(request->image_bytes), &end))
		return -EOVERFLOW;
	if (check_add_overflow(request->physical_base, request->image_bytes,
			       &physical_end))
		return -EOVERFLOW;
	for (virtual = request->virtual_base; virtual < end;
	     virtual += PAGE_SIZE) {
		error = ebpfos_runtime_successor_walk(
			request, image, virtual, &leaf);
		if (error == -ENOENT)
			continue;
		if (error)
			return error;
		if ((leaf & PTE_PFN_MASK) != request->physical_base +
		    (virtual - request->virtual_base) ||
		    ((leaf & _PAGE_RW) && !(leaf & _PAGE_NX)) ||
		    (leaf & _PAGE_USER))
			return -EPROTO;
		mapped++;
	}
	/* One generated direct-map alias is outside the packed high image. */
	if (mapped + 1 != request->mapped_pages)
		return -EPROTO;
	error = ebpfos_runtime_successor_root_page(
		request, image, request->lstar, false, true);
	if (error)
		return error;
	error = ebpfos_runtime_successor_root_page(
		request, image, request->cpu_root, false, true);
	if (error)
		return error;
	error = ebpfos_runtime_successor_root_page(
		request, image, request->component_probe, false, true);
	if (error)
		return error;
	error = ebpfos_runtime_successor_root_page(
		request, image, request->idtr, false, false);
	if (error)
		return error;
	idt_physical = request->physical_base +
		(request->idtr - request->virtual_base);
	idt = ebpfos_runtime_successor_physical(
		request, image, idt_physical,
		IDT_ENTRIES * sizeof(*idt));
	if (!idt)
		return -ERANGE;
	for (vector = 0; vector < request->idt_vectors; vector++) {
		u64 target;

		if (!idt[vector].bits.p || idt[vector].segment != __KERNEL_CS)
			return -EPROTO;
		target = gate_offset(&idt[vector]);
		error = ebpfos_runtime_successor_root_page(
			request, image, target, false, true);
		if (error)
			return error;
	}
	for (cpu = 0; cpu < request->cpus; cpu++) {
		if (request->cpu_stacks[cpu] <
			EBPFOS_RUNTIME_SUCCESSOR_PREFLIGHT_STACK_BYTES ||
		    !request->cpu_contexts[cpu])
			return -EINVAL;
		error = ebpfos_runtime_successor_root_page(
			request, image, request->cpu_stacks[cpu] -
			EBPFOS_RUNTIME_SUCCESSOR_PREFLIGHT_STACK_BYTES,
			true, false);
		if (error)
			return error;
		error = ebpfos_runtime_successor_root_page(
			request, image, request->cpu_stacks[cpu] - 1,
			true, false);
		if (error)
			return error;
		error = ebpfos_runtime_successor_root_page(
			request, image, request->cpu_contexts[cpu], true, false);
		if (error)
			return error;
	}
	if (!request->handoff_preflight || !request->handoff_alias ||
	    !request->handoff_physical || !request->handoff_bytes ||
	    !request->handoff_magic ||
	    !ebpfos_runtime_nonzero(request->handoff_sha256,
				   sizeof(request->handoff_sha256)) ||
	    !ebpfos_runtime_nonzero(request->handoff_descriptor_identity,
				   sizeof(request->handoff_descriptor_identity)) ||
	    request->handoff_physical < request->physical_base ||
	    check_add_overflow(request->handoff_physical,
			       request->handoff_bytes, &handoff_end) ||
	    handoff_end > physical_end ||
	    request->handoff_bytes >
		PAGE_SIZE - offset_in_page(request->handoff_physical) ||
	    request->handoff_preflight != request->virtual_base +
		(request->handoff_physical - request->physical_base) ||
	    request->handoff_alias !=
		(u64)(unsigned long)__va(request->handoff_physical))
		return -EINVAL;
	error = ebpfos_runtime_successor_root_page(
		request, image, request->handoff_preflight, false, true);
	if (error)
		return error;
	error = ebpfos_runtime_successor_mapping_page(
		request, image, request->handoff_alias,
		request->handoff_physical, false, true);
	if (error)
		return error;
	handoff = ebpfos_runtime_successor_physical(
		request, image, request->handoff_physical,
		request->handoff_bytes);
	if (!handoff)
		return -ERANGE;
	sha256(handoff, request->handoff_bytes, handoff_digest);
	if (memcmp(handoff_digest, request->handoff_sha256,
		   sizeof(handoff_digest)))
		return -EBADMSG;
	if (!request->publication_state ||
	    request->publication_capacity <
		sizeof(struct ebpfos_runtime_successor_transaction_header) ||
	    request->publication_capacity >
		EBPFOS_RUNTIME_SUCCESSOR_PUBLICATION_MAX_BYTES ||
	    !ebpfos_runtime_successor_virtual(request, image,
		request->publication_state, request->publication_capacity))
		return -EINVAL;
	error = ebpfos_runtime_successor_root_page(
		request, image, request->publication_state, true, false);
	if (error)
		return error;
	error = ebpfos_runtime_successor_root_page(
		request, image,
		request->publication_state + request->publication_capacity - 1,
		true, false);
	if (error)
		return error;
	if (memchr_inv(ebpfos_runtime_successor_virtual(
			request, image, request->publication_state,
			request->publication_capacity), 0,
		request->publication_capacity))
		return -EPROTO;
	return 0;
}

static long ebpfos_runtime_successor_stage(void __user *argp)
{
	struct ebpfos_runtime_successor_stage request;
	u8 digest[SHA256_DIGEST_SIZE];
	void *image = NULL;
	u64 reserved_bytes;
	long error = 0;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.version != EBPFOS_RUNTIME_ROOT_ABI_VERSION || request.flags ||
	    request.reserved || request.staged || !request.user_address ||
	    !request.image_bytes ||
	    request.image_bytes > EBPFOS_RUNTIME_SUCCESSOR_MAX_BYTES ||
	    request.physical_base & ~PAGE_MASK ||
	    request.virtual_base & ~PAGE_MASK ||
	    request.cr3 & ~PAGE_MASK ||
	    request.cpus != EBPFOS_RUNTIME_SUCCESSOR_CPUS ||
	    request.idt_vectors != IDT_ENTRIES || !request.mapped_pages ||
	    !ebpfos_runtime_nonzero(request.image_sha256,
				    sizeof(request.image_sha256)))
		return -EINVAL;
	reserved_bytes = PAGE_ALIGN(request.image_bytes);
	if (!ebpfos_runtime_successor_reserved_bytes ||
	    request.physical_base != ebpfos_runtime_successor_reserved_base ||
	    reserved_bytes > ebpfos_runtime_successor_reserved_bytes)
		return -ENXIO;
	mutex_lock(&ebpfos_runtime_successor.lock);
	if (ebpfos_runtime_successor.image) {
		error = -EBUSY;
		goto out;
	}
	image = memremap(request.physical_base, reserved_bytes, MEMREMAP_WB);
	if (!image) {
		error = -ENOMEM;
		goto out;
	}
	if (copy_from_user(image,
			   (void __user *)(uintptr_t)request.user_address,
			   request.image_bytes)) {
		error = -EFAULT;
		goto out;
	}
	memset((u8 *)image + request.image_bytes, 0,
	       reserved_bytes - request.image_bytes);
	sha256(image, request.image_bytes, digest);
	if (memcmp(digest, request.image_sha256, sizeof(digest))) {
		error = -EBADMSG;
		goto out;
	}
	error = ebpfos_runtime_successor_validate(&request, image);
	if (error)
		goto out;
	request.user_address = 0;
	request.staged = 1;
	if (copy_to_user(argp, &request, sizeof(request))) {
		error = -EFAULT;
		goto out;
	}
	ebpfos_runtime_successor.image = image;
	ebpfos_runtime_successor.reserved_bytes = reserved_bytes;
	ebpfos_runtime_successor.descriptor = request;
	image = NULL;
out:
	if (image)
		memunmap(image);
	mutex_unlock(&ebpfos_runtime_successor.lock);
	return error;
}

static bool ebpfos_runtime_successor_identity_nonzero(const u8 *identity)
{
	return ebpfos_runtime_nonzero(identity,
				      EBPFOS_RUNTIME_ROOT_DIGEST_SIZE);
}

static int ebpfos_runtime_successor_transaction_validate(
	const struct ebpfos_runtime_successor_publish *request, const void *blob,
	const struct ebpfos_runtime_successor_stage *stage, void *image)
{
	const struct ebpfos_runtime_successor_transaction_header *header = blob;
	const struct ebpfos_runtime_successor_transaction_record *records;
	size_t expected_bytes;
	u32 apic = 0, boot = 0, cpu_mask = 0, handoff = 0, index, other;
	u32 uart = 0;
	int error;

	if (request->transaction_bytes < sizeof(*header) ||
	    memcmp(header->magic, "EBPFOSRT", sizeof(header->magic)) ||
	    header->version != EBPFOS_RUNTIME_SUCCESSOR_PUBLICATION_VERSION ||
	    header->header_bytes != sizeof(*header) ||
	    header->record_bytes != sizeof(*records) || !header->record_count ||
	    header->record_count > EBPFOS_RUNTIME_SUCCESSOR_PUBLICATION_MAX_ROOTS ||
	    header->record_count != request->root_count ||
	    header->expected_epoch != request->expected_epoch ||
	    header->flags != EBPFOS_RUNTIME_SUCCESSOR_PUBLICATION_FLAGS ||
	    memcmp(header->image_sha256, stage->image_sha256,
		   sizeof(header->image_sha256)) ||
	    !ebpfos_runtime_successor_identity_nonzero(
		header->root_table_sha256) ||
	    !ebpfos_runtime_successor_identity_nonzero(
		header->entry_points_sha256) ||
	    !ebpfos_runtime_successor_identity_nonzero(
		header->boot_state_sha256))
		return -EPROTO;
	if (check_mul_overflow((size_t)header->record_count, sizeof(*records),
			       &expected_bytes) ||
	    check_add_overflow(expected_bytes, sizeof(*header), &expected_bytes) ||
	    expected_bytes != request->transaction_bytes)
		return -EOVERFLOW;
	records = (const void *)((const u8 *)blob + sizeof(*header));
	for (index = 0; index < header->record_count; index++) {
		const struct ebpfos_runtime_successor_transaction_record *record =
			&records[index];

		if (record->flags !=
			EBPFOS_RUNTIME_SUCCESSOR_PUBLICATION_RECORD_FLAGS ||
		    !ebpfos_runtime_successor_identity_nonzero(
			record->root_identity) ||
		    (!ebpfos_runtime_successor_identity_nonzero(
			record->component_identity) &&
		     !ebpfos_runtime_successor_identity_nonzero(
			record->descriptor_identity) &&
		     !ebpfos_runtime_successor_identity_nonzero(
			record->state_identity)))
			return -EPROTO;
		for (other = 0; other < index; other++)
			if (!memcmp(record->root_identity,
				    records[other].root_identity,
				    sizeof(record->root_identity)))
				return -EEXIST;
		switch (record->kind) {
		case EBPFOS_RUNTIME_SUCCESSOR_ROOT_KIND_CPU:
			if (record->cpu >= stage->cpus ||
			    cpu_mask & BIT(record->cpu) ||
			    !ebpfos_runtime_successor_identity_nonzero(
				record->component_identity) ||
			    !ebpfos_runtime_successor_identity_nonzero(
				record->descriptor_identity) ||
			    record->operands[0] != stage->cpu_root ||
			    record->operands[1] != stage->cpu_stacks[record->cpu] ||
			    record->operands[2] != stage->lstar ||
			    record->operands[3] != stage->idtr ||
			    record->operands[4] != IDT_ENTRIES * sizeof(gate_desc) - 1 ||
			    record->operands[5] != stage->cr3 ||
			    record->operands[6] != stage->cpu_contexts[record->cpu] ||
			    !record->operands[7] || !record->operands[8] ||
			    !record->operands[9] || !record->operands[11] ||
			    !record->operands[12] || !record->operands[13] ||
			    !record->operands[14] ||
			    record->operands[15] != stage->component_probe)
				return -EPROTO;
			error = ebpfos_runtime_successor_root_page(
				stage, image, record->operands[8], false, true);
			if (!error)
				error = ebpfos_runtime_successor_root_page(
					stage, image, record->operands[7], true, false);
			if (!error)
				error = ebpfos_runtime_successor_root_page(
					stage, image, record->operands[9], true, false);
			if (!error)
				error = ebpfos_runtime_successor_root_page(
					stage, image, record->operands[11], true, false);
			if (!error)
				error = ebpfos_runtime_successor_root_page(
					stage, image, record->operands[13], true, false);
			if (!error)
				error = ebpfos_runtime_successor_root_page(
					stage, image, record->operands[15], false, true);
			if (error)
				return error;
			cpu_mask |= BIT(record->cpu);
			break;
		case EBPFOS_RUNTIME_SUCCESSOR_ROOT_KIND_BOOT_TASK_MM:
			if (record->cpu != U32_MAX || boot++ ||
			    !ebpfos_runtime_successor_identity_nonzero(
				record->descriptor_identity) ||
			    !ebpfos_runtime_successor_identity_nonzero(
				record->state_identity) ||
			    !record->operands[0] || !record->operands[1] ||
			    !record->operands[2] || !record->operands[3] ||
			    record->operands[4] != stage->cr3 ||
			    !record->operands[5] || !record->operands[6] ||
			    !record->operands[7] || !record->operands[8])
				return -EPROTO;
			for (other = 0; other < 4; other++) {
				error = ebpfos_runtime_successor_root_page(
					stage, image, record->operands[other],
					true, false);
				if (error)
					return error;
			}
			for (other = 5; other < 9; other++) {
				error = ebpfos_runtime_successor_root_page(
					stage, image, record->operands[other],
					true, false);
				if (error)
					return error;
			}
			break;
		case EBPFOS_RUNTIME_SUCCESSOR_ROOT_KIND_APIC_TIMER:
			if (record->cpu != U32_MAX || apic++ ||
			    !ebpfos_runtime_successor_identity_nonzero(
				record->component_identity) ||
			    !record->operands[0])
				return -EPROTO;
			error = ebpfos_runtime_successor_root_page(
				stage, image, record->operands[0], false, true);
			if (error)
				return error;
			break;
		case EBPFOS_RUNTIME_SUCCESSOR_ROOT_KIND_UART_PIO:
			if (record->cpu != U32_MAX || uart++ ||
			    !ebpfos_runtime_successor_identity_nonzero(
				record->component_identity) ||
			    !record->operands[0])
				return -EPROTO;
			error = ebpfos_runtime_successor_root_page(
				stage, image, record->operands[0], false, true);
			if (error)
				return error;
			break;
		case EBPFOS_RUNTIME_SUCCESSOR_ROOT_KIND_HANDOFF_BRIDGE:
			if (record->cpu != U32_MAX || handoff++ ||
			    ebpfos_runtime_successor_identity_nonzero(
				record->component_identity) ||
			    !ebpfos_runtime_successor_identity_nonzero(
				record->descriptor_identity) ||
			    memcmp(record->descriptor_identity,
				   stage->handoff_descriptor_identity,
				   sizeof(record->descriptor_identity)) ||
			    ebpfos_runtime_successor_identity_nonzero(
				record->state_identity) ||
			    record->operands[0] != stage->handoff_preflight ||
			    record->operands[1] != stage->handoff_alias ||
			    record->operands[2] != stage->handoff_physical ||
			    record->operands[3] != stage->handoff_bytes ||
			    record->operands[4] != stage->handoff_magic)
				return -EPROTO;
			for (other = 5; other < ARRAY_SIZE(record->operands);
			     other++)
				if (record->operands[other])
					return -EPROTO;
			error = ebpfos_runtime_successor_root_page(
				stage, image, record->operands[0], false, true);
			if (!error)
				error = ebpfos_runtime_successor_mapping_page(
					stage, image, record->operands[1],
					record->operands[2], false, true);
			if (error)
				return error;
			break;
		default:
			return -EPROTO;
		}
	}
	return header->record_count == 8 &&
	       cpu_mask == GENMASK(stage->cpus - 1, 0) && boot == 1 &&
	       apic == 1 && uart == 1 && handoff == 1 ? 0 : -EPROTO;
}

static long ebpfos_runtime_successor_publish(void __user *argp)
{
	struct ebpfos_runtime_successor_publish request;
	u8 digest[SHA256_DIGEST_SIZE];
	void *blob = NULL, *destination;
	long error = 0;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.version != EBPFOS_RUNTIME_ROOT_ABI_VERSION || request.flags ||
	    request.reserved || request.admitted || request.published ||
	    !request.user_address || !request.transaction_bytes ||
	    request.transaction_bytes >
		EBPFOS_RUNTIME_SUCCESSOR_PUBLICATION_MAX_BYTES ||
	    !request.root_count ||
	    request.root_count > EBPFOS_RUNTIME_SUCCESSOR_PUBLICATION_MAX_ROOTS ||
	    !request.expected_epoch ||
	    !ebpfos_runtime_successor_identity_nonzero(
		request.transaction_sha256))
		return -EINVAL;
	blob = memdup_user((void __user *)(uintptr_t)request.user_address,
			   request.transaction_bytes);
	if (IS_ERR(blob))
		return PTR_ERR(blob);
	sha256(blob, request.transaction_bytes, digest);
	if (memcmp(digest, request.transaction_sha256, sizeof(digest))) {
		error = -EBADMSG;
		goto out_free;
	}
	mutex_lock(&ebpfos_runtime_successor.lock);
	if (!ebpfos_runtime_successor.image ||
	    ebpfos_runtime_successor.transaction_admitted) {
		error = -EBUSY;
		goto out_unlock;
	}
	if (request.transaction_bytes >
	    ebpfos_runtime_successor.descriptor.publication_capacity) {
		error = -E2BIG;
		goto out_unlock;
	}
	error = ebpfos_runtime_successor_transaction_validate(
		&request, blob, &ebpfos_runtime_successor.descriptor,
		ebpfos_runtime_successor.image);
	if (error)
		goto out_unlock;
	destination = ebpfos_runtime_successor_virtual(
		&ebpfos_runtime_successor.descriptor,
		ebpfos_runtime_successor.image,
		ebpfos_runtime_successor.descriptor.publication_state,
		ebpfos_runtime_successor.descriptor.publication_capacity);
	if (!destination || memchr_inv(
			destination, 0,
			ebpfos_runtime_successor.descriptor.publication_capacity)) {
		error = -ESTALE;
		goto out_unlock;
	}
	memcpy(destination, blob, request.transaction_bytes);
	memcpy(ebpfos_runtime_successor.transaction_sha256, digest,
	       sizeof(digest));
	ebpfos_runtime_successor.transaction_bytes = request.transaction_bytes;
	ebpfos_runtime_successor.transaction_epoch = request.expected_epoch;
	ebpfos_runtime_successor.transaction_admitted = true;
	request.user_address = 0;
	request.admitted = 1;
	if (copy_to_user(argp, &request, sizeof(request))) {
		memset(destination, 0, request.transaction_bytes);
		memset(ebpfos_runtime_successor.transaction_sha256, 0,
		       sizeof(ebpfos_runtime_successor.transaction_sha256));
		ebpfos_runtime_successor.transaction_bytes = 0;
		ebpfos_runtime_successor.transaction_epoch = 0;
		ebpfos_runtime_successor.transaction_admitted = false;
		error = -EFAULT;
	}
out_unlock:
	mutex_unlock(&ebpfos_runtime_successor.lock);
out_free:
	kfree(blob);
	return error;
}

struct ebpfos_runtime_successor_preflight_context {
	unsigned long entry;
	u64 magic;
	u64 cr3;
	u64 idtr;
	u64 lstar;
	u64 component_probe;
	u64 stacks[EBPFOS_RUNTIME_SUCCESSOR_CPUS];
	cpumask_t observed;
	cpumask_t cr3_switched;
	cpumask_t root_registers;
	cpumask_t reverified;
	cpumask_t components;
	atomic_t failures;
};

static void ebpfos_runtime_successor_preflight_cpu(void *opaque)
{
	struct ebpfos_runtime_successor_preflight_context *context = opaque;
	u64 (*entry)(u64, u64, u64, u64, u64, u64) = (void *)context->entry;
	struct desc_ptr donor_idtr, restored_idtr;
	unsigned long irq_flags;
	u32 cpu = raw_smp_processor_id();
	u64 donor_cr3, donor_lstar, restored_cr3, restored_lstar, value;

	if (cpu >= EBPFOS_RUNTIME_SUCCESSOR_CPUS) {
		atomic_inc(&context->failures);
		return;
	}
	local_irq_save(irq_flags);
	store_idt(&donor_idtr);
	donor_cr3 = __read_cr3();
	rdmsrl(MSR_LSTAR, donor_lstar);
	value = entry(cpu, context->cr3, context->stacks[cpu],
		      context->idtr, context->lstar, context->component_probe);
	store_idt(&restored_idtr);
	restored_cr3 = __read_cr3();
	rdmsrl(MSR_LSTAR, restored_lstar);
	local_irq_restore(irq_flags);
	if (value != (context->magic ^ cpu) ||
	    restored_cr3 != donor_cr3 || restored_lstar != donor_lstar ||
	    restored_idtr.size != donor_idtr.size ||
	    restored_idtr.address != donor_idtr.address) {
		atomic_inc(&context->failures);
		return;
	}
	cpumask_set_cpu(cpu, &context->cr3_switched);
	cpumask_set_cpu(cpu, &context->root_registers);
	cpumask_set_cpu(cpu, &context->reverified);
	cpumask_set_cpu(cpu, &context->components);
	cpumask_set_cpu(cpu, &context->observed);
}

static long ebpfos_runtime_successor_preflight(void __user *argp)
{
	struct ebpfos_runtime_successor_preflight_context context;
	struct ebpfos_runtime_successor_preflight request;
	cpumask_t expected;
	unsigned long alias_page;
	u32 cpu;
	int nx_error, rw_error;
	long error = 0;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.version != EBPFOS_RUNTIME_ROOT_ABI_VERSION || request.flags ||
	    !request.expected_epoch || !request.expected_magic ||
	    request.expected_cpus != EBPFOS_RUNTIME_SUCCESSOR_CPUS ||
	    request.observed_cpus || request.cr3_switched_cpus ||
	    request.root_register_cpus ||
	    request.reverified_cpus ||
	    request.component_cpus ||
	    request.preflighted || request.published || request.reserved ||
	    !ebpfos_runtime_successor_identity_nonzero(
		request.transaction_sha256))
		return -EINVAL;
	mutex_lock(&ebpfos_runtime_successor.lock);
	if (!ebpfos_runtime_successor.image ||
	    !ebpfos_runtime_successor.transaction_admitted ||
	    ebpfos_runtime_successor.handoff_preflighted) {
		error = -EBUSY;
		goto out_unlock;
	}
	if (request.expected_epoch !=
		ebpfos_runtime_successor.transaction_epoch ||
	    request.expected_magic !=
		ebpfos_runtime_successor.descriptor.handoff_magic ||
	    memcmp(request.transaction_sha256,
		   ebpfos_runtime_successor.transaction_sha256,
		   sizeof(request.transaction_sha256))) {
		error = -ESTALE;
		goto out_unlock;
	}
	cpus_read_lock();
	cpumask_clear(&expected);
	for (cpu = 0; cpu < EBPFOS_RUNTIME_SUCCESSOR_CPUS; cpu++)
		cpumask_set_cpu(cpu, &expected);
	if (!cpumask_equal(cpu_online_mask, &expected)) {
		error = -ENODEV;
		goto out_cpus;
	}
	context.entry = ebpfos_runtime_successor.descriptor.handoff_alias;
	context.magic = ebpfos_runtime_successor.descriptor.handoff_magic;
	context.cr3 = ebpfos_runtime_successor.descriptor.cr3;
	context.idtr = ebpfos_runtime_successor.descriptor.idtr;
	context.lstar = ebpfos_runtime_successor.descriptor.lstar;
	context.component_probe =
		ebpfos_runtime_successor.descriptor.component_probe;
	for (cpu = 0; cpu < EBPFOS_RUNTIME_SUCCESSOR_CPUS; cpu++)
		context.stacks[cpu] =
			ebpfos_runtime_successor.descriptor.cpu_stacks[cpu];
	cpumask_clear(&context.observed);
	cpumask_clear(&context.cr3_switched);
	cpumask_clear(&context.root_registers);
	cpumask_clear(&context.reverified);
	cpumask_clear(&context.components);
	atomic_set(&context.failures, 0);
	alias_page = context.entry & PAGE_MASK;
	error = set_memory_rox(alias_page, 1);
	if (!error)
		on_each_cpu(ebpfos_runtime_successor_preflight_cpu, &context, 1);
	nx_error = set_memory_nx(alias_page, 1);
	rw_error = set_memory_rw(alias_page, 1);
	if (!error && nx_error)
		error = nx_error;
	if (!error && rw_error)
		error = rw_error;
	if (!error && (atomic_read(&context.failures) ||
		       !cpumask_equal(&context.observed, &expected) ||
		       !cpumask_equal(&context.cr3_switched, &expected) ||
		       !cpumask_equal(&context.root_registers, &expected) ||
		       !cpumask_equal(&context.reverified, &expected) ||
		       !cpumask_equal(&context.components, &expected)))
		error = -EIO;
	if (error)
		goto out_cpus;
	request.observed_cpus = cpumask_weight(&context.observed);
	request.cr3_switched_cpus = cpumask_weight(&context.cr3_switched);
	request.root_register_cpus = cpumask_weight(&context.root_registers);
	request.reverified_cpus = cpumask_weight(&context.reverified);
	request.component_cpus = cpumask_weight(&context.components);
	request.preflighted = 1;
	if (copy_to_user(argp, &request, sizeof(request))) {
		error = -EFAULT;
		goto out_cpus;
	}
	ebpfos_runtime_successor.preflight_cpus = request.observed_cpus;
	ebpfos_runtime_successor.preflight_cr3_cpus =
		request.cr3_switched_cpus;
	ebpfos_runtime_successor.preflight_root_cpus =
		request.root_register_cpus;
	ebpfos_runtime_successor.preflight_reverified_cpus =
		request.reverified_cpus;
	ebpfos_runtime_successor.preflight_component_cpus =
		request.component_cpus;
	ebpfos_runtime_successor.handoff_preflighted = true;
out_cpus:
	cpus_read_unlock();
out_unlock:
	mutex_unlock(&ebpfos_runtime_successor.lock);
	return error;
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
	case EBPFOS_RUNTIME_ROOT_IOC_SUCCESSOR_STAGE:
		return ebpfos_runtime_successor_stage(argp);
	case EBPFOS_RUNTIME_ROOT_IOC_SUCCESSOR_PUBLISH:
		return ebpfos_runtime_successor_publish(argp);
	case EBPFOS_RUNTIME_ROOT_IOC_SUCCESSOR_PREFLIGHT:
		return ebpfos_runtime_successor_preflight(argp);
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
