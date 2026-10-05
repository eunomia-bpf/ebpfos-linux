// SPDX-License-Identifier: GPL-2.0-only
/* Direct C entry through an immutable executor-root binding. */
#include <linux/ebpfos_entry.h>
#include <linux/filter.h>
#include <linux/module.h>
#include "executor_root.h"

static __always_inline int
ebpfos_component_call_slot_inner(struct ebpfos_executor_root_slot *slot, u64 role,
				 const void *context, u32 *result, bool borrowed)
{
	struct ebpfos_executor_root_bundle *bundle;
	struct ebpfos_executor_root_role *target;
	struct bpf_tramp_run_ctx run_ctx = {};
	struct ebpfos_binding *binding;
	struct bpf_prog *prog;
	u64 start;
	u32 index;
	int error, retries = 0;

	if (!context || !result)
		return -EINVAL;
	if (!slot)
		return -ENOENT;
	if (!borrowed)
		rcu_read_lock();
retry:
	if (atomic_long_read_acquire(&slot->gate.state) & EBPFOS_GATE_DRAINING) {
		error = -EAGAIN;
		goto out;
	}
	bundle = rcu_dereference(slot->active);
	if (!bundle) {
		error = -ENOENT;
		goto out;
	}
	for (index = 0; index < bundle->role_count; index++) {
		target = &bundle->roles[index];
		if (target->snapshot.role_type >= role)
			break;
	}
	if (index == bundle->role_count || target->snapshot.role_type != role) {
		error = -ENOENT;
		goto out;
	}
	if (!target->entry) {
		error = -EOPNOTSUPP;
		goto out;
	}
	binding = target->binding;
	prog = binding->prog;
	/* Keep the stock recursion guard, run context and migration protection. */
	start = binding->prog_enter(prog, &run_ctx);
	if (!start) {
		binding->prog_exit(prog, 0, &run_ctx);
		error = -EBUSY;
		goto out;
	}
	error = ebpfos_binding_invocation_enter(binding);
	if (error) {
		binding->prog_exit(prog, 0, &run_ctx);
		/* Publication may close the old binding after we observed it. */
		if (error == -ESHUTDOWN && !retries++)
			goto retry;
		goto out;
	}
	/* The loaded stock JIT implements this C ABI. No redirection handler,
	 * function scope, argument accessor, staged return or per-shape stub.
	 * The stock enter/exit callbacks also account optional BPF statistics.
	 */
	cant_migrate();
	*result = target->entry(context, prog->insnsi);
	binding->prog_exit(prog, start, &run_ctx);
	/* This private path owns one count from its successful enter above and
	 * releases it exactly once. Other paired exits cannot consume that count;
	 * retirement changes only bit 63. Subtraction therefore cannot borrow into
	 * the entry sequence. Keep the full ordering of the former successful CAS.
	 * The public exit API retains its defensive zero-count check.
	 */
	atomic64_dec_return(&binding->invocation_state);
	error = 0;
out:
	if (!borrowed)
		rcu_read_unlock();
	return error;
}

int ebpfos_component_call_slot(struct ebpfos_executor_root_slot *slot, u64 role,
			       const void *context, u32 *result)
{
	return ebpfos_component_call_slot_inner(slot, role, context, result, false);
}
EXPORT_SYMBOL_GPL(ebpfos_component_call_slot);

int ebpfos_component_call_slot_rcu(struct ebpfos_executor_root_slot *slot, u64 role,
				   const void *context, u32 *result)
{
	return ebpfos_component_call_slot_inner(slot, role, context, result, true);
}
EXPORT_SYMBOL_GPL(ebpfos_component_call_slot_rcu);
