// SPDX-License-Identifier: GPL-2.0-only
/* Direct C entry through an immutable executor-root binding. */
#include <linux/ebpfos_entry.h>
#include <linux/filter.h>
#include <linux/module.h>
#include "executor_root.h"

int ebpfos_component_call_slot(struct ebpfos_executor_root_slot *slot, u64 role,
			       const void *context, u32 *result)
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
	ebpfos_binding_invocation_exit(binding);
	error = 0;
out:
	rcu_read_unlock();
	return error;
}
EXPORT_SYMBOL_GPL(ebpfos_component_call_slot);
