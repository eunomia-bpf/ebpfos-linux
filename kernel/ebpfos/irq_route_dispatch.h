/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _EBPFOS_IRQ_ROUTE_DISPATCH_H
#define _EBPFOS_IRQ_ROUTE_DISPATCH_H

#include <linux/bpf.h>
#include <linux/ebpfos.h>
#include <linux/errno.h>
#include <linux/filter.h>

/* Shared implementation for typed entries and the exported IRQ API. */
static __always_inline int
ebpfos_irq_route_call_slot_steps_ctx(struct ebpfos_executor_root_slot *slot, u64 role,
	const struct ebpfos_component_irq_frame *frame,
	u64 *epoch, u32 *provider_id, u32 *status, bool *pending,
	const struct bpf_prog_aux **owner, bool rcu_borrowed)
{
	/* try_begin initializes every field consumed by a successful lease. */
	struct ebpfos_executor_root_lease lease __uninitialized;
	struct ebpfos_executor_root_role_snapshot snapshot;
	struct bpf_tramp_run_ctx run_ctx = {};
	struct ebpfos_binding *binding;
	struct bpf_prog *provider;
	u64 start;
	int error, attempts = 0;

	if (!frame || !epoch || !provider_id || !status)
		return -EINVAL;
retry:
	if (rcu_borrowed)
		error = ebpfos_executor_root_lease_try_begin_slot_rcu(slot, role,
			&lease, &snapshot);
	else
		error = ebpfos_executor_root_lease_try_begin_slot(slot, role,
			&lease, &snapshot);
	if (error)
		return error;
	binding = lease.binding;
	provider = ebpfos_binding_prog(binding);
	if (!provider || !provider->aux || !provider->aux->ebpfos_component ||
	    provider->type != BPF_PROG_TYPE_RAW_TRACEPOINT ||
	    provider->sleepable) {
		error = -EOPNOTSUPP;
		goto out;
	}
	start = binding->prog_enter(provider, &run_ctx);
	if (!start) {
		binding->prog_exit(provider, 0, &run_ctx);
		error = -EBUSY;
		goto out;
	}
	error = ebpfos_binding_invocation_enter(binding);
	if (error) {
		binding->prog_exit(provider, 0, &run_ctx);
		if (error == -ESHUTDOWN && !attempts++) {
			if (!rcu_borrowed)
				ebpfos_executor_root_lease_end(&lease);
			goto retry;
		}
		goto out;
	}
	/* Keep the invocation and epoch lease across all verified bounded steps.
	 * The function entry disables preemption around this entire call.
	 */
	if (owner)
		*owner = provider->aux;
	do {
		if (pending)
			*pending = false;
		*status = bpf_prog_run(provider, frame);
	} while (pending && *pending);
	binding->prog_exit(provider, start, &run_ctx);
	ebpfos_binding_invocation_exit(binding);
	*epoch = lease.epoch;
	*provider_id = binding->prog_id;
	error = 0;
out:
	if (!rcu_borrowed)
		ebpfos_executor_root_lease_end(&lease);
	return error;
}

/* Standalone callers own a nested RCU lease. */
static __always_inline int
ebpfos_irq_route_call_slot_steps(struct ebpfos_executor_root_slot *slot, u64 role,
	const struct ebpfos_component_irq_frame *frame,
	u64 *epoch, u32 *provider_id, u32 *status, bool *pending,
	const struct bpf_prog_aux **owner)
{
	return ebpfos_irq_route_call_slot_steps_ctx(slot, role, frame, epoch,
		provider_id, status, pending, owner, false);
}

/* The typed function scope holds RCU through native result commit. */
static __always_inline int
ebpfos_irq_route_call_slot_steps_rcu(struct ebpfos_executor_root_slot *slot, u64 role,
	const struct ebpfos_component_irq_frame *frame,
	u64 *epoch, u32 *provider_id, u32 *status, bool *pending,
	const struct bpf_prog_aux **owner)
{
	return ebpfos_irq_route_call_slot_steps_ctx(slot, role, frame, epoch,
		provider_id, status, pending, owner, true);
}

static __always_inline int
ebpfos_irq_route_call_slot_inner(struct ebpfos_executor_root_slot *slot, u64 role,
	const struct ebpfos_component_irq_frame *frame,
	u64 *epoch, u32 *provider_id, u32 *status)
{
	return ebpfos_irq_route_call_slot_steps(slot, role, frame, epoch,
					      provider_id, status, NULL, NULL);
}

static __always_inline int
ebpfos_irq_route_call_slot_rcu(struct ebpfos_executor_root_slot *slot, u64 role,
	const struct ebpfos_component_irq_frame *frame,
	u64 *epoch, u32 *provider_id, u32 *status)
{
	return ebpfos_irq_route_call_slot_steps_rcu(slot, role, frame, epoch,
		provider_id, status, NULL, NULL);
}
#endif
