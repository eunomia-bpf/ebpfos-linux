// SPDX-License-Identifier: GPL-2.0-only
/* Non-sleepable dispatch through the per-handle executor-root bundle. */
#include <linux/bpf.h>
#include <linux/ebpfos.h>
#include <linux/ebpfos_irq_route.h>
#include <linux/errno.h>
#include <linux/filter.h>
#include <linux/module.h>

int ebpfos_irq_route_call_slot(struct ebpfos_executor_root_slot *slot, u64 role,
	const struct ebpfos_component_irq_frame *frame,
	u64 *epoch, u32 *provider_id, u32 *status)
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
	error = ebpfos_executor_root_lease_try_begin_slot(slot, role, &lease,
							   &snapshot);
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
			ebpfos_executor_root_lease_end(&lease);
			goto retry;
		}
		goto out;
	}
	*status = bpf_prog_run(provider, frame);
	binding->prog_exit(provider, start, &run_ctx);
	ebpfos_binding_invocation_exit(binding);
	*epoch = lease.epoch;
	*provider_id = binding->prog_id;
	error = 0;
out:
	ebpfos_executor_root_lease_end(&lease);
	return error;
}
EXPORT_SYMBOL_GPL(ebpfos_irq_route_call_slot);

int ebpfos_irq_route_call(u64 handle, u64 role,
	const struct ebpfos_component_irq_frame *frame,
	u64 *epoch, u32 *provider_id, u32 *status)
{
	if (!handle)
		return -EINVAL;
	return ebpfos_irq_route_call_slot(ebpfos_executor_root_lookup(handle),
		role, frame, epoch, provider_id, status);
}
EXPORT_SYMBOL_GPL(ebpfos_irq_route_call);
