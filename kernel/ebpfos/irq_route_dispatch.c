// SPDX-License-Identifier: GPL-2.0-only
/* Non-sleepable dispatch through the per-handle executor-root bundle. */
#include <linux/bpf.h>
#include <linux/ebpfos.h>
#include <linux/ebpfos_irq_route.h>
#include <linux/errno.h>
#include <linux/filter.h>
#include <linux/module.h>

int ebpfos_irq_route_call(u64 handle, u64 role,
	const struct ebpfos_component_irq_frame *frame,
	u64 *epoch, u32 *provider_id, u32 *status)
{
	struct ebpfos_executor_root_lease lease = {};
	struct ebpfos_executor_root_role_snapshot snapshot;
	struct bpf_tramp_run_ctx run_ctx = {};
	struct ebpfos_binding *binding;
	struct bpf_prog *provider;
	u64 start;
	int error, attempts = 0;

	if (!handle || !role || !frame || !epoch || !provider_id || !status)
		return -EINVAL;
retry:
	error = ebpfos_executor_root_lease_try_begin(handle, role, &lease,
						      &snapshot);
	if (error)
		return error;
	binding = lease.binding;
	provider = ebpfos_binding_prog(binding);
	if (!provider || !provider->aux || !provider->aux->ebpfos_component ||
	    provider->type != BPF_PROG_TYPE_RAW_TRACEPOINT ||
	    provider->sleepable ||
	    ebpfos_binding_use(binding) != EBPFOS_COMPONENT_USE_CALL_PROVIDER) {
		error = -EOPNOTSUPP;
		goto out;
	}
	start = bpf_trampoline_enter(provider)(provider, &run_ctx);
	if (!start) {
		bpf_trampoline_exit(provider)(provider, 0, &run_ctx);
		error = -EBUSY;
		goto out;
	}
	error = ebpfos_binding_invocation_enter(binding);
	if (error) {
		bpf_trampoline_exit(provider)(provider, 0, &run_ctx);
		if (error == -ESHUTDOWN && !attempts++) {
			ebpfos_executor_root_lease_end(&lease);
			goto retry;
		}
		goto out;
	}
	*status = bpf_prog_run(provider, frame);
	bpf_trampoline_exit(provider)(provider, start, &run_ctx);
	ebpfos_binding_invocation_exit(binding);
	*epoch = lease.epoch;
	*provider_id = binding->prog_id;
	error = 0;
out:
	ebpfos_executor_root_lease_end(&lease);
	return error;
}
EXPORT_SYMBOL_GPL(ebpfos_irq_route_call);
