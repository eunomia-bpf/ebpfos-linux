// SPDX-License-Identifier: GPL-2.0-only
/* Policy-free native dispatch to the existing executor-root binding. */
#include <linux/bpf.h>
#include <linux/ebpfos.h>
#include <linux/ebpfos_fops_route.h>
#include <linux/errno.h>
#include <linux/filter.h>

int ebpfos_fops_route_call(u64 handle, u64 role, void *frame,
			  u64 *epoch, u32 *provider_id, u32 *status)
{
	struct ebpfos_executor_root_lease lease = {};
	struct ebpfos_executor_root_role_snapshot role_snapshot;
	struct ebpfos_binding *binding;
	struct bpf_tramp_run_ctx run_ctx = {};
	struct bpf_prog *provider;
	u64 start;
	int error, attempts = 0;

	if (!handle || !role || !frame || !epoch || !provider_id || !status)
		return -EINVAL;
retry:
	error = ebpfos_executor_root_lease_begin(handle, role, &lease,
						  &role_snapshot);
	if (error)
		return error;
	binding = lease.binding;
	provider = ebpfos_binding_prog(binding);
	if (!provider || !provider->aux || !provider->aux->ebpfos_component ||
	    provider->type != BPF_PROG_TYPE_SYSCALL || !provider->sleepable ||
	    ebpfos_binding_use(binding) != EBPFOS_COMPONENT_USE_CALL_PROVIDER) {
		error = -EOPNOTSUPP;
		goto out;
	}
	start = __bpf_prog_enter_sleepable_recur(provider, &run_ctx);
	if (!start) {
		__bpf_prog_exit_sleepable_recur(provider, 0, &run_ctx);
		error = -EBUSY;
		goto out;
	}
	error = ebpfos_binding_invocation_enter(binding);
	if (error) {
		__bpf_prog_exit_sleepable_recur(provider, 0, &run_ctx);
		if (error == -ESHUTDOWN && !attempts++) {
			ebpfos_executor_root_lease_end(&lease);
			goto retry;
		}
		goto out;
	}
	*status = bpf_prog_run(provider, frame);
	__bpf_prog_exit_sleepable_recur(provider, 0, &run_ctx);
	ebpfos_binding_invocation_exit(binding);
	*epoch = lease.epoch;
	*provider_id = binding->prog_id;
	error = 0;
out:
	ebpfos_executor_root_lease_end(&lease);
	return error;
}
