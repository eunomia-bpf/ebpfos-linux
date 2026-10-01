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
	struct ebpfos_binding *binding;
	struct bpf_tramp_run_ctx run_ctx = {};
	struct bpf_prog *provider;
	u64 observed_epoch = 0, start;
	int error, attempts = 0;

	if (!handle || !role || !frame || !epoch || !provider_id || !status)
		return -EINVAL;
retry:
	binding = ebpfos_executor_root_binding_get(handle, role,
					     &observed_epoch);
	if (!binding)
		return -ENOENT;
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
			ebpfos_binding_put(binding);
			goto retry;
		}
		goto out;
	}
	*status = bpf_prog_run(provider, frame);
	__bpf_prog_exit_sleepable_recur(provider, 0, &run_ctx);
	ebpfos_binding_invocation_exit(binding);
	*epoch = observed_epoch;
	*provider_id = binding->prog_id;
	error = 0;
out:
	ebpfos_binding_put(binding);
	return error;
}
