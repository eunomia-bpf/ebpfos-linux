// SPDX-License-Identifier: GPL-2.0-only
/* A typed call borrows only a verified subprogram of one published program. */
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/ebpfos_typed.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/module.h>
#include "executor_root.h"
#include "step_scope.h"
#include "../../tools/lib/bpf/relo_core.h"

/* Stack-owned checkpoint storage, exposed to the compiler only as opaque
 * bytes through this enclosing BTF type. No allocation occurs on invocation.
 */
struct ebpfos_component_call {
	struct ebpfos_component_call *previous;
	struct ebpfos_executor_root_lease lease;
	struct bpf_tramp_run_ctx run;
	struct ebpfos_binding *binding;
	struct bpf_prog *program;
	struct ebpfos_step_scope step;
	u64 start;
	int fault;
};

static DEFINE_PER_CPU(struct ebpfos_component_call *, ebpfos_active_typed_call);

int ebpfos_component_typed_export(struct bpf_prog *prog, void **entry)
{
	const struct btf_type *function, *native, *prototype, *result;
	u32 i;
	int error;

	*entry = NULL;
	if (!prog->aux->btf || !prog->aux->func_info)
		return 0;
	for (i = 1; i < prog->aux->func_info_cnt; i++) {
		struct bpf_prog *subprog;

		function = btf_type_by_id(prog->aux->btf,
					prog->aux->func_info[i].type_id);
		if (!function || !btf_type_is_func(function))
			return -EINVAL;
		if (strcmp(btf_name_by_offset(prog->aux->btf, function->name_off),
			   "ebpfos_function_entry"))
			continue;
		if (*entry || !prog->jited || prog->sleepable ||
		    !prog->aux->ebpfos_component ||
		    prog->type != BPF_PROG_TYPE_TRACING ||
		    prog->expected_attach_type != BPF_TRACE_FENTRY ||
		    !prog->aux->attach_btf || !prog->aux->func ||
		    !prog->aux->func_info_aux ||
		    prog->aux->func_info_aux[i].unreliable ||
		    i >= prog->aux->real_func_cnt ||
		    btf_func_linkage(function) != BTF_FUNC_GLOBAL)
			return -EPROTOTYPE;
		native = btf_type_by_id(prog->aux->attach_btf,
					prog->aux->attach_btf_id);
		if (!native || !btf_type_is_func(native))
			return -EPROTOTYPE;
		prototype = btf_type_by_id(prog->aux->attach_btf, native->type);
		result = btf_type_skip_modifiers(prog->aux->attach_btf,
						prototype->type, NULL);
		/* Stock global subprogram returns are scalar. A matching BTF
		 * pointer declaration cannot authorize scalar bits as a pointer.
		 */
		if (!btf_type_is_void(result) && !btf_type_is_int(result) &&
		    !btf_is_any_enum(result))
			return -EOPNOTSUPP;
		/* Stock CO-RE matching includes prototype, scalar widths and
		 * pointee identities. No verifier result or type is changed.
		 */
		error = bpf_core_types_match(prog->aux->btf, function->type,
					   prog->aux->attach_btf, native->type);
		if (error <= 0)
			return error ?: -EPROTOTYPE;
		subprog = prog->aux->func[i];
		/* The stock subprogram C register ABI is usable here on x86.
		 * Tail calls require a caller-owned hidden register and must use
		 * the stock main entry instead. Exceptions also require its frame.
		 */
		if (!IS_ENABLED(CONFIG_X86_64) || IS_ENABLED(CONFIG_CFI) ||
		    !subprog || !subprog->jited ||
		    subprog->aux->tail_call_reachable || prog->aux->exception_cb ||
		    prog->aux->arena)
			return -EOPNOTSUPP;
		*entry = (void *)subprog->bpf_func;
	}
	return 0;
}

int ebpfos_component_typed_enter(struct ebpfos_executor_root_slot *slot,
				u64 role, u32 native_func_id,
				struct ebpfos_component_call *call,
				void **typed_entry)
{
	struct ebpfos_executor_root_bundle *bundle;
	struct ebpfos_executor_root_role *target;
	u32 i;
	int error;

	if (!call || !typed_entry)
		return -EINVAL;
	if (!slot)
		return -ENOENT;
	rcu_read_lock();
	if (atomic_long_read_acquire(&slot->gate.state) & EBPFOS_GATE_DRAINING) {
		error = -EAGAIN;
		goto release_rcu;
	}
	bundle = rcu_dereference(slot->active);
	if (!bundle) {
		error = -ENOENT;
		goto release_rcu;
	}
	for (i = 0; i < bundle->role_count; i++) {
		target = &bundle->roles[i];
		if (target->snapshot.role_type == role)
			break;
	}
	if (i == bundle->role_count || !target->typed_entry) {
		error = -EPROTOTYPE;
		goto release_rcu;
	}
	call->lease.slot = slot;
	call->lease.binding = target->binding;
	call->lease.epoch = bundle->epoch;
	call->lease.rcu_held = true;
	call->lease.rcu_borrowed = false;
	call->binding = target->binding;
	call->program = call->binding->prog;
	if (call->program->aux->attach_btf_id != native_func_id ||
	    call->program->aux->attach_btf != bpf_get_btf_vmlinux()) {
		error = -EPROTOTYPE;
		goto release_lease;
	}
	call->start = __bpf_prog_enter_recur(call->program, &call->run);
	if (!call->start) {
		error = -EBUSY;
		goto release_run;
	}
	error = ebpfos_binding_invocation_enter(call->binding);
	if (error)
		goto release_run;
	ebpfos_step_enter(&call->step, call->program->aux);
	call->previous = this_cpu_read(ebpfos_active_typed_call);
	call->fault = 0;
	this_cpu_write(ebpfos_active_typed_call, call);
	*typed_entry = target->typed_entry;
	return 0;
release_run:
	__bpf_prog_exit_recur(call->program, call->start, &call->run);
release_lease:
	ebpfos_executor_root_lease_end(&call->lease);
	return error;
release_rcu:
	rcu_read_unlock();
	return error;
}
EXPORT_SYMBOL_GPL(ebpfos_component_typed_enter);

int ebpfos_component_typed_exit(struct ebpfos_component_call *call)
{
	int fault = call->fault;

	if (!fault && call->step.pending) {
		call->step.pending = false;
		return 1;
	}
	this_cpu_write(ebpfos_active_typed_call, call->previous);
	ebpfos_step_exit(&call->step);
	__bpf_prog_exit_recur(call->program, call->start, &call->run);
	ebpfos_binding_invocation_exit(call->binding);
	ebpfos_executor_root_lease_end(&call->lease);
	return fault;
}
EXPORT_SYMBOL_GPL(ebpfos_component_typed_exit);

__bpf_kfunc_start_defs();
__bpf_kfunc void bpf_ebpfos_component_fault(s32 error)
{
	struct ebpfos_component_call *call = this_cpu_read(ebpfos_active_typed_call);

	/* An interrupt's unrelated BPF invocation must not fault its interrupted
	 * caller. Stock callbacks install/restore the current run context.
	 */
	if (call && current->bpf_ctx == &call->run.run_ctx && !call->fault)
		call->fault = error < 0 ? error : -EFAULT;
}
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(ebpfos_typed_fault_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_component_fault)
BTF_KFUNCS_END(ebpfos_typed_fault_ids)

static int ebpfos_typed_fault_filter(const struct bpf_prog *prog, u32 id)
{
	if (!btf_id_set8_contains(&ebpfos_typed_fault_ids, id))
		return 0;
	return !prog || !prog->aux || !prog->aux->ebpfos_component ||
		prog->sleepable || prog->type != BPF_PROG_TYPE_TRACING ||
		prog->expected_attach_type != BPF_TRACE_FENTRY;
}

static const struct btf_kfunc_id_set ebpfos_typed_fault_set = {
	.owner = THIS_MODULE, .set = &ebpfos_typed_fault_ids,
	.filter = ebpfos_typed_fault_filter,
};

static int __init ebpfos_typed_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING,
					 &ebpfos_typed_fault_set);
}
late_initcall(ebpfos_typed_init);
