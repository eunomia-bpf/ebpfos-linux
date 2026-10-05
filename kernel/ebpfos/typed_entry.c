// SPDX-License-Identifier: GPL-2.0-only
/* A typed call borrows only a verified subprogram of one published program. */
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/ebpfos_typed.h>
#include <linux/ebpfos_entry.h>
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
	bool step_active;
	bool context_root;
};

static DEFINE_PER_CPU(struct ebpfos_component_call *, ebpfos_active_typed_call);

static u64 ebpfos_component_no_lease(void)
{
	/* The returned address is a kernel API, usable only under typed_enter.
	 * An invalid caller must execute no BPF instruction or manufacture a
	 * native pointer. All supported native results fit in this register.
	 */
	return 0;
}

static int ebpfos_component_context_call(void *cookie, const void *context,
					 u64 *result)
{
	struct ebpfos_component_call *call = this_cpu_read(ebpfos_active_typed_call);
	struct bpf_prog *prog = cookie;
	struct ebpfos_step_scope *step;
	typedef u64 (__bpfcall *jit_call_t)(const void *, const struct bpf_insn *);

	if (!call || current->bpf_ctx != &call->run.run_ctx)
		return -EPROTOTYPE;
	/* The native marshaller's fallback value is only an unwind placeholder.
	 * Rejecting another program or backend must reach typed_exit's separate
	 * fault status, without faulting an unrelated interrupted BPF run.
	 * Context publication always supplies an initialized result scope.
	 */
	if (call->program != prog || !call->context_root) {
		if (!call->fault)
			call->fault = -EPROTOTYPE;
		return -EPROTOTYPE;
	}
	step = &call->step;
	ebpfos_step_result_reset(step);
	/* Execute the very root whose native context loads and result stores
	 * stock verification checked. Static subprogram facts remain internal.
	 */
	((jit_call_t)prog->bpf_func)(context, prog->insnsi);
	*result = step->has_result ? step->result : 0;
	ebpfos_step_pointer_clear(step);
	return 0;
}

int ebpfos_component_context_export(struct bpf_prog *prog, void **entry,
				    void **image)
{
	struct btf_func_model model;
	int error;

	*image = NULL;
	if (prog->type != BPF_PROG_TYPE_TRACING ||
	    prog->expected_attach_type != BPF_TRACE_FENTRY ||
	    !prog->aux->ebpfos_component || prog->sleepable)
		return 0;
	if (!IS_ENABLED(CONFIG_X86_64) || IS_ENABLED(CONFIG_CFI) || !prog->jited ||
	    !prog->aux->attach_btf || !prog->aux->dst_trampoline ||
	    prog->aux->exception_cb || prog->aux->arena ||
	    prog->aux->tail_call_reachable)
		return -EOPNOTSUPP;
	error = ebpfos_component_entry_model(prog->aux->attach_btf,
					     prog->aux->attach_btf_id, &model);
	if (error)
		return error;
	*image = arch_alloc_bpf_trampoline(PAGE_SIZE);
	if (!*image)
		return -ENOMEM;
	error = arch_prepare_bpf_call(*image, PAGE_SIZE, &model, prog,
				      ebpfos_component_context_call,
				      prog->aux->dst_trampoline->func.addr,
				      ebpfos_component_no_lease);
	if (error > 0)
		error = arch_protect_bpf_trampoline(*image, PAGE_SIZE);
	if (error < 0) {
		ebpfos_component_context_free(*image);
		*image = NULL;
		return error;
	}
	*entry = *image;
	return 0;
}

void ebpfos_component_context_free(void *image)
{
	if (image)
		arch_free_bpf_trampoline(image, PAGE_SIZE);
}

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
	call->step_active = target->needs_steps;
	call->context_root = target->context_image != NULL;
	if (call->step_active) {
		ebpfos_step_enter(&call->step, call->program->aux);
		call->step.pointer_result = target->pointer_result;
		if (target->pointer_result) {
			u32 key = 0;

			call->step.pointer_value = target->pointer_result->ops->map_lookup_elem(
				target->pointer_result, &key);
		}
	} else {
		/* Fault tracking is per-CPU even for a service-free export. The
		 * conservative loaded-call scan also covers its BPF subprograms.
		 */
		preempt_disable();
	}
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

	if (call->step_active && !fault && call->step.pending) {
		call->step.pending = false;
		return 1;
	}
	this_cpu_write(ebpfos_active_typed_call, call->previous);
	if (call->step_active) {
		if (!fault)
			ebpfos_step_result_transfer(&call->step);
		ebpfos_step_exit(&call->step);
	} else {
		preempt_enable();
	}
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
