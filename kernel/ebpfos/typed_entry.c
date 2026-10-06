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
#include "invocation.h"
#include "step_scope.h"
#include "../../tools/lib/bpf/relo_core.h"

/* Stack-owned checkpoint storage, exposed to the compiler only as opaque
 * bytes through this enclosing BTF type. No allocation occurs on invocation.
 */
struct ebpfos_component_call {
	struct ebpfos_component_call *previous;
	struct bpf_tramp_run_ctx run;
	struct ebpfos_binding *binding;
	struct bpf_prog *program;
	struct ebpfos_step_scope step;
	u64 start;
	unsigned long caller;
	int fault;
	bool step_active;
	bool context_root;
	bool wide_result;
	bool has_caller;
};

static DEFINE_PER_CPU(struct ebpfos_component_call *, ebpfos_active_typed_call);

static struct { u64 first, second; } ebpfos_component_no_lease(void)
{
	/* The returned address is a kernel API, usable only under typed_enter.
	 * An invalid caller must execute no BPF instruction or manufacture a
	 * native pointer. Clear both possible native integer return registers.
	 */
	return (typeof(ebpfos_component_no_lease())) {0, 0};
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
	/* A scalar context has no pointer channel. Its initialized ownership
	 * fields stay empty; only the per-entry scalar result needs resetting.
	 */
	if (step->pointer_result)
		ebpfos_step_result_reset(step);
	else
		step->has_result = false;
	/* Execute the very root whose native context loads and result stores
	 * stock verification checked. Static subprogram facts remain internal.
	 */
	((jit_call_t)prog->bpf_func)(context, prog->insnsi);
	*result = step->has_result ? step->result : 0;
	if (call->wide_result)
		result[1] = step->has_result ? step->result_high : 0;
	if (step->pointer_result)
		ebpfos_step_pointer_clear_if_live(step);
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
				      ebpfos_component_no_lease, false);
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

/* The compiler marks a callable export independently of its ELF name. Unit
 * assembly gives helpers distinct names in a multi-entry object. The marker
 * chooses a candidate only: stock global verification and native BTF matching
 * below still authorize the call. Parameter tags are not export declarations.
 */
static int ebpfos_typed_export_tag(const struct btf *btf, u32 func_id)
{
	u32 i;
	bool found = false;

	for (i = 1; i < btf_nr_types(btf); i++) {
		const struct btf_type *type = btf_type_by_id(btf, i);

		if (!type || BTF_INFO_KIND(type->info) != BTF_KIND_DECL_TAG ||
		    type->type != func_id ||
		    strcmp(btf_name_by_offset(btf, type->name_off),
			   "ebpfos.component.typed_entry"))
			continue;
		if (btf_decl_tag(type)->component_idx != -1)
			return -EPROTOTYPE;
		found = true;
	}
	return found;
}

int ebpfos_component_typed_export(struct bpf_prog *prog, void **entry)
{
	const struct btf_type *function, *native, *prototype, *result;
	u32 i;
	int error;

	*entry = NULL;
	if (!prog->aux->btf || !prog->aux->func_info)
		return 0;
	for (i = 0; i < prog->aux->func_info_cnt; i++) {
		struct bpf_prog *subprog;

		function = btf_type_by_id(prog->aux->btf,
					prog->aux->func_info[i].type_id);
		if (!function || !btf_type_is_func(function))
			return -EINVAL;
		error = ebpfos_typed_export_tag(prog->aux->btf,
					      prog->aux->func_info[i].type_id);
		if (error < 0)
			return error;
		/* The legacy name identifies a tracing export, not a raw context
		 * root. An explicit declaration still requires all checks below.
		 */
		if (!error && (prog->type != BPF_PROG_TYPE_TRACING ||
			      strcmp(btf_name_by_offset(prog->aux->btf, function->name_off),
				     "ebpfos_function_entry")))
			continue;
		if (!i || *entry || !prog->jited || prog->sleepable ||
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
		if (btf_type_is_struct(result)) {
			struct btf_func_model model;

			/* The native model admits only pointer-free, aligned integer
			 * aggregates fitting this architecture's return registers.
			 */
			error = ebpfos_component_entry_model(prog->aux->attach_btf,
							     prog->aux->attach_btf_id, &model);
			if (error)
				return error;
			/* A stock global BPF subprogram returns only R0. Two native
			 * registers require the checked context/result-pair backend.
			 */
			if (model.ret_size > 8)
				return -EOPNOTSUPP;
		} else if (!btf_type_is_void(result) && !btf_type_is_int(result) &&
			   !btf_is_any_enum(result)) {
			return -EOPNOTSUPP;
		}
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

static int ebpfos_component_typed_enter_inner(struct ebpfos_executor_root_slot *slot,
				u64 role, u32 native_func_id,
				struct ebpfos_component_call *call,
				void **typed_entry, u64 null_args)
{
	struct ebpfos_executor_root_bundle *bundle;
	struct ebpfos_executor_root_role *target;
	int error;
	bool locked = false;

	if (!call || !typed_entry)
		return -EINVAL;
	if (!slot)
		return -ENOENT;
	rcu_read_lock();
retry:
	if (atomic_long_read_acquire(&slot->gate.state) & EBPFOS_GATE_DRAINING) {
		error = -EAGAIN;
		goto release_rcu;
	}
	bundle = rcu_dereference(slot->active);
	if (!bundle) {
		error = -ENOENT;
		goto release_rcu;
	}
	target = ebpfos_executor_root_find_role(bundle, role);
	if (!target || !target->typed_entry) {
		error = -EPROTOTYPE;
		goto release_rcu;
	}
	if (null_args & ~target->null_args) {
		error = -EINVAL;
		goto release_rcu;
	}
	/* This API always owns a non-sleepable RCU hold. The selected binding
	 * and its entry remain immutable through that epoch; no sleepable or
	 * caller-borrowed lease state is needed in the opaque call storage.
	 */
	/* Publication bound the immutable native prototype in the vmlinux BTF
	 * namespace. Zero cannot name a FUNC, including a module-only export.
	 */
	if (!target->native_func_id || target->native_func_id != native_func_id) {
		error = -EPROTOTYPE;
		goto release_rcu;
	}
	call->binding = target->binding;
	call->program = call->binding->prog;
	/* Keep the epoch acquired before selection through final exit. The stock
	 * callback body can borrow it without nesting another RCU read section.
	 */
	call->start = __bpf_prog_enter_recur_rcu(call->program, &call->run);
	if (!call->start) {
		error = -EBUSY;
		goto release_run;
	}
	error = ebpfos_binding_acquire_invocation(call->binding);
	if (error) {
		__bpf_prog_exit_recur_rcu(call->program, call->start, &call->run);
		/* A publisher can retire the binding after this reader selects it.
		 * No BPF instruction or invocation count has been acquired. On
		 * this slow path only, serialize selection and count acquisition
		 * with publication. Repeated replacement cannot retire the retry's
		 * binding between those two operations. Keep the same RCU hold and
		 * repeat every gate, prototype and NULL-contract check.
		 */
		if (error == -ESHUTDOWN && !locked) {
			spin_lock(&slot->lock);
			locked = true;
			goto retry;
		}
		goto release_rcu;
	}
	if (unlikely(locked))
		spin_unlock(&slot->lock);
	call->step_active = target->needs_steps;
	call->context_root = target->context_image != NULL;
	call->wide_result = target->wide_result;
	if (call->step_active) {
		ebpfos_step_enter(&call->step, call->program->aux);
		call->step.pointer_result = target->pointer_result;
		if (target->pointer_result)
			call->step.pointer_value = this_cpu_ptr(target->pointer_value_percpu);
	} else {
		/* Fault tracking is per-CPU even for a service-free export. The
		 * conservative loaded-call scan also covers its BPF subprograms.
		 */
		preempt_disable();
	}
	call->previous = this_cpu_read(ebpfos_active_typed_call);
	call->fault = 0;
	call->has_caller = false;
	this_cpu_write(ebpfos_active_typed_call, call);
	*typed_entry = target->typed_entry;
	return 0;
release_run:
	__bpf_prog_exit_recur_rcu(call->program, call->start, &call->run);
release_rcu:
	if (unlikely(locked))
		spin_unlock(&slot->lock);
	rcu_read_unlock();
	return error;
}
int ebpfos_component_typed_enter(struct ebpfos_executor_root_slot *slot,
				u64 role, u32 native_func_id,
				struct ebpfos_component_call *call, void **typed_entry)
{
	return ebpfos_component_typed_enter_inner(slot, role, native_func_id,
						 call, typed_entry, 0);
}
EXPORT_SYMBOL_GPL(ebpfos_component_typed_enter);

int ebpfos_component_typed_enter_args(struct ebpfos_executor_root_slot *slot,
				u64 role, u32 native_func_id,
				struct ebpfos_component_call *call,
				void **typed_entry, u64 null_args)
{
	return ebpfos_component_typed_enter_inner(slot, role, native_func_id,
						 call, typed_entry, null_args);
}
EXPORT_SYMBOL_GPL(ebpfos_component_typed_enter_args);

int ebpfos_component_typed_enter_caller_args(struct ebpfos_executor_root_slot *slot,
				u64 role, u32 native_func_id,
				struct ebpfos_component_call *call,
				void **typed_entry, u64 null_args,
				unsigned long caller)
{
	int error = ebpfos_component_typed_enter_args(slot, role, native_func_id,
						    call, typed_entry, null_args);

	if (!error) {
		call->caller = caller;
		call->has_caller = true;
	}
	return error;
}
EXPORT_SYMBOL_GPL(ebpfos_component_typed_enter_caller_args);

int ebpfos_component_typed_enter_caller(struct ebpfos_executor_root_slot *slot,
				u64 role, u32 native_func_id,
				struct ebpfos_component_call *call,
				void **typed_entry, unsigned long caller)
{
	int error = ebpfos_component_typed_enter(slot, role, native_func_id,
					       call, typed_entry);

	if (!error) {
		call->caller = caller;
		call->has_caller = true;
	}
	return error;
}
EXPORT_SYMBOL_GPL(ebpfos_component_typed_enter_caller);

int ebpfos_component_typed_exit(struct ebpfos_component_call *call)
{
	int fault = call->fault;

	if (call->step_active && !fault && call->step.pending) {
		call->step.pending = false;
		return 1;
	}
	this_cpu_write(ebpfos_active_typed_call, call->previous);
	if (call->step_active) {
		if (!fault && call->step.pointer_result)
			ebpfos_step_result_transfer(&call->step);
		ebpfos_step_exit(&call->step);
	} else {
		preempt_enable();
	}
	__bpf_prog_exit_recur_rcu(call->program, call->start, &call->run);
	/* A successful typed_enter owns one active count through all retained
	 * steps. This final exit releases it exactly once. Retirement changes
	 * only bit 63; other paired exits cannot consume this call's count.
	 * The decrement cannot borrow into the cumulative entry sequence and
	 * retains the full ordering of the public exit's successful CAS.
	 */
	atomic64_dec_return(&call->binding->invocation_state);
	/* Paired with this call's successful enter, through every retained
	 * step. Publication retires the immutable binding only after this hold.
	 */
	rcu_read_unlock();
	return fault;
}
EXPORT_SYMBOL_GPL(ebpfos_component_typed_exit);

__bpf_kfunc_start_defs();
/* An address is observation, not pointer authority. The toolchain guards
 * the source body with this query, before any of its effects, so an old
 * native entry cannot silently substitute its own frame or zero.
 */
__bpf_kfunc int bpf_ebpfos_component_caller(u64 *caller, u32 caller__sz,
					struct bpf_prog_aux *aux)
{
	struct ebpfos_component_call *call = this_cpu_read(ebpfos_active_typed_call);

	if (caller__sz != sizeof(*caller))
		return 0;
	*caller = 0;
	if (!call || call->program->aux != aux ||
	    current->bpf_ctx != &call->run.run_ctx)
		return 0;
	if (!call->has_caller) {
		if (!call->fault)
			call->fault = -ENODATA;
		return 0;
	}
	*caller = call->caller;
	return 1;
}

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
BTF_ID_FLAGS(func, bpf_ebpfos_component_caller)
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
