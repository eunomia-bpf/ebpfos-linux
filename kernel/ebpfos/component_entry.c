// SPDX-License-Identifier: GPL-2.0-only
/* Direct C entry through an immutable executor-root binding. */
#include <linux/ebpfos_entry.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "executor_root.h"
#include "step_scope.h"

struct ebpfos_native_entry {
	struct ebpfos_executor_root_slot *slot;
	u64 role;
	struct btf *btf;
	u32 func_id;
	bool pointer_result;
	void *image;
};

/* Like the stock dispatcher, the target is a verified, loaded JIT image,
 * not a C function with a compiler CFI hash. Its native result register is
 * the complete 64-bit BPF R0; the legacy bpf_func_t API exposes only u32.
 */
static __always_inline __bpfcall u64
ebpfos_run_jit(bpf_func_t entry, const void *context, const struct bpf_insn *insns)
{
	u64 (*function)(const void *, const struct bpf_insn *) = (void *)entry;

	return function(context, insns);
}

static __always_inline int
ebpfos_component_call_slot_inner(struct ebpfos_executor_root_slot *slot, u64 role,
				 const void *context, u64 *result, bool borrowed,
				 const struct ebpfos_native_entry *native)
{
	struct ebpfos_executor_root_bundle *bundle;
	struct ebpfos_executor_root_role *target;
	struct bpf_tramp_run_ctx run_ctx = {};
	/* step_enter initializes all metadata; step_read cannot expose state until
	 * step_save has initialized exactly size bytes. Avoid clearing unused
	 * checkpoint storage on every call, including programs that never yield.
	 */
	struct ebpfos_step_scope step __uninitialized;
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
	/* The native arguments must match the BTF contract that provided pointer
	 * authority to stock verification. A different target is a pre-entry
	 * miss, never an invitation to reinterpret its typed context.
	 */
	if ((native && native->pointer_result && !target->pointer_result) ||
	    (prog->type == BPF_PROG_TYPE_TRACING &&
	    (!native || prog->aux->attach_btf != native->btf ||
	     prog->aux->attach_btf_id != native->func_id))) {
		error = -EPROTOTYPE;
		goto out;
	}
	/* Publication only makes non-sleepable RAW_TRACEPOINT roles callable
	 * here. bpf_trampoline_enter/exit select these stock callbacks for that
	 * type. Call them directly without changing their guard or accounting.
	 */
	start = __bpf_prog_enter_recur(prog, &run_ctx);
	if (!start) {
		__bpf_prog_exit_recur(prog, 0, &run_ctx);
		error = -EBUSY;
		goto out;
	}
	error = ebpfos_binding_invocation_enter(binding);
	if (error) {
		__bpf_prog_exit_recur(prog, 0, &run_ctx);
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
	if (target->needs_steps) {
		ebpfos_step_enter(&step, prog->aux);
		step.pointer_result = target->pointer_result;
		if (target->pointer_result) {
			u32 key = 0;

			/* A one-entry per-CPU array always has key zero. The scope
			 * pins this CPU through all resumable entries.
			 */
			step.pointer_value = target->pointer_result->ops->map_lookup_elem(
				target->pointer_result, &key);
		}
		do {
			step.pending = false;
			step.has_result = false;
			if (step.pointer_value)
				WRITE_ONCE(*step.pointer_value, NULL);
			/* Stock JIT returns the full BPF R0 in the native result
			 * register, as the struct_ops trampoline does. No interpreter
			 * or native-signature function is called through this ABI.
			 */
			*result = ebpfos_run_jit(target->entry, context, prog->insnsi);
			if (prog->type == BPF_PROG_TYPE_TRACING)
				*result = step.has_result ? step.result : 0;
			/* Even a provider that omits capture cannot retain a native
			 * caller's borrowed pointer into the next invocation.
			 */
			if (step.pointer_value)
				WRITE_ONCE(*step.pointer_value, NULL);
		} while (step.pending);
		ebpfos_step_exit(&step);
	} else {
		*result = ebpfos_run_jit(target->entry, context, prog->insnsi);
	}
	__bpf_prog_exit_recur(prog, start, &run_ctx);
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
	u64 value __uninitialized;
	int error;

	if (!result)
		return -EINVAL;
	error = ebpfos_component_call_slot_inner(slot, role, context, &value, false, NULL);
	if (!error)
		*result = value;
	return error;
}
EXPORT_SYMBOL_GPL(ebpfos_component_call_slot);

int ebpfos_component_call_slot_rcu(struct ebpfos_executor_root_slot *slot, u64 role,
				   const void *context, u32 *result)
{
	u64 value __uninitialized;
	int error;

	if (!result)
		return -EINVAL;
	error = ebpfos_component_call_slot_inner(slot, role, context, &value, true, NULL);
	if (!error)
		*result = value;
	return error;
}
EXPORT_SYMBOL_GPL(ebpfos_component_call_slot_rcu);

int ebpfos_component_call_slot64(struct ebpfos_executor_root_slot *slot, u64 role,
				 const void *context, u64 *result)
{
	return ebpfos_component_call_slot_inner(slot, role, context, result, false, NULL);
}
EXPORT_SYMBOL_GPL(ebpfos_component_call_slot64);

int ebpfos_component_entry_model(struct btf *btf, u32 func_id,
				 struct btf_func_model *model)
{
	const struct btf_type *function, *prototype;
	u32 i, words = 0;
	int error;

	if (!btf || !model)
		return -EINVAL;
	function = btf_type_by_id(btf, func_id);
	if (!function || !btf_type_is_func(function))
		return -EINVAL;
	prototype = btf_type_by_id(btf, function->type);
	if (!prototype || !btf_type_is_func_proto(prototype))
		return -EINVAL;
	memset(model, 0, sizeof(*model));
	error = btf_distill_func_proto(NULL, btf, prototype,
				       btf_name_by_offset(btf, function->name_off), model);
	if (error)
		return error;
	for (i = 0; i < model->nr_args; i++) {
		/* The model has no alignment/class information for native i128.
		 * Its stack ABI cannot be inferred from size alone.
		 */
		if (model->arg_size[i] > 8 &&
		    !(model->arg_flags[i] & BTF_FMODEL_STRUCT_ARG))
			return -EOPNOTSUPP;
		words += DIV_ROUND_UP(model->arg_size[i], 8);
	}
	if (words > MAX_BPF_FUNC_ARGS || model->ret_size > 8)
		return -EOPNOTSUPP;
	if (btf_type_is_ptr(btf_type_skip_modifiers(btf, prototype->type, NULL))) {
		const struct btf_type *pointee = btf_type_resolve_ptr(btf, prototype->type, NULL);

		/* Stock kptr fields accept pointers to structs, never arbitrary
		 * scalar addresses. Owned results need a transfer contract too.
		 */
		if (!pointee || !btf_type_is_struct(pointee))
			return -EOPNOTSUPP;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(ebpfos_component_entry_model);

static int ebpfos_native_call(void *cookie, const void *context, u64 *result)
{
	struct ebpfos_native_entry *entry = cookie;

	return ebpfos_component_call_slot_inner(entry->slot, entry->role, context,
					       result, false, entry);
}

struct ebpfos_native_entry *
ebpfos_component_entry_create(struct ebpfos_executor_root_slot *slot, u64 role,
			      struct btf *btf, u32 func_id, void *fallback)
{
	struct btf_func_model model;
	struct ebpfos_native_entry *entry;
	const struct btf_type *prototype;
	int error;

	if (!slot || !fallback)
		return ERR_PTR(-EINVAL);
	error = ebpfos_component_entry_model(btf, func_id, &model);
	if (error)
		return ERR_PTR(error);
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return ERR_PTR(-ENOMEM);
	entry->slot = slot;
	entry->role = role;
	entry->btf = btf;
	btf_get(btf);
	entry->func_id = func_id;
	prototype = btf_type_by_id(btf, btf_type_by_id(btf, func_id)->type);
	entry->pointer_result = btf_type_is_ptr(
		btf_type_skip_modifiers(btf, prototype->type, NULL));
	entry->image = arch_alloc_bpf_trampoline(PAGE_SIZE);
	if (!entry->image) {
		error = -ENOMEM;
		goto free_entry;
	}
	error = arch_prepare_bpf_call(entry->image, PAGE_SIZE, &model, entry,
				      ebpfos_native_call, fallback);
	if (error > 0)
		error = arch_protect_bpf_trampoline(entry->image, PAGE_SIZE);
	if (error < 0) {
		arch_free_bpf_trampoline(entry->image, PAGE_SIZE);
		goto free_entry;
	}
	return entry;
free_entry:
	btf_put(entry->btf);
	kfree(entry);
	return ERR_PTR(error);
}
EXPORT_SYMBOL_GPL(ebpfos_component_entry_create);

void *ebpfos_component_entry_address(const struct ebpfos_native_entry *entry)
{
	return entry->image;
}
EXPORT_SYMBOL_GPL(ebpfos_component_entry_address);

void ebpfos_component_entry_destroy(struct ebpfos_native_entry *entry)
{
	arch_free_bpf_trampoline(entry->image, PAGE_SIZE);
	btf_put(entry->btf);
	kfree(entry);
}
EXPORT_SYMBOL_GPL(ebpfos_component_entry_destroy);
