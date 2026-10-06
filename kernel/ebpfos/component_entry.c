// SPDX-License-Identifier: GPL-2.0-only
/* Direct C entry through an immutable executor-root binding. */
#include <linux/ebpfos_entry.h>
#include <linux/btf.h>
#include <linux/filter.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "executor_root.h"
#include "invocation.h"
#include "step_scope.h"

struct ebpfos_native_entry {
	struct ebpfos_executor_root_slot *slot;
	u64 role;
	struct btf *btf;
	u32 func_id;
	bool pointer_result;
	bool wide_result;
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
	int error;
	bool locked = false;

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
	/* A typed export's admission root discards its native result. Its
	 * actual C ABI must be invoked through the typed lease entry instead.
	 */
	if (target->typed_entry && !target->context_image) {
		error = -EPROTOTYPE;
		goto out;
	}
	/* Reference transfer needs the native lease's separate fault status.
	 * The legacy context API cannot commit a fault-free owned C result.
	 */
	if (target->pointer_result &&
	    target->pointer_result->record->fields[0].type == BPF_KPTR_REF) {
		error = -EPROTOTYPE;
		goto out;
	}
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
	error = ebpfos_binding_acquire_invocation(binding);
	if (error) {
		__bpf_prog_exit_recur(prog, 0, &run_ctx);
		/* A publisher may retire the selected binding before count
		 * acquisition. No BPF instruction or count has been acquired.
		 * Serialize the retry with publication so repeated replacement
		 * cannot turn this race into a native fallback. Recheck the gate,
		 * role and native contract under the same RCU epoch hold.
		 */
		if (error == -ESHUTDOWN && !locked) {
			spin_lock(&slot->lock);
			locked = true;
			goto retry;
		}
		goto out;
	}
	if (unlikely(locked)) {
		spin_unlock(&slot->lock);
		locked = false;
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
			/* Publication bound the channel's per-CPU anchor. The scope
			 * pins this CPU through all resumable entries.
			 */
			step.pointer_value = this_cpu_ptr(target->pointer_value_percpu);
		}
		do {
			step.pending = false;
			/* A scalar scope has no channel or reference to release. As
			 * with the typed context entry, reset only its result flag.
			 * Pointer scopes still consume the channel and any result
			 * retained by a preceding resumable entry.
			 */
			if (step.pointer_result)
				ebpfos_step_result_reset(&step);
			else
				step.has_result = false;
			/* Stock JIT returns the full BPF R0 in the native result
			 * register, as the struct_ops trampoline does. No interpreter
			 * or native-signature function is called through this ABI.
			 */
			*result = ebpfos_run_jit(target->entry, context, prog->insnsi);
			if (prog->type == BPF_PROG_TYPE_TRACING)
				*result = step.has_result ? step.result : 0;
			if (native && native->wide_result)
				result[1] = step.has_result ? step.result_high : 0;
			/* Even a provider that omits capture cannot retain a native
			 * caller's borrowed pointer into the next invocation.
			 */
			ebpfos_step_pointer_clear_if_live(&step);
		} while (step.pending);
		if (step.pointer_result)
			ebpfos_step_result_transfer(&step);
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
	if (unlikely(locked))
		spin_unlock(&slot->lock);
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

/* Classify the integer-only native x86 ABI supported by typed contexts.
 * An aggregate containing an unaligned field is MEMORY, irrespective of
 * its size or the number of available registers. Pointers end here. Bound
 * this walk as well as the stock BTF resolver: previously resolved child
 * types can form a deeper valid graph, which must not exhaust kernel stack.
 */
static int ebpfos_native_arg_alignment(const struct btf *btf, u32 id, u32 offset, u32 depth,
				     u32 *alignment, bool *memory, bool *ambiguous)
{
	const struct btf_type *type = btf_type_skip_modifiers(btf, id, NULL);
	u32 size, i;
	int error;

	if (depth >= 32)
		return -E2BIG;
	if (!type)
		return -EINVAL;
	*alignment = 1;
	if (btf_type_is_ptr(type)) {
		*alignment = sizeof(void *);
	} else if (btf_type_is_int(type) || btf_is_any_enum(type)) {
		if (!type->size || type->size > 8 || !is_power_of_2(type->size))
			return -EOPNOTSUPP;
		*alignment = type->size;
	} else if (btf_type_is_array(type)) {
		const struct btf_array *array = btf_array(type);
		const struct btf_type *element;

		if (!array->nelems)
			return 0;
		element = btf_type_by_id(btf, array->type);
		element = btf_resolve_size(btf, element, &size);
		if (IS_ERR(element))
			return PTR_ERR(element);
		if (!size)
			return 0;
		error = ebpfos_native_arg_alignment(btf, array->type, offset, depth + 1,
						    alignment, memory, ambiguous);
		if (error)
			return error;
		if (array->nelems > 1 && size % *alignment)
			*memory = true;
		return 0;
	} else if (btf_type_is_struct(type)) {
		const struct btf_member *member = btf_type_member(type);

		/* BTF also omits explicit alignment of an ordinary record. A
		 * char[8] record has the same BTF with alignment 1 or 8, but
		 * nested at byte 1 the latter changes the native argument to
		 * MEMORY (and a return to hidden sret). Record size is always a
		 * multiple of its alignment, bounding the possible alignments.
		 * If this offset satisfies even the largest possible alignment,
		 * the missing attribute cannot change the classification here.
		 */
		if (type->size && offset % (type->size & -type->size))
			*ambiguous = true;
		for (i = 0; i < btf_type_vlen(type); i++, member++) {
			const struct btf_type *field;
			u32 field_alignment, bits = __btf_member_bit_offset(type, member);

			/* A bitfield does not require an aligned integer load, but
			 * its enclosing record can still have that integer's native
			 * alignment. BTF omits packed/alignment attributes: an 8-byte
			 * record containing one unsigned-long bit and char[7] has
			 * identical BTF with native alignment 8 or 1. Nested at byte
			 * 1, these are MEMORY and INTEGER respectively. Do not guess
			 * a native ABI from the bitfield's occupied bits alone.
			 * sizeof is a multiple of alignment, bounding the possible
			 * alignment even for a compact packed bitfield record.
			 */
			if (__btf_member_bitfield_size(type, member)) {
				field = btf_type_skip_modifiers(btf, member->type, NULL);
				if (!field || (!btf_type_is_int(field) && !btf_is_any_enum(field)) ||
				    !field->size || field->size > 8 || !is_power_of_2(field->size))
					return -EOPNOTSUPP;
				field_alignment = min(field->size, type->size & -type->size);
				*alignment = max(*alignment, field_alignment);
				if (offset % field_alignment)
					*ambiguous = true;
				continue;
			}
			field = btf_type_by_id(btf, member->type);
			field = btf_resolve_size(btf, field, &size);
			if (IS_ERR(field))
				return PTR_ERR(field);
			if (!size)
				continue;
			if (bits % 8)
				*memory = true;
			error = ebpfos_native_arg_alignment(btf, member->type,
							    offset + bits / 8,
							    depth + 1,
							    &field_alignment, memory, ambiguous);
			if (error)
				return error;
			*alignment = max(*alignment, field_alignment);
		}
		return 0;
	} else {
		/* SSE/x87 and wide integers require a different native model. */
		return -EOPNOTSUPP;
	}
	if (offset % *alignment)
		*memory = true;
	return 0;
}

int ebpfos_component_entry_model(struct btf *btf, u32 func_id,
				 struct btf_func_model *model)
{
	const struct btf_type *function, *prototype;
	u32 i, words = 0, registers = 0, stack_words = 0;
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
		if (IS_ENABLED(CONFIG_X86_64) &&
		    model->arg_flags[i] & BTF_FMODEL_STRUCT_ARG) {
			u32 alignment;
			bool memory = false, ambiguous = false;

			error = ebpfos_native_arg_alignment(btf, btf_params(prototype)[i].type,
							    0, 0, &alignment, &memory, &ambiguous);
			if (error)
				return error;
			/* A definitely unaligned ordinary field fixes the entire
			 * argument to MEMORY, irrespective of a nested record's
			 * alignment. Otherwise BTF cannot choose the call convention.
			 */
			if (ambiguous && !memory)
				return -EOPNOTSUPP;
			if (memory)
				model->arg_flags[i] |= BTF_FMODEL_MEMORY_ARG;
		}
		/* The model has no alignment/class information for native i128.
		 * Its stack ABI cannot be inferred from size alone.
		 */
		if (model->arg_size[i] > 8 &&
		    !(model->arg_flags[i] & BTF_FMODEL_STRUCT_ARG))
			return -EOPNOTSUPP;
		if (IS_ENABLED(CONFIG_X86_64)) {
			u32 count = DIV_ROUND_UP(model->arg_size[i], 8);

			if ((model->arg_flags[i] & BTF_FMODEL_MEMORY_ARG) ||
			    registers + count > 6) {
				if (model->arg_flags[i] & BTF_FMODEL_STRUCT_ARG) {
					u32 alignment = model->arg_size[i] & -model->arg_size[i];

					/* Explicit record alignment can also insert padding
					 * between stack arguments. The stock marshaller uses
					 * contiguous eight-byte slots, so reject a placement
					 * whose padding depends on an omitted BTF attribute.
					 */
					if (alignment > 8 && (stack_words * 8) % alignment)
						return -EOPNOTSUPP;
				}
				stack_words += count;
			} else {
				registers += count;
			}
		}
		words += DIV_ROUND_UP(model->arg_size[i], 8);
	}
	if (words > MAX_BPF_FUNC_ARGS || model->ret_size > 16 ||
	    (model->ret_size > 8 && !(model->ret_flags & BTF_FMODEL_STRUCT_ARG)))
		return -EOPNOTSUPP;
	if (IS_ENABLED(CONFIG_X86_64) && model->ret_flags & BTF_FMODEL_STRUCT_ARG) {
		u32 alignment;
		bool memory = false, ambiguous = false;

		/* Integer return words have no hidden native result pointer.
		 * The stock integer-field walk skips bitfields, so apply the
		 * same aggregate alignment classification to the return too.
		 */
		error = ebpfos_native_arg_alignment(btf, prototype->type, 0, 0,
						    &alignment, &memory, &ambiguous);
		if (error)
			return error;
		if (memory || ambiguous)
			return -EOPNOTSUPP;
	}
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
	entry->wide_result = model.ret_size > 8;
	prototype = btf_type_by_id(btf, btf_type_by_id(btf, func_id)->type);
	entry->pointer_result = btf_type_is_ptr(
		btf_type_skip_modifiers(btf, prototype->type, NULL));
	entry->image = arch_alloc_bpf_trampoline(PAGE_SIZE);
	if (!entry->image) {
		error = -ENOMEM;
		goto free_entry;
	}
	error = arch_prepare_bpf_call(entry->image, PAGE_SIZE, &model, entry,
				      ebpfos_native_call, fallback, fallback, true);
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
