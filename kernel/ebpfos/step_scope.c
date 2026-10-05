// SPDX-License-Identifier: GPL-2.0-only
/* Scalar loop continuations, independent of the diagnostic function route. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h> /* Complete bpf_prog graph for the implicit aux BTF. */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/string.h>
#include "step_scope.h"

DEFINE_PER_CPU(struct ebpfos_step_scope *, ebpfos_active_step);

/* Shared first-fault recorder checks the active stock run context. */
extern void bpf_ebpfos_component_fault(s32 error);

/* Publication accepts only the native prototype's exact kernel BTF type.
 * Stock kptr metadata owns the destructor and its module lifetime; the
 * invocation's program/map lease keeps both live through this cleanup.
 */
static void ebpfos_step_pointer_put(struct ebpfos_step_scope *scope, void *value)
{
	const struct btf_field *field;

	if (!value || !scope->pointer_result)
		return;
	field = &scope->pointer_result->record->fields[0];
	if (field->type == BPF_KPTR_REF)
		field->kptr.dtor(value);
}

void ebpfos_step_pointer_clear(struct ebpfos_step_scope *scope)
{
	if (scope->pointer_value)
		ebpfos_step_pointer_put(scope, xchg(scope->pointer_value, NULL));
}

void ebpfos_step_result_reset(struct ebpfos_step_scope *scope)
{
	ebpfos_step_pointer_clear(scope);
	ebpfos_step_pointer_put(scope, scope->owned_result);
	scope->owned_result = NULL;
	scope->has_result = false;
}

void ebpfos_step_result_transfer(struct ebpfos_step_scope *scope)
{
	scope->owned_result = NULL;
}

__bpf_kfunc_start_defs();

/* A tracing entry must return zero under stock FENTRY verification. Its
 * native scalar result travels separately in the invocation, never in ctx.
 */
__bpf_kfunc void bpf_ebpfos_component_result(u64 result, struct bpf_prog_aux *aux)
{
	struct ebpfos_step_scope *scope = this_cpu_read(ebpfos_active_step);

	if (scope && scope->owner == aux) {
		scope->result = result;
		scope->result_high = 0;
		scope->has_result = true;
	}
}

/* Both words remain scalars. The native model admits only pointer-free
 * integer aggregates; typed pointers retain their checked kptr channel.
 */
__bpf_kfunc void bpf_ebpfos_component_result_pair(u64 first, u64 second,
						struct bpf_prog_aux *aux)
{
	struct ebpfos_step_scope *scope = this_cpu_read(ebpfos_active_step);

	if (scope && scope->owner == aux) {
		scope->result = first;
		scope->result_high = second;
		scope->has_result = true;
	}
}

/* The map's kptr field, not a scalar argument, carries pointer authority.
 * Publication checked it against the native result type; the stock verifier
 * checks every store and rejects stack, map-value and fabricated addresses.
 * Consume immediately into this logical invocation so nested calls cannot
 * overwrite an earlier result. REF kptrs transfer their checked reference
 * to the invocation; only successful native exit transfers it to the caller.
 */
__bpf_kfunc void bpf_ebpfos_component_pointer_result(struct bpf_map *map__map,
						   struct bpf_prog_aux *aux)
{
	struct ebpfos_step_scope *scope = this_cpu_read(ebpfos_active_step);

	if (!scope || scope->owner != aux)
		return;
	if (scope->pointer_result != map__map) {
		/* A discarded result is not a successful native NULL return. */
		bpf_ebpfos_component_fault(-EPROTO);
		return;
	}
	ebpfos_step_pointer_put(scope, scope->owned_result);
	scope->result = (unsigned long)xchg(scope->pointer_value, NULL);
	scope->result_high = 0;
	scope->owned_result = map__map->record->fields[0].type == BPF_KPTR_REF ?
		(void *)(unsigned long)scope->result : NULL;
	scope->has_result = true;
}

__bpf_kfunc int bpf_ebpfos_function_step_read(void *dst, u32 dst__sz,
					  struct bpf_prog_aux *aux)
{
	struct ebpfos_step_scope *scope = this_cpu_read(ebpfos_active_step);

	if (!scope || scope->owner != aux || !scope->valid ||
	    dst__sz != scope->size)
		return 0;
	memcpy(dst, scope->state, dst__sz);
	return 1;
}

__bpf_kfunc void bpf_ebpfos_function_step_save(const void *src, u32 src__sz,
					   struct bpf_prog_aux *aux)
{
	struct ebpfos_step_scope *scope = this_cpu_read(ebpfos_active_step);

	if (!scope || scope->owner != aux || !src__sz ||
	    src__sz > sizeof(scope->state))
		return;
	memcpy(scope->state, src, src__sz);
	scope->size = src__sz;
	scope->valid = true;
	scope->pending = true;
}

__bpf_kfunc_end_defs();

static bool ebpfos_step_calls_native(const struct bpf_prog *prog)
{
	u32 index;

	for (index = 0; index < prog->len; index++) {
		const struct bpf_insn *call = &prog->insnsi[index];

		/* A tail call's destination is not in this program's call graph. */
		if (call->code == (BPF_JMP | BPF_TAIL_CALL))
			return true;
		if (call->code != (BPF_JMP | BPF_CALL) ||
		    call->src_reg == BPF_PSEUDO_CALL)
			continue;
		/* Native helpers/kfuncs are opaque and can wrap a step service.
		 * Keep a scope for them without inspecting or assuming their bodies.
		 * Compiled BPF subprograms are inspected separately below.
		 */
		return true;
	}
	return false;
}

bool ebpfos_step_program_needs_scope(const struct bpf_prog *prog)
{
	u32 index;

	if (!prog || !prog->jited || ebpfos_step_calls_native(prog))
		return true;
	/* A service may live in a compiled subprogram rather than the entry. */
	for (index = 0; index < prog->aux->real_func_cnt; index++) {
		const struct bpf_prog *function;

		if (!prog->aux->func)
			return true;
		function = prog->aux->func[index];
		if (!function || ebpfos_step_calls_native(function))
			return true;
	}
	return false;
}

BTF_KFUNCS_START(ebpfos_step_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_function_step_read)
BTF_ID_FLAGS(func, bpf_ebpfos_function_step_save)
BTF_ID_FLAGS(func, bpf_ebpfos_component_result)
BTF_ID_FLAGS(func, bpf_ebpfos_component_pointer_result)
BTF_ID_FLAGS(func, bpf_ebpfos_component_result_pair)
BTF_KFUNCS_END(ebpfos_step_ids)

BTF_ID_LIST(ebpfos_result_service_ids)
BTF_ID(func, bpf_ebpfos_component_result)
BTF_ID(func, bpf_ebpfos_component_pointer_result)
BTF_ID(func, bpf_ebpfos_component_result_pair)

static int ebpfos_step_filter(const struct bpf_prog *prog, u32 id)
{
	if (!btf_id_set8_contains(&ebpfos_step_ids, id))
		return 0;
	if (prog && prog->type == BPF_PROG_TYPE_TRACING &&
	    prog->aux && prog->aux->attach_func_proto) {
		const struct btf_type *result = btf_type_skip_modifiers(
			prog->aux->attach_btf, prog->aux->attach_func_proto->type, NULL);
		bool pointer = btf_type_is_ptr(result);

		if (((id == ebpfos_result_service_ids[0] ||
		      id == ebpfos_result_service_ids[2]) && pointer) ||
		    (id == ebpfos_result_service_ids[1] && !pointer))
			return 1;
		if (id == ebpfos_result_service_ids[2] &&
		    (!btf_type_is_struct(result) || result->size <= 8 || result->size > 16))
			return 1;
	}
	if ((id == ebpfos_result_service_ids[1] || id == ebpfos_result_service_ids[2]) &&
	    (!prog || prog->type != BPF_PROG_TYPE_TRACING))
		return 1;
	return !prog || !prog->aux || !prog->aux->ebpfos_component ||
	       (prog->type != BPF_PROG_TYPE_RAW_TRACEPOINT &&
		!(prog->type == BPF_PROG_TYPE_TRACING &&
		  prog->expected_attach_type == BPF_TRACE_FENTRY)) || prog->sleepable;
}

static const struct btf_kfunc_id_set ebpfos_step_set = {
	.owner = THIS_MODULE,
	.set = &ebpfos_step_ids,
	.filter = ebpfos_step_filter,
};

static int __init ebpfos_step_init(void)
{
	/* RAW_TRACEPOINT and TRACING resolve to the same stock tracing hook. */
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_RAW_TRACEPOINT,
					 &ebpfos_step_set);
}
late_initcall(ebpfos_step_init);
