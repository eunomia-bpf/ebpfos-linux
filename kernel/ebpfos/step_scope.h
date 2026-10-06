/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _EBPFOS_STEP_SCOPE_H
#define _EBPFOS_STEP_SCOPE_H

#include <linux/percpu.h>
#include <linux/preempt.h>

struct bpf_prog_aux;
struct bpf_prog;
struct bpf_map;

/* Conservative publication-time selection; unknown targets retain a scope. */
bool ebpfos_step_program_needs_scope(const struct bpf_prog *prog);

/* One logical invocation owns its checkpoint across all bounded entries. */
struct ebpfos_step_scope {
	struct ebpfos_step_scope *previous;
	const struct bpf_prog_aux *owner;
	struct bpf_map *pointer_result;
	void **pointer_value;
	void *owned_result;
	bool valid;
	bool pending;
	bool has_result;
	bool pointer_owned;
	u32 size;
	u64 result;
	u64 result_high;
	u8 state[64];
};

DECLARE_PER_CPU(struct ebpfos_step_scope *, ebpfos_active_step);

void ebpfos_step_pointer_clear(struct ebpfos_step_scope *scope);
/* Capture normally empties this CPU's channel before cleanup. Keep the
 * empty path at the caller; a live reference still reaches atomic removal
 * and the stock destructor in ebpfos_step_pointer_clear().
 */
static __always_inline void ebpfos_step_pointer_clear_if_live(struct ebpfos_step_scope *scope)
{
	if (scope->pointer_value && READ_ONCE(*scope->pointer_value))
		ebpfos_step_pointer_clear(scope);
}

void ebpfos_step_result_reset(struct ebpfos_step_scope *scope);
/* Only a completed, fault-free native call may transfer this reference. */
void ebpfos_step_result_transfer(struct ebpfos_step_scope *scope);

static inline void ebpfos_step_enter(struct ebpfos_step_scope *scope,
				     const struct bpf_prog_aux *owner)
{
	preempt_disable();
	scope->previous = this_cpu_read(ebpfos_active_step);
	scope->owner = owner;
	scope->pointer_result = NULL;
	scope->pointer_value = NULL;
	scope->owned_result = NULL;
	scope->valid = false;
	scope->pending = false;
	scope->has_result = false;
	scope->pointer_owned = false;
	scope->size = 0;
	this_cpu_write(ebpfos_active_step, scope);
}

static inline void ebpfos_step_exit(struct ebpfos_step_scope *scope)
{
	/* Without a published pointer channel, enter initialized owned_result
	 * to NULL and no result service can acquire a reference in this scope.
	 */
	if (scope->pointer_result)
		ebpfos_step_result_reset(scope);
	else
		scope->has_result = false;
	this_cpu_write(ebpfos_active_step, scope->previous);
	preempt_enable();
}

#endif
