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
	bool valid;
	bool pending;
	bool has_result;
	u64 result;
	u32 size;
	u8 state[64];
};

DECLARE_PER_CPU(struct ebpfos_step_scope *, ebpfos_active_step);

static inline void ebpfos_step_enter(struct ebpfos_step_scope *scope,
				     const struct bpf_prog_aux *owner)
{
	preempt_disable();
	scope->previous = this_cpu_read(ebpfos_active_step);
	scope->owner = owner;
	scope->pointer_result = NULL;
	scope->pointer_value = NULL;
	scope->valid = false;
	scope->pending = false;
	scope->has_result = false;
	scope->size = 0;
	this_cpu_write(ebpfos_active_step, scope);
}

static inline void ebpfos_step_exit(struct ebpfos_step_scope *scope)
{
	this_cpu_write(ebpfos_active_step, scope->previous);
	preempt_enable();
}

#endif
