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

__bpf_kfunc_start_defs();

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

BTF_KFUNCS_START(ebpfos_step_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_function_step_read)
BTF_ID_FLAGS(func, bpf_ebpfos_function_step_save)
BTF_KFUNCS_END(ebpfos_step_ids)

static int ebpfos_step_filter(const struct bpf_prog *prog, u32 id)
{
	if (!btf_id_set8_contains(&ebpfos_step_ids, id))
		return 0;
	return !prog || !prog->aux || !prog->aux->ebpfos_component ||
	       prog->type != BPF_PROG_TYPE_RAW_TRACEPOINT || prog->sleepable;
}

static const struct btf_kfunc_id_set ebpfos_step_set = {
	.owner = THIS_MODULE,
	.set = &ebpfos_step_ids,
	.filter = ebpfos_step_filter,
};

static int __init ebpfos_step_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_RAW_TRACEPOINT,
					 &ebpfos_step_set);
}
late_initcall(ebpfos_step_init);
