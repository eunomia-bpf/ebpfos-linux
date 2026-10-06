// SPDX-License-Identifier: GPL-2.0-only
/* Publication reuses the stock BTF argument decoder of the checked entry. */
#include <linux/btf.h>
#include <linux/ebpfos_typed.h>
#include <linux/filter.h>

int ebpfos_component_typed_null_args(struct bpf_prog *prog, void *entry, u64 *mask)
{
	u32 i;

	*mask = 0;
	for (i = 1; i < min(prog->aux->func_info_cnt, prog->aux->real_func_cnt); i++) {
		struct bpf_prog *subprog = prog->aux->func[i];

		if ((void *)subprog->bpf_func == entry)
			return btf_func_null_args(prog, i, mask);
	}
	return -EPROTOTYPE;
}

int ebpfos_component_context_null_args(struct bpf_prog *prog, u64 *mask)
{
	const struct btf_type *prototype = prog->aux->attach_func_proto;
	struct btf *btf = prog->aux->attach_btf;
	struct btf_func_model model;
	u32 i, offset = 0;
	int error;

	*mask = 0;
	error = btf_distill_func_proto(NULL, btf, prototype,
				       prog->aux->attach_func_name, &model);
	if (error)
		return error;
	for (i = 0; i < model.nr_args; i++) {
		const struct btf_type *type = btf_type_skip_modifiers(
			btf, btf_params(prototype)[i].type, NULL);

		if (btf_type_is_ptr(type)) {
			struct bpf_insn_access_aux access = { .reg_type = SCALAR_VALUE };

			/* Ask the same decoder used by stock context verification.
			 * A scalar context word permits zero without granting pointer
			 * authority. Other pointer words must explicitly permit NULL.
			 */
			if (!btf_ctx_access(offset, sizeof(u64), BPF_READ, prog, &access))
				return -EPROTOTYPE;
			if (access.reg_type == SCALAR_VALUE ||
			    access.reg_type & PTR_MAYBE_NULL)
				*mask |= BIT_ULL(i);
		}
		/* Permission bits name native arguments, not flattened context
		 * words. Aggregates consume their full rounded context width.
		 */
		offset += round_up(model.arg_size[i], sizeof(u64));
	}
	return 0;
}
