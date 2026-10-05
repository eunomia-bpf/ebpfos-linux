// SPDX-License-Identifier: GPL-2.0-only
/* Publication reuses the stock BTF argument decoder of the checked export. */
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
