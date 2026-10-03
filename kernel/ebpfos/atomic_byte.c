// SPDX-License-Identifier: GPL-2.0-only
/* Byte compare-exchange for verifier-checked component memory. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/module.h>

__bpf_kfunc_start_defs();

__bpf_kfunc u8 bpf_ebpfos_effect_atomic_cmpxchg8(void *ptr, u32 ptr__sz,
						  u8 expected, u8 desired)
{
	if (!ptr || ptr__sz != sizeof(u8))
		return 0;
	__atomic_compare_exchange_n((u8 *)ptr, &expected, desired, false,
				    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
	return expected;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(ebpfos_atomic_byte_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_effect_atomic_cmpxchg8)
BTF_KFUNCS_END(ebpfos_atomic_byte_ids)

static int ebpfos_atomic_byte_filter(const struct bpf_prog *prog, u32 id)
{
	if (!btf_id_set8_contains(&ebpfos_atomic_byte_ids, id))
		return 0;
	return !prog || !prog->aux || !prog->aux->ebpfos_component ||
	       prog->type != BPF_PROG_TYPE_SYSCALL;
}

static const struct btf_kfunc_id_set ebpfos_atomic_byte_set = {
	.owner = THIS_MODULE,
	.set = &ebpfos_atomic_byte_ids,
	.filter = ebpfos_atomic_byte_filter,
};

static int __init ebpfos_atomic_byte_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					 &ebpfos_atomic_byte_set);
}
late_initcall(ebpfos_atomic_byte_init);
