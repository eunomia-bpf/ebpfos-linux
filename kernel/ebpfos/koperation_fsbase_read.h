/* SPDX-License-Identifier: GPL-2.0-only */
/* Read-only machine instructions. These values grant no pointer authority. */
#ifndef EBPFOS_KOPERATION_FSBASE_READ_H
#define EBPFOS_KOPERATION_FSBASE_READ_H
#ifdef CONFIG_X86_64
__bpf_kfunc u64 bpf_ebpfos_x86_rdfsbase32(void)
{
	u32 value;
	asm volatile("rdfsbase %0" : "=r" (value));
	return value;
}
__bpf_kfunc u64 bpf_ebpfos_kop_rdfsbase32(void)
{
	return 0; /* Only the checked proof or bound instruction executes. */
}
__bpf_kfunc u64 bpf_ebpfos_x86_rdfsbase64(void)
{
	u64 value;
	asm volatile("rdfsbase %0" : "=r" (value));
	return value;
}
__bpf_kfunc u64 bpf_ebpfos_kop_rdfsbase64(void)
{
	return 0; /* Only the checked proof or bound instruction executes. */
}
#endif
#endif
