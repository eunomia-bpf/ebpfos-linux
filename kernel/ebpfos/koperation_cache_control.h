/* SPDX-License-Identifier: GPL-2.0-only */
/* Architectural cache instructions; the source compiler owns their ordering. */
#ifdef CONFIG_X86
__bpf_kfunc u64 bpf_ebpfos_x86_wbinvd(void)
{
	asm volatile("wbinvd" : : : "memory");
	return 0;
}
__bpf_kfunc u64 bpf_ebpfos_kop_wbinvd(void)
{
	return 0; /* Only the checked proof or bound instruction executes. */
}
__bpf_kfunc u64 bpf_ebpfos_x86_wbnoinvd(void)
{
	if (!boot_cpu_has(X86_FEATURE_WBNOINVD))
		return -EOPNOTSUPP;
	asm volatile("wbnoinvd" : : : "memory");
	return 0;
}
__bpf_kfunc u64 bpf_ebpfos_kop_wbnoinvd(void)
{
	return 0; /* Only the checked proof or bound instruction executes. */
}
#endif
