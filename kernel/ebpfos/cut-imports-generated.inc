/* Generated from exact-image cut bindings and BTF. */
BTF_KFUNCS_START(ebpfos_cut_scalar_ids)
BTF_ID_FLAGS(func, arch_mmap_rnd, KF_SLEEPABLE)
BTF_ID_FLAGS(func, can_do_mlock, KF_SLEEPABLE)
BTF_ID_FLAGS(func, exec_task_namespaces, KF_SLEEPABLE)
BTF_ID_FLAGS(func, futex_hash_allocate_default, KF_SLEEPABLE)
BTF_ID_FLAGS(func, get_next_ino, KF_SLEEPABLE)
BTF_ID_FLAGS(func, get_random_u16, KF_SLEEPABLE)
BTF_ID_FLAGS(func, get_random_u32, KF_SLEEPABLE)
BTF_ID_FLAGS(func, get_random_u64, KF_SLEEPABLE)
BTF_ID_FLAGS(func, irq_fpu_usable, KF_SLEEPABLE)
BTF_ID_FLAGS(func, is_current_pgrp_orphaned, KF_SLEEPABLE)
BTF_ID_FLAGS(func, ktime_get, KF_SLEEPABLE)
BTF_ID_FLAGS(func, pipe_is_unprivileged_user, KF_SLEEPABLE)
BTF_ID_FLAGS(func, rcu_is_cpu_rrupt_from_idle, KF_SLEEPABLE)
BTF_ID_FLAGS(func, sched_clock, KF_SLEEPABLE)
BTF_ID_FLAGS(func, timekeeping_valid_for_hres, KF_SLEEPABLE)
BTF_ID_FLAGS(func, unshare_files, KF_SLEEPABLE)
BTF_ID_FLAGS(func, uprobe_deny_signal, KF_SLEEPABLE)
BTF_KFUNCS_END(ebpfos_cut_scalar_ids)

static int ebpfos_cut_scalar_filter(const struct bpf_prog *prog, u32 id)
{
	if (!btf_id_set8_contains(&ebpfos_cut_scalar_ids, id))
		return 0;
	return !prog || !prog->aux ||
	       !prog->aux->ebpfos_component ||
	       prog->type != BPF_PROG_TYPE_SYSCALL || !prog->sleepable;
}
static const struct btf_kfunc_id_set ebpfos_cut_scalar_set = {
	.owner = THIS_MODULE,
	.set = &ebpfos_cut_scalar_ids,
	.filter = ebpfos_cut_scalar_filter,
};
static int __init ebpfos_cut_scalar_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					 &ebpfos_cut_scalar_set);
}
late_initcall(ebpfos_cut_scalar_init);
