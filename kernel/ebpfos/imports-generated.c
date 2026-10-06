/* Generated from kernel BTF and Clang cleanup AST. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>

__bpf_kfunc_start_defs();
extern struct file * fget(unsigned int arg0);
extern void fput(struct file *arg0);
__bpf_kfunc struct file * bpf_ebpfos_import_fget(unsigned int arg0)
{
	return fget(arg0);
}
__bpf_kfunc void bpf_ebpfos_import_fput(struct file *arg0)
{
	fput(arg0);
}

#ifdef EBPFOS_CONTEXT_DEFS_INCLUDE
#include EBPFOS_CONTEXT_DEFS_INCLUDE
#endif

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(ebpfos_import_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_import_fget, KF_ACQUIRE | KF_RET_NULL | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_import_fput, KF_RELEASE | KF_SLEEPABLE)
#ifdef EBPFOS_CUT_IMPORTS_INCLUDE
#include EBPFOS_CUT_IMPORTS_INCLUDE
#else
#include "cut-imports-generated.inc"
#endif
BTF_KFUNCS_END(ebpfos_import_ids)

#ifdef EBPFOS_CUT_TRACING_IMPORTS_INCLUDE
BTF_KFUNCS_START(ebpfos_tracing_import_ids)
#include EBPFOS_CUT_TRACING_IMPORTS_INCLUDE
#ifdef EBPFOS_CONTEXT_IDS_INCLUDE
#include EBPFOS_CONTEXT_IDS_INCLUDE
#endif
BTF_KFUNCS_END(ebpfos_tracing_import_ids)
#endif

static int ebpfos_import_filter(const struct bpf_prog *prog, u32 id)
{
	if (!btf_id_set8_contains(&ebpfos_import_ids, id))
		return 0;
	return !prog || !prog->aux ||
	       !prog->aux->ebpfos_component ||
	       prog->type != BPF_PROG_TYPE_SYSCALL || !prog->sleepable;
}
static const struct btf_kfunc_id_set ebpfos_import_set = {
	.owner = THIS_MODULE,
	.set = &ebpfos_import_ids,
	.filter = ebpfos_import_filter,
};
#ifdef EBPFOS_CUT_TRACING_IMPORTS_INCLUDE
static int ebpfos_tracing_import_filter(const struct bpf_prog *prog, u32 id)
{
	if (!btf_id_set8_contains(&ebpfos_tracing_import_ids, id))
		return 0;
	return !prog || !prog->aux || !prog->aux->ebpfos_component ||
	       prog->type != BPF_PROG_TYPE_TRACING || prog->sleepable;
}
static const struct btf_kfunc_id_set ebpfos_tracing_import_set = {
	.owner = THIS_MODULE,
	.set = &ebpfos_tracing_import_ids,
	.filter = ebpfos_tracing_import_filter,
};
#endif
static int __init ebpfos_import_init(void)
{
	int err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					  &ebpfos_import_set);
#ifdef EBPFOS_CUT_TRACING_IMPORTS_INCLUDE
	/* The common hook has its own bounded ID set. The filter below
	 * still grants these imports only to non-sleepable tracing
	 * components; it also avoids consuming the tracing hook's slots
	 * needed by the component operation services.
	 */
	if (!err)
		err = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,
						&ebpfos_tracing_import_set);
#endif
	return err;
}
late_initcall(ebpfos_import_init);
