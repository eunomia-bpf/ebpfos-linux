// SPDX-License-Identifier: GPL-2.0-only
/* Task-owned syscall bindings. Publication and graph leases are cold; a
 * syscall enters its resolved body directly. No program runner is involved. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/filter.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/ebpfos_task_view.h>
#include <asm/syscall.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include "function_views.h"
#include "function_contract.h"
#include "function_native_context.h"
#include "syscall_kfuncs.h"

struct task_view {
 u64 generation;
 u32 count;
 sys_call_ptr_t table[NR_syscalls];
 struct ebpfos_function_binding bindings[];
};

static int task_view_release(struct inode *inode, struct file *file)
{
 struct task_view *view = file->private_data;
 u32 i;
 for (i = 0; i < view->count; ++i)
  ebpfos_function_binding_put(&view->bindings[i]);
 kvfree(view);
 return 0;
}
static void task_view_fdinfo(struct seq_file *out, struct file *file)
{
 struct task_view *view = file->private_data;
 u32 nr;
 seq_printf(out, "generation:\t%llu\nfunctions:\t%u\n", view->generation, view->count);
 for (nr = 0; nr < NR_syscalls; ++nr)
  if (view->table[nr] != sys_call_table[nr])
   seq_printf(out, "syscall:\t%u\t%px\n", nr, view->table[nr]);
}
static const struct file_operations task_view_ops = {
 .owner = THIS_MODULE, .release = task_view_release,
 .show_fdinfo = task_view_fdinfo, .llseek = noop_llseek,
};

void ebpfos_task_view_fork(struct task_struct *task)
{
 if (task->ebpfos_task_view) get_file(task->ebpfos_task_view);
}
void ebpfos_task_view_free(struct task_struct *task)
{
 if (task->ebpfos_task_view) fput(task->ebpfos_task_view);
}

/* Bind only actual syscall exports, never a caller-provided address or ordinal.
 * The source descriptor and loaded export supply the complete checked ABI.
 * A native bpf control entry guarantees self-selection has no old-view frame
 * beneath it. Each other task retains its own lease through sleeping calls. */
static int task_view_open(const struct ebpfos_function_view_source *sources,
 u32 count, u64 generation)
{
 struct btf *native = bpf_get_btf_vmlinux();
 struct task_view *view;
 u32 i, j, nr;
 int error = -EINVAL;
 if (IS_ERR_OR_NULL(native) || !count || count > NR_syscalls) return -EINVAL;
 if (!IS_ENABLED(CONFIG_X86_64) || IS_ENABLED(CONFIG_CFI)) return -EOPNOTSUPP;
 view = kvzalloc(struct_size(view, bindings, count), GFP_KERNEL);
 if (!view) return -ENOMEM;
 view->count = count;view->generation = generation;
 memcpy(view->table, sys_call_table, sizeof(view->table));
 for (i = 0; i < count; ++i) {
  const struct btf_type *function = btf_type_by_id(native, sources[i].native_function);
  struct bpf_prog *program;
  unsigned long address, target;
  if (!function || !btf_type_is_func(function)) goto fail;
  address = kallsyms_lookup_name(btf_name_by_offset(native, function->name_off));
  if (!address) {error = -ENOENT;goto fail;}
  for (nr = 0; nr < NR_syscalls; ++nr)
   if ((unsigned long)sys_call_table[nr] == address) break;
  if (nr == NR_syscalls) {error = -ENOENT;goto fail;}
  if (nr == __NR_bpf) {error = -EBUSY;goto fail;}
  if (view->table[nr] != sys_call_table[nr]) {error = -ENOTUNIQ;goto fail;}
  /* An aliased syscall is ambiguous unless all aliases agree. */
  for (j = nr + 1; j < NR_syscalls; ++j)
   if ((unsigned long)sys_call_table[j] == address) {error = -ENOTUNIQ;goto fail;}
  /* A syscall entered from userspace is a sleepable task context. A graph
   * verified there need not pretend to be a non-sleepable tracing hook.
   * Keep the actual program domain; native callable/context checks below
   * still cover the export and every reachable callee and callback. */
  program = bpf_prog_get_type_dev(sources[i].program, BPF_PROG_TYPE_SYSCALL, false);
  if (IS_ERR(program) && PTR_ERR(program) == -EINVAL)
   program = bpf_prog_get_type_dev(sources[i].program, BPF_PROG_TYPE_TRACING, false);
  if (IS_ERR(program)) {error = PTR_ERR(program);goto fail;}
  view->bindings[i].program = program;
  if (!program->aux->ebpfos_component ||
      (program->type == BPF_PROG_TYPE_SYSCALL ?
       (!program->sleepable || program->expected_attach_type != 0) :
       (program->sleepable || program->expected_attach_type != BPF_TRACE_REPLACE))) {
   error = -EOPNOTSUPP;goto fail;
  }
  if (!cell_callable(native, function, program, sources[i].compiled_function, &target)) {
   error = -EPROTOTYPE;goto fail;
  }
  if (!entry_context(program, target)) {error = -EOPNOTSUPP;goto fail;}
  view->bindings[i].address = target;
  view->table[nr] = (sys_call_ptr_t)target;
 }
 error = anon_inode_getfd("ebpfos-task-view", &task_view_ops, view, O_CLOEXEC | O_RDONLY);
 if (error >= 0) return error;
fail:
 for (i = 0; i < count; ++i) ebpfos_function_binding_put(&view->bindings[i]);
 kvfree(view);return error;
}

__bpf_kfunc_start_defs();
__bpf_kfunc int bpf_ebpfos_task_view_open(
 const struct ebpfos_function_view_source *sources, u32 sources__sz, u64 generation)
{
 struct ebpfos_function_view_source *snapshot;
 int result;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (!sources__sz || sources__sz % sizeof(*sources) ||
     sources__sz / sizeof(*sources) > NR_syscalls) return -EINVAL;
 snapshot = kmemdup(sources, sources__sz, GFP_KERNEL);
 if (!snapshot) return -ENOMEM;
 result = task_view_open(snapshot, sources__sz / sizeof(*sources), generation);
 kfree(snapshot);return result;
}
__bpf_kfunc int bpf_ebpfos_task_view_select(int descriptor)
{
 struct file *old = current->ebpfos_task_view, *next = NULL;
 const sys_call_ptr_t *table = sys_call_table;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 /* The native bpf user entry is outside every selected syscall frame.
  * Merely having a native bpf slot would not exclude a nested invocation
  * from another, still-live selected syscall. Do not drop its graph lease. */
 if (syscall_get_nr(current, task_pt_regs(current)) != __NR_bpf ||
     current->ebpfos_syscalls[__NR_bpf] != sys_call_table[__NR_bpf]) return -EBUSY;
 if (descriptor != -1) {
  next = fget(descriptor);
  if (!next) return -EBADF;
  if (next->f_op != &task_view_ops) {fput(next);return -EINVAL;}
  table = ((struct task_view *)next->private_data)->table;
 }
 /* Only current can change these fields. Entry observes them on the next
  * syscall; fork takes its lease after copying current's complete task. */
 current->ebpfos_task_view = next;
 current->ebpfos_syscalls = table;
 if (old) fput(old);
 return 0;
}
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(task_view_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_task_view_open, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_task_view_select, KF_SLEEPABLE)
BTF_KFUNCS_END(task_view_ids)
static const struct btf_kfunc_id_set task_view_kfuncs;
static int task_view_filter(const struct bpf_prog *prog, u32 id)
{
 const struct btf_kfunc_id_set *sets[] = { &task_view_kfuncs };
 return ebpfos_syscall_kfunc_filter(prog, id, sets, ARRAY_SIZE(sets));
}
static const struct btf_kfunc_id_set task_view_kfuncs = {
 .owner = THIS_MODULE, .set = &task_view_ids, .filter = task_view_filter,
};
static int __init task_view_init(void)
{return register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &task_view_kfuncs);}
late_initcall(task_view_init);
