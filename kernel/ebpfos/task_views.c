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
#include <linux/pid.h>
#include <linux/resume_user_mode.h>
#include <linux/bitmap.h>
#include <asm/syscall.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include "function_views.h"
#include "function_contract.h"
#include "function_native_context.h"
#include "syscall_kfuncs.h"
#include <linux/workqueue.h>
#include "function_lifetime.h"

struct task_view {
 u64 generation;
 u32 count;
 bool revocable;
 struct delayed_work release_work;
 sys_call_ptr_t table[NR_syscalls];
 struct ebpfos_function_binding bindings[];
};

/* One cold request per task. NULL next means the original native table.
 * The task owns the incoming file reference until publication or cancellation.
 * Active and pending references are protected by task_lock; only current
 * publishes a table, after every old syscall/unit frame has unwound. */
struct ebpfos_task_view_request { struct file *next; };
static void task_view_request_free(struct ebpfos_task_view_request *request)
{
 if (!request) return;
 if (request->next) fput(request->next);
 kfree(request);
}

/* This runs ONLY at return to user mode, never at a general task_work_run()
 * site inside a syscall. The entire syscall graph, including inline copies
 * and nested/sleeping callees, has returned before this boundary. No test or
 * trampoline is added to ordinary selected calls. */
void ebpfos_task_view_resume(void)
{
 struct ebpfos_task_view_request *request;
 struct file *old = NULL;
 task_lock(current);
 request = current->ebpfos_task_view_request;
 if (request) {
  current->ebpfos_task_view_request = NULL;
  old = current->ebpfos_task_view;
  current->ebpfos_task_view = request->next;
  current->ebpfos_syscalls = request->next ?
   ((struct task_view *)request->next->private_data)->table : sys_call_table;
  request->next = NULL;
 }
 task_unlock(current);
 if (old) fput(old);
 kfree(request);
}

static void task_view_free(struct task_view *view)
{
 u32 i;
 for (i = 0; i < view->count; ++i)
  ebpfos_function_binding_put(&view->bindings[i]);
 kvfree(view);
}
static bool task_view_code_contains(void *opaque, unsigned long ip)
{
 struct task_view *view = opaque;
 u32 i;
 for (i = 0; i < view->count; ++i)
  if (ebpfos_program_contains(view->bindings[i].program, ip) ||
      (view->bindings[i].module &&
       within_module_mem_type(ip, view->bindings[i].module, MOD_TEXT))) return true;
 return false;
}
static void task_view_release_work(struct work_struct *work)
{
 struct task_view *view = container_of(to_delayed_work(work), struct task_view, release_work);
 if (!ebpfos_code_quiescent(task_view_code_contains, view)) task_view_free(view);
 else schedule_delayed_work(&view->release_work, HZ / 10);
}
static int task_view_release(struct inode *inode, struct file *file)
{
 struct task_view *view = file->private_data;
 u32 i;
 bool retire = view->revocable;
 /* Revocation may have removed the last file lease inside its own body.
  * Keep the graph through grace periods and every outstanding old frame. */
 for (i = 0; i < view->count; ++i)
  retire |= view->bindings[i].module != NULL;
 if (retire) schedule_delayed_work(&view->release_work, 0);
 else task_view_free(view);
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
 /* A request names one task, not future children. A fork within its old
  * syscall inherits the old complete view and its independent code lease. */
 task->ebpfos_task_view_request = NULL;
 if (task->ebpfos_task_view) get_file(task->ebpfos_task_view);
 if (task->ebpfos_object_view) get_file(task->ebpfos_object_view);
}
void ebpfos_task_view_free(struct task_struct *task)
{
 task_view_request_free(task->ebpfos_task_view_request);
 if (task->ebpfos_task_view) fput(task->ebpfos_task_view);
 if (task->ebpfos_object_view) fput(task->ebpfos_object_view);
}

/* Bind only actual syscall exports, never a caller-provided address or ordinal.
 * The source descriptor and loaded export supply the complete checked ABI.
 * A native bpf control entry guarantees self-selection has no old-view frame
 * beneath it. Each other task retains its own lease through sleeping calls. */
static int task_view_slot(struct btf *native, u32 id, unsigned long *used)
{
 const struct btf_type *function = btf_type_by_id(native, id);
 unsigned long address;
 u32 nr, j;
 if (!function || !btf_type_is_func(function)) return -EINVAL;
 address = kallsyms_lookup_name(btf_name_by_offset(native, function->name_off));
 if (!address) return -ENOENT;
 for (nr = 0; nr < NR_syscalls; ++nr)
  if ((unsigned long)sys_call_table[nr] == address) break;
 if (nr == NR_syscalls) return -ENOENT;
 if (nr == __NR_bpf) return -EBUSY;
 for (j = nr + 1; j < NR_syscalls; ++j)
  if ((unsigned long)sys_call_table[j] == address) return -ENOTUNIQ;
 if (test_and_set_bit(nr, used)) return -ENOTUNIQ;
 return nr;
}
static int task_view_open(const struct ebpfos_function_view_source *sources,
 u32 count, u64 generation, bool revocable)
{
 struct btf *native = bpf_get_btf_vmlinux();
 struct task_view *view;
 DECLARE_BITMAP(used, NR_syscalls);
 u32 i, nr;
 int error = -EINVAL;
 if (revocable && (!IS_ENABLED(CONFIG_HAVE_RELIABLE_STACKTRACE) ||
     !IS_ENABLED(CONFIG_TASKS_RCU))) return -EOPNOTSUPP;
 if (IS_ERR_OR_NULL(native) || !count || count > NR_syscalls) return -EINVAL;
 if (!IS_ENABLED(CONFIG_X86_64) || IS_ENABLED(CONFIG_CFI)) return -EOPNOTSUPP;
 view = kvzalloc(struct_size(view, bindings, count), GFP_KERNEL);
 if (!view) return -ENOMEM;
 view->count = count;view->generation = generation;view->revocable = revocable;
 INIT_DELAYED_WORK(&view->release_work, task_view_release_work);
 memcpy(view->table, sys_call_table, sizeof(view->table));
 bitmap_zero(used, NR_syscalls);
 for (i = 0; i < count; ++i) {
  const struct btf_type *function = btf_type_by_id(native, sources[i].native_function);
  struct bpf_prog *program;
  unsigned long target;
  int slot = task_view_slot(native, sources[i].native_function, used);
  if (slot < 0) {error = slot;goto fail;}
  nr = slot;
  /* A syscall entered from userspace is a sleepable task context. A graph
   * verified there need not pretend to be a non-sleepable tracing hook.
   * Keep the actual program domain; native callable/context checks below
   * still cover the export and every reachable callee and callback. */
  program = bpf_prog_get_type_dev(sources[i].program, BPF_PROG_TYPE_SYSCALL, false);
  if (IS_ERR(program) && PTR_ERR(program) == -EINVAL)
   program = bpf_prog_get_type_dev(sources[i].program, BPF_PROG_TYPE_TRACING, false);
  if (IS_ERR(program)) {error = PTR_ERR(program);goto fail;}
  view->bindings[i].program = program;
  /* Escaped callback addresses need a separate owner lease. Do not promise
   * fault revocation for a graph whose lifetime a stack scan cannot close. */
  if (revocable && ebpfos_program_addresses(program)) {error = -EOPNOTSUPP;goto fail;}
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

/* Import RT's already checked native/verified exports, retaining their code
 * directly rather than a parent view. Native bodies have ordinary module
 * trust and callback ownership. They switch/roll back at the same user-return
 * boundary; automatic in-body fault revocation requires a verified graph. */
static int task_view_import(u32 descriptor, u64 generation)
{
 struct btf *native = bpf_get_btf_vmlinux();
 const struct ebpfos_function_view *source;
 struct task_view *view;
 struct file *file;
 DECLARE_BITMAP(used, NR_syscalls);
 u32 i;
 int error;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (IS_ERR_OR_NULL(native)) return -EINVAL;
 if (!IS_ENABLED(CONFIG_X86_64) || IS_ENABLED(CONFIG_CFI) ||
     !IS_ENABLED(CONFIG_HAVE_RELIABLE_STACKTRACE) || !IS_ENABLED(CONFIG_TASKS_RCU))
  return -EOPNOTSUPP;
 file = ebpfos_function_view_get(descriptor);
 if (IS_ERR(file)) return PTR_ERR(file);
 source = ebpfos_function_view_data(file);
 if (!source->count || source->count > NR_syscalls) {error = -EINVAL;goto put_file;}
 view = kvzalloc(struct_size(view, bindings, source->count), GFP_KERNEL);
 if (!view) {error = -ENOMEM;goto put_file;}
 view->count = source->count;view->generation = generation;view->revocable = true;
 INIT_DELAYED_WORK(&view->release_work, task_view_release_work);
 memcpy(view->table, sys_call_table, sizeof(view->table));
 bitmap_zero(used, NR_syscalls);
 for (i = 0; i < source->count; ++i) {
  const struct ebpfos_function_binding *binding = &source->members[i].binding;
  int slot = task_view_slot(native, source->members[i].native_function, used);
  if (slot < 0) {error = slot;goto fail;}
  if (binding->program) {
   if (ebpfos_program_addresses(binding->program) ||
       !entry_context(binding->program, binding->address)) {error = -EOPNOTSUPP;goto fail;}
   bpf_prog_inc(binding->program);
  } else view->revocable = false;
  if (binding->module) __module_get(binding->module);
  view->bindings[i] = *binding;
  view->table[slot] = (sys_call_ptr_t)binding->address;
 }
 error = anon_inode_getfd("ebpfos-task-view", &task_view_ops, view, O_CLOEXEC | O_RDONLY);
 if (error >= 0) goto put_file;
fail:
 task_view_free(view);
put_file:
 fput(file);return error;
}

__bpf_kfunc_start_defs();
static int task_view_open_snapshot(
 const struct ebpfos_function_view_source *sources, u32 sources__sz, u64 generation, bool revocable)
{
 struct ebpfos_function_view_source *snapshot;
 int result;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (!sources__sz || sources__sz % sizeof(*sources) ||
     sources__sz / sizeof(*sources) > NR_syscalls) return -EINVAL;
 snapshot = kmemdup(sources, sources__sz, GFP_KERNEL);
 if (!snapshot) return -ENOMEM;
 result = task_view_open(snapshot, sources__sz / sizeof(*sources), generation, revocable);
 kfree(snapshot);return result;
}
__bpf_kfunc int bpf_ebpfos_task_view_open(
 const struct ebpfos_function_view_source *sources, u32 sources__sz, u64 generation)
{return task_view_open_snapshot(sources, sources__sz, generation, false);}
__bpf_kfunc int bpf_ebpfos_task_view_open_revocable(
 const struct ebpfos_function_view_source *sources, u32 sources__sz, u64 generation)
{return task_view_open_snapshot(sources, sources__sz, generation, true);}
__bpf_kfunc int bpf_ebpfos_task_view_import(u32 descriptor, u64 generation)
{return task_view_import(descriptor, generation);}
/* Only the calling task loses its binding. This is a failure-path operation,
 * not a runner or a check on successful calls. Retirement owns the old graph
 * until every frame is clear, including the frame making this request. */
__bpf_kfunc int bpf_ebpfos_task_view_revoke(void)
{
 struct ebpfos_task_view_request *request;
 struct file *old;
 task_lock(current);
 old = current->ebpfos_task_view;
 if (!old || !((struct task_view *)old->private_data)->revocable) {
  task_unlock(current);
  return old ? -EOPNOTSUPP : -ENOENT;
 }
 /* A fault takes precedence over an earlier requested update. */
 request = current->ebpfos_task_view_request;
 current->ebpfos_task_view_request = NULL;
 current->ebpfos_syscalls = sys_call_table;
 current->ebpfos_task_view = NULL;
 task_unlock(current);
 task_view_request_free(request);
 fput(old);
 return 0;
}
__bpf_kfunc int bpf_ebpfos_task_view_select(int descriptor)
{
 struct file *old, *next = NULL;
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
 task_lock(current);
 if (current->ebpfos_task_view_request) {
  task_unlock(current);
  if (next) fput(next);
  return -EBUSY;
 }
 old = current->ebpfos_task_view;
 /* Only current can change these fields. Entry observes them on the next
  * syscall; fork takes its lease after copying current's complete task. */
 current->ebpfos_task_view = next;
 current->ebpfos_syscalls = table;
 task_unlock(current);
 if (old) fput(old);
 return 0;
}

static struct file *task_view_get(int descriptor)
{
 struct file *file;
 if (descriptor == -1) return NULL;
 file = fget(descriptor);
 if (!file) return ERR_PTR(-EBADF);
 if (file->f_op == &task_view_ops) return file;
 fput(file);return ERR_PTR(-EINVAL);
}
/* Compare the actual old file identity, not a caller-chosen generation.
 * pidfds prevent task-ID reuse; both descriptors belong to the requester.
 * All failures leave the task's complete active and pending views unchanged. */
__bpf_kfunc int bpf_ebpfos_task_view_request(int pidfd, int expected, int next)
{
 struct ebpfos_task_view_request *request;
 struct task_struct *task;
 struct file *old, *incoming;
 unsigned int flags;
 int error = 0;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 old = task_view_get(expected);
 if (IS_ERR(old)) return PTR_ERR(old);
 incoming = task_view_get(next);
 if (IS_ERR(incoming)) {error = PTR_ERR(incoming);goto put_old;}
 request = kzalloc(sizeof(*request), GFP_KERNEL);
 if (!request) {error = -ENOMEM;goto put_incoming;}
 request->next = incoming;
 task = pidfd_get_task(pidfd, &flags);
 if (IS_ERR(task)) {error = PTR_ERR(task);goto free_request;}
 task_lock(task);
 if (task->flags & (PF_KTHREAD | PF_EXITING)) error = -ESRCH;
 else if (task->ebpfos_task_view != old) error = -ESTALE;
 else if (task->ebpfos_task_view_request) error = -EBUSY;
 else {task->ebpfos_task_view_request = request;request = NULL;}
 task_unlock(task);
 /* No wakeup of a sleeping old unit. A running userspace task is kicked
  * into the same return boundary; blocked tasks finish their old call. */
 if (!error) set_notify_resume(task);
 put_task_struct(task);
free_request:
 task_view_request_free(request);
 goto put_old;
put_incoming:
 if (incoming) fput(incoming);
put_old:
 if (old) fput(old);
 return error;
}
/* Return 1 while a request is pending, 0 after publication/cancellation.
 * Cancel never rolls back an already published view; queue its predecessor
 * with request() for an ordinary boundary-safe rollback. */
static int task_view_pending(int pidfd, bool cancel)
{
 struct ebpfos_task_view_request *request;
 struct task_struct *task;
 unsigned int flags;
 int result;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 task = pidfd_get_task(pidfd, &flags);
 if (IS_ERR(task)) return PTR_ERR(task);
 task_lock(task);
 request = task->ebpfos_task_view_request;
 result = request ? 1 : 0;
 if (cancel) task->ebpfos_task_view_request = NULL;
 task_unlock(task);
 if (cancel) task_view_request_free(request);
 put_task_struct(task);
 return result;
}
__bpf_kfunc int bpf_ebpfos_task_view_pending(int pidfd)
{return task_view_pending(pidfd, false);}
__bpf_kfunc int bpf_ebpfos_task_view_cancel(int pidfd)
{return task_view_pending(pidfd, true);}
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(task_view_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_task_view_open, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_task_view_open_revocable, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_task_view_import, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_task_view_revoke, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_task_view_select, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_task_view_request, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_task_view_pending, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_task_view_cancel, KF_SLEEPABLE)
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
