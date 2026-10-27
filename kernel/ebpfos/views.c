// SPDX-License-Identifier: GPL-2.0-only
/* One owner for process-view files, independent of the producer/consumer's
 * compilation unit. All type checks and file/program ownership stay cold.
 */
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/filter.h>
#include <linux/btf.h>
#include <linux/capability.h>
#include <linux/seq_file.h>
#include <linux/ebpfos_operations.h>
#include "function_contract.h"
#include "function_views.h"
#include "syscall_kfuncs.h"
#include "function_native.h"
static void prepared_tables_free(struct ebpfos_function_view *view);
static int ebpfos_function_view_release(struct inode *inode, struct file *file)
{
 struct ebpfos_function_view *view = file->private_data;
 u32 i;
 prepared_tables_free(view);
 for (i = 0; i < view->count; ++i)
  ebpfos_function_binding_put(&view->members[i].binding);
 kvfree(view);
 return 0;
}
static void ebpfos_function_view_fdinfo(struct seq_file *output, struct file *file)
{
 const struct ebpfos_function_view *view = file->private_data;
 u32 i;
 seq_printf(output, "generation:\t%llu\nfunctions:\t%u\n", view->generation, view->count);
 for (i = 0; i < view->count; ++i) {
  const struct ebpfos_function_view_member *member = &view->members[i];
  seq_printf(output, "function:\t%u\t%u\n", member->native_function,
   member->binding.program ? member->binding.program->aux->id : 0);
 }
}
static const struct file_operations ebpfos_function_view_operations = {
 .owner = THIS_MODULE,
 .release = ebpfos_function_view_release,
 .llseek = noop_llseek,
 .show_fdinfo = ebpfos_function_view_fdinfo,
};
/* The kernel owner supplies already prepared bindings. Ownership transfers
 * only on success; an unpublished failure remains the caller's to release.
 */
int ebpfos_function_view_publish(struct ebpfos_function_view *view)
{
 struct btf *native = bpf_get_btf_vmlinux();
 u32 i;
 if (IS_ERR_OR_NULL(native)) return -EOPNOTSUPP;
 for (i = 0; i < view->count; ++i) {
  struct ebpfos_function_view_member *member = &view->members[i];
  const struct btf_type *function = btf_type_by_id(native, member->native_function);
  if (!function || !btf_type_is_func(function)) return -EINVAL;
  /* A missing entry cannot match an object's operations. Keep this case
   * unchanged; constructors retain their existing callable checks. */
  member->native_address = kallsyms_lookup_name(btf_name_by_offset(native, function->name_off));
 }
 raw_spin_lock_init(&view->object_lock);
 INIT_LIST_HEAD(&view->object_files);
 INIT_LIST_HEAD(&view->object_tables);
 INIT_LIST_HEAD(&view->object_targets);
 return anon_inode_getfd("ebpfos-function-view", &ebpfos_function_view_operations,
                        view, O_CLOEXEC | O_RDONLY);
}
struct file *ebpfos_function_view_get(u32 descriptor)
{
 struct file *file = fget(descriptor);
 if (!file) return ERR_PTR(-EBADF);
 if (file->f_op != &ebpfos_function_view_operations) {
  fput(file);return ERR_PTR(-EINVAL);
 }
 return file;
}
/* The source array is a kernel-owned snapshot. Validate every member before
 * publishing any table; retain every loaded graph through the file lease.
 */
int ebpfos_function_view_open_pure(
 const struct ebpfos_function_view_source *sources, u32 count, u64 generation,
 enum bpf_prog_type type, struct btf *native)
{
 struct ebpfos_function_view *view;
 u32 i;
 int error;
 if (!count || !native) return -EINVAL;
 view = kvzalloc(struct_size(view, members, count), GFP_KERNEL);
 if (!view) return -ENOMEM;
 view->count = count;view->generation = generation;
 for (i = 0; i < count; ++i) {
  const struct btf_type *function = btf_type_by_id(native, sources[i].native_function);
  error = ebpfos_function_binding_open_pure(&view->members[i].binding,
    sources[i].program, type, native, function, sources[i].compiled_function);
  if (error) goto fail;
  view->members[i].native_function = sources[i].native_function;
 }
 error = ebpfos_function_view_publish(view);
 if (error >= 0) return error;
fail:
 for (i = 0; i < count; ++i)
  ebpfos_function_binding_put(&view->members[i].binding);
 kvfree(view);return error;
}

EXPORT_SYMBOL_GPL(ebpfos_function_view_publish);
EXPORT_SYMBOL_GPL(ebpfos_function_view_get);
EXPORT_SYMBOL_GPL(ebpfos_function_view_open_pure);

/* Copy immutable bindings, not parent-file links: a replaced graph need not
 * remain resident merely because a derived view still exists. Resolve every
 * import by native identity and publish only the complete result. No call
 * enters this path. The source views already own checked binding contracts.
 */
int ebpfos_function_view_compose(u32 base_descriptor,
 const struct ebpfos_function_view_import *imports, u32 count, u64 generation)
{
 struct file *base_file;
 const struct ebpfos_function_view *base;
 struct ebpfos_function_view *next;
 u32 i, j;
 int error;
 if (!count) return -EINVAL;
 base_file = ebpfos_function_view_get(base_descriptor);
 if (IS_ERR(base_file)) return PTR_ERR(base_file);
 base = ebpfos_function_view_data(base_file);
 next = kvzalloc(struct_size(next, members, base->count), GFP_KERNEL);
 if (!next) { fput(base_file);return -ENOMEM; }
 next->count = base->count;next->generation = generation;
 for (i = 0; i < base->count; ++i) {
  next->members[i] = base->members[i];
  if (next->members[i].binding.program)
   bpf_prog_inc(next->members[i].binding.program);
  if (next->members[i].binding.module)
   __module_get(next->members[i].binding.module);
 }
 for (i = 0; i < count; ++i) {
  const struct ebpfos_function_view_member *target, *source;
  struct file *source_file;
  struct ebpfos_function_view_member *destination;
  for (j = 0; j < i; ++j)
   if (imports[j].native_function == imports[i].native_function) {
    error = -ENOTUNIQ;goto fail;
   }
  target = ebpfos_function_view_find(next, imports[i].native_function);
  if (IS_ERR(target)) { error = PTR_ERR(target);goto fail; }
  source_file = ebpfos_function_view_get(imports[i].view);
  if (IS_ERR(source_file)) { error = PTR_ERR(source_file);goto fail; }
  source = ebpfos_function_view_find(ebpfos_function_view_data(source_file), imports[i].native_function);
  if (IS_ERR(source)) { error = PTR_ERR(source);fput(source_file);goto fail; }
  destination = &next->members[target - next->members];
  ebpfos_function_binding_put(&destination->binding);
  destination->binding = source->binding;
  if (destination->binding.program) bpf_prog_inc(destination->binding.program);
  if (destination->binding.module) __module_get(destination->binding.module);
  fput(source_file);
 }
 error = ebpfos_function_view_publish(next);
 if (error >= 0) { fput(base_file);return error; }
fail:
 for (i = 0; i < next->count; ++i)
  ebpfos_function_binding_put(&next->members[i].binding);
 kvfree(next);fput(base_file);return error;
}
EXPORT_SYMBOL_GPL(ebpfos_function_view_compose);

/* A verified runtime may prepare a view in the calling process. Snapshot the
 * complete request before acquiring graphs; the ordinary file descriptor is
 * the only published result. Invocation never enters this service.
 */
__bpf_kfunc_start_defs();
__bpf_kfunc int bpf_ebpfos_function_view_open_pure(
 const struct ebpfos_function_view_source *sources, u32 sources__sz,
 u64 generation, u32 program_type)
{
 struct ebpfos_function_view_source *snapshot;
 struct btf *native;
 int result;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (!sources__sz || sources__sz % sizeof(*sources)) return -EINVAL;
 native = bpf_get_btf_vmlinux();
 if (IS_ERR_OR_NULL(native)) return -EINVAL;
 snapshot = kmemdup(sources, sources__sz, GFP_KERNEL);
 if (!snapshot) return -ENOMEM;
 result = ebpfos_function_view_open_pure(snapshot, sources__sz / sizeof(*sources),
   generation, program_type, native);
 kfree(snapshot);return result;
}
__bpf_kfunc int bpf_ebpfos_function_view_compose(u32 base,
 const struct ebpfos_function_view_import *imports, u32 imports__sz, u64 generation)
{
 struct ebpfos_function_view_import *snapshot;
 int result;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (!imports__sz || imports__sz % sizeof(*imports)) return -EINVAL;
 snapshot = kmemdup(imports, imports__sz, GFP_KERNEL);
 if (!snapshot) return -ENOMEM;
 result = ebpfos_function_view_compose(base, snapshot, imports__sz / sizeof(*imports), generation);
 kfree(snapshot);return result;
}
__bpf_kfunc int bpf_ebpfos_function_view_open_native(
 const struct ebpfos_function_view_native_source *sources, u32 sources__sz, u64 generation)
{
 struct ebpfos_function_view_native_source *snapshot;
 int result;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (!sources__sz || sources__sz % sizeof(*sources)) return -EINVAL;
 snapshot = kmemdup(sources, sources__sz, GFP_KERNEL);
 if (!snapshot) return -ENOMEM;
 result = ebpfos_function_view_open_native(snapshot, sources__sz / sizeof(*sources), generation);
 kfree(snapshot);return result;
}
__bpf_kfunc int bpf_ebpfos_function_view_open_native_btf(
 const struct ebpfos_function_view_native_source *sources, u32 sources__sz,
 u64 generation, u32 descriptor)
{
 struct ebpfos_function_view_native_source *snapshot;
 int result;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (!sources__sz || sources__sz % sizeof(*sources)) return -EINVAL;
 snapshot = kmemdup(sources, sources__sz, GFP_KERNEL);
 if (!snapshot) return -ENOMEM;
 result = ebpfos_function_view_open_native_btf(snapshot,
   sources__sz / sizeof(*sources), generation, descriptor);
 kfree(snapshot);return result;
}
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(view_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_function_view_open_pure, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_view_open_native, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_view_open_native_btf, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_view_compose, KF_SLEEPABLE)
BTF_KFUNCS_END(view_ids)
static const struct btf_kfunc_id_set view_kfuncs;
static int view_filter(const struct bpf_prog *prog, u32 id)
{
 const struct btf_kfunc_id_set *sets[] = { &view_kfuncs };
 return ebpfos_syscall_kfunc_filter(prog, id, sets, ARRAY_SIZE(sets));
}
static const struct btf_kfunc_id_set view_kfuncs = {
 .owner = THIS_MODULE, .set = &view_ids, .filter = view_filter,
};
static int __init view_init(void)
{return register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &view_kfuncs);}
#ifndef MODULE
late_initcall(view_init);
#endif

/* Native construction is a trusted kernel API, never a raw userspace address.
 * Restrict it to permanent image text so an object lease cannot outlive code.
 * Loadable native modules require their own module reference before support. */
int ebpfos_function_view_open_native(
 const struct ebpfos_function_view_native_source *sources, u32 count, u64 generation)
{
 struct btf *native = bpf_get_btf_vmlinux();
 struct ebpfos_function_view *view;
 u32 i, j;
 int error = -EINVAL;
 if (!IS_ENABLED(CONFIG_X86_64) || IS_ENABLED(CONFIG_CFI)) return -EOPNOTSUPP;
 if (!count || IS_ERR_OR_NULL(native)) return -EINVAL;
 view = kvzalloc(struct_size(view, members, count), GFP_KERNEL);
 if (!view) return -ENOMEM;
 view->count = count;view->generation = generation;
 for (i = 0; i < count; ++i) {
  const struct btf_type *source = btf_type_by_id(native, sources[i].native_function);
  const struct btf_type *target = btf_type_by_id(native, sources[i].replacement);
  unsigned long address;
  for (j = 0; j < i; ++j)
   if (sources[j].native_function == sources[i].native_function) { error = -ENOTUNIQ;goto fail; }
  if (!source || !target || !btf_type_is_func(source) || !btf_type_is_func(target) ||
      source->type != target->type) { error = -EPROTOTYPE;goto fail; }
  address = kallsyms_lookup_name(btf_name_by_offset(native, target->name_off));
  if (!address || !core_kernel_text(address)) { error = -ENOENT;goto fail; }
  view->members[i].native_function = sources[i].native_function;
  view->members[i].binding.address = address;
 }
 error = ebpfos_function_view_publish(view);
 if (error >= 0) return error;
fail:
 kvfree(view);return error;
}
EXPORT_SYMBOL_GPL(ebpfos_function_view_open_native);

/* The caller supplies a loaded module's BTF fd, never a raw code address.
 * Each export retains its module until every task and object reference dies. */
int ebpfos_function_view_open_native_btf(
 const struct ebpfos_function_view_native_source *sources, u32 count, u64 generation,
 u32 descriptor)
{
 struct btf *native = bpf_get_btf_vmlinux(), *target_btf;
 struct ebpfos_function_view *view;
 struct module *module;
 u32 i, j;
 int error = -EINVAL;
 if (!IS_ENABLED(CONFIG_X86_64) || IS_ENABLED(CONFIG_CFI)) return -EOPNOTSUPP;
 if (!count || IS_ERR_OR_NULL(native)) return -EINVAL;
 target_btf = btf_get_by_fd(descriptor);
 if (IS_ERR(target_btf)) return PTR_ERR(target_btf);
 module = btf_try_get_module(target_btf);
 if (!module) {error = -ENOENT;goto put_btf;}
 view = kvzalloc(struct_size(view, members, count), GFP_KERNEL);
 if (!view) {error = -ENOMEM;goto put_module;}
 view->count = count;view->generation = generation;
 for (i = 0; i < count; ++i) {
  const struct btf_type *source = btf_type_by_id(native, sources[i].native_function);
  const struct btf_type *target = btf_type_by_id(target_btf, sources[i].replacement);
  unsigned long address;
  for (j = 0; j < i; ++j)
   if (sources[j].native_function == sources[i].native_function) {error = -ENOTUNIQ;goto fail;}
  if (sources[i].replacement < btf_nr_types(native) || !source || !target ||
      !btf_type_is_func(source) || !btf_type_is_func(target) ||
      !cell_layout(native, source->type, target_btf, target->type, 0, false)) {
   error = -EPROTOTYPE;goto fail;
  }
  address = ebpfos_module_function(module, btf_name_by_offset(target_btf, target->name_off));
  if (!address) {error = -ENOENT;goto fail;}
  __module_get(module);
  view->members[i].native_function = sources[i].native_function;
  view->members[i].binding.module = module;
  view->members[i].binding.address = address;
 }
 error = ebpfos_function_view_publish(view);
 if (error >= 0) goto put_module;
fail:
 for (i = 0; i < count; ++i) ebpfos_function_binding_put(&view->members[i].binding);
 kvfree(view);
put_module:
 module_put(module);
put_btf:
 btf_put(target_btf);
 return error;
}
EXPORT_SYMBOL_GPL(ebpfos_function_view_open_native_btf);

/* Task and file views have the same x86-64 configuration as before. */
#if defined(CONFIG_EBPFOS) && defined(CONFIG_X86_64)

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

/* Immutable requests can be shared by every task in a cgroup. The owner
 * and each pending task hold a reference; publication acquires a separate
 * file reference for the task's complete active syscall version. */
#include <linux/refcount.h>
struct ebpfos_task_view_request {
 refcount_t references;
 struct rcu_head rcu;
 struct file *next;
};
static void task_view_request_rcu(struct rcu_head *rcu)
{
 struct ebpfos_task_view_request *request = container_of(rcu, struct ebpfos_task_view_request, rcu);
 if (request->next) fput(request->next);
 kfree(request);
}
static void task_view_request_free(struct ebpfos_task_view_request *request)
{
 if (request && refcount_dec_and_test(&request->references))
  call_rcu(&request->rcu, task_view_request_rcu);
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
  current->ebpfos_task_view = request->next ? get_file(request->next) : NULL;
  current->ebpfos_syscalls = request->next ?
   ((struct task_view *)request->next->private_data)->table : sys_call_table;
 }
 task_unlock(current);
 if (old) fput(old);
 task_view_request_free(request);
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
#include <linux/cgroup.h>
#include <linux/bpf_entry_cgroup.h>
#if defined(CONFIG_EBPFOS_ENTRY_LINK) && defined(CONFIG_CGROUP_BPF)
struct ebpfos_cgroup_view {
 struct cgroup *group;
 struct ebpfos_task_view_request *request;
 bool attached;
};
/* A permanent owner reference makes restoration allocation-free. */
static struct ebpfos_task_view_request global_request = {
 .references = REFCOUNT_INIT(1),
};
void ebpfos_cgroup_request_put(struct ebpfos_task_view_request *request)
{ task_view_request_free(request); }
struct ebpfos_task_view_request *ebpfos_cgroup_prepare(
 const struct bpf_entry_target *sources, u32 count, u64 generation)
{
 struct ebpfos_task_view_request *request;
 struct btf *native = bpf_get_btf_vmlinux();
 struct task_view *view;
 struct file *file;
 DECLARE_BITMAP(used, NR_syscalls);
 unsigned int i, roots = 0;
 int error;
 if (!count || IS_ERR_OR_NULL(native)) return ERR_PTR(-EINVAL);
 if (!IS_ENABLED(CONFIG_HAVE_RELIABLE_STACKTRACE) || !IS_ENABLED(CONFIG_TASKS_RCU))
  return ERR_PTR(-EOPNOTSUPP);
 view = kvzalloc(struct_size(view, bindings, count), GFP_KERNEL);
 if (!view) return ERR_PTR(-ENOMEM);
 view->count = count;view->generation = generation;view->revocable = true;
 INIT_DELAYED_WORK(&view->release_work, task_view_release_work);
 memcpy(view->table, sys_call_table, sizeof(view->table));
 bitmap_zero(used, NR_syscalls);
 for (i = 0; i < count; ++i) {
  struct bpf_prog *program = sources[i].program;
  int slot = task_view_slot(native, sources[i].function, used);
  /* Private members retain code with their syscall roots. They acquire no
   * per-process direct-call dispatch of their own. */
  if (slot < 0 && slot != -ENOENT) {error = slot;goto fail;}
  if (ebpfos_program_addresses(program)) {error = -EOPNOTSUPP;goto fail;}
  bpf_prog_inc(program);
  view->bindings[i].program = program;
  view->bindings[i].address = sources[i].address;
  if (program->type == BPF_PROG_TYPE_NATIVE && program->aux->mod) {
   __module_get(program->aux->mod);
   view->bindings[i].module = program->aux->mod;
  }
  if (slot >= 0) {view->table[slot] = (sys_call_ptr_t)sources[i].address;++roots;}
 }
 if (!roots) {error = -EOPNOTSUPP;goto fail;}
 request = kzalloc(sizeof(*request), GFP_KERNEL);
 if (!request) {error = -ENOMEM;goto fail;}
 file = anon_inode_getfile("bpf-entry-cgroup-table", &task_view_ops, view, O_RDONLY);
 if (IS_ERR(file)) {error = PTR_ERR(file);kfree(request);goto fail;}
 refcount_set(&request->references, 1);
 request->next = file;
 return request;
fail:
 task_view_free(view);return ERR_PTR(error);
}
/* All owner publication, membership movement and fork selection serialize on
 * css_set_lock. Lookup and queueing therefore cannot install an older request
 * after an update has already queued a newer version for the same task. */
static struct ebpfos_task_view_request *cgroup_request_locked(struct task_struct *task)
{
 struct cgroup *group;
 struct ebpfos_cgroup_view *view;
 lockdep_assert_held(&css_set_lock);
 for (group = task_dfl_cgroup(task); group; group = cgroup_parent(group)) {
  view = group->bpf.entry_view;
  if (view) return view->request;
 }
 return &global_request;
}
void ebpfos_cgroup_task_move(struct task_struct *task)
{
 struct ebpfos_task_view_request *request, *old;
 lockdep_assert_held(&css_set_lock);
 if (task->flags & (PF_KTHREAD | PF_EXITING)) return;
 request = cgroup_request_locked(task);
 task_lock(task);
 if (!task->ebpfos_task_view_request && task->ebpfos_task_view == request->next) {
  task_unlock(task);return;
 }
 refcount_inc(&request->references);
 old = task->ebpfos_task_view_request;
 task->ebpfos_task_view_request = request;
 task_unlock(task);
 task_view_request_free(old);
 set_notify_resume(task);
}
void ebpfos_cgroup_exec(void)
{
 unsigned long flags;
 spin_lock_irqsave(&css_set_lock, flags);
 ebpfos_cgroup_task_move(current);
 spin_unlock_irqrestore(&css_set_lock, flags);
}
static void cgroup_refresh_locked(void)
{
 struct task_struct *leader, *task;
 lockdep_assert_held(&css_set_lock);
 rcu_read_lock();
 for_each_process_thread(leader, task) ebpfos_cgroup_task_move(task);
 rcu_read_unlock();
}
struct ebpfos_cgroup_view *ebpfos_cgroup_view_create(int fd,
 struct ebpfos_task_view_request *request)
{
 struct ebpfos_cgroup_view *view;
 struct cgroup *group = cgroup_get_from_fd(fd);
 if (IS_ERR(group)) return ERR_CAST(group);
 if (group->root != &cgrp_dfl_root) {cgroup_put(group);return ERR_PTR(-EOPNOTSUPP);}
 view = kzalloc(sizeof(*view), GFP_KERNEL);
 if (!view) {cgroup_put(group);return ERR_PTR(-ENOMEM);}
 view->group = group;view->request = request;
 return view;
}
int ebpfos_cgroup_view_attach(struct ebpfos_cgroup_view *view)
{
 unsigned long flags;
 int error = 0;
 cgroup_lock();
 if (cgroup_is_dead(view->group)) {error = -ENOENT;goto out;}
 spin_lock_irqsave(&css_set_lock, flags);
 if (view->group->bpf.entry_view) error = -EBUSY;
 else {
  view->group->bpf.entry_view = view;
  WRITE_ONCE(view->attached, true);
  cgroup_refresh_locked();
 }
 spin_unlock_irqrestore(&css_set_lock, flags);
out:
 cgroup_unlock();return error;
}
int ebpfos_cgroup_view_update(struct ebpfos_cgroup_view *view,
 struct ebpfos_task_view_request *next)
{
 struct ebpfos_task_view_request *old = NULL;
 unsigned long flags;
 int error = 0;
 cgroup_lock();
 spin_lock_irqsave(&css_set_lock, flags);
 if (!view->attached) error = -ENOLINK;
 else {
  old = view->request;view->request = next;
  cgroup_refresh_locked();
 }
 spin_unlock_irqrestore(&css_set_lock, flags);
 cgroup_unlock();
 task_view_request_free(old);
 return error;
}
void ebpfos_cgroup_view_detach(struct ebpfos_cgroup_view *view)
{
 unsigned long flags;
 cgroup_lock();
 spin_lock_irqsave(&css_set_lock, flags);
 if (view->attached) {
  view->group->bpf.entry_view = NULL;
  WRITE_ONCE(view->attached, false);
  cgroup_refresh_locked();
 }
 spin_unlock_irqrestore(&css_set_lock, flags);
 cgroup_unlock();
}
void ebpfos_cgroup_offline(struct cgroup *group)
{
 struct ebpfos_cgroup_view *view;
 unsigned long flags;
 /* The cgroup lifetime notifier already holds cgroup_mutex. */
 spin_lock_irqsave(&css_set_lock, flags);
 view = group->bpf.entry_view;
 if (view) {
  group->bpf.entry_view = NULL;
  WRITE_ONCE(view->attached, false);
  cgroup_refresh_locked();
 }
 spin_unlock_irqrestore(&css_set_lock, flags);
}
void ebpfos_cgroup_view_put(struct ebpfos_cgroup_view *view)
{
 if (!view) return;
 task_view_request_free(view->request);
 cgroup_put(view->group);kfree(view);
}
u64 ebpfos_cgroup_view_id(const struct ebpfos_cgroup_view *view)
{ return view ? cgroup_id(view->group) : 0; }
bool ebpfos_cgroup_view_active(const struct ebpfos_cgroup_view *view)
{ return view && READ_ONCE(view->attached); }
#endif

// SPDX-License-Identifier: GPL-2.0-only
/* Owners opt in where operations-table identity is not a type protocol and
 * the table stays fixed through release. Resolve once; ordinary file
 * references retain the selected code through asynchronous I/O. */
#include <linux/btf.h>
#include <linux/capability.h>
#include <linux/interrupt.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/sched.h>
#include <linux/ebpfos_file_view.h>
#include <linux/filter.h>
#include "function_views.h"
#include "syscall_kfuncs.h"

struct bound_file_operations {
 struct file_operations operations;
 const struct file_operations *original;
 struct file *view;
 refcount_t files;
 struct list_head entry;
 struct list_head view_entry;
};

/* Resolve once at open; callback dispatch uses the existing operations slots.
 * Count file objects, not descriptors: dup and asynchronous references delay
 * release of their existing file rather than opening another one. */
static DEFINE_MUTEX(bound_files_lock);
static LIST_HEAD(bound_files);

struct ebpfos_operations {
 struct file *view;
 struct module *original_owner;
 refcount_t references;
 bool prepared;
 const void *original;
 void *table;
 struct list_head entry;
 u32 count;
 u32 offsets[];
};

/* BTF describes the slots, not a list of method names. Inode, protocol and
 * scheduler tables use this same preparation and code ownership path. */
static struct ebpfos_operations *operations_prepare(struct file *lease,
 const void *original, u32 type_id, size_t size, struct module *original_owner)
{
 struct btf *native = bpf_get_btf_vmlinux();
 const struct btf_type *record;
 const struct btf_member *members;
 struct ebpfos_function_view *view;
 struct ebpfos_operations *bound;
 unsigned long flags;
 u32 i, j;
 int error = -EINVAL;

 if (!original || IS_ERR_OR_NULL(native)) goto put_view;
 record = btf_type_by_id(native, type_id);
 if (!record || !btf_type_is_struct(record) || size != record->size) {
  error = -EPROTOTYPE;goto put_view;
 }
 if (!try_module_get(original_owner)) {error = -ENOENT;goto put_view;}
 view = lease->private_data;
 bound = kzalloc(struct_size(bound, offsets, btf_type_vlen(record)), GFP_KERNEL);
 if (!bound) {error = -ENOMEM;goto put_owner;}
 bound->table = kmemdup(original, size, GFP_KERNEL);
 if (!bound->table) {error = -ENOMEM;goto free_bound;}
 bound->view = lease;
 bound->original_owner = original_owner;
 refcount_set(&bound->references, 1);
 bound->original = original;
 members = btf_members(record);
 for (i = 0; i < btf_type_vlen(record); ++i) {
  const struct btf_type *pointer, *prototype;
  unsigned long address;
  u32 offset = btf_member_bit_offset(record, i) / 8;
  const struct ebpfos_function_view_member *match = NULL;

  pointer = btf_type_skip_modifiers(native, members[i].type, NULL);
  if (!pointer || !btf_type_is_ptr(pointer)) continue;
  prototype = btf_type_skip_modifiers(native, pointer->type, NULL);
  if (!prototype || !btf_type_is_func_proto(prototype)) continue;
  if (btf_member_bitfield_size(record, i) ||
      btf_member_bit_offset(record, i) % 8 ||
      offset % sizeof(address) ||
      offset > size || sizeof(address) > size - offset) goto free_table;
  memcpy(&address, original + offset, sizeof(address));
  if (!address) continue;
  for (j = 0; j < view->count; ++j) {
   const struct ebpfos_function_view_member *member = &view->members[j];
   const struct btf_type *function;
   if (address != member->native_address) continue;
   if (match) {error = -ENOTUNIQ;goto free_table;}
   function = btf_type_by_id(native, member->native_function);
   if (!function || !btf_type_is_func(function) ||
       !cell_layout(native, function->type, native, pointer->type, 0, false)) {
    error = -EPROTOTYPE;goto free_table;
   }
   match = member;
  }
  if (!match) continue;
  memcpy(bound->table + offset, &match->binding.address, sizeof(address));
  bound->offsets[bound->count++] = offset;
 }
 if (!bound->count) {error = -ENOENT;goto free_table;}
 raw_spin_lock_irqsave(&view->object_lock, flags);
 if (view->object_revoked) {
  raw_spin_unlock_irqrestore(&view->object_lock, flags);
  error = -EOWNERDEAD;goto free_table;
 }
 list_add(&bound->entry, &view->object_tables);
 raw_spin_unlock_irqrestore(&view->object_lock, flags);
 return bound;
free_table:
 kfree(bound->table);
free_bound:
 kfree(bound);
put_owner:
 module_put(original_owner);
put_view:
 fput(lease);
 return ERR_PTR(error);
}
struct ebpfos_operations *ebpfos_operations_prepare(u32 descriptor,
 const void *original, u32 type_id, size_t size)
{
 struct file *lease = ebpfos_function_view_get(descriptor);
 if (IS_ERR(lease)) return ERR_CAST(lease);
 return operations_prepare(lease, original, type_id, size, NULL);
}
EXPORT_SYMBOL_GPL(ebpfos_operations_prepare);

/* A prepared table belongs to the view. Each published object owns a file
 * reference, not a reference from the view back to itself. */
static void prepared_table_free(struct ebpfos_operations *bound)
{
 struct ebpfos_function_view *view;
 unsigned long flags;
 if (!bound) return;
 view = bound->view->private_data;
 raw_spin_lock_irqsave(&view->object_lock, flags);
 list_del(&bound->entry);
 raw_spin_unlock_irqrestore(&view->object_lock, flags);
 module_put(bound->original_owner);
 kfree(bound->table);kfree(bound);
}
static void prepared_tables_free(struct ebpfos_function_view *view)
{
 struct ebpfos_operations_target *target, *next;
 list_for_each_entry_safe(target, next, &view->object_targets, entry) {
  prepared_table_free(target->operations);
  list_del(&target->entry);kfree(target);
 }
}

struct ebpfos_operations *ebpfos_operations_current(const void *original,
 u32 type_id, size_t size, struct module *original_owner)
{
 struct file *lease;
 struct ebpfos_function_view *view;
 struct ebpfos_operations_target *target;
 if (!in_task() || !current->mm || !current->ebpfos_object_view) return NULL;
 lease = current->ebpfos_object_view;
 view = lease->private_data;
 if (READ_ONCE(view->object_revoked)) return NULL;
 list_for_each_entry(target, &view->object_targets, entry) {
  if (target->address != (unsigned long)original || target->type != type_id) continue;
  return ebpfos_operations_get(target->operations);
 }
 return NULL;
}
EXPORT_SYMBOL_GPL(ebpfos_operations_current);

struct ebpfos_operations_owner {
 struct file *view;
 struct rcu_head rcu;
 u32 type;
 bool resolved;
};
struct ebpfos_operations_owner *ebpfos_operations_reserve(u32 type_id, gfp_t gfp)
{
 struct file *lease;
 struct ebpfos_function_view *view;
 struct ebpfos_operations_target *target;
 struct ebpfos_operations_owner *owner;
 if (!in_task() || !current->mm || !current->ebpfos_object_view) return NULL;
 lease = current->ebpfos_object_view;view = lease->private_data;
 if (READ_ONCE(view->object_revoked)) return NULL;
 list_for_each_entry(target, &view->object_targets, entry) {
  if (target->type != type_id) continue;
  owner = kzalloc(sizeof(*owner), gfp);
  if (!owner) return ERR_PTR(-ENOMEM);
  owner->view = get_file(lease);owner->type = type_id;
  return owner;
 }
 return NULL;
}
EXPORT_SYMBOL_GPL(ebpfos_operations_reserve);

const void *ebpfos_operations_resolve(struct ebpfos_operations_owner *owner,
 const void *original)
{
 struct ebpfos_function_view *view;
 struct ebpfos_operations_target *target;
 if (!owner || owner->resolved) return original;
 owner->resolved = true;view = owner->view->private_data;
 if (!READ_ONCE(view->object_revoked))
  list_for_each_entry(target, &view->object_targets, entry)
   if (target->address == (unsigned long)original && target->type == owner->type)
    return target->operations->table;
 /* The first publication did not use this view. Later aliases and changes
  * to an already published object do not select another creation binding. */
 fput(owner->view);owner->view = NULL;
 return original;
}
EXPORT_SYMBOL_GPL(ebpfos_operations_resolve);

static void operations_owner_release(struct rcu_head *rcu)
{
 struct ebpfos_operations_owner *owner = container_of(rcu, struct ebpfos_operations_owner, rcu);
 if (owner->view) fput(owner->view);
 kfree(owner);
}
void ebpfos_operations_owner_put(struct ebpfos_operations_owner *owner)
{
 if (owner) call_rcu(&owner->rcu, operations_owner_release);
}
EXPORT_SYMBOL_GPL(ebpfos_operations_owner_put);

const void *ebpfos_operations_table(const struct ebpfos_operations *bound)
{ return bound->table; }
EXPORT_SYMBOL_GPL(ebpfos_operations_table);
u32 ebpfos_operations_bound(const struct ebpfos_operations *bound)
{ return bound->count; }
EXPORT_SYMBOL_GPL(ebpfos_operations_bound);

void ebpfos_operations_put(struct ebpfos_operations *bound)
{
 struct ebpfos_function_view *view;
 unsigned long flags;
 if (!bound) return;
 if (bound->prepared) {fput(bound->view);return;}
 if (!refcount_dec_and_test(&bound->references)) return;
 view = bound->view->private_data;
 raw_spin_lock_irqsave(&view->object_lock, flags);
 list_del(&bound->entry);
 raw_spin_unlock_irqrestore(&view->object_lock, flags);
 fput(bound->view);
 module_put(bound->original_owner);
 kfree(bound->table);
 kfree(bound);
}
EXPORT_SYMBOL_GPL(ebpfos_operations_put);

struct ebpfos_operations *ebpfos_operations_get(struct ebpfos_operations *bound)
{
 if (bound) {
  if (bound->prepared) get_file(bound->view);
  else refcount_inc(&bound->references);
 }
 return bound;
}
EXPORT_SYMBOL_GPL(ebpfos_operations_get);

static int bound_file_release(struct inode *inode, struct file *file)
{
 struct bound_file_operations *bound = container_of(file->f_op,
   struct bound_file_operations, operations);
 const struct file_operations *original = bound->original;
 bool last;
 unsigned long flags;
 struct ebpfos_function_view *view = bound->view->private_data;
 int result;
 file->f_op = original;
 result = original->release ? original->release(inode, file) : 0;
 /* __fput still calls fops_put after release; restore its original owner
  * before releasing this file's table reference and the code lease. */
 file->f_op = original;
 mutex_lock(&bound_files_lock);
 raw_spin_lock_irqsave(&view->object_lock, flags);
 last = refcount_dec_and_test(&bound->files);
 if (last) { list_del(&bound->entry);list_del(&bound->view_entry); }
 raw_spin_unlock_irqrestore(&view->object_lock, flags);
 mutex_unlock(&bound_files_lock);
 if (last) {
  fput(bound->view);
  kfree(bound);
 }
 return result;
}

int ebpfos_object_view_select(int descriptor)
{
 struct file *next = NULL, *old;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (!in_task() || !current->mm) return -EOPNOTSUPP;
 if (descriptor != -1) {
  next = ebpfos_function_view_get(descriptor);
  if (IS_ERR(next)) return PTR_ERR(next);
  if (READ_ONCE(ebpfos_function_view_data(next)->object_revoked)) {
   fput(next);return -EOWNERDEAD;
  }
  {
   struct ebpfos_function_view *view = next->private_data;
   unsigned long flags;
   raw_spin_lock_irqsave(&view->object_lock, flags);
   view->object_selected = true;
   raw_spin_unlock_irqrestore(&view->object_lock, flags);
  }
 }
 old = current->ebpfos_object_view;
 current->ebpfos_object_view = next;
 if (old) fput(old);
 return 0;
}
EXPORT_SYMBOL_GPL(ebpfos_object_view_select);

/* Revoke future dispatch through every object sharing this binding. Calls
 * which already fetched an old pointer can finish: ordinary file references
 * retain the table and its code lease until the final callback is dead.
 * Keep the release wrapper; restoring f_op itself would lose that ownership.
 * This operation neither unwinds old calls nor reverses their shared writes.
 */
static void revoke_file_bindings(struct ebpfos_function_view *view)
{
 struct bound_file_operations *bound;
 struct ebpfos_operations *table;
 unsigned long flags;
 u32 i;
 raw_spin_lock_irqsave(&view->object_lock, flags);
 WRITE_ONCE(view->object_revoked, true);
 list_for_each_entry(table, &view->object_tables, entry) {
  for (i = 0; i < table->count; ++i) {
   u32 offset = table->offsets[i];
   unsigned long address;
   memcpy(&address, table->original + offset, sizeof(address));
   WRITE_ONCE(*(unsigned long *)(table->table + offset), address);
  }
 }
 list_for_each_entry(bound, &view->object_files, view_entry) {
  WRITE_ONCE(bound->operations.llseek, bound->original->llseek);
  WRITE_ONCE(bound->operations.read, bound->original->read);
  WRITE_ONCE(bound->operations.write, bound->original->write);
  WRITE_ONCE(bound->operations.read_iter, bound->original->read_iter);
  WRITE_ONCE(bound->operations.fsync, bound->original->fsync);
 }
 raw_spin_unlock_irqrestore(&view->object_lock, flags);
}
static int object_view_revoke(u32 descriptor)
{
 struct file *lease;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 lease = ebpfos_function_view_get(descriptor);
 if (IS_ERR(lease)) return PTR_ERR(lease);
 revoke_file_bindings(lease->private_data);
 fput(lease);
 return 0;
}

int ebpfos_file_view_open(struct file *file)
{
 struct ebpfos_function_view *view;
 struct bound_file_operations *bound;
 struct file *lease;
 unsigned int i, changed = 0;
 unsigned long flags;
 bool matches = false;
 int error = 0;
 /* Object work never resolves a task's selection after creation. A new
  * object created in an interrupt or a kernel thread starts globally. */
 if (!in_task() || !current->mm || !current->ebpfos_object_view) return 0;
 lease = current->ebpfos_object_view;
 view = lease->private_data;
 mutex_lock(&bound_files_lock);
 if (READ_ONCE(view->object_revoked)) goto unlock;
 list_for_each_entry(bound, &bound_files, entry) {
  if (bound->view == lease && bound->original == file->f_op) {
   raw_spin_lock_irqsave(&view->object_lock, flags);
   if (view->object_revoked) {raw_spin_unlock_irqrestore(&view->object_lock, flags);goto unlock;}
   refcount_inc(&bound->files);
   file->f_op = &bound->operations;
   raw_spin_unlock_irqrestore(&view->object_lock, flags);
   goto unlock;
  }
 }
 /* Unrelated files keep their original operations without allocating a
  * private table. The immutable view was already resolved at publication. */
 for (i = 0; i < view->count; ++i) {
  const struct ebpfos_function_view_member *member = &view->members[i];
  unsigned long address = member->native_address;
  if (IS_ERR(ebpfos_function_view_find(view, member->native_function))) {
   error = -ENOTUNIQ;goto unlock;
  }
  matches |= address && (address == (unsigned long)file->f_op->llseek ||
    address == (unsigned long)file->f_op->read ||
    address == (unsigned long)file->f_op->write ||
    address == (unsigned long)file->f_op->read_iter ||
    address == (unsigned long)file->f_op->fsync);
 }
 if (!matches) goto unlock;
 bound = kzalloc(sizeof(*bound), GFP_KERNEL);
 if (!bound) { error = -ENOMEM;goto unlock; }
 bound->operations = *file->f_op;
 bound->original = file->f_op;
 for (i = 0; i < view->count; ++i) {
  const struct ebpfos_function_view_member *member = &view->members[i];
  unsigned long address = member->native_address;
  if (address && address == (unsigned long)file->f_op->llseek) {
   bound->operations.llseek = (void *)member->binding.address;
   changed++;
  }
  if (address && address == (unsigned long)file->f_op->read) {
   bound->operations.read = (void *)member->binding.address;
   changed++;
  }
  if (address && address == (unsigned long)file->f_op->write) {
   bound->operations.write = (void *)member->binding.address;
   changed++;
  }
  if (address && address == (unsigned long)file->f_op->read_iter) {
   bound->operations.read_iter = (void *)member->binding.address;
   changed++;
  }
  if (address && address == (unsigned long)file->f_op->fsync) {
   bound->operations.fsync = (void *)member->binding.address;
   changed++;
  }
 }
 if (!changed) goto free;
 raw_spin_lock_irqsave(&view->object_lock, flags);
 if (view->object_revoked) {raw_spin_unlock_irqrestore(&view->object_lock, flags);goto free;}
 bound->view = get_file(lease);
 refcount_set(&bound->files, 1);
 bound->operations.release = bound_file_release;
 list_add(&bound->entry, &bound_files);
 list_add(&bound->view_entry, &view->object_files);
 file->f_op = &bound->operations;
 raw_spin_unlock_irqrestore(&view->object_lock, flags);
 goto unlock;
free:
 kfree(bound);
unlock:
 mutex_unlock(&bound_files_lock);
 return error;
}
EXPORT_SYMBOL_GPL(ebpfos_file_view_open);

__bpf_kfunc_start_defs();
/* The linker supplies only tables whose address uses admit copying. Names
 * resolve to permanent image storage; code addresses are still selected from
 * the existing BTF-checked view. This list is sealed at first selection. */
__bpf_kfunc int bpf_ebpfos_object_view_tables(u32 descriptor,
 const struct ebpfos_operations_table_source *sources, u32 sources__sz)
{
 struct ebpfos_operations_table_source *snapshot;
 struct ebpfos_operations_target *target, *next, *existing;
 struct ebpfos_function_view *view;
 struct btf *native = bpf_get_btf_vmlinux();
 struct file *lease;
 unsigned long flags;
 u32 i, count;
 int error = 0;
 LIST_HEAD(prepared);
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (!sources__sz || sources__sz % sizeof(*sources) || IS_ERR_OR_NULL(native)) return -EINVAL;
 snapshot = kmemdup(sources, sources__sz, GFP_KERNEL);
 if (!snapshot) return -ENOMEM;
 lease = ebpfos_function_view_get(descriptor);
 if (IS_ERR(lease)) {error = PTR_ERR(lease);goto free_snapshot;}
 view = lease->private_data;
 count = sources__sz / sizeof(*sources);
 for (i = 0; i < count; ++i) {
  const struct btf_type *type = btf_type_by_id(native, snapshot[i].type);
  unsigned long address, bytes, offset;
  if (!type || !btf_type_is_struct(type) || !type->size ||
      !memchr(snapshot[i].symbol, 0, sizeof(snapshot[i].symbol))) {error = -EINVAL;goto finish;}
  address = kallsyms_lookup_name(snapshot[i].symbol);
  if (!address || !is_kernel(address) || !is_kernel(address + type->size - 1) ||
      !kallsyms_lookup_size_offset(address, &bytes, &offset) || offset ||
      bytes < type->size) {error = -ENOENT;goto finish;}
  target = kzalloc(sizeof(*target), GFP_KERNEL);
  if (!target) {error = -ENOMEM;goto finish;}
  target->address = address;target->type = snapshot[i].type;
  target->operations = operations_prepare(get_file(lease), (const void *)address,
    target->type, type->size, NULL);
  if (IS_ERR(target->operations)) {
   error = PTR_ERR(target->operations);kfree(target);goto finish;
  }
  target->operations->prepared = true;
  fput(target->operations->view);
  list_add_tail(&target->entry, &prepared);
 }
 raw_spin_lock_irqsave(&view->object_lock, flags);
 if (view->object_selected || view->object_revoked) {error = -EBUSY;goto unlock_targets;}
 list_for_each_entry(target, &prepared, entry) {
  list_for_each_entry(existing, &view->object_targets, entry)
   if (existing->address == target->address) {error = -ENOTUNIQ;goto unlock_targets;}
  list_for_each_entry(existing, &prepared, entry)
   if (existing != target && existing->address == target->address) {error = -ENOTUNIQ;goto unlock_targets;}
 }
 list_splice_tail_init(&prepared, &view->object_targets);
unlock_targets:
 raw_spin_unlock_irqrestore(&view->object_lock, flags);
finish:
 list_for_each_entry_safe(target, next, &prepared, entry) {
  prepared_table_free(target->operations);
  list_del(&target->entry);kfree(target);
 }
 fput(lease);
free_snapshot:
 kfree(snapshot);
 return error;
}
__bpf_kfunc int bpf_ebpfos_object_view_select(int descriptor)
{ return ebpfos_object_view_select(descriptor); }
__bpf_kfunc int bpf_ebpfos_object_view_revoke(u32 descriptor)
{ return object_view_revoke(descriptor); }
/* The verified argument is a live file held by the native caller or iterator.
 * No task selection, descriptor lookup, allocation or sleeping lock is used.
 * Keep table/code leases until their ordinary final file releases. */
__bpf_kfunc int bpf_ebpfos_file_view_revoke(struct file *file)
{
 const struct file_operations *operations = READ_ONCE(file->f_op);
 struct bound_file_operations *bound;
 if (!operations || operations->release != bound_file_release) return -ENOENT;
 bound = container_of(operations, struct bound_file_operations, operations);
 revoke_file_bindings(bound->view->private_data);
 return 0;
}
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(object_view_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_object_view_tables, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_object_view_select, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_object_view_revoke, KF_SLEEPABLE)
BTF_KFUNCS_END(object_view_ids)
static const struct btf_kfunc_id_set object_view_kfuncs;
static int object_view_filter(const struct bpf_prog *prog, u32 id)
{
 const struct btf_kfunc_id_set *sets[] = { &object_view_kfuncs };
 return ebpfos_syscall_kfunc_filter(prog, id, sets, ARRAY_SIZE(sets));
}
static const struct btf_kfunc_id_set object_view_kfuncs = {
 .owner = THIS_MODULE, .set = &object_view_ids, .filter = object_view_filter,
};
BTF_KFUNCS_START(file_fault_ids)
/* Authorize code which can revoke another file's binding when it is loaded;
 * the callback may later run in an ordinary unprivileged application. */
BTF_ID_FLAGS(func, bpf_ebpfos_file_view_revoke, KF_DESTRUCTIVE)
BTF_KFUNCS_END(file_fault_ids)
bool ebpfos_file_view_fault_call(const struct bpf_insn *insn)
{
 if (insn->code != (BPF_JMP | BPF_CALL) ||
     insn->src_reg != BPF_PSEUDO_KFUNC_CALL || insn->off) return false;
 /* Far-call JITs retain the BTF ID. x86 resolves it to a core-relative
  * address before JIT; kfunc_tab has already been freed at binding time. */
 if (bpf_jit_supports_far_kfunc_call())
  return file_fault_ids.cnt == 1 && insn->imm == file_fault_ids.pairs[0].id;
 return (unsigned long)__bpf_call_base + insn->imm ==
  (unsigned long)bpf_ebpfos_file_view_revoke;
}
static const struct btf_kfunc_id_set file_fault_kfuncs = {
 .owner = THIS_MODULE, .set = &file_fault_ids,
};
static int __init object_view_init(void)
{
 int error = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &object_view_kfuncs);
 return error ? error : register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &file_fault_kfuncs);
}
late_initcall(object_view_init);

#endif /* CONFIG_EBPFOS && CONFIG_X86_64 */
