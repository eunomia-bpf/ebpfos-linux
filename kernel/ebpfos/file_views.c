// SPDX-License-Identifier: GPL-2.0-only
/* Resolve an object's operations once. Ordinary file references protect the
 * selected view through duplicated descriptors and asynchronous I/O. */
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
 unsigned long flags;
 raw_spin_lock_irqsave(&view->object_lock, flags);
 WRITE_ONCE(view->object_revoked, true);
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
 struct btf *native;
 unsigned int i, changed = 0;
 unsigned long flags;
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
 native = bpf_get_btf_vmlinux();
 if (IS_ERR_OR_NULL(native)) { error = -EOPNOTSUPP;goto unlock; }
 bound = kzalloc(sizeof(*bound), GFP_KERNEL);
 if (!bound) { error = -ENOMEM;goto unlock; }
 bound->operations = *file->f_op;
 bound->original = file->f_op;
 for (i = 0; i < view->count; ++i) {
  const struct ebpfos_function_view_member *member = &view->members[i];
  const struct btf_type *function = btf_type_by_id(native, member->native_function);
  unsigned long address;
  if (IS_ERR(ebpfos_function_view_find(view, member->native_function))) {
   error = -ENOTUNIQ;goto free;
  }
  if (!function || !btf_type_is_func(function)) { error = -EINVAL;goto free; }
  address = kallsyms_lookup_name(btf_name_by_offset(native, function->name_off));
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
