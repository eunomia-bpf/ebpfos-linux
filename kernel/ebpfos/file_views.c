// SPDX-License-Identifier: GPL-2.0-only
/* Resolve an object's operations once. Ordinary file references protect the
 * selected view through duplicated descriptors and asynchronous I/O. */
#include <linux/btf.h>
#include <linux/capability.h>
#include <linux/interrupt.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>
#include <linux/ebpfos_file_view.h>
#include "function_views.h"
#include "syscall_kfuncs.h"

struct bound_file_operations {
 struct file_operations operations;
 const struct file_operations *original;
 struct file *view;
};

static int bound_file_release(struct inode *inode, struct file *file)
{
 struct bound_file_operations *bound = container_of(file->f_op,
   struct bound_file_operations, operations);
 const struct file_operations *original = bound->original;
 int result;
 file->f_op = original;
 result = original->release ? original->release(inode, file) : 0;
 /* __fput still calls fops_put after release; restore its original owner
  * before freeing this private operations table and the code lease. */
 file->f_op = original;
 fput(bound->view);
 kfree(bound);
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
 }
 old = current->ebpfos_object_view;
 current->ebpfos_object_view = next;
 if (old) fput(old);
 return 0;
}
EXPORT_SYMBOL_GPL(ebpfos_object_view_select);

int ebpfos_file_view_open(struct file *file)
{
 const struct ebpfos_function_view *view;
 struct bound_file_operations *bound;
 struct file *lease;
 struct btf *native;
 unsigned int i, changed = 0;
 /* Object work never resolves a task's selection after creation. A new
  * object created in an interrupt or a kernel thread starts globally. */
 if (!in_task() || !current->mm || !current->ebpfos_object_view) return 0;
 lease = current->ebpfos_object_view;
 view = ebpfos_function_view_data(lease);
 native = bpf_get_btf_vmlinux();
 if (IS_ERR_OR_NULL(native)) return -EOPNOTSUPP;
 bound = kzalloc(sizeof(*bound), GFP_KERNEL);
 if (!bound) return -ENOMEM;
 bound->operations = *file->f_op;
 bound->original = file->f_op;
 for (i = 0; i < view->count; ++i) {
  const struct ebpfos_function_view_member *member = &view->members[i];
  const struct btf_type *function = btf_type_by_id(native, member->native_function);
  unsigned long address;
  if (IS_ERR(ebpfos_function_view_find(view, member->native_function))) {
   kfree(bound);return -ENOTUNIQ;
  }
  if (!function || !btf_type_is_func(function)) { kfree(bound);return -EINVAL; }
  address = kallsyms_lookup_name(btf_name_by_offset(native, function->name_off));
  if (address && address == (unsigned long)file->f_op->llseek) {
   bound->operations.llseek = (void *)member->binding.address;
   changed++;
  }
  if (address && address == (unsigned long)file->f_op->read) {
   bound->operations.read = (void *)member->binding.address;
   changed++;
  }
  if (address && address == (unsigned long)file->f_op->read_iter) {
   bound->operations.read_iter = (void *)member->binding.address;
   changed++;
  }
 }
 if (!changed) { kfree(bound);return 0; }
 bound->view = get_file(lease);
 bound->operations.release = bound_file_release;
 file->f_op = &bound->operations;
 return 0;
}
EXPORT_SYMBOL_GPL(ebpfos_file_view_open);

__bpf_kfunc_start_defs();
__bpf_kfunc int bpf_ebpfos_object_view_select(int descriptor)
{ return ebpfos_object_view_select(descriptor); }
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(object_view_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_object_view_select, KF_SLEEPABLE)
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
static int __init object_view_init(void)
{ return register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &object_view_kfuncs); }
late_initcall(object_view_init);
