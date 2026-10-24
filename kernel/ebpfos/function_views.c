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
#include "function_contract.h"
#include "function_views.h"
#include "syscall_kfuncs.h"
#include "function_native.h"
static int ebpfos_function_view_release(struct inode *inode, struct file *file)
{
 struct ebpfos_function_view *view = file->private_data;
 u32 i;
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
