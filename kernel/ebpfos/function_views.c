// SPDX-License-Identifier: GPL-2.0-only
/* One owner for process-view files, independent of the producer/consumer's
 * compilation unit. All type checks and file/program ownership stay cold.
 */
#include <linux/module.h>
#include <linux/filter.h>
#include <linux/btf.h>
#include <linux/capability.h>
#include "function_contract.h"
#include "function_views.h"
#include "syscall_kfuncs.h"
static int ebpfos_function_view_release(struct inode *inode, struct file *file)
{
 struct ebpfos_function_view *view = file->private_data;
 u32 i;
 for (i = 0; i < view->count; ++i)
  ebpfos_function_binding_put(&view->members[i].binding);
 kvfree(view);
 return 0;
}
static const struct file_operations ebpfos_function_view_operations = {
 .owner = THIS_MODULE,
 .release = ebpfos_function_view_release,
 .llseek = noop_llseek,
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
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(view_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_function_view_open_pure, KF_SLEEPABLE)
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
