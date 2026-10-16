// SPDX-License-Identifier: GPL-2.0-only
/* One owner for process-view files, independent of the producer/consumer's
 * compilation unit. All type checks and file/program ownership stay cold.
 */
#include <linux/module.h>
#include <linux/filter.h>
#include <linux/btf.h>
#include "function_contract.h"
#include "function_views.h"
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
