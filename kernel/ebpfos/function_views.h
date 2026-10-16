/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_VIEWS_H
#define EBPFOS_FUNCTION_VIEWS_H
/* Immutable function tables use ordinary file references for fork, exec and
 * object lifetime. A task selects a table with its existing descriptor table;
 * a consumer resolves a slot once when creating an object, then keeps a file
 * reference while the object's ordinary operations can reach that code.
 * No task hook, per-call version lookup or alternate verifier is required.
 */
#include <linux/anon_inodes.h>
#include <linux/file.h>
#include <linux/slab.h>
#include "function_contract.h"
struct ebpfos_function_view_member {
 u32 native_function;
 struct ebpfos_function_binding binding;
};
struct ebpfos_function_view {
 u64 generation;
 u32 count;
 struct ebpfos_function_view_member members[];
};
struct ebpfos_function_view_source {
 u32 program, native_function, compiled_function;
};
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
static inline int ebpfos_function_view_publish(struct ebpfos_function_view *view)
{
 return anon_inode_getfd("ebpfos-function-view", &ebpfos_function_view_operations,
                        view, O_CLOEXEC | O_RDONLY);
}
static inline struct file *ebpfos_function_view_get(u32 descriptor)
{
 struct file *file = fget(descriptor);
 if (!file) return ERR_PTR(-EBADF);
 if (file->f_op != &ebpfos_function_view_operations) {
  fput(file);return ERR_PTR(-EINVAL);
 }
 return file;
}
static inline const struct ebpfos_function_view *
ebpfos_function_view_data(const struct file *file)
{
 return file->private_data;
}
/* The source array is a kernel-owned snapshot. Validate every member before
 * publishing any table; retain every loaded graph through the file lease.
 */
static inline int ebpfos_function_view_open_pure(
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
#endif
