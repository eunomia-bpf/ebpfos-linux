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
#include <linux/bpf.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include "function_binding.h"
struct ebpfos_function_view_member {
 u32 native_function;
 struct ebpfos_function_binding binding;
};
struct ebpfos_function_view {
 u64 generation;
 u32 count;
 /* Cold object binding state; immutable code members and leases stay valid. */
 bool object_revoked;
 raw_spinlock_t object_lock;
 struct list_head object_files;
 struct ebpfos_function_view_member members[];
};
struct ebpfos_function_view_source {
 u32 program, native_function, compiled_function;
};
/* Image-resident native bodies are trusted like built-in kernel code.
 * The constructor checks exact native BTF prototypes; no BPF admission. */
struct ebpfos_function_view_native_source { u32 native_function, replacement; };
int ebpfos_function_view_open_native(
 const struct ebpfos_function_view_native_source *sources, u32 count, u64 generation);
int ebpfos_function_view_open_native_btf(
 const struct ebpfos_function_view_native_source *sources, u32 count, u64 generation,
 u32 descriptor);
/* Import an already checked export, retaining its existing code graph. */
struct ebpfos_function_view_import { u32 view, native_function; };
/* Resolve an export once while preparing an object's operations. The table
 * has no ordinal ABI: reordered exports retain their native identities.
 * An absent or ambiguous export cannot supply a unique binding. The caller
 * holds the view's file reference for every use of the returned member. */
static inline const struct ebpfos_function_view_member *
ebpfos_function_view_find(const struct ebpfos_function_view *view, u32 native_function)
{
 const struct ebpfos_function_view_member *found = NULL;
 u32 i;
 for (i = 0; i < view->count; ++i) {
  if (view->members[i].native_function != native_function) continue;
  if (found) return ERR_PTR(-ENOTUNIQ);
  found = &view->members[i];
 }
 return found ? found : ERR_PTR(-ENOENT);
}
/* Prepared kernel-owned bindings transfer only on successful publication. */
int ebpfos_function_view_publish(struct ebpfos_function_view *view);
struct file *ebpfos_function_view_get(u32 descriptor);
static inline const struct ebpfos_function_view *
ebpfos_function_view_data(const struct file *file)
{
 return file->private_data;
}
/* The source array is a kernel-owned snapshot; every binding is prepared
 * before the file becomes visible. Failed preparation drops all leases.
 */
int ebpfos_function_view_open_pure(
 const struct ebpfos_function_view_source *sources, u32 count, u64 generation,
 enum bpf_prog_type type, struct btf *native);
int ebpfos_function_view_compose(u32 base,
 const struct ebpfos_function_view_import *imports, u32 count, u64 generation);
#endif
