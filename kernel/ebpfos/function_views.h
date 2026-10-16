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
#include "function_binding.h"
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
#endif
