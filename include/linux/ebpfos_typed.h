/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_TYPED_H
#define _LINUX_EBPFOS_TYPED_H

#include <linux/types.h>

struct ebpfos_executor_root_slot;
struct ebpfos_component_call;
struct bpf_prog;

/* Arguments and results stay in the native compiler ABI. This object owns
 * only the published epoch, stock execution scope and separate fault status.
 * Its size/alignment are exported in BTF for compiler-generated call sites.
 */
int ebpfos_component_typed_enter(struct ebpfos_executor_root_slot *slot,
				u64 role, u32 native_func_id,
				struct ebpfos_component_call *call,
				void **typed_entry);
int ebpfos_component_typed_exit(struct ebpfos_component_call *call);

/* Bit i denotes a NULL native pointer argument. Publication caches the
 * checked global BTF contract; invalid NULLs miss before program entry.
 */
int ebpfos_component_typed_enter_args(struct ebpfos_executor_root_slot *slot,
				u64 role, u32 native_func_id,
				struct ebpfos_component_call *call,
				void **typed_entry, u64 null_args);
int ebpfos_component_typed_enter_caller_args(struct ebpfos_executor_root_slot *slot,
				u64 role, u32 native_func_id,
				struct ebpfos_component_call *call,
				void **typed_entry, u64 null_args,
				unsigned long caller);
int ebpfos_component_typed_null_args(struct bpf_prog *prog, void *entry, u64 *mask);
/* Checked context roots use their stock native BTF context-access contract. */
int ebpfos_component_context_null_args(struct bpf_prog *prog, u64 *mask);

/* The compiler captures the logical native caller before entering L1.
 * Keep it with the lease, including across bounded-step re-entry.
 */
int ebpfos_component_typed_enter_caller(struct ebpfos_executor_root_slot *slot,
				u64 role, u32 native_func_id,
				struct ebpfos_component_call *call,
				void **typed_entry, unsigned long caller);

/* Publication resolves this from verified func_info, never a supplied code
 * address. Absence means the old context entry; malformed typed exports fail.
 */
int ebpfos_component_typed_export(struct bpf_prog *prog, void **entry);

/* A stock-verified tracing context root can also expose a native C entry.
 * Its publication-owned image marshals the actual native BTF prototype;
 * only the checked main root executes, never a caller-specialized subprog.
 */
int ebpfos_component_context_export(struct bpf_prog *prog, void **entry,
				    void **image);
void ebpfos_component_context_free(void *image);

#endif
