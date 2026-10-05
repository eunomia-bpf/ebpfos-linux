/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_ENTRY_H
#define _LINUX_EBPFOS_ENTRY_H

#include <linux/types.h>

struct ebpfos_executor_root_slot;
struct ebpfos_native_entry;
struct btf;
struct btf_func_model;

/*
 * C entry to a published, non-sleepable component. The context layout is the
 * one checked by the stock verifier for the loaded program. Native-signature
 * lowering belongs to the compiler; this API does not reinterpret arguments,
 * marshal objects, or manufacture pointer authority.
 *
 * Cache the stable slot, never its program address. Each call observes one
 * complete published epoch and holds it through return. On a closed gate or
 * missing role no program executes: the caller can take its native fallback.
 * A successful call returns zero, separately from the program's u32 result.
 */
int ebpfos_component_call_slot(struct ebpfos_executor_root_slot *slot, u64 role,
			       const void *context, u32 *result);

/*
 * A running component already holds its root's RCU epoch across imports. A
 * typed native import bridge may borrow that hold; it must last through this
 * call's return. Gate checks, rebinding and exact invocation accounting are
 * unchanged. The stock program callbacks still own their execution context.
 */
int ebpfos_component_call_slot_rcu(struct ebpfos_executor_root_slot *slot, u64 role,
				   const void *context, u32 *result);

/* The JIT's complete scalar R0, separate from pre-entry errors. The stock
 * verifier still governs whether a program may return a scalar or pointer.
 */
int ebpfos_component_call_slot64(struct ebpfos_executor_root_slot *slot, u64 role,
				 const void *context, u64 *result);

/* Distill the actual BTF FUNC, never a guessed prototype. Architecture limits
 * remain explicit (currently <=12 words, <=16-byte struct arguments, no
 * aggregate result or variadic arguments). This is marshalling, not authority
 * for dereferencing pointer arguments in a loaded BPF program.
 */
int ebpfos_component_entry_model(struct btf *btf, u32 func_id,
				 struct btf_func_model *model);
struct ebpfos_native_entry *
ebpfos_component_entry_create(struct ebpfos_executor_root_slot *slot, u64 role,
			      struct btf *btf, u32 func_id, void *fallback);
void *ebpfos_component_entry_address(const struct ebpfos_native_entry *entry);
/* Caller must first remove/drain every native call site referencing the entry.
 * Root drain alone does not cover a caller still in the marshalling prologue.
 */
void ebpfos_component_entry_destroy(struct ebpfos_native_entry *entry);

#endif
