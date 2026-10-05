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

/* Publication resolves this from verified func_info, never a supplied code
 * address. Absence means the old context entry; malformed typed exports fail.
 */
int ebpfos_component_typed_export(struct bpf_prog *prog, void **entry);

#endif
