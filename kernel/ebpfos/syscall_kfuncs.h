/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_SYSCALL_KFUNCS_H
#define EBPFOS_SYSCALL_KFUNCS_H
#include <linux/bpf.h>
#include <linux/btf_ids.h>

/* Register existing machine operations and their native proof services through
 * the ordinary kfunc registry. Instruction descriptors retain their semantics.
 */

static inline int ebpfos_register_syscall_kfuncs(
 const struct btf_kfunc_id_set * const *sets, size_t count)
{
 size_t i;
 int error;
 for (i = 0; i < count; i++) {
  error = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, sets[i]);
  if (error) return error;
 }
 return 0;
}
#endif
