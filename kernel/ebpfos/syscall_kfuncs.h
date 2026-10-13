/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_SYSCALL_KFUNCS_H
#define EBPFOS_SYSCALL_KFUNCS_H
#include <linux/bpf.h>
#include <linux/btf_ids.h>

/* Use one existing common-hook entry per service rather than duplicating
 * registrations across hooks. Preserve the original syscall-only context;
 * common-hook filters must leave unrelated services' policy intact. */
static inline int ebpfos_syscall_kfunc_filter(const struct bpf_prog *prog,
 u32 id, const struct btf_kfunc_id_set * const *sets, size_t count)
{
 size_t i;
 for (i = 0; i < count; i++)
  if (btf_id_set8_contains(sets[i]->set, id))
   return !prog || prog->type != BPF_PROG_TYPE_SYSCALL;
 return 0;
}

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
