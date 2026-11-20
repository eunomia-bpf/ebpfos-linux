/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_SYSCALL_KFUNCS_H
#define EBPFOS_SYSCALL_KFUNCS_H
#include <linux/bpf.h>
#include <linux/btf_ids.h>

/* Existing machine operations and their actual native proof services are
 * frame-independent. Permit their verification in the checked, non-sleepable
 * native-replacement domain too. Unrelated syscall services keep their original
 * policy. The ordinary verifier, proof expansion and cold native-closure checks
 * remain mandatory; this adds no instruction or operation definition.
 */
static inline int ebpfos_syscall_kfunc_filter(const struct bpf_prog *prog,
 u32 id,const struct btf_kfunc_id_set * const *sets,size_t count)
{
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
