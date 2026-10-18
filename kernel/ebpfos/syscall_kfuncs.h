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
static inline bool ebpfos_instruction_member(u32 id,
 const struct btf_kfunc_id_set * const *sets,size_t count)
{
 size_t i,j;
 for (i=0;i<count;++i) {
  const struct btf_kfunc_id_set *set=sets[i];
  if (!set->kop_descs) continue;
  for (j=0;j<set->set->cnt;++j) {
   const struct bpf_kop *kop=set->kop_descs[j];
   if (!kop) continue;
   if (set->set->pairs[j].id==id || (kop->proof_kfunc_id && kop->proof_kfunc_id==id))
    return true;
   if (kop->proof_kfunc_id_for_payload &&
       kop->proof_kfunc_id_for_payload(set->set->pairs[j].id)==id)
    return true;
  }
 }
 return false;
}
static inline int ebpfos_syscall_kfunc_filter(const struct bpf_prog *prog,
 u32 id,const struct btf_kfunc_id_set * const *sets,size_t count)
{
 size_t i;
 for (i=0;i<count;++i) if (btf_id_set8_contains(sets[i]->set,id)) {
  if (!prog) return 1;
  if (prog->type==BPF_PROG_TYPE_SYSCALL) return 0;
  return !(prog->type==BPF_PROG_TYPE_TRACING &&
   prog->expected_attach_type==BPF_TRACE_REPLACE && !prog->sleepable &&
   prog->aux && prog->aux->ebpfos_component && ebpfos_instruction_member(id,sets,count));
 }
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
