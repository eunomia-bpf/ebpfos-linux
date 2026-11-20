/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_ENTRY_EPOCH_H
#define EBPFOS_FUNCTION_ENTRY_EPOCH_H
/* Migration exports have int(unsigned int) native ABI. Verified and trusted
 * eBPF exports use the same cold binding as component entries; the program
 * fd retains their complete JIT graph. Staged native exports remain supported.
 * APPLY saves
 * current data before writes; UNDO restores that snapshot after any refusal.
 * The inverse is a separate program operating on current retained values.
 * Source ownership/population and equivalence remain compiler obligations.
 */
static struct bpf_prog *entry_epoch_program(struct entry_set *set, u32 fd,
 unsigned long *address)
{
 struct bpf_prog *program = bpf_prog_get(fd);
 struct btf *btf;
 int error;
 if (IS_ERR(program)) return program;
 btf = program->aux->attach_btf;
 error = bpf_entry_program_address(btf, program->aux->attach_btf_id,
  program, false, address);
 if (error) {bpf_prog_put(program);return ERR_PTR(error);}
 return program;
}
struct entry_epoch_call {
 unsigned long address;
 bool called;
 int undo_error;
};
static int entry_epoch_update(void *opaque)
{
 struct entry_epoch_call *call = opaque;
 call->called = true;
 return ((int (*)(u32))(void *)call->address)(BPF_ENTRY_EPOCH_APPLY);
}
static void entry_epoch_undo(void *opaque)
{
 struct entry_epoch_call *call = opaque;
 if (call->called) call->undo_error =
  ((int (*)(u32))(void *)call->address)(BPF_ENTRY_EPOCH_UNDO);
}
static int entry_epoch_apply(struct entry_set *set, unsigned int from,
 unsigned int to, unsigned long address)
{
 struct entry_epoch_call call = { .address = address };
 struct text_poke_pair *pairs;
 int error;
 pairs = entry_native_pairs(from ? entry_generation(set, from)->slots : set->slots,
  to ? entry_generation(set, to)->slots : set->slots, set->slot_count,
  from ? entry_generation_slot(from) + 1 : 0, to ? entry_generation_slot(to) + 1 : 0);
 if (IS_ERR(pairs)) return PTR_ERR(pairs);
 error = smp_text_poke_quiescent_transaction(pairs, set->slot_count,
  entry_epoch_update, entry_epoch_undo, &call);
 kvfree(pairs);

 if (!error && to && !set->published) {
  set->published = true;list_add_tail(&set->retained, &entry_retained);
 }
 return error;
}
#endif
