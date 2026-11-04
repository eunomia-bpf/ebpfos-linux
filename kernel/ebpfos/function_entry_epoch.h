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
static bool entry_epoch_contains(void *opaque, unsigned long ip)
{
 struct entry_set *set = opaque, *generation;
 struct entry_lifetime lifetime = { .generation = set, .slot = 0 };
 /* Closed private native populations have all source users in this module.
  * Conservatively include the whole resident module, including notrace
  * helpers and callbacks, as well as every retained replacement graph. */
 if (within_module_mem_type(ip, set->source_module, MOD_TEXT)) return true;
 if (entry_code_contains(&lifetime, ip)) return true;
 lifetime.slot = 1;if (entry_code_contains(&lifetime, ip)) return true;
 list_for_each_entry(generation, &set->generations, generation_node) {
  lifetime.generation = generation;lifetime.slot = 0;
  if (entry_code_contains(&lifetime, ip)) return true;
 }
 return false;
}
struct entry_epoch_call {
 struct entry_set *set;
 unsigned long address;
 bool called;
 int undo_error;
};
static int entry_epoch_update(void *opaque)
{
 struct entry_epoch_call *call = opaque;
 int error = ebpfos_code_stopped(entry_epoch_contains, call->set);
 if (error) return error;
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
 struct entry_epoch_call call = { .set = set, .address = address };
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
