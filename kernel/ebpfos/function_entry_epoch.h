/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_ENTRY_EPOCH_H
#define EBPFOS_FUNCTION_ENTRY_EPOCH_H
/* Staged native migration programs have int(unsigned int) ABI. APPLY saves
 * current data before writes; UNDO restores that snapshot after any refusal.
 * The inverse is a separate program operating on current retained values.
 * Source ownership/population and equivalence remain compiler obligations.
 */
static struct bpf_prog *entry_epoch_program(struct entry_set *set, u32 fd)
{
 struct bpf_prog *program = bpf_prog_get(fd);
 const struct btf_type *function, *prototype, *result, *argument;
 struct btf *btf;
 int error = -EOPNOTSUPP;
 if (IS_ERR(program)) return program;
 if (program->type != BPF_PROG_TYPE_NATIVE || !set->source_module ||
     program->aux->mod != set->source_module) goto fail;
 btf = program->aux->attach_btf;
 function = btf_type_by_id(btf, program->aux->attach_btf_id);
 prototype = function ? btf_type_skip_modifiers(btf, function->type, NULL) : NULL;
 error = -EPROTOTYPE;
 if (!prototype || !btf_type_is_func_proto(prototype) || btf_type_vlen(prototype) != 1) goto fail;
 result = btf_type_skip_modifiers(btf, prototype->type, NULL);
 argument = btf_type_skip_modifiers(btf, btf_params(prototype)[0].type, NULL);
 if (!result || !argument || !btf_type_is_int(result) || !btf_type_is_int(argument) ||
     result->size != sizeof(int) || argument->size != sizeof(u32) ||
     btf_int_bits(result) != 32 || btf_int_bits(argument) != 32 ||
     !(btf_int_encoding(result) & BTF_INT_SIGNED) ||
     btf_int_encoding(argument)) goto fail;
 return program;
fail:
 bpf_prog_put(program);return ERR_PTR(error);
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
 struct bpf_prog *program;
 bool called;
 int undo_error;
};
static int entry_epoch_update(void *opaque)
{
 struct entry_epoch_call *call = opaque;
 int error = ebpfos_code_stopped(entry_epoch_contains, call->set);
 if (error) return error;
 call->called = true;
 return ((int (*)(u32))(void *)call->program->bpf_func)(BPF_ENTRY_EPOCH_APPLY);
}
static void entry_epoch_undo(void *opaque)
{
 struct entry_epoch_call *call = opaque;
 if (call->called) call->undo_error =
  ((int (*)(u32))(void *)call->program->bpf_func)(BPF_ENTRY_EPOCH_UNDO);
}
static int entry_epoch_apply(struct entry_set *set, unsigned int from,
 unsigned int to, struct bpf_prog *program)
{
 struct entry_epoch_call call = { .set = set, .program = program };
 struct text_poke_pair *pairs;
 int error;
 if (!set->epoch_mode || set->has_ftrace || set->table_count || !set->source_module) return -EOPNOTSUPP;
 pairs = entry_native_pairs(from ? entry_generation(set, from)->slots : set->slots,
  to ? entry_generation(set, to)->slots : set->slots, set->slot_count,
  from ? entry_generation_slot(from) + 1 : 0, to ? entry_generation_slot(to) + 1 : 0);
 if (IS_ERR(pairs)) return PTR_ERR(pairs);
 error = smp_text_poke_quiescent_transaction(pairs, set->slot_count,
  entry_epoch_update, entry_epoch_undo, &call);
 kvfree(pairs);
 if (call.undo_error) {set->poisoned = true;return -EUCLEAN;}
 if (!error && to && !set->published) {
  set->published = true;list_add_tail(&set->retained, &entry_retained);
 }
 return error;
}
#endif
