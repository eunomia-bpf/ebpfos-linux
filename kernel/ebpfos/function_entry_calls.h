/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_ENTRY_CALLS_H
#define EBPFOS_FUNCTION_ENTRY_CALLS_H
#include <asm/insn.h>
#include <linux/module_symbol.h>

static bool entry_module_noinstr(struct module *module, unsigned long address)
{
 unsigned long begin = (unsigned long)module->noinstr_text_start;
 return address >= begin && address - begin < module->noinstr_text_size;
}

/* Decode actual function instructions, never scan immediate bytes for an
 * opcode. This first staged form covers direct module-local users only.
 * Source contracts must exclude indirect/outside-module callers, mutable
 * call bindings, NMI and transaction users. Native versions remain trusted
 * exceptions, not verifier admissions.
 */
static int entry_call_scan(struct module *module, unsigned long target,
 struct entry_native_slot *slots, unsigned int capacity, unsigned int *count)
{
 struct mod_kallsyms *symbols;
 unsigned int i;
 int error = 0;
 mutex_lock(&text_mutex);
 rcu_read_lock();
 symbols = rcu_dereference(module->kallsyms);
 for (i = 0; symbols && i < symbols->num_symtab; ++i) {
  const Elf_Sym *symbol = &symbols->symtab[i];
  unsigned long address = kallsyms_symbol_value(symbol), offset = 0;
  if (ELF_ST_TYPE(symbol->st_info) != STT_FUNC ||
      !within_module_mem_type(address, module, MOD_TEXT)) continue;
  if (!symbol->st_size) {error = -EOPNOTSUPP;break;}
  if (!within_module_mem_type(address + symbol->st_size - 1, module, MOD_TEXT)) {
   error = -EINVAL;break;
  }
  while (offset < symbol->st_size) {
   struct insn instruction;
   unsigned long ip = address + offset, destination;
   unsigned int j;
   error = insn_decode(&instruction, (void *)ip,
    min_t(unsigned long, MAX_INSN_SIZE, symbol->st_size - offset), INSN_MODE_64);
   if (error || !instruction.length) {error = -EILSEQ;goto out;}
   offset += instruction.length;
   /* Refuse a short, prefixed or conditional branch to this entry rather
    * than silently publishing only its five-byte callers. */
   if (!((instruction.opcode.nbytes == 1 &&
          (instruction.opcode.bytes[0] == 0xe8 || instruction.opcode.bytes[0] == 0xe9 ||
           instruction.opcode.bytes[0] == 0xeb ||
           (instruction.opcode.bytes[0] >= 0x70 && instruction.opcode.bytes[0] <= 0x7f) ||
           (instruction.opcode.bytes[0] >= 0xe0 && instruction.opcode.bytes[0] <= 0xe3))) ||
         (instruction.opcode.nbytes == 2 && instruction.opcode.bytes[0] == 0x0f &&
          instruction.opcode.bytes[1] >= 0x80 && instruction.opcode.bytes[1] <= 0x8f))) continue;
   destination = ip + instruction.length +
    (instruction.immediate.nbytes == 1 ? (long)(s8)instruction.immediate.value :
                                       (long)(s32)instruction.immediate.value);
   if (destination != target) continue;
   if (instruction.length != 5 || instruction.opcode.nbytes != 1 ||
       (instruction.opcode.bytes[0] != 0xe8 && instruction.opcode.bytes[0] != 0xe9)) {
    error = -EOPNOTSUPP;goto out;
   }
   if (slots) {
    /* Aliases may describe the same instruction more than once. */
    for (j = 0; j < *count; ++j) if (slots[j].ip == ip) break;
    if (j < *count) continue;
    if (*count >= capacity) {error = -EOVERFLOW;goto out;}
    slots[*count] = (struct entry_native_slot){ .ip = ip, .original = target,
     .call = instruction.opcode.bytes[0] == 0xe8 };
   }
   ++*count;
  }
 }
out:
 rcu_read_unlock();
 mutex_unlock(&text_mutex);return error;
}
static int entry_module_calls(struct entry_set *set, unsigned long address,
 unsigned long target, struct entry_set *owner)
{
 struct entry_native_slot *slots;
 unsigned int count = 0, i, start = set->slot_count;
 int error;
 /* Other modules may acquire any exported symbol after this link is made.
  * A module-local scan cannot close those callers. */
 if (module_address_is_exported(set->source_module, address)) return -EOPNOTSUPP;
 if (owner) {
  for (i = 0; i < owner->slot_count; ++i)
   if (owner->slots[i].original == address) ++count;
 } else {
  error = entry_call_scan(set->source_module, address, NULL, 0, &count);
  if (error) return error;
 }
 if (!count) return -ENOENT;
 /* Leave room for the remaining reserved-entry members as well. */
 slots = kvrealloc(set->slots, array_size((size_t)start + count + set->count, sizeof(*slots)), GFP_KERNEL | __GFP_ZERO);
 if (!slots) return -ENOMEM;
 set->slots = slots;
 if (owner) {
  for (i = 0; i < owner->slot_count; ++i)
   if (owner->slots[i].original == address) slots[set->slot_count++] = owner->slots[i];
 } else {
  error = entry_call_scan(set->source_module, address, slots, start + count,
   &set->slot_count);
  if (error) return error;
  if (set->slot_count == start) return -ENOENT;
 }
 for (i = start; i < set->slot_count; ++i) {
  u8 instruction[5];
  slots[i].target[0] = slots[i].target[1] = target;
  if (!entry_native_instruction(&slots[i], 1, instruction)) return -ERANGE;
 }
 return 0;
}
#endif
