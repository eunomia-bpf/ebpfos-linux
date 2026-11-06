/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_ENTRY_CALLS_H
#define EBPFOS_FUNCTION_ENTRY_CALLS_H
#include <asm/insn.h>
#include <asm/sections.h>
#include <linux/module_symbol.h>

static bool entry_module_noinstr(struct module *module, unsigned long address)
{
 unsigned long begin;
 if (!module)
  return address >= (unsigned long)__noinstr_text_start &&
   address < (unsigned long)__noinstr_text_end;
 begin = (unsigned long)module->noinstr_text_start;
 return address >= begin && address - begin < module->noinstr_text_size;
}

/* Decode actual function instructions, never scan immediate bytes for an
 * opcode. Core and module callers share the same direct-call journal.
 * Native versions remain trusted exceptions, not verifier admissions.
 */
static int entry_call_scan_range(unsigned long address, unsigned long size,
 unsigned long target, struct entry_native_slot *slots, unsigned int *count)
{
 unsigned long offset = 0;
 int error = 0;
 while (offset < size) {
  struct insn instruction;
  unsigned long ip = address + offset, destination;
  unsigned int j;
  error = insn_decode(&instruction, (void *)ip,
   min_t(unsigned long, MAX_INSN_SIZE, size - offset), INSN_MODE_64);

  offset += instruction.length;
  /* Decode calls and branches from their instruction boundaries. */
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

  if (slots) {
   /* Aliases may describe the same instruction more than once. */
   for (j = 0; j < *count; ++j) if (slots[j].ip == ip) break;
   if (j < *count) continue;

   slots[*count] = (struct entry_native_slot){ .ip = ip, .original = target,
    .call = instruction.opcode.bytes[0] == 0xe8 };
  }
  ++*count;
 }
 return error;
}
struct entry_core_call_scan {
 unsigned long target, previous;
 struct entry_native_slot *slots;
 unsigned int *count;
};
static int entry_core_call_scan(void *opaque, const char *name, unsigned long address)
{
 struct entry_core_call_scan *scan = opaque;
 unsigned long size, offset;
 /* Kallsyms includes aliases and data. Decode each resident text range once. */
 if (address == scan->previous || !core_kernel_text(address)) return 0;
 scan->previous = address;
 kallsyms_lookup_size_offset(address, &size, &offset);
 return entry_call_scan_range(address, size, scan->target, scan->slots, scan->count);
}
static int entry_call_scan(struct module *module, unsigned long target,
 struct entry_native_slot *slots, unsigned int capacity, unsigned int *count)
{
 struct mod_kallsyms *symbols;
 unsigned int i;
 int error = 0;
 mutex_lock(&text_mutex);
 if (!module) {
  struct entry_core_call_scan scan = {.target=target, .slots=slots, .count=count};
  error = kallsyms_on_each_symbol(entry_core_call_scan, &scan);
 } else {
  rcu_read_lock();
  symbols = rcu_dereference(module->kallsyms);
  for (i = 0; symbols && i < symbols->num_symtab; ++i) {
   const Elf_Sym *symbol = &symbols->symtab[i];
   unsigned long address = kallsyms_symbol_value(symbol);
   if (ELF_ST_TYPE(symbol->st_info) != STT_FUNC ||
       !within_module_mem_type(address, module, MOD_TEXT)) continue;
   if (!symbol->st_size) {error = -EOPNOTSUPP;break;}
   if (!within_module_mem_type(address + symbol->st_size - 1, module, MOD_TEXT)) {
    error = -EINVAL;break;
   }
   error = entry_call_scan_range(address, symbol->st_size, target, slots, count);
  }
  rcu_read_unlock();
 }
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
 if (owner) {
  for (i = 0; i < owner->slot_count; ++i)
   if (owner->slots[i].original == address) ++count;
 } else {
  error = entry_call_scan(set->source_module, address, NULL, 0, &count);
  if (error) return error;
 }
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
 }
 for (i = start; i < set->slot_count; ++i) {
  u8 instruction[5];
  slots[i].target[0] = slots[i].target[1] = target;
 }
 return 0;
}
#endif
