/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_ENTRY_SLOTS_H
#define EBPFOS_FUNCTION_ENTRY_SLOTS_H
#include <linux/kprobes.h>
#include <linux/sort.h>
#include "entry_slot_instruction.h"

/* Optional immutable compiler output. An absent table leaves the existing
 * ftrace path intact. These entries reserve patch space, not a callable ABI.
 */
extern const void *const *const ebpfos_native_entry_functions __weak;
extern const u8 *const ebpfos_native_entry_offsets __weak;
extern const u32 ebpfos_native_entry_function_count __weak;

static unsigned long entry_native_location(unsigned long address)
{
 static const u8 endbr[4] = { 0xf3, 0x0f, 0x1e, 0xfa };
 u8 actual[4];
 unsigned int i, offset = sizeof(endbr);
 if (!&ebpfos_native_entry_functions || !&ebpfos_native_entry_function_count)
  return 0;
 for (i = 0; i < ebpfos_native_entry_function_count; ++i)
  if ((unsigned long)ebpfos_native_entry_functions[i] == address) break;
 if (i == ebpfos_native_entry_function_count) return 0;
 /* Older producers reserve after ENDBR. A producer can also identify the
  * zero offset of a function without an indirect landing pad. The immutable
  * offset remains valid after the instruction has become a direct jump. */
 if (&ebpfos_native_entry_offsets) {
  if (!ebpfos_native_entry_offsets) return 0;
  offset = ebpfos_native_entry_offsets[i];
  if (offset && offset != sizeof(endbr)) return 0;
 }
 if (offset && (copy_from_kernel_nofault(actual, (void *)address, sizeof(actual)) ||
     memcmp(actual, endbr, sizeof(actual)))) return 0;
 /* The producer also uses Linux's ordinary NOKPROBE metadata. A second
  * patch owner must not install a breakpoint inside this instruction.
  */
 if (IS_ENABLED(CONFIG_KPROBES) && !within_kprobe_blacklist(address)) return 0;
 return address + offset;
}

static bool entry_module_readonly(struct module *module, unsigned long begin, size_t size)
{
 return size && begin + size >= begin &&
  within_module_mem_type(begin, module, MOD_RODATA) &&
  within_module_mem_type(begin + size - 1, module, MOD_RODATA);
}
static unsigned long entry_module_native_location(struct module *module, unsigned long address)
{
 unsigned long table_symbol, count_symbol, offsets_symbol;
 const void *const *table;
 const u8 *offsets;
 u32 count, i;
 u8 offset, endbr[4];
 static const u8 expected[4] = { 0xf3, 0x0f, 0x1e, 0xfa };
 table_symbol = find_kallsyms_symbol_value(module, "ebpfos_native_entry_functions");
 count_symbol = find_kallsyms_symbol_value(module, "ebpfos_native_entry_function_count");
 offsets_symbol = find_kallsyms_symbol_value(module, "ebpfos_native_entry_offsets");
 if (!entry_module_readonly(module, table_symbol, sizeof(table)) ||
     !entry_module_readonly(module, count_symbol, sizeof(count)) ||
     !entry_module_readonly(module, offsets_symbol, sizeof(offsets))) return 0;
 memcpy(&table, (void *)table_symbol, sizeof(table));
 memcpy(&count, (void *)count_symbol, sizeof(count));
 memcpy(&offsets, (void *)offsets_symbol, sizeof(offsets));
 if (!entry_module_readonly(module, (unsigned long)table, count * sizeof(*table)) ||
     !entry_module_readonly(module, (unsigned long)offsets, count)) return 0;
 for (i = 0; i < count; ++i) if ((unsigned long)table[i] == address) break;
 if (i == count) return 0;
 offset = offsets[i];
 if (offset && offset != sizeof(expected)) return 0;
 if (offset && (copy_from_kernel_nofault(endbr, (void *)address, sizeof(endbr)) ||
                memcmp(endbr, expected, sizeof(endbr)))) return 0;
 if (IS_ENABLED(CONFIG_KPROBES) && !within_kprobe_blacklist(address)) return 0;
 return address + offset;
}

/* entry_lock serializes journal ownership; text_mutex serializes Linux text
 * mutation. Preflight every byte and displacement before queuing any update.
 * No verifier, JIT, invocation gate or runtime code allocation lives here.
 */
static int entry_native_pair_order(const void *a, const void *b)
{
 const struct text_poke_pair *first = a, *second = b;
 return first->addr < second->addr ? -1 : first->addr > second->addr;
}
static struct text_poke_pair *entry_native_pairs(struct entry_native_slot *old,
 struct entry_native_slot *next, unsigned int count, unsigned int from, unsigned int to)
{
 struct text_poke_pair *pairs;
 unsigned int i;
 int error = -ERANGE;
 if (!count) return NULL;
 pairs = kvmalloc_array(count, sizeof(*pairs), GFP_KERNEL);
 if (!pairs) return ERR_PTR(-ENOMEM);
 for (i = 0; i < count; ++i) {
  pairs[i].addr = (void *)old[i].ip;
  if (old[i].ip != next[i].ip) {error = -EINVAL;goto fail;}
  if (!entry_native_instruction(&old[i], from, pairs[i].before) ||
      !entry_native_instruction(&next[i], to, pairs[i].after)) goto fail;
 }
 sort(pairs, count, sizeof(*pairs), entry_native_pair_order, NULL);
 return pairs;
fail:
 kvfree(pairs);return ERR_PTR(error);
}
static int entry_native_apply(struct entry_native_slot *old, struct entry_native_slot *next,
 unsigned int count, unsigned int from, unsigned int to)
{
 struct text_poke_pair *pairs = entry_native_pairs(old, next, count, from, to);
 int error;
 if (IS_ERR(pairs)) return PTR_ERR(pairs);
 if (!count) return 0;
 mutex_lock(&text_mutex);
 error = smp_text_poke_transaction(pairs, count);
 mutex_unlock(&text_mutex);
 kvfree(pairs);
 return error;
}

#endif
