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
extern const u32 ebpfos_native_entry_function_count __weak;

static unsigned long entry_native_location(unsigned long address)
{
 static const u8 endbr[4] = { 0xf3, 0x0f, 0x1e, 0xfa };
 u8 actual[4];
 unsigned int i;
 if (!&ebpfos_native_entry_functions || !&ebpfos_native_entry_function_count)
  return 0;
 for (i = 0; i < ebpfos_native_entry_function_count; ++i)
  if ((unsigned long)ebpfos_native_entry_functions[i] == address) break;
 if (i == ebpfos_native_entry_function_count ||
     copy_from_kernel_nofault(actual, (void *)address, sizeof(actual)) ||
     memcmp(actual, endbr, sizeof(actual))) return 0;
 /* The producer also uses Linux's ordinary NOKPROBE metadata. A second
  * patch owner must not install a breakpoint inside this instruction.
  */
 if (IS_ENABLED(CONFIG_KPROBES) && !within_kprobe_blacklist(address)) return 0;
 return address + sizeof(endbr);
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
static int entry_native_apply(struct entry_native_slot *old, struct entry_native_slot *next, unsigned int count,
 unsigned int from, unsigned int to)
{
 struct text_poke_pair *pairs;
 unsigned int i;
 int error = -ERANGE;
 if (!count) return 0;
 pairs = kvmalloc_array(count, sizeof(*pairs), GFP_KERNEL);
 if (!pairs) return -ENOMEM;
 for (i = 0; i < count; ++i) {
  pairs[i].addr = (void *)old[i].ip;
  if (old[i].ip != next[i].ip) {error = -EINVAL;goto out;}
  if (!entry_native_instruction(&old[i], from, pairs[i].before) ||
      !entry_native_instruction(&next[i], to, pairs[i].after)) goto out;
 }
 sort(pairs, count, sizeof(*pairs), entry_native_pair_order, NULL);
 mutex_lock(&text_mutex);
 error = smp_text_poke_transaction(pairs, count);
 mutex_unlock(&text_mutex);
out:
 kvfree(pairs);
 return error;
}
#endif
