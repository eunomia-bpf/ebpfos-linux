/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_ENTRY_SLOTS_H
#define EBPFOS_FUNCTION_ENTRY_SLOTS_H
#include <linux/kprobes.h>
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
static int entry_native_apply(struct entry_native_slot *slots, unsigned int count,
 unsigned int from, unsigned int to)
{
 unsigned int i;
 int error = 0;
 u8 expected[5], replacement[5], actual[5];
 if (!count) return 0;
 mutex_lock(&text_mutex);
 for (i = 0; i < count; ++i) {
  if (!entry_native_instruction(&slots[i], from, expected) ||
      !entry_native_instruction(&slots[i], to, replacement)) {error = -ERANGE;goto out;}
  if (copy_from_kernel_nofault(actual, (void *)slots[i].ip, sizeof(actual)) ||
      memcmp(actual, expected, sizeof(actual))) {error = -ESTALE;goto out;}
 }
 for (i = 0; i < count; ++i) {
  entry_native_instruction(&slots[i], to, replacement);
  smp_text_poke_batch_add((void *)slots[i].ip, replacement, sizeof(replacement),
    to ? NULL : entry_native_emulation);
 }
 smp_text_poke_batch_finish();
out:
 mutex_unlock(&text_mutex);
 return error;
}
#endif
