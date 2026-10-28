/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_ENTRY_SLOT_INSTRUCTION_H
#define EBPFOS_ENTRY_SLOT_INSTRUCTION_H

/* LLVM's five-byte NOP differs from Linux's breakpoint-emulation NOP.
 * Preserve the actual bytes on restoration; use the canonical equivalent
 * only as the emulation instruction passed to the stock text patcher.
 */
static const unsigned char entry_native_nop[5] = { 0x0f, 0x1f, 0x44, 0, 8 };
static const unsigned char entry_native_emulation[5] = { 0x0f, 0x1f, 0x44, 0, 0 };
struct entry_native_slot {
 unsigned long ip, target[2], original;
 bool call, ftrace;
};

static inline bool entry_native_jump(unsigned long ip, unsigned long target,
 unsigned char instruction[5])
{
 unsigned long distance = target - (ip + 5);
 unsigned int i;
 if (sizeof(unsigned long) != 8 || distance != (unsigned long)(long)(int)distance)
  return false;
 instruction[0] = 0xe9;
 for (i = 0; i < 4; ++i) instruction[i + 1] = distance >> (i * 8);
 return true;
}

static inline bool entry_native_instruction(const struct entry_native_slot *slot,
 unsigned int generation, unsigned char instruction[5])
{
 unsigned int i;
 if (generation > 2) return false;
 if (generation || slot->original) {
  if (!entry_native_jump(slot->ip, generation ? slot->target[generation - 1] : slot->original, instruction)) return false;
  if (slot->call) instruction[0] = 0xe8;
  return true;
 }
 for (i = 0; i < 5; ++i) instruction[i] = slot->ftrace ? entry_native_emulation[i] : entry_native_nop[i];
 return true;
}
#endif
