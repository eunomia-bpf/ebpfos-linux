/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_BPF_EXTABLE_H
#define _ASM_X86_BPF_EXTABLE_H

#include <linux/bits.h>

/*
 * Metadata encoding for exception handling in JITed code.
 *
 * Format of `fixup` and `data` fields in `struct exception_table_entry`:
 *
 * Bit layout of `fixup` (32-bit):
 *
 * +-----------+--------+-----------+---------+----------+
 * | 31        | 30-24  |   23-16   |   15-8  |    7-0   |
 * |           |        |           |         |          |
 * | ARENA_ACC | Unused | ARENA_REG | DST_REG | INSN_LEN |
 * +-----------+--------+-----------+---------+----------+
 *
 * - INSN_LEN (8 bits): Length of faulting insn (max x86 insn = 15 bytes (fits in 8 bits)).
 * - DST_REG  (8 bits): Offset of dst_reg from reg2pt_regs[] (max offset = 112 (fits in 8 bits)).
 *                      This is set to DONT_CLEAR if the insn is a store.
 * - ARENA_REG (8 bits): Offset of the register that is used to calculate the
 *                       address for load/store when accessing the arena region.
 * - ARENA_ACCESS (1 bit): This bit is set when the faulting instruction accessed the arena region.
 *
 * Bit layout of `data` (32-bit):
 *
 * +--------------+--------+--------------+
 * |	31-16	  |  15-8  |     7-0      |
 * |              |	   |              |
 * | ARENA_OFFSET | Unused |  EX_TYPE_BPF |
 * +--------------+--------+--------------+
 *
 * - ARENA_OFFSET (16 bits): Offset used to calculate the address for load/store when
 *                           accessing the arena region.
 *
 * The encoding is shared by whoever emits the entries and whoever applies
 * them, and those need not be the same kernel: placed native code carries its
 * entries to an image that has no JIT and still has to apply them.
 */

#define DONT_CLEAR 1
#define FIXUP_INSN_LEN_MASK	GENMASK(7, 0)
#define FIXUP_REG_MASK		GENMASK(15, 8)
#define FIXUP_ARENA_REG_MASK	GENMASK(23, 16)
#define FIXUP_ARENA_ACCESS	BIT(31)
#define DATA_ARENA_OFFSET_MASK	GENMASK(31, 16)

#endif /* _ASM_X86_BPF_EXTABLE_H */
