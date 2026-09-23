// SPDX-License-Identifier: GPL-2.0-only
/* Apply an EX_TYPE_BPF fixup.
 *
 * The x86 JIT emits these entries, but it is not necessarily the kernel that
 * applies them: placed native code carries its entries into an image built
 * without a JIT, and that image still has to resume the faulting access.  So
 * the handler lives with the fault path that calls it rather than with the
 * emitter, and is built whenever either side is present.
 */
#include <linux/bitfield.h>
#include <linux/bpf.h>
#include <linux/printk.h>
#include <asm/bpf_extable.h>
#include <asm/extable.h>
#include <asm/ptrace.h>

bool ex_handler_bpf(const struct exception_table_entry *x, struct pt_regs *regs)
{
	u32 reg = FIELD_GET(FIXUP_REG_MASK, x->fixup);
	u32 insn_len = FIELD_GET(FIXUP_INSN_LEN_MASK, x->fixup);
	bool is_arena = !!(x->fixup & FIXUP_ARENA_ACCESS);
	bool is_write = (reg == DONT_CLEAR);
	unsigned long addr;
	s16 off;
	u32 arena_reg;

	if (is_arena) {
		arena_reg = FIELD_GET(FIXUP_ARENA_REG_MASK, x->fixup);
		off = FIELD_GET(DATA_ARENA_OFFSET_MASK, x->data);
		addr = *(unsigned long *)((void *)regs + arena_reg) + off;
		bpf_prog_report_arena_violation(is_write, addr, regs->ip);
	}

	/* jump over faulting load and clear dest register */
	if (reg != DONT_CLEAR)
		*(unsigned long *)((void *)regs + reg) = 0;
	regs->ip += insn_len;

	return true;
}
