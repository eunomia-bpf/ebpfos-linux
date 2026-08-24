/* SPDX-License-Identifier: GPL-2.0-only */
/* Policy-free x86-64 entry plumbing for the generated syscall root. */
#include <linux/linkage.h>
#include <asm/asm-offsets.h>
#include <asm/errno.h>
#include <asm/nospec-branch.h>
#include <asm/page_types.h>
#include <asm/percpu.h>
#include <asm/segment.h>

#include "../../arch/x86/entry/calling.h"

.code64
.section .entry.text, "ax"

SYM_CODE_START(ebpfos_runtime_syscall_entry)
	UNWIND_HINT_ENTRY
	ENDBR
	swapgs
	movq	%rsp, PER_CPU_VAR(cpu_tss_rw + TSS_sp2)
	SWITCH_TO_KERNEL_CR3 scratch_reg=%rsp
	movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp
	pushq	$__USER_DS
	pushq	PER_CPU_VAR(cpu_tss_rw + TSS_sp2)
	pushq	%r11
	pushq	$__USER_CS
	pushq	%rcx
	pushq	%rax
	PUSH_AND_CLEAR_REGS rax=$-ENOSYS
	movq	%rsp, %rdi
	IBRS_ENTER
	UNTRAIN_RET
	CLEAR_BRANCH_HISTORY
	call	ebpfos_runtime_syscall_dispatch
	IBRS_EXIT
	POP_REGS pop_rdi=0
	movq	%rsp, %rdi
	movq	PER_CPU_VAR(cpu_tss_rw + TSS_sp0), %rsp
	UNWIND_HINT_END_OF_STACK
	pushq	RSP-RDI(%rdi)
	pushq	(%rdi)
	STACKLEAK_ERASE_NOCLOBBER
	SWITCH_TO_USER_CR3_STACK scratch_reg=%rdi
	popq	%rdi
	popq	%rsp
	swapgs
	CLEAR_CPU_BUFFERS
	sysretq
	int3
SYM_CODE_END(ebpfos_runtime_syscall_entry)
