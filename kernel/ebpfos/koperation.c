// SPDX-License-Identifier: GPL-2.0-only
/* A verifier-checked terminal effect with no machine-root controls. */
#include <crypto/sha2.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/ebpfos.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#ifdef CONFIG_X86
#include <asm/cpufeature.h>
#include <asm/current.h>
#include <asm/irqflags.h>
#include <asm/special_insns.h>
#include <asm/tsc.h>
#endif
#include "koperation_xadd64.generated.h"
#include "koperation_atomic64.generated.h"
#include "koperation_atomic32.generated.h"
#include "koperation_bit64.generated.h"
#include "koperation_compiler_barrier.generated.h"
#include "koperation_tzcnt64.generated.h"
#include "koperation_load32.generated.h"
#include "koperation_current_task.generated.h"
#include "koperation_cmp_mask.generated.h"
#include "koperation_opcode.generated.h"

__bpf_kfunc_start_defs();
__bpf_kfunc void bpf_ebpfos_kprog_terminal_effect(void) { }
__bpf_kfunc u64 bpf_ebpfos_kop_xadd64(u64 *ptr, u64 delta)
{
	return 0; /* Only the verified proof or its bound JIT emission executes. */
}
__bpf_kfunc u64 bpf_ebpfos_kop_atomic64(u64 *ptr, u64 value, u64 expected)
{
	return 0; /* KOperation calls require JIT emission after proof checking. */
}
__bpf_kfunc u32 bpf_ebpfos_kop_atomic32(u32 *ptr, u32 value, u32 expected)
{
	return 0; /* KOperation calls require JIT emission after proof checking. */
}
__bpf_kfunc u64 bpf_ebpfos_kop_bit64(u64 *base, u64 index)
{
	return 0; /* KOperation calls require JIT emission after proof checking. */
}
__bpf_kfunc void bpf_ebpfos_kop_compiler_barrier(void) { }
__bpf_kfunc u64 bpf_ebpfos_kop_tzcnt64(u64 value)
{
	return 0; /* Only the verified proof or its bound JIT emission executes. */
}
__bpf_kfunc u32 bpf_ebpfos_kop_load32(u32 *ptr)
{
	return 0; /* Only the verified proof or its bound JIT emission executes. */
}
__bpf_kfunc struct task_struct *bpf_ebpfos_kop_current_task(void)
{
	return NULL; /* Only the verified proof or its bound JIT emission executes. */
}
__bpf_kfunc u64 bpf_ebpfos_kop_cmp_mask(u64 left, u64 right)
{
	return 0; /* Only the verified proof or its bound JIT emission executes. */
}
__bpf_kfunc u64 bpf_ebpfos_x86_pushf64(void)
{
#ifdef CONFIG_X86
	return native_save_fl();
#else
	return 0;
#endif
}
__bpf_kfunc u64 bpf_ebpfos_kop_pushf64(void)
{
	return 0; /* Only the typed proof or its bound JIT emission executes. */
}
#ifdef CONFIG_X86
__bpf_kfunc void bpf_ebpfos_kop_cli_save(unsigned long *flags)
{
	/* Only the stock IRQ-save proof or bound JIT emission executes. */
}
__bpf_kfunc void bpf_ebpfos_kop_popf64_restore(unsigned long *flags)
{
	/* Only the stock IRQ-restore proof or bound JIT emission executes. */
}
__bpf_kfunc void bpf_ebpfos_kop_sti_restore(unsigned long *flags)
{
	/* Only the stock IRQ-restore proof or bound JIT emission executes. */
}
__bpf_kfunc u64 bpf_ebpfos_x86_read_cr0(void)
{
	return native_read_cr0();
}
__bpf_kfunc u64 bpf_ebpfos_kop_read_cr0(void)
{
	return 0; /* Only the typed proof or its bound JIT emission executes. */
}
__bpf_kfunc u64 bpf_ebpfos_x86_read_cr2(void)
{
	return native_read_cr2();
}
__bpf_kfunc u64 bpf_ebpfos_kop_read_cr2(void)
{
	return 0; /* Only the typed proof or its bound JIT emission executes. */
}
__bpf_kfunc u64 bpf_ebpfos_x86_read_cr3(void)
{
	return __read_cr3();
}
__bpf_kfunc u64 bpf_ebpfos_kop_read_cr3(void)
{
	return 0; /* Only the typed proof or its bound JIT emission executes. */
}
__bpf_kfunc u64 bpf_ebpfos_x86_read_cr4(void)
{
	return native_read_cr4();
}
__bpf_kfunc u64 bpf_ebpfos_kop_read_cr4(void)
{
	return 0; /* Only the typed proof or its bound JIT emission executes. */
}
__bpf_kfunc u64 bpf_ebpfos_x86_reload_cr3(void)
{
	/* The operand is read from the running CPU, never supplied by BPF. */
	asm volatile("mov %%cr3, %%rax; mov %%rax, %%cr3" : : : "rax", "memory");
	return 0;
}
__bpf_kfunc u64 bpf_ebpfos_kop_reload_cr3(void)
{
	return 0; /* Only the typed proof or its bound JIT emission executes. */
}
#endif
__bpf_kfunc u64 bpf_ebpfos_x86_rdtsc(void)
{
#ifdef CONFIG_X86
	return rdtsc();
#else
	return 0;
#endif
}
__bpf_kfunc u64 bpf_ebpfos_kop_rdtsc(void)
{
	return 0; /* Only the typed proof or its bound JIT emission executes. */
}
__bpf_kfunc u64 bpf_ebpfos_x86_rdtscp(u32 *aux)
{
#ifdef CONFIG_X86
	u32 low, high, tsc_aux;

	if (!boot_cpu_has(X86_FEATURE_RDTSCP))
		return 0;
	asm volatile("rdtscp" : "=a"(low), "=d"(high), "=c"(tsc_aux)
		     : : "memory");
	*aux = tsc_aux;
	return (u64)high << 32 | low;
#else
	return 0;
#endif
}
__bpf_kfunc u64 bpf_ebpfos_kop_rdtscp(u32 *aux)
{
	return 0; /* Only the typed proof or its bound JIT emission executes. */
}
__bpf_kfunc u64 bpf_ebpfos_x86_rdseed64(u8 *success)
{
#ifdef CONFIG_X86
	u64 value;

	if (!boot_cpu_has(X86_FEATURE_RDSEED)) {
		*success = 0;
		return 0;
	}
	asm volatile("rdseed %0; setc %1" : "=r"(value), "=m"(*success) : : "cc");
	return value;
#else
	*success = 0;
	return 0;
#endif
}
__bpf_kfunc u64 bpf_ebpfos_kop_rdseed64(u8 *success)
{
	return 0; /* Only the typed proof or its bound JIT emission executes. */
}
__bpf_kfunc u64 bpf_ebpfos_x86_cpuid(u32 leaf, u32 subleaf, u64 *out)
{
#ifdef CONFIG_X86
	u32 eax = leaf, ebx, ecx = subleaf, edx;

	asm volatile("cpuid" : "+a"(eax), "=b"(ebx), "+c"(ecx), "=d"(edx));
	*out = (u64)edx << 32 | ecx;
	return (u64)ebx << 32 | eax;
#else
	return 0;
#endif
}
__bpf_kfunc u64 bpf_ebpfos_kop_cpuid(u32 leaf, u32 subleaf, u64 *out)
{
	return 0; /* Only the typed proof or its bound JIT emission executes. */
}
__bpf_kfunc u64 bpf_ebpfos_x86_clflush(u8 *ptr)
{
#ifdef CONFIG_X86
	if (!boot_cpu_has(X86_FEATURE_CLFLUSH))
		return 0;
	asm volatile("clflush (%0)" : : "r"(ptr) : "memory");
#endif
	return 0;
}
__bpf_kfunc u64 bpf_ebpfos_kop_clflush(u8 *ptr)
{
	return 0; /* Only the typed proof or its bound JIT emission executes. */
}
__bpf_kfunc u64 bpf_ebpfos_x86_clflushopt(u8 *ptr)
{
#ifdef CONFIG_X86
	if (!boot_cpu_has(X86_FEATURE_CLFLUSHOPT))
		return 0;
	asm volatile("clflushopt (%0)" : : "r"(ptr) : "memory");
#endif
	return 0;
}
__bpf_kfunc u64 bpf_ebpfos_kop_clflushopt(u8 *ptr)
{
	return 0; /* Only the typed proof or its bound JIT emission executes. */
}
__bpf_kfunc u64 bpf_ebpfos_x86_clwb(u8 *ptr)
{
#ifdef CONFIG_X86
	if (!boot_cpu_has(X86_FEATURE_CLWB))
		return 0;
	asm volatile("clwb (%0)" : : "r"(ptr) : "memory");
#endif
	return 0;
}
__bpf_kfunc u64 bpf_ebpfos_kop_clwb(u8 *ptr)
{
	return 0; /* Only the typed proof or its bound JIT emission executes. */
}
__bpf_kfunc u64 bpf_ebpfos_x86_invlpg(u64 addr)
{
#ifdef CONFIG_X86
	asm volatile("invlpg (%0)" : : "r"(addr) : "memory");
#endif
	return 0;
}
__bpf_kfunc u64 bpf_ebpfos_kop_invlpg(u64 addr)
{
	return 0; /* Only the typed proof or its bound JIT emission executes. */
}
#ifdef CONFIG_X86
__bpf_kfunc u64 bpf_ebpfos_x86_prefetcht0(u8 *ptr)
{
	asm volatile("prefetcht0 (%0)" : : "r"(ptr) : "memory");
	return 0;
}
__bpf_kfunc u64 bpf_ebpfos_kop_prefetcht0(u8 *ptr)
{
	return 0; /* Only the typed proof or its bound JIT emission executes. */
}
__bpf_kfunc u64 bpf_ebpfos_x86_prefetchw(u8 *ptr)
{
	if (!boot_cpu_has(X86_FEATURE_3DNOWPREFETCH))
		return 0;
	asm volatile("prefetchw (%0)" : : "r"(ptr) : "memory");
	return 0;
}
__bpf_kfunc u64 bpf_ebpfos_kop_prefetchw(u8 *ptr)
{
	return 0; /* Only the typed proof or its bound JIT emission executes. */
}
#endif
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(ebpfos_kprog_pushf64_service_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_pushf64)
BTF_KFUNCS_END(ebpfos_kprog_pushf64_service_ids)

BTF_KFUNCS_START(ebpfos_kprog_pushf64_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_pushf64)
BTF_KFUNCS_END(ebpfos_kprog_pushf64_ids)

#ifdef CONFIG_X86
BTF_KFUNCS_START(ebpfos_kprog_cli_save_service_ids)
BTF_ID_FLAGS(func, bpf_local_irq_save)
BTF_KFUNCS_END(ebpfos_kprog_cli_save_service_ids)

BTF_KFUNCS_START(ebpfos_kprog_cli_save_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_cli_save)
BTF_KFUNCS_END(ebpfos_kprog_cli_save_ids)

BTF_KFUNCS_START(ebpfos_kprog_popf64_restore_service_ids)
BTF_ID_FLAGS(func, bpf_local_irq_restore)
BTF_KFUNCS_END(ebpfos_kprog_popf64_restore_service_ids)

BTF_KFUNCS_START(ebpfos_kprog_popf64_restore_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_popf64_restore)
BTF_KFUNCS_END(ebpfos_kprog_popf64_restore_ids)

BTF_KFUNCS_START(ebpfos_kprog_sti_restore_service_ids)
BTF_ID_FLAGS(func, bpf_local_irq_restore)
BTF_KFUNCS_END(ebpfos_kprog_sti_restore_service_ids)

BTF_KFUNCS_START(ebpfos_kprog_sti_restore_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_sti_restore)
BTF_KFUNCS_END(ebpfos_kprog_sti_restore_ids)

BTF_KFUNCS_START(ebpfos_kprog_read_cr0_service_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_read_cr0)
BTF_KFUNCS_END(ebpfos_kprog_read_cr0_service_ids)

BTF_KFUNCS_START(ebpfos_kprog_read_cr0_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_read_cr0)
BTF_KFUNCS_END(ebpfos_kprog_read_cr0_ids)

BTF_KFUNCS_START(ebpfos_kprog_read_cr2_service_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_read_cr2)
BTF_KFUNCS_END(ebpfos_kprog_read_cr2_service_ids)

BTF_KFUNCS_START(ebpfos_kprog_read_cr2_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_read_cr2)
BTF_KFUNCS_END(ebpfos_kprog_read_cr2_ids)

BTF_KFUNCS_START(ebpfos_kprog_read_cr3_service_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_read_cr3)
BTF_KFUNCS_END(ebpfos_kprog_read_cr3_service_ids)

BTF_KFUNCS_START(ebpfos_kprog_read_cr3_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_read_cr3)
BTF_KFUNCS_END(ebpfos_kprog_read_cr3_ids)

BTF_KFUNCS_START(ebpfos_kprog_read_cr4_service_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_read_cr4)
BTF_KFUNCS_END(ebpfos_kprog_read_cr4_service_ids)

BTF_KFUNCS_START(ebpfos_kprog_read_cr4_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_read_cr4)
BTF_KFUNCS_END(ebpfos_kprog_read_cr4_ids)

BTF_KFUNCS_START(ebpfos_kprog_reload_cr3_service_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_reload_cr3)
BTF_KFUNCS_END(ebpfos_kprog_reload_cr3_service_ids)

BTF_KFUNCS_START(ebpfos_kprog_reload_cr3_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_reload_cr3)
BTF_KFUNCS_END(ebpfos_kprog_reload_cr3_ids)
#endif

BTF_KFUNCS_START(ebpfos_kprog_rdtsc_service_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_rdtsc)
BTF_KFUNCS_END(ebpfos_kprog_rdtsc_service_ids)

BTF_KFUNCS_START(ebpfos_kprog_rdtsc_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_rdtsc)
BTF_KFUNCS_END(ebpfos_kprog_rdtsc_ids)

BTF_KFUNCS_START(ebpfos_kprog_rdtscp_service_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_rdtscp)
BTF_KFUNCS_END(ebpfos_kprog_rdtscp_service_ids)

BTF_KFUNCS_START(ebpfos_kprog_rdtscp_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_rdtscp)
BTF_KFUNCS_END(ebpfos_kprog_rdtscp_ids)

BTF_KFUNCS_START(ebpfos_kprog_rdseed64_service_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_rdseed64)
BTF_KFUNCS_END(ebpfos_kprog_rdseed64_service_ids)

BTF_KFUNCS_START(ebpfos_kprog_rdseed64_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_rdseed64)
BTF_KFUNCS_END(ebpfos_kprog_rdseed64_ids)

BTF_KFUNCS_START(ebpfos_kprog_cpuid_service_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_cpuid)
BTF_KFUNCS_END(ebpfos_kprog_cpuid_service_ids)

BTF_KFUNCS_START(ebpfos_kprog_cpuid_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_cpuid)
BTF_KFUNCS_END(ebpfos_kprog_cpuid_ids)

BTF_KFUNCS_START(ebpfos_kprog_clflush_service_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_clflush)
BTF_KFUNCS_END(ebpfos_kprog_clflush_service_ids)

BTF_KFUNCS_START(ebpfos_kprog_clflush_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_clflush)
BTF_KFUNCS_END(ebpfos_kprog_clflush_ids)

BTF_KFUNCS_START(ebpfos_kprog_clflushopt_service_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_clflushopt)
BTF_KFUNCS_END(ebpfos_kprog_clflushopt_service_ids)

BTF_KFUNCS_START(ebpfos_kprog_clflushopt_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_clflushopt)
BTF_KFUNCS_END(ebpfos_kprog_clflushopt_ids)

BTF_KFUNCS_START(ebpfos_kprog_clwb_service_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_clwb)
BTF_KFUNCS_END(ebpfos_kprog_clwb_service_ids)

BTF_KFUNCS_START(ebpfos_kprog_clwb_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_clwb)
BTF_KFUNCS_END(ebpfos_kprog_clwb_ids)

BTF_KFUNCS_START(ebpfos_kprog_invlpg_service_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_invlpg)
BTF_KFUNCS_END(ebpfos_kprog_invlpg_service_ids)

BTF_KFUNCS_START(ebpfos_kprog_invlpg_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_invlpg)
BTF_KFUNCS_END(ebpfos_kprog_invlpg_ids)

#ifdef CONFIG_X86
BTF_KFUNCS_START(ebpfos_kprog_prefetcht0_service_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_prefetcht0)
BTF_KFUNCS_END(ebpfos_kprog_prefetcht0_service_ids)

BTF_KFUNCS_START(ebpfos_kprog_prefetcht0_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_prefetcht0)
BTF_KFUNCS_END(ebpfos_kprog_prefetcht0_ids)

BTF_KFUNCS_START(ebpfos_kprog_prefetchw_service_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_prefetchw)
BTF_KFUNCS_END(ebpfos_kprog_prefetchw_service_ids)

BTF_KFUNCS_START(ebpfos_kprog_prefetchw_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_prefetchw)
BTF_KFUNCS_END(ebpfos_kprog_prefetchw_ids)
#endif

static const struct btf_kfunc_id_set ebpfos_kprog_pushf64_service_set = {
	.set = &ebpfos_kprog_pushf64_service_ids,
};

#ifdef CONFIG_X86
static const struct btf_kfunc_id_set ebpfos_kprog_read_cr0_service_set = {
	.set = &ebpfos_kprog_read_cr0_service_ids,
};
static const struct btf_kfunc_id_set ebpfos_kprog_read_cr2_service_set = {
	.set = &ebpfos_kprog_read_cr2_service_ids,
};
static const struct btf_kfunc_id_set ebpfos_kprog_read_cr3_service_set = {
	.set = &ebpfos_kprog_read_cr3_service_ids,
};
static const struct btf_kfunc_id_set ebpfos_kprog_read_cr4_service_set = {
	.set = &ebpfos_kprog_read_cr4_service_ids,
};
static const struct btf_kfunc_id_set ebpfos_kprog_reload_cr3_service_set = {
	.set = &ebpfos_kprog_reload_cr3_service_ids,
};
#endif

static const struct btf_kfunc_id_set ebpfos_kprog_rdtsc_service_set = {
	.set = &ebpfos_kprog_rdtsc_service_ids,
};

static const struct btf_kfunc_id_set ebpfos_kprog_rdtscp_service_set = {
	.set = &ebpfos_kprog_rdtscp_service_ids,
};

static const struct btf_kfunc_id_set ebpfos_kprog_rdseed64_service_set = {
	.set = &ebpfos_kprog_rdseed64_service_ids,
};

static const struct btf_kfunc_id_set ebpfos_kprog_cpuid_service_set = {
	.set = &ebpfos_kprog_cpuid_service_ids,
};

static const struct btf_kfunc_id_set ebpfos_kprog_clflush_service_set = {
	.set = &ebpfos_kprog_clflush_service_ids,
};

static const struct btf_kfunc_id_set ebpfos_kprog_clflushopt_service_set = {
	.set = &ebpfos_kprog_clflushopt_service_ids,
};

static const struct btf_kfunc_id_set ebpfos_kprog_clwb_service_set = {
	.set = &ebpfos_kprog_clwb_service_ids,
};

static const struct btf_kfunc_id_set ebpfos_kprog_invlpg_service_set = {
	.set = &ebpfos_kprog_invlpg_service_ids,
};

#ifdef CONFIG_X86
static const struct btf_kfunc_id_set ebpfos_kprog_prefetcht0_service_set = {
	.set = &ebpfos_kprog_prefetcht0_service_ids,
};
static const struct btf_kfunc_id_set ebpfos_kprog_prefetchw_service_set = {
	.set = &ebpfos_kprog_prefetchw_service_ids,
};
#endif

static int ebpfos_kop_bind_typed_proof(enum ebpfos_kop_opcode_index opcode,
		u32 service_id, struct bpf_insn *insns)
{
	const struct ebpfos_kop_opcode_spec *spec = &ebpfos_kop_opcode_specs[opcode];

	if (!insns || !service_id ||
	    spec->proof_kind != EBPFOS_KOP_PROOF_TYPED_EFFECT ||
	    spec->proof_len != 1)
		return -EINVAL;
	insns[0] = spec->proof[0];
	insns[0].imm = service_id;
	return 1;
}

/* Each reviewed MC recipe expands to exactly one bound KOperation. */
#define EBPFOS_DEFINE_TYPED_OPCODE_KOP(name, opcode, available) \
static int ebpfos_kop_##name##_instantiate(u64 payload, struct bpf_insn *insns) \
{ \
	if (!insns || ebpfos_kprog_##name##_ids.cnt != 1 || \
	    ebpfos_kprog_##name##_service_ids.cnt != 1 || \
	    payload != ebpfos_kprog_##name##_ids.pairs[0].id) \
		return -EINVAL; \
	return ebpfos_kop_bind_typed_proof(EBPFOS_KOP_OPCODE_##opcode, \
		ebpfos_kprog_##name##_service_ids.pairs[0].id, insns); \
} \
static int ebpfos_kop_##name##_requirements(u64 payload, \
		u64 *capability_mask, u64 *effect_mask, \
		u8 semantic_sha256[SHA256_DIGEST_SIZE]) \
{ \
	const struct ebpfos_kop_opcode_spec *spec = \
		&ebpfos_kop_opcode_specs[EBPFOS_KOP_OPCODE_##opcode]; \
	if (!capability_mask || !effect_mask || !semantic_sha256 || \
	    ebpfos_kprog_##name##_ids.cnt != 1 || \
	    payload != ebpfos_kprog_##name##_ids.pairs[0].id) \
		return -EINVAL; \
	*capability_mask = 0; \
	*effect_mask = 0; \
	memcpy(semantic_sha256, spec->semantic_sha256, SHA256_DIGEST_SIZE); \
	return 0; \
} \
static int ebpfos_kop_##name##_emit_x86(u8 *image, u32 *offset, bool emit, \
		u64 payload, const struct bpf_prog *prog, const u8 *final_ip) \
{ \
	const struct ebpfos_kop_opcode_spec *spec = \
		&ebpfos_kop_opcode_specs[EBPFOS_KOP_OPCODE_##opcode]; \
	(void)prog; \
	(void)final_ip; \
	if (!IS_ENABLED(CONFIG_X86) || !(available)) \
		return -EOPNOTSUPP; \
	if (!offset || (emit && !image) || ebpfos_kprog_##name##_ids.cnt != 1 || \
	    payload != ebpfos_kprog_##name##_ids.pairs[0].id) \
		return -EINVAL; \
	if (emit) \
		memcpy(image + *offset, spec->native, spec->native_len); \
	*offset += spec->native_len; \
	return spec->native_len; \
} \
static struct bpf_kop ebpfos_kop_##name = { \
	.max_insn_cnt = 1, \
	.max_emit_bytes = 48, \
	.requirements = ebpfos_kop_##name##_requirements, \
	.instantiate_insn = ebpfos_kop_##name##_instantiate, \
	.emit_x86 = ebpfos_kop_##name##_emit_x86, \
}; \
static const struct bpf_kop * const ebpfos_kprog_##name##_descs[] = { \
	&ebpfos_kop_##name, \
}; \
static const struct btf_kfunc_id_set ebpfos_kprog_##name##_set = { \
	.set = &ebpfos_kprog_##name##_ids, \
	.kop_descs = ebpfos_kprog_##name##_descs, \
}

EBPFOS_KOP_TYPED_PORTABLE_ROWS(EBPFOS_DEFINE_TYPED_OPCODE_KOP)
#ifdef CONFIG_X86
EBPFOS_KOP_TYPED_X86_ROWS(EBPFOS_DEFINE_TYPED_OPCODE_KOP)
#endif
#undef EBPFOS_DEFINE_TYPED_OPCODE_KOP

BTF_KFUNCS_START(ebpfos_kprog_terminal_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kprog_terminal_effect, KF_NORETURN)
BTF_KFUNCS_END(ebpfos_kprog_terminal_ids)

BTF_KFUNCS_START(ebpfos_kprog_atomic_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_xadd64)
BTF_KFUNCS_END(ebpfos_kprog_atomic_ids)

BTF_KFUNCS_START(ebpfos_kprog_atomic64_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_atomic64)
BTF_KFUNCS_END(ebpfos_kprog_atomic64_ids)

BTF_KFUNCS_START(ebpfos_kprog_atomic32_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_atomic32)
BTF_KFUNCS_END(ebpfos_kprog_atomic32_ids)

BTF_KFUNCS_START(ebpfos_kprog_bit64_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_bit64)
BTF_KFUNCS_END(ebpfos_kprog_bit64_ids)

BTF_KFUNCS_START(ebpfos_kprog_compiler_barrier_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_compiler_barrier)
BTF_KFUNCS_END(ebpfos_kprog_compiler_barrier_ids)

BTF_KFUNCS_START(ebpfos_kprog_tzcnt64_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_tzcnt64)
BTF_KFUNCS_END(ebpfos_kprog_tzcnt64_ids)

BTF_KFUNCS_START(ebpfos_kprog_load32_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_load32)
BTF_KFUNCS_END(ebpfos_kprog_load32_ids)

BTF_KFUNCS_START(ebpfos_kprog_current_task_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_current_task)
BTF_KFUNCS_END(ebpfos_kprog_current_task_ids)

BTF_KFUNCS_START(ebpfos_kprog_cmp_mask_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_cmp_mask)
BTF_KFUNCS_END(ebpfos_kprog_cmp_mask_ids)

static int ebpfos_kop_cmp_mask_op(u64 payload)
{
	if (ebpfos_kprog_cmp_mask_ids.cnt != 1 ||
	    payload >> 8 != ebpfos_kprog_cmp_mask_ids.pairs[0].id)
		return -EINVAL;
	switch (payload & 0xff) {
	case 1: return 32;
	case 2: return 64;
	default: return -EINVAL;
	}
}

static int ebpfos_kop_cmp_mask_instantiate(u64 payload,
					   struct bpf_insn *insns)
{
	int width = ebpfos_kop_cmp_mask_op(payload);

	if (!insns || width < 0)
		return -EINVAL;
	insns[0] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[1] = width == 32 ?
		BPF_JMP32_REG(BPF_JGE, BPF_REG_2, BPF_REG_1, 1) :
		BPF_JMP_REG(BPF_JGE, BPF_REG_2, BPF_REG_1, 1);
	insns[2] = BPF_MOV64_IMM(BPF_REG_0, -1);
	insns[3] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_0);
	return 4;
}

static int ebpfos_kop_cmp_mask_requirements(u64 payload,
		u64 *capability_mask, u64 *effect_mask,
		u8 semantic_sha256[SHA256_DIGEST_SIZE])
{
	static const u8 digest32[SHA256_DIGEST_SIZE] =
		EBPFOS_KOP_CMP_MASK32_SEMANTIC_SHA256;
	static const u8 digest64[SHA256_DIGEST_SIZE] =
		EBPFOS_KOP_CMP_MASK64_SEMANTIC_SHA256;
	int width = ebpfos_kop_cmp_mask_op(payload);

	if (!capability_mask || !effect_mask || !semantic_sha256 || width < 0)
		return -EINVAL;
	*capability_mask = 0;
	*effect_mask = 0;
	memcpy(semantic_sha256, width == 32 ? digest32 : digest64,
	       SHA256_DIGEST_SIZE);
	return 0;
}

static int ebpfos_kop_cmp_mask_emit_x86(u8 *image, u32 *offset,
			bool emit, u64 payload, const struct bpf_prog *prog,
			const u8 *final_ip)
{
	static const u8 native32[] = EBPFOS_KOP_CMP_MASK32_NATIVE_BYTES;
	static const u8 native64[] = EBPFOS_KOP_CMP_MASK64_NATIVE_BYTES;
	const u8 *native;
	size_t len;
	int width = ebpfos_kop_cmp_mask_op(payload);

	(void)prog;
	(void)final_ip;
#ifndef CONFIG_X86
	return -EOPNOTSUPP;
#endif
	if (!offset || (emit && !image) || width < 0)
		return -EINVAL;
	native = width == 32 ? native32 : native64;
	len = width == 32 ? sizeof(native32) : sizeof(native64);
	if (emit)
		memcpy(image + *offset, native, len);
	*offset += len;
	return len;
}

static struct bpf_kop ebpfos_kop_cmp_mask = {
	.max_insn_cnt = 4,
	.max_emit_bytes = 6,
	.requirements = ebpfos_kop_cmp_mask_requirements,
	.instantiate_insn = ebpfos_kop_cmp_mask_instantiate,
	.emit_x86 = ebpfos_kop_cmp_mask_emit_x86,
};

static const struct bpf_kop * const ebpfos_kprog_cmp_mask_descs[] = {
	&ebpfos_kop_cmp_mask,
};

static const struct btf_kfunc_id_set ebpfos_kprog_cmp_mask_set = {
	.set = &ebpfos_kprog_cmp_mask_ids,
	.kop_descs = ebpfos_kprog_cmp_mask_descs,
};

static int ebpfos_kop_current_task_instantiate(u64 payload,
					       struct bpf_insn *insns)
{
	if (!insns || ebpfos_kprog_current_task_ids.cnt != 1 ||
	    payload != ebpfos_kprog_current_task_ids.pairs[0].id)
		return -EINVAL;
	insns[0] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0,
				BPF_FUNC_get_current_task_btf);
	return 1;
}

static int ebpfos_kop_current_task_requirements(u64 payload,
		u64 *capability_mask, u64 *effect_mask,
		u8 semantic_sha256[SHA256_DIGEST_SIZE])
{
	static const u8 digest[SHA256_DIGEST_SIZE] =
		EBPFOS_KOP_CURRENT_TASK_SEMANTIC_SHA256;

	if (!capability_mask || !effect_mask || !semantic_sha256 ||
	    ebpfos_kprog_current_task_ids.cnt != 1 ||
	    payload != ebpfos_kprog_current_task_ids.pairs[0].id)
		return -EINVAL;
	*capability_mask = 0;
	*effect_mask = 0;
	memcpy(semantic_sha256, digest, sizeof(digest));
	return 0;
}

static int ebpfos_kop_current_task_emit_x86(u8 *image, u32 *offset,
			bool emit, u64 payload, const struct bpf_prog *prog,
			const u8 *final_ip)
{
	static const u8 prefix[] = EBPFOS_KOP_CURRENT_TASK_NATIVE_PREFIX;
#ifdef CONFIG_X86
	unsigned long address = (unsigned long)&current_task;
#endif

	(void)prog;
	(void)final_ip;
#ifndef CONFIG_X86
	return -EOPNOTSUPP;
#else
	if ((unsigned long)(long)(s32)address != address)
		return -ERANGE;
#endif
	if (!offset || (emit && !image) ||
	    ebpfos_kprog_current_task_ids.cnt != 1 ||
	    payload != ebpfos_kprog_current_task_ids.pairs[0].id)
		return -EINVAL;
	if (emit) {
		memcpy(image + *offset, prefix, sizeof(prefix));
#ifdef CONFIG_X86
		put_unaligned_le32((u32)address, image + *offset + sizeof(prefix));
#endif
	}
	*offset += sizeof(prefix) + sizeof(u32);
	return sizeof(prefix) + sizeof(u32);
}

static struct bpf_kop ebpfos_kop_current_task = {
	.max_insn_cnt = 1,
	.max_emit_bytes = 9,
	.requirements = ebpfos_kop_current_task_requirements,
	.instantiate_insn = ebpfos_kop_current_task_instantiate,
	.emit_x86 = ebpfos_kop_current_task_emit_x86,
};

static const struct bpf_kop * const ebpfos_kprog_current_task_descs[] = {
	&ebpfos_kop_current_task,
};

static const struct btf_kfunc_id_set ebpfos_kprog_current_task_set = {
	.set = &ebpfos_kprog_current_task_ids,
	.kop_descs = ebpfos_kprog_current_task_descs,
};

static int ebpfos_kop_load32_instantiate(u64 payload, struct bpf_insn *insns)
{
	if (!insns || ebpfos_kprog_load32_ids.cnt != 1 ||
	    payload != ebpfos_kprog_load32_ids.pairs[0].id)
		return -EINVAL;
	insns[0] = BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0);
	return 1;
}

static int ebpfos_kop_load32_requirements(u64 payload,
		u64 *capability_mask, u64 *effect_mask,
		u8 semantic_sha256[SHA256_DIGEST_SIZE])
{
	static const u8 digest[SHA256_DIGEST_SIZE] =
		EBPFOS_KOP_LOAD32_SEMANTIC_SHA256;

	if (!capability_mask || !effect_mask || !semantic_sha256 ||
	    ebpfos_kprog_load32_ids.cnt != 1 ||
	    payload != ebpfos_kprog_load32_ids.pairs[0].id)
		return -EINVAL;
	*capability_mask = 0;
	*effect_mask = 0;
	memcpy(semantic_sha256, digest, sizeof(digest));
	return 0;
}

static int ebpfos_kop_load32_emit_x86(u8 *image, u32 *offset,
			bool emit, u64 payload, const struct bpf_prog *prog,
			const u8 *final_ip)
{
	static const u8 native[] = EBPFOS_KOP_LOAD32_NATIVE_BYTES;

	(void)prog;
	(void)final_ip;
#ifndef CONFIG_X86
	return -EOPNOTSUPP;
#endif
	if (!offset || (emit && !image) ||
	    ebpfos_kprog_load32_ids.cnt != 1 ||
	    payload != ebpfos_kprog_load32_ids.pairs[0].id)
		return -EINVAL;
	if (emit)
		memcpy(image + *offset, native, sizeof(native));
	*offset += sizeof(native);
	return sizeof(native);
}

static struct bpf_kop ebpfos_kop_load32 = {
	.max_insn_cnt = 1,
	.max_emit_bytes = 2,
	.requirements = ebpfos_kop_load32_requirements,
	.instantiate_insn = ebpfos_kop_load32_instantiate,
	.emit_x86 = ebpfos_kop_load32_emit_x86,
};

static const struct bpf_kop * const ebpfos_kprog_load32_descs[] = {
	&ebpfos_kop_load32,
};

static const struct btf_kfunc_id_set ebpfos_kprog_load32_set = {
	.set = &ebpfos_kprog_load32_ids,
	.kop_descs = ebpfos_kprog_load32_descs,
};

static int ebpfos_kop_tzcnt64_instantiate(u64 payload,
					 struct bpf_insn *insns)
{
	static const struct { u16 mask; u8 shift; } stages[] = {
		{ 0xffff, 16 }, { 0xff, 8 }, { 0xf, 4 },
		{ 0x3, 2 }, { 0x1, 1 },
	};
	int zero_branch, n = 0;
	u32 i;

	if (!insns || ebpfos_kprog_tzcnt64_ids.cnt != 1 ||
	    payload != ebpfos_kprog_tzcnt64_ids.pairs[0].id)
		return -EINVAL;
	insns[n++] = BPF_MOV64_IMM(BPF_REG_0, 64);
	zero_branch = n++;
	insns[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
	insns[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_1);
	insns[n++] = BPF_MOV32_REG(BPF_REG_3, BPF_REG_2);
	insns[n++] = BPF_JMP_IMM(BPF_JNE, BPF_REG_3, 0, 2);
	insns[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 32);
	insns[n++] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_2, 32);
	for (i = 0; i < ARRAY_SIZE(stages); i++) {
		insns[n++] = BPF_MOV64_REG(BPF_REG_3, BPF_REG_2);
		insns[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_3, stages[i].mask);
		insns[n++] = BPF_JMP_IMM(BPF_JNE, BPF_REG_3, 0, 2);
		insns[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, stages[i].shift);
		insns[n++] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_2, stages[i].shift);
	}
	insns[zero_branch] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0,
					   n - zero_branch - 1);
	/* Both paths must land inside the verifier's proof region. */
	insns[n++] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_0);
	return n;
}

static int ebpfos_kop_tzcnt64_requirements(u64 payload,
		u64 *capability_mask, u64 *effect_mask,
		u8 semantic_sha256[SHA256_DIGEST_SIZE])
{
	static const u8 digest[SHA256_DIGEST_SIZE] =
		EBPFOS_KOP_TZCNT64_SEMANTIC_SHA256;

	if (!capability_mask || !effect_mask || !semantic_sha256 ||
	    ebpfos_kprog_tzcnt64_ids.cnt != 1 ||
	    payload != ebpfos_kprog_tzcnt64_ids.pairs[0].id)
		return -EINVAL;
	*capability_mask = 0;
	*effect_mask = 0;
	memcpy(semantic_sha256, digest, sizeof(digest));
	return 0;
}

static int ebpfos_kop_tzcnt64_emit_x86(u8 *image, u32 *offset,
			bool emit, u64 payload, const struct bpf_prog *prog,
			const u8 *final_ip)
{
	static const u8 native[] = EBPFOS_KOP_TZCNT64_NATIVE_BYTES;

	(void)prog;
	(void)final_ip;
#ifdef CONFIG_X86
	if (!boot_cpu_has(X86_FEATURE_BMI1))
		return -EOPNOTSUPP;
#else
	return -EOPNOTSUPP;
#endif
	if (!offset || (emit && !image) ||
	    ebpfos_kprog_tzcnt64_ids.cnt != 1 ||
	    payload != ebpfos_kprog_tzcnt64_ids.pairs[0].id)
		return -EINVAL;
	if (emit)
		memcpy(image + *offset, native, sizeof(native));
	*offset += sizeof(native);
	return sizeof(native);
}

static struct bpf_kop ebpfos_kop_tzcnt64 = {
	.max_insn_cnt = 34,
	.max_emit_bytes = 5,
	.requirements = ebpfos_kop_tzcnt64_requirements,
	.instantiate_insn = ebpfos_kop_tzcnt64_instantiate,
	.emit_x86 = ebpfos_kop_tzcnt64_emit_x86,
};

static const struct bpf_kop * const ebpfos_kprog_tzcnt64_descs[] = {
	&ebpfos_kop_tzcnt64,
};

static const struct btf_kfunc_id_set ebpfos_kprog_tzcnt64_set = {
	.set = &ebpfos_kprog_tzcnt64_ids,
	.kop_descs = ebpfos_kprog_tzcnt64_descs,
};

static int ebpfos_kop_barrier_op(u64 payload)
{
	u64 id;

	if (ebpfos_kprog_compiler_barrier_ids.cnt != 1)
		return -EINVAL;
	id = ebpfos_kprog_compiler_barrier_ids.pairs[0].id;
	if (payload == id)
		return 1;
	if (payload == (id << 8 | 2))
		return 2;
	return -EINVAL;
}

static int ebpfos_kop_compiler_barrier_instantiate(u64 payload,
						  struct bpf_insn *insns)
{
	if (!insns || ebpfos_kop_barrier_op(payload) < 0)
		return -EINVAL;
	/* The IR side effect and memory clobber carry the compile-order rule. */
	insns[0] = BPF_MOV64_IMM(BPF_REG_0, 0);
	return 1;
}

static int ebpfos_kop_compiler_barrier_requirements(u64 payload,
		u64 *capability_mask, u64 *effect_mask,
		u8 semantic_sha256[SHA256_DIGEST_SIZE])
{
	static const u8 digest[SHA256_DIGEST_SIZE] =
		EBPFOS_KOP_COMPILER_BARRIER_SEMANTIC_SHA256;
	static const u8 pause_digest[SHA256_DIGEST_SIZE] =
		EBPFOS_KOP_PAUSE_SEMANTIC_SHA256;
	int op = ebpfos_kop_barrier_op(payload);

	if (!capability_mask || !effect_mask || !semantic_sha256 ||
	    op < 0)
		return -EINVAL;
	*capability_mask = 0;
	*effect_mask = 0;
	memcpy(semantic_sha256, op == 1 ? digest : pause_digest,
	       sizeof(digest));
	return 0;
}

static int ebpfos_kop_compiler_barrier_emit_x86(u8 *image, u32 *offset,
				bool emit, u64 payload, const struct bpf_prog *prog,
				const u8 *final_ip)
{
	static const u8 native[] = EBPFOS_KOP_COMPILER_BARRIER_NATIVE_BYTES;
	static const u8 pause_native[] = EBPFOS_KOP_PAUSE_NATIVE_BYTES;
	int op = ebpfos_kop_barrier_op(payload);
	const u8 *bytes = op == 1 ? native : pause_native;
	u32 len = op == 1 ? sizeof(native) : sizeof(pause_native);

	(void)prog;
	(void)final_ip;
	if (!offset || (emit && !image) || op < 0)
		return -EINVAL;
	if (emit)
		memcpy(image + *offset, bytes, len);
	*offset += len;
	return len;
}

static struct bpf_kop ebpfos_kop_compiler_barrier = {
	.max_insn_cnt = 1,
	.max_emit_bytes = 4,
	.requirements = ebpfos_kop_compiler_barrier_requirements,
	.instantiate_insn = ebpfos_kop_compiler_barrier_instantiate,
	.emit_x86 = ebpfos_kop_compiler_barrier_emit_x86,
};

static const struct bpf_kop * const ebpfos_kprog_compiler_barrier_descs[] = {
	&ebpfos_kop_compiler_barrier,
};

static const struct btf_kfunc_id_set ebpfos_kprog_compiler_barrier_set = {
	.set = &ebpfos_kprog_compiler_barrier_ids,
	.kop_descs = ebpfos_kprog_compiler_barrier_descs,
};

static const struct ebpfos_kop_bit64_spec *ebpfos_kop_bit64_spec(u64 payload)
{
	u8 op = payload & 0xff;
	u32 i;

	if (ebpfos_kprog_bit64_ids.cnt != 1 ||
	    payload >> 8 != ebpfos_kprog_bit64_ids.pairs[0].id)
		return NULL;
	for (i = 0; i < ARRAY_SIZE(ebpfos_kop_bit64_specs); i++)
		if (ebpfos_kop_bit64_specs[i].op == op)
			return &ebpfos_kop_bit64_specs[i];
	return NULL;
}

static int ebpfos_kop_bit64_instantiate(u64 payload, struct bpf_insn *insns)
{
	const struct ebpfos_kop_bit64_spec *spec = ebpfos_kop_bit64_spec(payload);
	int n = 0;

	if (!insns || !spec)
		return -EINVAL;
	/* x86 memory bit indexing uses a signed word offset and bit modulo 64. */
	insns[n++] = BPF_MOV64_REG(BPF_REG_3, BPF_REG_1);
	insns[n++] = BPF_MOV64_REG(BPF_REG_4, BPF_REG_2);
	insns[n++] = BPF_ALU64_IMM(BPF_ARSH, BPF_REG_4, 6);
	insns[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_4, 3);
	insns[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_3, BPF_REG_4);
	if (spec->op == EBPFOS_KOP_BIT64_RESET_NOLOCK ||
	    spec->op == EBPFOS_KOP_BIT64_SET_NOLOCK) {
		insns[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
		insns[n++] = BPF_MOV64_REG(BPF_REG_4, BPF_REG_2);
		insns[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_4, 63);
		insns[n++] = BPF_ALU64_REG(BPF_LSH, BPF_REG_0, BPF_REG_4);
		if (spec->op == EBPFOS_KOP_BIT64_RESET_NOLOCK)
			insns[n++] = BPF_ALU64_IMM(BPF_XOR, BPF_REG_0, -1);
		insns[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_3, 0);
		insns[n++] = BPF_ALU64_REG(
			spec->op == EBPFOS_KOP_BIT64_SET_NOLOCK ? BPF_OR : BPF_AND,
			BPF_REG_4, BPF_REG_0);
		insns[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_3, BPF_REG_4, 0);
		insns[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
	} else if (spec->op == EBPFOS_KOP_BIT64_TEST) {
		insns[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_3, 0);
		insns[n++] = BPF_MOV64_REG(BPF_REG_4, BPF_REG_2);
		insns[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_4, 63);
		insns[n++] = BPF_ALU64_REG(BPF_RSH, BPF_REG_0, BPF_REG_4);
		insns[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 1);
	} else {
		insns[n++] = BPF_MOV64_REG(BPF_REG_4, BPF_REG_2);
		insns[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_4, 63);
		insns[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
		insns[n++] = BPF_ALU64_REG(BPF_LSH, BPF_REG_0, BPF_REG_4);
		insns[n++] = BPF_MOV64_REG(BPF_REG_4, BPF_REG_0);
		if (spec->op == EBPFOS_KOP_BIT64_RESET)
			insns[n++] = BPF_ALU64_IMM(BPF_XOR, BPF_REG_0, -1);
		insns[n++] = BPF_ATOMIC_OP(BPF_DW,
			spec->op == EBPFOS_KOP_BIT64_SET ? BPF_OR | BPF_FETCH :
			BPF_AND | BPF_FETCH, BPF_REG_3, BPF_REG_0, 0);
		insns[n++] = BPF_ALU64_REG(BPF_AND, BPF_REG_0, BPF_REG_4);
		insns[n++] = BPF_MOV64_REG(BPF_REG_4, BPF_REG_2);
		insns[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_4, 63);
		insns[n++] = BPF_ALU64_REG(BPF_RSH, BPF_REG_0, BPF_REG_4);
	}
	insns[n++] = BPF_MOV64_IMM(BPF_REG_3, 0);
	insns[n++] = BPF_MOV64_IMM(BPF_REG_4, 0);
	return n;
}

static int ebpfos_kop_bit64_requirements(
	u64 payload, u64 *capability_mask, u64 *effect_mask,
	u8 semantic_sha256[SHA256_DIGEST_SIZE])
{
	const struct ebpfos_kop_bit64_spec *spec = ebpfos_kop_bit64_spec(payload);

	if (!spec || !capability_mask || !effect_mask || !semantic_sha256)
		return -EINVAL;
	*capability_mask = 0;
	*effect_mask = 0;
	memcpy(semantic_sha256, spec->semantic_sha256, SHA256_DIGEST_SIZE);
	return 0;
}

static int ebpfos_kop_bit64_emit_x86(u8 *image, u32 *offset, bool emit,
				     u64 payload, const struct bpf_prog *prog,
				     const u8 *final_ip)
{
	const struct ebpfos_kop_bit64_spec *spec = ebpfos_kop_bit64_spec(payload);

	(void)prog;
	(void)final_ip;
	if (!spec || !offset || (emit && !image))
		return -EINVAL;
	if (emit)
		memcpy(image + *offset, spec->native, spec->native_len);
	*offset += spec->native_len;
	return spec->native_len;
}

static struct bpf_kop ebpfos_kop_bit64 = {
	.max_insn_cnt = 18,
	.max_emit_bytes = 15,
	.requirements = ebpfos_kop_bit64_requirements,
	.instantiate_insn = ebpfos_kop_bit64_instantiate,
	.emit_x86 = ebpfos_kop_bit64_emit_x86,
};

static const struct bpf_kop * const ebpfos_kprog_bit64_descs[] = {
	&ebpfos_kop_bit64,
};

static const struct btf_kfunc_id_set ebpfos_kprog_bit64_set = {
	.set = &ebpfos_kprog_bit64_ids,
	.kop_descs = ebpfos_kprog_bit64_descs,
};

static const struct ebpfos_kop_atomic32_spec *
ebpfos_kop_atomic32_spec(u64 payload)
{
	u8 op = payload & 0xff;
	u32 i;

	if (ebpfos_kprog_atomic32_ids.cnt != 1 ||
	    payload >> 8 != ebpfos_kprog_atomic32_ids.pairs[0].id)
		return NULL;
	for (i = 0; i < ARRAY_SIZE(ebpfos_kop_atomic32_specs); i++)
		if (ebpfos_kop_atomic32_specs[i].op == op)
			return &ebpfos_kop_atomic32_specs[i];
	return NULL;
}

static int ebpfos_kop_atomic32_instantiate(u64 payload, struct bpf_insn *insns)
{
	const struct ebpfos_kop_atomic32_spec *spec =
		ebpfos_kop_atomic32_spec(payload);

	if (!insns || !spec)
		return -EINVAL;
	switch (spec->op) {
	case EBPFOS_KOP_ATOMIC32_CMPXCHG:
		insns[0] = BPF_MOV32_REG(BPF_REG_0, BPF_REG_3);
		insns[1] = BPF_ATOMIC_OP(BPF_W, BPF_CMPXCHG,
					 BPF_REG_1, BPF_REG_2, 0);
		break;
	case EBPFOS_KOP_ATOMIC32_XCHG:
	case EBPFOS_KOP_ATOMIC32_ADD:
		insns[0] = BPF_MOV32_REG(BPF_REG_0, BPF_REG_2);
		insns[1] = BPF_ATOMIC_OP(BPF_W,
			spec->op == EBPFOS_KOP_ATOMIC32_XCHG ? BPF_XCHG :
			BPF_ADD | BPF_FETCH, BPF_REG_1, BPF_REG_0, 0);
		break;
	case EBPFOS_KOP_ATOMIC32_INC:
	case EBPFOS_KOP_ATOMIC32_DEC:
		insns[0] = BPF_MOV32_IMM(BPF_REG_0,
			spec->op == EBPFOS_KOP_ATOMIC32_INC ? 1 : -1);
		insns[1] = BPF_ATOMIC_OP(BPF_W, BPF_ADD | BPF_FETCH,
					 BPF_REG_1, BPF_REG_0, 0);
		break;
	case EBPFOS_KOP_ATOMIC32_AND:
	case EBPFOS_KOP_ATOMIC32_OR:
		insns[0] = BPF_MOV32_REG(BPF_REG_0, BPF_REG_2);
		insns[1] = BPF_ATOMIC_OP(BPF_W,
			spec->op == EBPFOS_KOP_ATOMIC32_AND ? BPF_AND : BPF_OR,
			BPF_REG_1, BPF_REG_0, 0);
		insns[2] = BPF_MOV32_IMM(BPF_REG_0, 0);
		return 3;
	default:
		return -EINVAL;
	}
	return 2;
}

static int ebpfos_kop_atomic32_requirements(
	u64 payload, u64 *capability_mask, u64 *effect_mask,
	u8 semantic_sha256[SHA256_DIGEST_SIZE])
{
	const struct ebpfos_kop_atomic32_spec *spec =
		ebpfos_kop_atomic32_spec(payload);

	if (!spec || !capability_mask || !effect_mask || !semantic_sha256)
		return -EINVAL;
	*capability_mask = 0;
	*effect_mask = 0;
	memcpy(semantic_sha256, spec->semantic_sha256, SHA256_DIGEST_SIZE);
	return 0;
}

static int ebpfos_kop_atomic32_emit_x86(u8 *image, u32 *offset, bool emit,
					u64 payload, const struct bpf_prog *prog,
					const u8 *final_ip)
{
	const struct ebpfos_kop_atomic32_spec *spec =
		ebpfos_kop_atomic32_spec(payload);

	(void)prog;
	(void)final_ip;
	if (!spec || !offset || (emit && !image))
		return -EINVAL;
	if (emit)
		memcpy(image + *offset, spec->native, spec->native_len);
	*offset += spec->native_len;
	return spec->native_len;
}

static struct bpf_kop ebpfos_kop_atomic32 = {
	.max_insn_cnt = 3,
	.max_emit_bytes = 9,
	.requirements = ebpfos_kop_atomic32_requirements,
	.instantiate_insn = ebpfos_kop_atomic32_instantiate,
	.emit_x86 = ebpfos_kop_atomic32_emit_x86,
};

static const struct bpf_kop * const ebpfos_kprog_atomic32_descs[] = {
	&ebpfos_kop_atomic32,
};

static const struct btf_kfunc_id_set ebpfos_kprog_atomic32_set = {
	.set = &ebpfos_kprog_atomic32_ids,
	.kop_descs = ebpfos_kprog_atomic32_descs,
};

static const struct ebpfos_kop_atomic64_spec *
ebpfos_kop_atomic64_spec(u64 payload)
{
	u8 op = payload & 0xff;
	u32 i;

	if (ebpfos_kprog_atomic64_ids.cnt != 1 ||
	    payload >> 8 != ebpfos_kprog_atomic64_ids.pairs[0].id)
		return NULL;
	for (i = 0; i < ARRAY_SIZE(ebpfos_kop_atomic64_specs); i++)
		if (ebpfos_kop_atomic64_specs[i].op == op)
			return &ebpfos_kop_atomic64_specs[i];
	return NULL;
}

static int ebpfos_kop_atomic64_instantiate(u64 payload, struct bpf_insn *insns)
{
	const struct ebpfos_kop_atomic64_spec *spec =
		ebpfos_kop_atomic64_spec(payload);

	if (!insns || !spec)
		return -EINVAL;
	switch (spec->op) {
	case EBPFOS_KOP_ATOMIC64_CMPXCHG:
		insns[0] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_3);
		insns[1] = BPF_ATOMIC_OP(BPF_DW, BPF_CMPXCHG,
					 BPF_REG_1, BPF_REG_2, 0);
		break;
	case EBPFOS_KOP_ATOMIC64_XCHG:
	case EBPFOS_KOP_ATOMIC64_ADD:
		insns[0] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_2);
		insns[1] = BPF_ATOMIC_OP(BPF_DW,
			spec->op == EBPFOS_KOP_ATOMIC64_XCHG ? BPF_XCHG :
			BPF_ADD | BPF_FETCH, BPF_REG_1, BPF_REG_0, 0);
		break;
	case EBPFOS_KOP_ATOMIC64_INC:
	case EBPFOS_KOP_ATOMIC64_DEC:
		insns[0] = BPF_MOV64_IMM(BPF_REG_0,
			spec->op == EBPFOS_KOP_ATOMIC64_INC ? 1 : -1);
		insns[1] = BPF_ATOMIC_OP(BPF_DW, BPF_ADD | BPF_FETCH,
					 BPF_REG_1, BPF_REG_0, 0);
		break;
	case EBPFOS_KOP_ATOMIC64_AND:
	case EBPFOS_KOP_ATOMIC64_OR:
		insns[0] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_2);
		insns[1] = BPF_ATOMIC_OP(BPF_DW,
			spec->op == EBPFOS_KOP_ATOMIC64_AND ? BPF_AND : BPF_OR,
			BPF_REG_1, BPF_REG_0, 0);
		insns[2] = BPF_MOV64_IMM(BPF_REG_0, 0);
		return 3;
	default:
		return -EINVAL;
	}
	return 2;
}

static int ebpfos_kop_atomic64_requirements(
	u64 payload, u64 *capability_mask, u64 *effect_mask,
	u8 semantic_sha256[SHA256_DIGEST_SIZE])
{
	const struct ebpfos_kop_atomic64_spec *spec =
		ebpfos_kop_atomic64_spec(payload);

	if (!spec || !capability_mask || !effect_mask || !semantic_sha256)
		return -EINVAL;
	*capability_mask = 0;
	*effect_mask = 0;
	memcpy(semantic_sha256, spec->semantic_sha256, SHA256_DIGEST_SIZE);
	return 0;
}

static int ebpfos_kop_atomic64_emit_x86(u8 *image, u32 *offset, bool emit,
					u64 payload, const struct bpf_prog *prog,
					const u8 *final_ip)
{
	const struct ebpfos_kop_atomic64_spec *spec =
		ebpfos_kop_atomic64_spec(payload);

	(void)prog;
	(void)final_ip;
	if (!spec || !offset || (emit && !image))
		return -EINVAL;
	if (emit)
		memcpy(image + *offset, spec->native, spec->native_len);
	*offset += spec->native_len;
	return spec->native_len;
}

static struct bpf_kop ebpfos_kop_atomic64 = {
	.max_insn_cnt = 3,
	.max_emit_bytes = 12,
	.requirements = ebpfos_kop_atomic64_requirements,
	.instantiate_insn = ebpfos_kop_atomic64_instantiate,
	.emit_x86 = ebpfos_kop_atomic64_emit_x86,
};

static const struct bpf_kop * const ebpfos_kprog_atomic64_descs[] = {
	&ebpfos_kop_atomic64,
};

static const struct btf_kfunc_id_set ebpfos_kprog_atomic64_set = {
	.set = &ebpfos_kprog_atomic64_ids,
	.kop_descs = ebpfos_kprog_atomic64_descs,
};

static bool ebpfos_kop_xadd64_payload(u64 payload)
{
	return ebpfos_kprog_atomic_ids.cnt == 1 &&
	       payload == ebpfos_kprog_atomic_ids.pairs[0].id;
}

static int ebpfos_kop_xadd64_instantiate(u64 payload, struct bpf_insn *insns)
{
	if (!insns || !ebpfos_kop_xadd64_payload(payload))
		return -EINVAL;
	insns[0] = EBPFOS_KOP_XADD64_PROOF0;
	insns[1] = EBPFOS_KOP_XADD64_PROOF1;
	return 2;
}

static int ebpfos_kop_xadd64_emit_x86(u8 *image, u32 *offset, bool emit,
				      u64 payload, const struct bpf_prog *prog,
				      const u8 *final_ip)
{
	/* BPF r1=RDI, r2=RSI, r0=RAX. lock xaddq (%rdi),%rax. */
	static const u8 native[] = EBPFOS_KOP_XADD64_NATIVE_BYTES;

	(void)prog;
	(void)final_ip;
	if (!offset || (emit && !image) || !ebpfos_kop_xadd64_payload(payload))
		return -EINVAL;
	if (emit)
		memcpy(image + *offset, native, sizeof(native));
	*offset += sizeof(native);
	return sizeof(native);
}

static struct bpf_kop ebpfos_kop_xadd64 = {
	.max_insn_cnt = 2,
	.max_emit_bytes = 8,
	.semantic_sha256 = EBPFOS_KOP_XADD64_SEMANTIC_SHA256,
	.instantiate_insn = ebpfos_kop_xadd64_instantiate,
	.emit_x86 = ebpfos_kop_xadd64_emit_x86,
};

static const struct bpf_kop * const ebpfos_kprog_atomic_descs[] = {
	&ebpfos_kop_xadd64,
};

static const struct btf_kfunc_id_set ebpfos_kprog_atomic_set = {
	.set = &ebpfos_kprog_atomic_ids,
	.kop_descs = ebpfos_kprog_atomic_descs,
};

/* sha256("ebpfos-koperation-terminal-effect-v2:x86_64:f390:verified-native-backedge:verifier-noreturn") */
static const u8 ebpfos_kprog_terminal_semantic_sha256[SHA256_DIGEST_SIZE] = {
	0xf4, 0xae, 0x65, 0xa5, 0x34, 0xd1, 0xa6, 0xb0,
	0x5d, 0xae, 0x97, 0x22, 0xcd, 0xad, 0xaa, 0x25,
	0xa3, 0xf0, 0x97, 0x01, 0x75, 0x51, 0x85, 0x69,
	0x37, 0x5c, 0x2b, 0xf2, 0x70, 0x71, 0x62, 0x93,
};

static bool ebpfos_kprog_terminal_payload(u64 payload)
{
	return ebpfos_kprog_terminal_ids.cnt == 1 &&
	       payload == ebpfos_kprog_terminal_ids.pairs[0].id;
}

static int ebpfos_kprog_terminal_instantiate(u64 payload,
					      struct bpf_insn *insns)
{
	u32 effect_tag;

	if (!insns || !ebpfos_kprog_terminal_payload(payload))
		return -EINVAL;
	effect_tag = get_unaligned_le32(
		ebpfos_kprog_terminal_semantic_sha256) & S32_MAX;
	insns[0] = BPF_MOV64_IMM(BPF_REG_0, effect_tag);
	return 1;
}

static int ebpfos_kprog_terminal_requirements(
	u64 payload, u64 *capability_mask, u64 *effect_mask,
	u8 semantic_sha256[SHA256_DIGEST_SIZE])
{
	if (!capability_mask || !effect_mask || !semantic_sha256 ||
	    !ebpfos_kprog_terminal_payload(payload))
		return -EINVAL;
	*capability_mask = EBPFOS_CAP_KPROG_TERMINAL_ROOT;
	*effect_mask = EBPFOS_EFFECT_KPROG_TERMINAL_WAIT;
	memcpy(semantic_sha256, ebpfos_kprog_terminal_semantic_sha256,
	       SHA256_DIGEST_SIZE);
	return 0;
}

static int ebpfos_kprog_terminal_emit_x86(
	u8 *image, u32 *offset, bool emit, u64 payload,
	const struct bpf_prog *prog, const u8 *final_ip)
{
	static const u8 terminal[] = { 0xf3, 0x90 };

	(void)prog;
	(void)final_ip;
	if (!offset || (emit && !image) ||
	    !ebpfos_kprog_terminal_payload(payload))
		return -EINVAL;
	if (emit)
		memcpy(image + *offset, terminal, sizeof(terminal));
	*offset += sizeof(terminal);
	return sizeof(terminal);
}

static struct bpf_kop ebpfos_kprog_terminal = {
	.max_insn_cnt = 1,
	.max_emit_bytes = 2,
	.noreturn_native_backedge = true,
	.capability_mask = EBPFOS_CAP_KPROG_TERMINAL_ROOT,
	.effect_mask = EBPFOS_EFFECT_KPROG_TERMINAL_WAIT,
	.semantic_sha256 = {
		0xf4, 0xae, 0x65, 0xa5, 0x34, 0xd1, 0xa6, 0xb0,
		0x5d, 0xae, 0x97, 0x22, 0xcd, 0xad, 0xaa, 0x25,
		0xa3, 0xf0, 0x97, 0x01, 0x75, 0x51, 0x85, 0x69,
		0x37, 0x5c, 0x2b, 0xf2, 0x70, 0x71, 0x62, 0x93,
	},
	.requirements = ebpfos_kprog_terminal_requirements,
	.instantiate_insn = ebpfos_kprog_terminal_instantiate,
	.emit_x86 = ebpfos_kprog_terminal_emit_x86,
};

static const struct bpf_kop * const ebpfos_kprog_terminal_descs[] = {
	&ebpfos_kprog_terminal,
};

static int ebpfos_kprog_terminal_filter(const struct bpf_prog *prog,
					u32 kfunc_id)
{
	if (!btf_id_set8_contains(&ebpfos_kprog_terminal_ids, kfunc_id))
		return 0;
	if (!prog || !prog->aux)
		return 1;
	if (prog->aux->ebpfos_component)
		return 0;
	return prog->type != BPF_PROG_TYPE_SYSCALL || !prog->sleepable;
}

static const struct btf_kfunc_id_set ebpfos_kprog_terminal_set = {
	.set = &ebpfos_kprog_terminal_ids,
	.filter = ebpfos_kprog_terminal_filter,
	.kop_descs = ebpfos_kprog_terminal_descs,
};

static int ebpfos_kprog_component_filter(const struct bpf_prog *prog, u32 id);

#define EBPFOS_COMPONENT_KOP_SET(name) \
	static const struct btf_kfunc_id_set name##_component_set = { \
		.set = &name##_ids, \
		.filter = ebpfos_kprog_component_filter, \
		.kop_descs = name##_descs, \
	}

EBPFOS_COMPONENT_KOP_SET(ebpfos_kprog_atomic);
EBPFOS_COMPONENT_KOP_SET(ebpfos_kprog_atomic64);
EBPFOS_COMPONENT_KOP_SET(ebpfos_kprog_atomic32);
EBPFOS_COMPONENT_KOP_SET(ebpfos_kprog_bit64);
EBPFOS_COMPONENT_KOP_SET(ebpfos_kprog_compiler_barrier);
EBPFOS_COMPONENT_KOP_SET(ebpfos_kprog_tzcnt64);
EBPFOS_COMPONENT_KOP_SET(ebpfos_kprog_load32);
EBPFOS_COMPONENT_KOP_SET(ebpfos_kprog_current_task);
EBPFOS_COMPONENT_KOP_SET(ebpfos_kprog_cmp_mask);
EBPFOS_COMPONENT_KOP_SET(ebpfos_kprog_pushf64);

/* The descriptor's scalar proof calls this same read-only flags service. */
static const struct btf_kfunc_id_set ebpfos_kprog_pushf64_component_service_set = {
	.set = &ebpfos_kprog_pushf64_service_ids,
	.filter = ebpfos_kprog_component_filter,
};

static const struct btf_kfunc_id_set * const component_sets[] = {
		&ebpfos_kprog_atomic_component_set,
		&ebpfos_kprog_atomic64_component_set,
		&ebpfos_kprog_atomic32_component_set,
		&ebpfos_kprog_bit64_component_set,
		&ebpfos_kprog_compiler_barrier_component_set,
		&ebpfos_kprog_tzcnt64_component_set,
		&ebpfos_kprog_load32_component_set,
		&ebpfos_kprog_current_task_component_set,
		&ebpfos_kprog_cmp_mask_component_set,
		&ebpfos_kprog_pushf64_component_set,
		&ebpfos_kprog_pushf64_component_service_set,
	};

static int ebpfos_kprog_component_filter(const struct bpf_prog *prog, u32 id)
{
	size_t i;

	/* Tracing, raw tracepoints and LSM share one stock kfunc hook. This
	 * filter must not reject unrelated services registered in that hook.
	 */
	for (i = 0; i < ARRAY_SIZE(component_sets); i++)
		if (btf_id_set8_contains(component_sets[i]->set, id))
			return !prog || !prog->aux || !prog->aux->ebpfos_component ||
			       (prog->type != BPF_PROG_TYPE_RAW_TRACEPOINT &&
				!(prog->type == BPF_PROG_TYPE_TRACING &&
				  prog->expected_attach_type == BPF_TRACE_FENTRY)) ||
			       prog->sleepable;
	return 0;
}

static int __init ebpfos_kprog_register(void)
{
	size_t i;
	int err;

	if (ebpfos_kprog_pushf64_service_ids.cnt != 1)
		return -EINVAL;
	ebpfos_kop_pushf64.proof_kfunc_id =
		ebpfos_kprog_pushf64_service_ids.pairs[0].id;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_pushf64_service_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
					    &ebpfos_kprog_pushf64_service_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_pushf64_set);
	if (err)
		return err;
#ifdef CONFIG_X86
	if (ebpfos_kprog_cli_save_service_ids.cnt != 1 ||
	    ebpfos_kprog_popf64_restore_service_ids.cnt != 1 ||
	    ebpfos_kprog_sti_restore_service_ids.cnt != 1)
		return -EINVAL;
	ebpfos_kop_cli_save.proof_kfunc_id =
		ebpfos_kprog_cli_save_service_ids.pairs[0].id;
	ebpfos_kop_popf64_restore.proof_kfunc_id =
		ebpfos_kprog_popf64_restore_service_ids.pairs[0].id;
	ebpfos_kop_sti_restore.proof_kfunc_id =
		ebpfos_kprog_sti_restore_service_ids.pairs[0].id;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
					    &ebpfos_kprog_cli_save_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
					    &ebpfos_kprog_popf64_restore_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_cli_save_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_popf64_restore_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS,
					    &ebpfos_kprog_sti_restore_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_sti_restore_set);
	if (err)
		return err;
#define EBPFOS_REGISTER_READ_CR(number) \
	do { \
		if (ebpfos_kprog_read_cr##number##_service_ids.cnt != 1) \
			return -EINVAL; \
		ebpfos_kop_read_cr##number.proof_kfunc_id = \
			ebpfos_kprog_read_cr##number##_service_ids.pairs[0].id; \
		err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, \
			&ebpfos_kprog_read_cr##number##_service_set); \
		if (err) \
			return err; \
		err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, \
			&ebpfos_kprog_read_cr##number##_set); \
		if (err) \
			return err; \
	} while (0)
	EBPFOS_REGISTER_READ_CR(0);
	EBPFOS_REGISTER_READ_CR(2);
	EBPFOS_REGISTER_READ_CR(3);
	EBPFOS_REGISTER_READ_CR(4);
#undef EBPFOS_REGISTER_READ_CR
	if (ebpfos_kprog_reload_cr3_service_ids.cnt != 1)
		return -EINVAL;
	ebpfos_kop_reload_cr3.proof_kfunc_id =
		ebpfos_kprog_reload_cr3_service_ids.pairs[0].id;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_reload_cr3_service_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_reload_cr3_set);
	if (err)
		return err;
#endif
	if (ebpfos_kprog_rdtsc_service_ids.cnt != 1)
		return -EINVAL;
	ebpfos_kop_rdtsc.proof_kfunc_id =
		ebpfos_kprog_rdtsc_service_ids.pairs[0].id;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_rdtsc_service_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_rdtsc_set);
	if (err)
		return err;
	if (ebpfos_kprog_rdtscp_service_ids.cnt != 1)
		return -EINVAL;
	ebpfos_kop_rdtscp.proof_kfunc_id =
		ebpfos_kprog_rdtscp_service_ids.pairs[0].id;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_rdtscp_service_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_rdtscp_set);
	if (err)
		return err;
	if (ebpfos_kprog_rdseed64_service_ids.cnt != 1)
		return -EINVAL;
	ebpfos_kop_rdseed64.proof_kfunc_id =
		ebpfos_kprog_rdseed64_service_ids.pairs[0].id;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_rdseed64_service_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_rdseed64_set);
	if (err)
		return err;
	if (ebpfos_kprog_cpuid_service_ids.cnt != 1)
		return -EINVAL;
	ebpfos_kop_cpuid.proof_kfunc_id =
		ebpfos_kprog_cpuid_service_ids.pairs[0].id;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_cpuid_service_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_cpuid_set);
	if (err)
		return err;
	if (ebpfos_kprog_clflush_service_ids.cnt != 1)
		return -EINVAL;
	ebpfos_kop_clflush.proof_kfunc_id =
		ebpfos_kprog_clflush_service_ids.pairs[0].id;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_clflush_service_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_clflush_set);
	if (err)
		return err;
#ifdef CONFIG_X86
	if (ebpfos_kprog_clflushopt_service_ids.cnt != 1 ||
	    ebpfos_kprog_clwb_service_ids.cnt != 1)
		return -EINVAL;
	ebpfos_kop_clflushopt.proof_kfunc_id =
		ebpfos_kprog_clflushopt_service_ids.pairs[0].id;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_clflushopt_service_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_clflushopt_set);
	if (err)
		return err;
	ebpfos_kop_clwb.proof_kfunc_id =
		ebpfos_kprog_clwb_service_ids.pairs[0].id;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_clwb_service_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_clwb_set);
	if (err)
		return err;
	if (ebpfos_kprog_invlpg_service_ids.cnt != 1)
		return -EINVAL;
	ebpfos_kop_invlpg.proof_kfunc_id =
		ebpfos_kprog_invlpg_service_ids.pairs[0].id;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_invlpg_service_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_invlpg_set);
	if (err)
		return err;
	if (ebpfos_kprog_prefetcht0_service_ids.cnt != 1)
		return -EINVAL;
	ebpfos_kop_prefetcht0.proof_kfunc_id =
		ebpfos_kprog_prefetcht0_service_ids.pairs[0].id;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_prefetcht0_service_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_prefetcht0_set);
	if (err)
		return err;
	if (ebpfos_kprog_prefetchw_service_ids.cnt != 1)
		return -EINVAL;
	ebpfos_kop_prefetchw.proof_kfunc_id =
		ebpfos_kprog_prefetchw_service_ids.pairs[0].id;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_prefetchw_service_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_prefetchw_set);
	if (err)
		return err;
#endif
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_terminal_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_atomic_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_atomic64_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_atomic32_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_bit64_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					 &ebpfos_kprog_compiler_barrier_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					 &ebpfos_kprog_tzcnt64_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_load32_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					    &ebpfos_kprog_current_task_set);
	if (err)
		return err;
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					 &ebpfos_kprog_cmp_mask_set);
	if (err)
		return err;
	for (i = 0; i < ARRAY_SIZE(component_sets); i++) {
		err = register_btf_kfunc_id_set(BPF_PROG_TYPE_RAW_TRACEPOINT,
						component_sets[i]);
		if (err)
			return err;
	}
	return 0;
}
late_initcall(ebpfos_kprog_register);
