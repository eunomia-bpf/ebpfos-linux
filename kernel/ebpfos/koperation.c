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
__bpf_kfunc_end_defs();

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

static int ebpfos_kop_compiler_barrier_instantiate(u64 payload,
						  struct bpf_insn *insns)
{
	if (!insns || ebpfos_kprog_compiler_barrier_ids.cnt != 1 ||
	    payload != ebpfos_kprog_compiler_barrier_ids.pairs[0].id)
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

	if (!capability_mask || !effect_mask || !semantic_sha256 ||
	    ebpfos_kprog_compiler_barrier_ids.cnt != 1 ||
	    payload != ebpfos_kprog_compiler_barrier_ids.pairs[0].id)
		return -EINVAL;
	*capability_mask = 0;
	*effect_mask = 0;
	memcpy(semantic_sha256, digest, sizeof(digest));
	return 0;
}

static int ebpfos_kop_compiler_barrier_emit_x86(u8 *image, u32 *offset,
				bool emit, u64 payload, const struct bpf_prog *prog,
				const u8 *final_ip)
{
	static const u8 native[] = EBPFOS_KOP_COMPILER_BARRIER_NATIVE_BYTES;

	(void)prog;
	(void)final_ip;
	if (!offset || (emit && !image) ||
	    ebpfos_kprog_compiler_barrier_ids.cnt != 1 ||
	    payload != ebpfos_kprog_compiler_barrier_ids.pairs[0].id)
		return -EINVAL;
	if (emit)
		memcpy(image + *offset, native, sizeof(native));
	*offset += sizeof(native);
	return sizeof(native);
}

static struct bpf_kop ebpfos_kop_compiler_barrier = {
	.max_insn_cnt = 1,
	.max_emit_bytes = 2,
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
	if (spec->op == EBPFOS_KOP_BIT64_RESET_NOLOCK) {
		insns[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
		insns[n++] = BPF_MOV64_REG(BPF_REG_4, BPF_REG_2);
		insns[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_4, 63);
		insns[n++] = BPF_ALU64_REG(BPF_LSH, BPF_REG_0, BPF_REG_4);
		insns[n++] = BPF_ALU64_IMM(BPF_XOR, BPF_REG_0, -1);
		insns[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_4, BPF_REG_3, 0);
		insns[n++] = BPF_ALU64_REG(BPF_AND, BPF_REG_4, BPF_REG_0);
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

static int __init ebpfos_kprog_register(void)
{
	int err;

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
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					 &ebpfos_kprog_cmp_mask_set);
}
late_initcall(ebpfos_kprog_register);
