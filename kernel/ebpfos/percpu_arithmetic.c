// SPDX-License-Identifier: GPL-2.0-only
/* One GS arithmetic instruction; stock object selection and the identical
 * read/modify/write are the proof. Neither scalar storage nor a pointer field
 * acquires write permission from this descriptor.
 */
#include <crypto/sha2.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/unaligned.h>

#ifdef CONFIG_X86_64
#define ARITHMETIC_ROWS(X) \
 X(add, 32, BPF_W, BPF_ADD, 0, 0x01) \
 X(sub, 32, BPF_W, BPF_SUB, 0, 0x29) \
 X(inc, 32, BPF_W, BPF_ADD, 1, 0x00) \
 X(dec, 32, BPF_W, BPF_SUB, 1, 0x08) \
 X(add, 64, BPF_DW, BPF_ADD, 0, 0x01) \
 X(sub, 64, BPF_DW, BPF_SUB, 0, 0x29) \
 X(inc, 64, BPF_DW, BPF_ADD, 1, 0x00) \
 X(dec, 64, BPF_DW, BPF_SUB, 1, 0x08) \
 X(and, 8, BPF_B, BPF_AND, 0, 0x20) \
 X(or, 8, BPF_B, BPF_OR, 0, 0x08) \
 X(xor, 8, BPF_B, BPF_XOR, 0, 0x30) \
 X(and, 16, BPF_H, BPF_AND, 0, 0x21) \
 X(or, 16, BPF_H, BPF_OR, 0, 0x09) \
 X(xor, 16, BPF_H, BPF_XOR, 0, 0x31) \
 X(and, 32, BPF_W, BPF_AND, 0, 0x21) \
 X(or, 32, BPF_W, BPF_OR, 0, 0x09) \
 X(xor, 32, BPF_W, BPF_XOR, 0, 0x31) \
 X(and, 64, BPF_DW, BPF_AND, 0, 0x21) \
 X(or, 64, BPF_DW, BPF_OR, 0, 0x09) \
 X(xor, 64, BPF_DW, BPF_XOR, 0, 0x31)

__bpf_kfunc_start_defs();
#define DECL(op, width, size, alu, unary, opcode) \
__bpf_kfunc u64 bpf_ebpfos_kop_percpu_##op##width(void *template, u64 value) { return 0; }
ARITHMETIC_ROWS(DECL)
#undef DECL
__bpf_kfunc_end_defs();

/* Low 16 bits: nonnegative signed-16 field offset. High bits: no result (0),
 * ZF (1), or SF (2). The source width and opcode belong to the descriptor.
 */
static bool arithmetic_payload(u64 payload)
{
	return (payload & 0xffff) <= S16_MAX && (payload >> 16) <= 2;
}

static int arithmetic_requirements(u64 payload, u64 *cap, u64 *effects,
				   u8 digest[SHA256_DIGEST_SIZE])
{
	/* sha256("percpu-arithmetic-v1:original-symbol;stock-selection;exact-width-and-opcode;field-write-authority;typed-store-check;single-GS-memory-access;ZF-or-SF;proof-and-native-r3-zero;r6-input-copy") */
	static const u8 semantics[SHA256_DIGEST_SIZE] = {
		0x56, 0x18, 0x8d, 0xa7, 0xcc, 0x8c, 0x6c, 0xcf, 0xb0, 0xdf, 0xed, 0xff, 0xd3, 0xda, 0x4d, 0xc4, 0x64, 0x28, 0x04, 0x70, 0x69, 0xeb, 0x41, 0x0a, 0x0b, 0xd2, 0xb5, 0x5c, 0x1c, 0xd0, 0x6d, 0x14
	};
	if (!cap || !effects || !digest || !arithmetic_payload(payload))
		return -EINVAL;
	*cap = 0;
	*effects = 0;
	memcpy(digest, semantics, sizeof(semantics));
	return 0;
}

static int arithmetic_proof(u64 payload, struct bpf_insn *insns,
			    unsigned width, unsigned size, unsigned alu, bool unary)
{
	unsigned n = 0, flag = payload >> 16;

	if (!insns || !arithmetic_payload(payload))
		return -EINVAL;
	insns[n++] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_2);
	insns[n++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_this_cpu_ptr);
	insns[n++] = BPF_LDX_MEM(size, BPF_REG_3, BPF_REG_0, payload & 0xffff);
	insns[n++] = unary ? (width <= 32 ? BPF_ALU32_IMM(alu, BPF_REG_3, 1) :
					 BPF_ALU64_IMM(alu, BPF_REG_3, 1)) :
			    (width <= 32 ? BPF_ALU32_REG(alu, BPF_REG_3, BPF_REG_6) :
					 BPF_ALU64_REG(alu, BPF_REG_3, BPF_REG_6));
	if (width < 32)
		insns[n++] = BPF_ALU32_IMM(BPF_AND, BPF_REG_3, (1U << width) - 1);
	insns[n++] = BPF_STX_MEM(size, BPF_REG_0, BPF_REG_3, payload & 0xffff);
	insns[n++] = BPF_MOV32_IMM(BPF_REG_0, 0);
	if (flag) {
		if (flag == 1) {
			insns[n++] = BPF_JMP_IMM(BPF_JNE, BPF_REG_3, 0, 1);
			insns[n++] = BPF_MOV32_IMM(BPF_REG_0, 1);
		} else if (width < 32) {
			insns[n++] = BPF_MOV32_REG(BPF_REG_0, BPF_REG_3);
			insns[n++] = BPF_ALU32_IMM(BPF_RSH, BPF_REG_0, width - 1);
		} else {
			insns[n++] = width == 32 ? BPF_JMP32_IMM(BPF_JSGE, BPF_REG_3, 0, 1) :
				BPF_JMP_IMM(BPF_JSGE, BPF_REG_3, 0, 1);
			insns[n++] = BPF_MOV32_IMM(BPF_REG_0, 1);
		}
	}
	insns[n++] = BPF_MOV32_IMM(BPF_REG_3, 0);
	return n;
}

static int arithmetic_emit(u8 *image, u32 *offset, bool emit, u64 payload,
			   unsigned width, bool unary, unsigned opcode)
{
	u8 native[24];
	unsigned n = 0, flag = payload >> 16;

	if (!offset || (emit && !image) || !arithmetic_payload(payload))
		return -EINVAL;
	/* Native r6 = BPF argument r2, identical to the proof. */
	native[n++] = 0x48; native[n++] = 0x89; native[n++] = 0xf3;
	native[n++] = 0x65;
	if (width == 16) native[n++] = 0x66;
	if (width == 8) native[n++] = 0x40; /* SIL, not legacy DH. */
	if (width == 64) native[n++] = 0x48;
	native[n++] = unary ? 0xff : opcode;
	native[n++] = unary ? 0x87 | opcode : 0xb7;
	put_unaligned_le32(payload & 0xffff, native + n); n += 4;
	/* INC/DEC retain their native CF behavior; all bookkeeping preserves flags.
	 * There is exactly one memory access, including when a flag is returned.
	 */
	native[n++] = 0xba; put_unaligned_le32(0, native + n); n += 4;
	native[n++] = 0xb8; put_unaligned_le32(0, native + n); n += 4;
	if (flag) {
		native[n++] = 0x0f; native[n++] = flag == 1 ? 0x94 : 0x98;
		native[n++] = 0xc0;
	}
	if (emit) memcpy(image + *offset, native, n);
	*offset += n;
	return n;
}

static int arithmetic_component_filter(const struct bpf_prog *prog, u32 id)
{
	return !prog || !prog->aux || !prog->aux->ebpfos_component ||
	       prog->type != BPF_PROG_TYPE_RAW_TRACEPOINT || prog->sleepable;
}

#define DEFINE(op, width, size, alu, unary, opcode) \
BTF_KFUNCS_START(percpu_##op##width##_ids) \
BTF_ID_FLAGS(func, bpf_ebpfos_kop_percpu_##op##width) \
BTF_KFUNCS_END(percpu_##op##width##_ids) \
static int percpu_##op##width##_proof(u64 p, struct bpf_insn *i) \
{ return arithmetic_proof(p, i, width, size, alu, unary); } \
static int percpu_##op##width##_emit(u8 *i, u32 *o, bool emit, u64 p, \
 const struct bpf_prog *prog, const u8 *ip) \
{ return arithmetic_emit(i, o, emit, p, width, unary, opcode); } \
static const struct bpf_kop percpu_##op##width##_desc = { \
 .max_insn_cnt = 10, .max_emit_bytes = 24, .requirements = arithmetic_requirements, \
 .instantiate_insn = percpu_##op##width##_proof, .emit_x86 = percpu_##op##width##_emit }; \
static const struct bpf_kop * const percpu_##op##width##_descs[] = { &percpu_##op##width##_desc }; \
static const struct btf_kfunc_id_set percpu_##op##width##_set = { \
 .set = &percpu_##op##width##_ids, .kop_descs = percpu_##op##width##_descs }; \
static const struct btf_kfunc_id_set percpu_##op##width##_component_set = { \
 .set = &percpu_##op##width##_ids, .kop_descs = percpu_##op##width##_descs, \
 .filter = arithmetic_component_filter };
ARITHMETIC_ROWS(DEFINE)
#undef DEFINE

static int __init arithmetic_register(void)
{
	int err;
#define REGISTER(op, width, size, alu, unary, opcode) \
 err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &percpu_##op##width##_set); \
 if (err) return err; \
 err = register_btf_kfunc_id_set(BPF_PROG_TYPE_RAW_TRACEPOINT, &percpu_##op##width##_component_set); \
 if (err) return err;
	ARITHMETIC_ROWS(REGISTER)
#undef REGISTER
	return 0;
}
late_initcall(arithmetic_register);
#endif
