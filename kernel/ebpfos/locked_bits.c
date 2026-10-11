// SPDX-License-Identifier: GPL-2.0-only
/* Exact subword locked AND/OR. Ordinary proof loads/stores check the actual
 * destination, stored scalar and current function's field authority. Native
 * emission retains the single remotely atomic source operation and flags.
 */
#include <crypto/sha2.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/string.h>
#include "koperation_locked_bits.generated.h"

#ifdef CONFIG_X86_64
#define LOCKED_BITS_ROWS(X) \
 X(and, AND, 8, BPF_B, u8) X(or, OR, 8, BPF_B, u8) \
 X(and, AND, 16, BPF_H, u16) X(or, OR, 16, BPF_H, u16)

__bpf_kfunc_start_defs();
#define LOCKED_DECL(op, upper, width, size, type) \
__bpf_kfunc u32 bpf_ebpfos_kop_locked_##op##width(type *ptr, u32 mask) { return 0; }
LOCKED_BITS_ROWS(LOCKED_DECL)
#undef LOCKED_DECL
__bpf_kfunc_end_defs();

static int locked_component_filter(const struct bpf_prog *prog, u32 id)
{
	return !prog || !prog->aux || !prog->aux->ebpfos_component ||
	       prog->type != BPF_PROG_TYPE_RAW_TRACEPOINT || prog->sleepable;
}

#define LOCKED_DEFINE(op, upper, width, size, type) \
BTF_KFUNCS_START(locked_##op##width##_ids) \
BTF_ID_FLAGS(func, bpf_ebpfos_kop_locked_##op##width) \
BTF_KFUNCS_END(locked_##op##width##_ids) \
static bool locked_##op##width##_payload(u64 p) \
{ return locked_##op##width##_ids.cnt == 1 && p == locked_##op##width##_ids.pairs[0].id; } \
static int locked_##op##width##_proof(u64 p, struct bpf_insn *insns) \
{ \
 if (!insns || !locked_##op##width##_payload(p)) return -EINVAL; \
 insns[0] = BPF_LDX_MEM(size, BPF_REG_3, BPF_REG_1, 0); \
 insns[1] = BPF_ALU32_REG(BPF_##upper, BPF_REG_3, BPF_REG_2); \
 insns[2] = BPF_STX_MEM(size, BPF_REG_1, BPF_REG_3, 0); \
 insns[3] = BPF_MOV32_IMM(BPF_REG_3, 0); \
 insns[4] = BPF_MOV32_IMM(BPF_REG_0, 0); \
 return 5; \
} \
static int locked_##op##width##_requirements(u64 p, u64 *cap, u64 *effects, u8 d[SHA256_DIGEST_SIZE]) \
{ \
 static const u8 digest[] = EBPFOS_KOP_LOCKED_##upper##width##_SEMANTIC_SHA256; \
 if (!cap || !effects || !d || !locked_##op##width##_payload(p)) return -EINVAL; \
 *cap = 0; *effects = 0; memcpy(d, digest, sizeof(digest)); return 0; \
} \
static int locked_##op##width##_emit(u8 *image, u32 *offset, bool emit, u64 p, \
 const struct bpf_prog *prog, const u8 *ip) \
{ \
 static const u8 native[] = EBPFOS_KOP_LOCKED_##upper##width##_NATIVE_BYTES; \
 if (!offset || (emit && !image) || !locked_##op##width##_payload(p)) return -EINVAL; \
 if (emit) memcpy(image + *offset, native, sizeof(native)); \
 *offset += sizeof(native); return sizeof(native); \
} \
static const struct bpf_kop locked_##op##width##_desc = { \
 .max_insn_cnt = 5, .max_emit_bytes = 16, \
 .requirements = locked_##op##width##_requirements, .instantiate_insn = locked_##op##width##_proof, \
 .emit_x86 = locked_##op##width##_emit }; \
static const struct bpf_kop * const locked_##op##width##_descs[] = { &locked_##op##width##_desc }; \
static const struct btf_kfunc_id_set locked_##op##width##_set = { \
 .set = &locked_##op##width##_ids, .kop_descs = locked_##op##width##_descs }; \
static const struct btf_kfunc_id_set locked_##op##width##_component_set = { \
 .set = &locked_##op##width##_ids, .kop_descs = locked_##op##width##_descs, \
 .filter = locked_component_filter };
LOCKED_BITS_ROWS(LOCKED_DEFINE)
#undef LOCKED_DEFINE

static int __init locked_bits_init(void)
{
	int err;
#define LOCKED_REGISTER(op, upper, width, size, type) \
 err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &locked_##op##width##_set); \
 if (err) return err; \
 err = register_btf_kfunc_id_set(BPF_PROG_TYPE_RAW_TRACEPOINT, &locked_##op##width##_component_set); \
 if (err) return err;
	LOCKED_BITS_ROWS(LOCKED_REGISTER)
#undef LOCKED_REGISTER
	return 0;
}
late_initcall(locked_bits_init);
#endif
