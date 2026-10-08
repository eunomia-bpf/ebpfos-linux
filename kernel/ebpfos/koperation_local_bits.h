/* SPDX-License-Identifier: GPL-2.0-only */
#include "koperation_local_bits.generated.h"

#define EBPFOS_LOCAL_BITS_ROWS(X) \
 X(and, AND, 8, BPF_B, 32, u8, u32) \
 X(or, OR, 8, BPF_B, 32, u8, u32) \
 X(and, AND, 16, BPF_H, 32, u16, u32) \
 X(or, OR, 16, BPF_H, 32, u16, u32) \
 X(and, AND, 32, BPF_W, 32, u32, u32) \
 X(or, OR, 32, BPF_W, 32, u32, u32) \
 X(and, AND, 64, BPF_DW, 64, u64, u64) \
 X(or, OR, 64, BPF_DW, 64, u64, u64)

__bpf_kfunc_start_defs();
#define EBPFOS_LOCAL_BITS_DECL(op, upper, width, span, alu, type, mask_type) \
__bpf_kfunc u32 bpf_ebpfos_kop_local_##op##width(type *ptr, mask_type mask) \
{ return 0; /* Only the proof or bound single memory instruction executes. */ }
EBPFOS_LOCAL_BITS_ROWS(EBPFOS_LOCAL_BITS_DECL)
#undef EBPFOS_LOCAL_BITS_DECL
__bpf_kfunc_end_defs();

/* Stock memory checking sees both the read and write at the source width.
 * No trusted pointer, fabricated capability or native per-CPU address enters
 * the proof. The emitted AND/OR is indivisible against local interrupts but
 * is not a remote LOCK operation. XOR only defines the scalar return ABI.
 */
#define EBPFOS_LOCAL_BITS_DEFINE(op, upper, width, span, alu, type, mask_type) \
BTF_KFUNCS_START(ebpfos_kprog_local_##op##width##_ids) \
BTF_ID_FLAGS(func, bpf_ebpfos_kop_local_##op##width) \
BTF_KFUNCS_END(ebpfos_kprog_local_##op##width##_ids) \
static bool ebpfos_kop_local_##op##width##_payload(u64 payload) \
{ return ebpfos_kprog_local_##op##width##_ids.cnt == 1 && \
  payload == ebpfos_kprog_local_##op##width##_ids.pairs[0].id; } \
static int ebpfos_kop_local_##op##width##_instantiate(u64 payload, struct bpf_insn *insns) \
{ \
 if (!insns || !ebpfos_kop_local_##op##width##_payload(payload)) return -EINVAL; \
 insns[0] = BPF_LDX_MEM(span, BPF_REG_3, BPF_REG_1, 0); \
 insns[1] = BPF_ALU##alu##_REG(BPF_##upper, BPF_REG_3, BPF_REG_2); \
 insns[2] = BPF_STX_MEM(span, BPF_REG_1, BPF_REG_3, 0); \
 insns[3] = BPF_MOV32_IMM(BPF_REG_0, 0); \
 return 4; \
} \
static int ebpfos_kop_local_##op##width##_requirements(u64 payload, u64 *cap, \
 u64 *effects, u8 semantic_sha256[SHA256_DIGEST_SIZE]) \
{ \
 static const u8 digest[] = EBPFOS_KOP_LOCAL_##upper##width##_SEMANTIC_SHA256; \
 if (!cap || !effects || !semantic_sha256 || !ebpfos_kop_local_##op##width##_payload(payload)) return -EINVAL; \
 *cap = 0; *effects = 0; memcpy(semantic_sha256, digest, sizeof(digest)); return 0; \
} \
static int ebpfos_kop_local_##op##width##_emit_x86(u8 *image, u32 *offset, bool emit, \
 u64 payload, const struct bpf_prog *prog, const u8 *final_ip) \
{ \
 static const u8 native[] = EBPFOS_KOP_LOCAL_##upper##width##_NATIVE_BYTES; \
 if (!offset || (emit && !image) || !ebpfos_kop_local_##op##width##_payload(payload)) return -EINVAL; \
 if (emit) memcpy(image + *offset, native, sizeof(native)); \
 *offset += sizeof(native); return sizeof(native); \
} \
static struct bpf_kop ebpfos_kop_local_##op##width = { \
 .max_insn_cnt = 4, .max_emit_bytes = 8, \
 .requirements = ebpfos_kop_local_##op##width##_requirements, \
 .instantiate_insn = ebpfos_kop_local_##op##width##_instantiate, \
 .emit_x86 = ebpfos_kop_local_##op##width##_emit_x86, \
}; \
static const struct bpf_kop * const ebpfos_kprog_local_##op##width##_descs[] = { \
 &ebpfos_kop_local_##op##width, \
}; \
static const struct btf_kfunc_id_set ebpfos_kprog_local_##op##width##_set = { \
 .set = &ebpfos_kprog_local_##op##width##_ids, \
 .kop_descs = ebpfos_kprog_local_##op##width##_descs, \
};
EBPFOS_LOCAL_BITS_ROWS(EBPFOS_LOCAL_BITS_DEFINE)
#undef EBPFOS_LOCAL_BITS_DEFINE
