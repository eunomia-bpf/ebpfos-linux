/* SPDX-License-Identifier: GPL-2.0-only */
#include "koperation_local_cmpxchg32.generated.h"
#include "koperation_local_cmpxchg64.generated.h"

/* Always store, including a failed comparison: x86 CMPXCHG needs write
 * authority even on failure. The stock proof checks both spans and preserves
 * the old word in R0. Only the emitted unlocked instruction is indivisible
 * with respect to local interrupts; no remote LOCK ordering is added.
 */
#define EBPFOS_LOCAL_CMPXCHG(width, bpf_width, word, jump) \
static bool ebpfos_kop_local_cmpxchg##width##_payload(u64 payload) \
{ \
	return ebpfos_kprog_local_cmpxchg##width##_ids.cnt == 1 && \
		payload == ebpfos_kprog_local_cmpxchg##width##_ids.pairs[0].id; \
} \
static int ebpfos_kop_local_cmpxchg##width##_instantiate(u64 payload, struct bpf_insn *insns) \
{ \
	if (!insns || !ebpfos_kop_local_cmpxchg##width##_payload(payload)) \
		return -EINVAL; \
	insns[0] = BPF_LDX_MEM(bpf_width, BPF_REG_0, BPF_REG_1, 0); \
	insns[1] = BPF_MOV##word##_REG(BPF_REG_4, BPF_REG_0); \
	insns[2] = jump(BPF_JNE, BPF_REG_0, BPF_REG_3, 1); \
	insns[3] = BPF_MOV##word##_REG(BPF_REG_4, BPF_REG_2); \
	insns[4] = BPF_STX_MEM(bpf_width, BPF_REG_1, BPF_REG_4, 0); \
	return 5; \
} \
static int ebpfos_kop_local_cmpxchg##width##_requirements(u64 payload, \
	u64 *capability_mask, u64 *effect_mask, u8 semantic_sha256[SHA256_DIGEST_SIZE]) \
{ \
	static const u8 digest[] = EBPFOS_KOP_LOCAL_CMPXCHG##width##_SEMANTIC_SHA256; \
	if (!capability_mask || !effect_mask || !semantic_sha256 || \
	    !ebpfos_kop_local_cmpxchg##width##_payload(payload)) \
		return -EINVAL; \
	*capability_mask = 0; *effect_mask = 0; \
	memcpy(semantic_sha256, digest, sizeof(digest)); \
	return 0; \
} \
static int ebpfos_kop_local_cmpxchg##width##_emit_x86(u8 *image, u32 *offset, bool emit, \
	u64 payload, const struct bpf_prog *prog, const u8 *final_ip) \
{ \
	static const u8 native[] = EBPFOS_KOP_LOCAL_CMPXCHG##width##_NATIVE_BYTES; \
	if (!offset || (emit && !image) || !ebpfos_kop_local_cmpxchg##width##_payload(payload)) \
		return -EINVAL; \
	if (emit) memcpy(image + *offset, native, sizeof(native)); \
	*offset += sizeof(native); return sizeof(native); \
} \
static struct bpf_kop ebpfos_kop_local_cmpxchg##width = { \
	.max_insn_cnt = 5, .max_emit_bytes = 8, \
	.requirements = ebpfos_kop_local_cmpxchg##width##_requirements, \
	.instantiate_insn = ebpfos_kop_local_cmpxchg##width##_instantiate, \
	.emit_x86 = ebpfos_kop_local_cmpxchg##width##_emit_x86, \
}; \
static const struct bpf_kop * const ebpfos_kprog_local_cmpxchg##width##_descs[] = { \
	&ebpfos_kop_local_cmpxchg##width, \
}; \
static const struct btf_kfunc_id_set ebpfos_kprog_local_cmpxchg##width##_set = { \
	.set = &ebpfos_kprog_local_cmpxchg##width##_ids, \
	.kop_descs = ebpfos_kprog_local_cmpxchg##width##_descs, \
}
EBPFOS_LOCAL_CMPXCHG(32, BPF_W, 32, BPF_JMP32_REG);
EBPFOS_LOCAL_CMPXCHG(64, BPF_DW, 64, BPF_JMP_REG);
#undef EBPFOS_LOCAL_CMPXCHG
