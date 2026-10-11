// SPDX-License-Identifier: GPL-2.0-only
/* Memory XCHG is implicitly locked at its exact source width. The ordinary
 * proof load/store checks bounds, scalar storage and source write authority;
 * native emission supplies the indivisible exchange. Register MOV scaffolding
 * preserves R1-R5 and architectural flags around that one memory operation.
 */
#include <crypto/sha2.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/string.h>
#include "koperation_locked_xchg.generated.h"

#ifdef CONFIG_X86_64
#define XCHG_ROWS(X) X(8, BPF_B, u8) X(16, BPF_H, u16)

__bpf_kfunc_start_defs();
#define XCHG_DECL(width, size, type) \
__bpf_kfunc u32 bpf_ebpfos_kop_locked_xchg##width(type *ptr, u32 value) { return 0; }
XCHG_ROWS(XCHG_DECL)
#undef XCHG_DECL
__bpf_kfunc_end_defs();

static int xchg_context_filter(const struct bpf_prog *prog, u32 id);

#define XCHG_DEFINE(width, size, type) \
BTF_KFUNCS_START(xchg##width##_ids) \
BTF_ID_FLAGS(func, bpf_ebpfos_kop_locked_xchg##width) \
BTF_KFUNCS_END(xchg##width##_ids) \
static bool xchg##width##_payload(u64 p) \
{ return xchg##width##_ids.cnt == 1 && p == xchg##width##_ids.pairs[0].id; } \
static int xchg##width##_proof(u64 p, struct bpf_insn *insns) \
{ \
 if (!insns || !xchg##width##_payload(p)) return -EINVAL; \
 insns[0] = BPF_LDX_MEM(size, BPF_REG_0, BPF_REG_1, 0); \
 insns[1] = BPF_STX_MEM(size, BPF_REG_1, BPF_REG_2, 0); \
 return 2; \
} \
static int xchg##width##_requirements(u64 p, u64 *cap, u64 *effects, u8 d[SHA256_DIGEST_SIZE]) \
{ \
 static const u8 digest[] = EBPFOS_KOP_LOCKED_XCHG##width##_SEMANTIC_SHA256; \
 if (!cap || !effects || !d || !xchg##width##_payload(p)) return -EINVAL; \
 *cap = 0; *effects = 0; memcpy(d, digest, sizeof(digest)); return 0; \
} \
static int xchg##width##_emit(u8 *image, u32 *offset, bool emit, u64 p, \
 const struct bpf_prog *prog, const u8 *ip) \
{ \
 static const u8 native[] = EBPFOS_KOP_LOCKED_XCHG##width##_NATIVE_BYTES; \
 if (!offset || (emit && !image) || !xchg##width##_payload(p)) return -EINVAL; \
 if (emit) memcpy(image + *offset, native, sizeof(native)); \
 *offset += sizeof(native); return sizeof(native); \
} \
static const struct bpf_kop xchg##width##_desc = { \
 .max_insn_cnt = 2, .max_emit_bytes = 16, \
 .requirements = xchg##width##_requirements, .instantiate_insn = xchg##width##_proof, \
 .emit_x86 = xchg##width##_emit }; \
static const struct bpf_kop * const xchg##width##_descs[] = { &xchg##width##_desc }; \
static const struct btf_kfunc_id_set xchg##width##_set = { \
 .set = &xchg##width##_ids, .kop_descs = xchg##width##_descs, \
 .filter = xchg_context_filter };
XCHG_ROWS(XCHG_DEFINE)
#undef XCHG_DEFINE

static int xchg_context_filter(const struct bpf_prog *prog, u32 id)
{
	/* COMMON filters also see unrelated kfuncs: constrain only our IDs.
	 * One registration serves both declared contexts, without consuming a
	 * second entry or increasing either stock per-hook capacity.
	 */
	if (!xchg8_payload(id) && !xchg16_payload(id))
		return 0;
	if (!prog)
		return 1;
	if (prog->type == BPF_PROG_TYPE_SYSCALL)
		return 0;
	return !prog->aux || !prog->aux->ebpfos_component ||
	       prog->type != BPF_PROG_TYPE_RAW_TRACEPOINT || prog->sleepable;
}

static int __init locked_xchg_init(void)
{
	int err;
#define XCHG_REGISTER(width, size, type) \
 err = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &xchg##width##_set); \
 if (err) return err;
	XCHG_ROWS(XCHG_REGISTER)
#undef XCHG_REGISTER
	return 0;
}
late_initcall(locked_xchg_init);
#endif
