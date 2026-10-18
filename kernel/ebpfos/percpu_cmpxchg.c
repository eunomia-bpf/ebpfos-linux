// SPDX-License-Identifier: GPL-2.0-only
/* One unlocked GS CMPXCHG. Stock CPU selection and exact-width ordinary
 * loads/stores check the destination, including a failed comparison.
 */
#include <crypto/sha2.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include "component_context.h"
#include <linux/string.h>
#include <linux/unaligned.h>

#ifdef CONFIG_X86_64
#define COMPARE_ROWS(X) X(8, BPF_B) X(16, BPF_H) X(32, BPF_W) X(64, BPF_DW)
__bpf_kfunc_start_defs();
#define DECL(width, size) \
__bpf_kfunc u64 bpf_ebpfos_kop_percpu_area_cmpxchg##width(void *template, u64 desired, u64 expected) { return 0; }
COMPARE_ROWS(DECL)
#undef DECL
__bpf_kfunc_end_defs();

static bool compare_payload(u64 payload)
{
	return payload <= 0xffffff;
}

static int compare_requirements(u64 payload, u64 *cap, u64 *effects,
				u8 digest[SHA256_DIGEST_SIZE])
{
	const char *semantics =
		"percpu-area-cmpxchg-v1:offset24;stock-selection;exact-width;always-checked-store;zeroextended-old;single-unlocked-GS-CMPXCHG;r6-desired;r7-normalized-expected;r3-r4-r5-zero";
	if (!cap || !effects || !digest || !compare_payload(payload))
		return -EINVAL;
	*cap = 0;
	*effects = 0;
	sha256(semantics, strlen(semantics), digest);
	return 0;
}

static int compare_proof(u64 payload, struct bpf_insn *insns,
			 unsigned width, unsigned size)
{
	unsigned n = 0;
	if (!insns || !compare_payload(payload))
		return -EINVAL;
	insns[n++] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_2);
	insns[n++] = width == 64 ? BPF_MOV64_REG(BPF_REG_7, BPF_REG_3) :
		BPF_MOV32_REG(BPF_REG_7, BPF_REG_3);
	if (width < 32)
		insns[n++] = BPF_ALU32_IMM(BPF_AND, BPF_REG_7, width == 8 ? 0xff : 0xffff);
	insns[n++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_this_cpu_ptr);
	insns[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, payload);
	insns[n++] = BPF_MOV64_REG(BPF_REG_4, BPF_REG_0);
	insns[n++] = BPF_LDX_MEM(size, BPF_REG_0, BPF_REG_4, 0);
	insns[n++] = BPF_MOV64_REG(BPF_REG_5, BPF_REG_0);
	insns[n++] = BPF_JMP_REG(BPF_JNE, BPF_REG_0, BPF_REG_7, 1);
	insns[n++] = BPF_MOV64_REG(BPF_REG_5, BPF_REG_6);
	/* x86 writes the old word back on failure, so permission is required
	 * on both paths. A conditional proof store would incorrectly accept
	 * read-only memory or missing writer authority on failure.
	 */
	insns[n++] = BPF_STX_MEM(size, BPF_REG_4, BPF_REG_5, 0);
	insns[n++] = BPF_MOV32_IMM(BPF_REG_3, 0);
	insns[n++] = BPF_MOV32_IMM(BPF_REG_4, 0);
	insns[n++] = BPF_MOV32_IMM(BPF_REG_5, 0);
	return n;
}

static int compare_emit(u8 *image, u32 *offset, bool emit, u64 payload,
			unsigned width)
{
	u8 native[36];
	unsigned n = 0;
	if (!offset || (emit && !image) || !compare_payload(payload))
		return -EINVAL;
	native[n++] = 0x48; native[n++] = 0x89; native[n++] = 0xf3; /* r6 = desired */
	if (width < 32) {
		native[n++] = 0x44; native[n++] = 0x0f;
		native[n++] = width == 8 ? 0xb6 : 0xb7;
		native[n++] = 0xea; /* movzx r13d, dl/dx */
	} else {
		native[n++] = width == 64 ? 0x49 : 0x41;
		native[n++] = 0x89; native[n++] = 0xd5; /* r7 = normalized expected */
	}
	native[n++] = 0x4c; native[n++] = 0x89; native[n++] = 0xe8; /* r0 = r7 */
	native[n++] = 0x65;
	if (width == 16) native[n++] = 0x66;
	if (width == 8 || width == 64) native[n++] = width == 8 ? 0x40 : 0x48;
	native[n++] = 0x0f; native[n++] = width == 8 ? 0xb0 : 0xb1;
	native[n++] = 0xb7; /* cmpxchg gs:[rdi + disp32], sil/si/esi/rsi */
	put_unaligned_le32(payload, native + n); n += 4;
	/* AL/AX retain zero high bits from the normalized accumulator. MOV
	 * clears the proof scratch outputs without changing CMPXCHG's flags.
	 */
	native[n++] = 0xba; put_unaligned_le32(0, native + n); n += 4;
	native[n++] = 0xb9; put_unaligned_le32(0, native + n); n += 4;
	native[n++] = 0x41; native[n++] = 0xb8;
	put_unaligned_le32(0, native + n); n += 4;
	if (emit) memcpy(image + *offset, native, n);
	*offset += n;
	return n;
}

static int compare_context_filter(const struct bpf_prog *prog, u32 id);
#define DEFINE(width, size) \
BTF_KFUNCS_START(percpu_area_cmpxchg##width##_ids) \
BTF_ID_FLAGS(func, bpf_ebpfos_kop_percpu_area_cmpxchg##width) \
BTF_KFUNCS_END(percpu_area_cmpxchg##width##_ids) \
static int compare##width##_proof(u64 p, struct bpf_insn *i) \
{ return compare_proof(p, i, width, size); } \
static int compare##width##_emit(u8 *i, u32 *o, bool emit, u64 p, \
 const struct bpf_prog *prog, const u8 *ip) \
{ return compare_emit(i, o, emit, p, width); } \
static const struct bpf_kop compare##width##_desc = { \
 .max_insn_cnt = 14, .max_emit_bytes = 36, .requirements = compare_requirements, \
 .instantiate_insn = compare##width##_proof, .emit_x86 = compare##width##_emit }; \
static const struct bpf_kop * const compare##width##_descs[] = { &compare##width##_desc }; \
static const struct btf_kfunc_id_set compare##width##_set = { \
 .set = &percpu_area_cmpxchg##width##_ids, .kop_descs = compare##width##_descs, \
 .filter = compare_context_filter };
COMPARE_ROWS(DEFINE)
#undef DEFINE

static int compare_context_filter(const struct bpf_prog *prog, u32 id)
{
	bool ours = false;
#define MATCH(width, size) ours |= !!btf_id_set8_contains(&percpu_area_cmpxchg##width##_ids, id);
	COMPARE_ROWS(MATCH)
#undef MATCH
	if (!ours) return 0;
	if (!prog) return 1;
	if (prog->type == BPF_PROG_TYPE_SYSCALL) return 0;
	return !ebpfos_non_sleepable_component(prog);
}

static int __init compare_register(void)
{
	int err;
	struct btf *btf = bpf_get_btf_vmlinux();
	if (IS_ERR_OR_NULL(btf) ||
	    btf_find_by_name_kind(btf, "__percpu_area", BTF_KIND_VAR) < 1)
		return 0;
#define REGISTER(width, size) \
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &compare##width##_set); \
	if (err) return err;
	COMPARE_ROWS(REGISTER)
#undef REGISTER
	return 0;
}
late_initcall(compare_register);
#endif
