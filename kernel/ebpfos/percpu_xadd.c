// SPDX-License-Identifier: GPL-2.0-only
/* Unlocked GS XADD, including its old-value result. Stock selection and
 * load/add/store checks retain the source field's type and write authority.
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
#define XADD_ROWS(X) X(32, BPF_W) X(64, BPF_DW)
__bpf_kfunc_start_defs();
#define DECL(width, size) \
__bpf_kfunc u64 bpf_ebpfos_kop_percpu_xadd##width(void *template, u64 value) { return 0; } \
__bpf_kfunc u64 bpf_ebpfos_kop_percpu_area_xadd##width(void *template, u64 value) { return 0; }
XADD_ROWS(DECL)
#undef DECL
__bpf_kfunc_end_defs();

static bool xadd_payload(u64 payload, bool area)
{
	return payload <= (area ? 0xffffff : S16_MAX);
}

static int xadd_requirements(u64 payload, u64 *cap, u64 *effects,
			     u8 digest[SHA256_DIGEST_SIZE], bool area)
{
	const char *semantics = area ?
		"percpu-area-xadd-v1:offset24;stock-selection;checked-load-add-store;old-value;single-unlocked-GS-XADD;r6-wide-sum;r3-zero" :
		"percpu-xadd-v1:offset15;stock-selection;checked-load-add-store;old-value;single-unlocked-GS-XADD;r6-wide-sum;r3-zero";
	if (!cap || !effects || !digest || !xadd_payload(payload, area))
		return -EINVAL;
	*cap = 0;
	*effects = 0;
	sha256(semantics, strlen(semantics), digest);
	return 0;
}

static int xadd_proof(u64 payload, struct bpf_insn *insns, unsigned size, bool area)
{
	unsigned n = 0;
	if (!insns || !xadd_payload(payload, area))
		return -EINVAL;
	insns[n++] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_2);
	insns[n++] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_this_cpu_ptr);
	if (area) insns[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, payload);
	insns[n++] = BPF_MOV64_REG(BPF_REG_3, BPF_REG_0);
	insns[n++] = BPF_LDX_MEM(size, BPF_REG_0, BPF_REG_3, area ? 0 : payload);
	insns[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_6, BPF_REG_0);
	insns[n++] = BPF_STX_MEM(size, BPF_REG_3, BPF_REG_6, area ? 0 : payload);
	insns[n++] = BPF_MOV32_IMM(BPF_REG_3, 0);
	return n;
}

static int xadd_emit(u8 *image, u32 *offset, bool emit, u64 payload,
		     unsigned width, bool area)
{
	u8 native[24];
	unsigned n = 0;
	if (!offset || (emit && !image) || !xadd_payload(payload, area))
		return -EINVAL;
	if (width == 64) native[n++] = 0x48;
	native[n++] = 0x89; native[n++] = 0xf0; /* r0 = r2, exact source width. */
	native[n++] = 0x65;
	if (width == 64) native[n++] = 0x48;
	native[n++] = 0x0f; native[n++] = 0xc1; native[n++] = 0x87;
	put_unaligned_le32(payload, native + n); n += 4;
	/* LEA models the proof's r6 sum without disturbing XADD's flags.
	 * Both paths return the old field and leave r3 zero. No CPU selection
	 * helper or second memory access intervenes at native execution.
	 */
	native[n++] = 0x48; native[n++] = 0x8d; native[n++] = 0x1c; native[n++] = 0x30;
	native[n++] = 0xba; put_unaligned_le32(0, native + n); n += 4;
	if (emit) memcpy(image + *offset, native, n);
	*offset += n;
	return n;
}

static int xadd_context_filter(const struct bpf_prog *prog, u32 id);

#define DEFINE(prefix, area, width, size) \
BTF_KFUNCS_START(prefix##width##_ids) \
BTF_ID_FLAGS(func, bpf_ebpfos_kop_##prefix##width) \
BTF_KFUNCS_END(prefix##width##_ids) \
static int prefix##width##_proof(u64 p, struct bpf_insn *i) \
{ return xadd_proof(p, i, size, area); } \
static int prefix##width##_emit(u8 *i, u32 *o, bool emit, u64 p, \
 const struct bpf_prog *prog, const u8 *ip) \
{ return xadd_emit(i, o, emit, p, width, area); } \
static int prefix##width##_requirements(u64 p, u64 *c, u64 *e, u8 d[SHA256_DIGEST_SIZE]) \
{ return xadd_requirements(p, c, e, d, area); } \
static const struct bpf_kop prefix##width##_desc = { \
 .max_insn_cnt = 7 + area, .max_emit_bytes = 24, .requirements = prefix##width##_requirements, \
 .instantiate_insn = prefix##width##_proof, .emit_x86 = prefix##width##_emit }; \
static const struct bpf_kop * const prefix##width##_descs[] = { &prefix##width##_desc }; \
static const struct btf_kfunc_id_set prefix##width##_set = { \
 .set = &prefix##width##_ids, .kop_descs = prefix##width##_descs, \
 .filter = xadd_context_filter };
#define OLD_DEFINE(width, size) DEFINE(percpu_xadd, false, width, size)
#define AREA_DEFINE(width, size) DEFINE(percpu_area_xadd, true, width, size)
XADD_ROWS(OLD_DEFINE)
XADD_ROWS(AREA_DEFINE)
#undef OLD_DEFINE
#undef AREA_DEFINE
#undef DEFINE

static int xadd_context_filter(const struct bpf_prog *prog, u32 id)
{
	bool ours = false;
#define MATCH(width, size) \
	ours |= btf_id_set8_contains(&percpu_xadd##width##_ids, id) || \
		btf_id_set8_contains(&percpu_area_xadd##width##_ids, id);
	XADD_ROWS(MATCH)
#undef MATCH
	/* Common filters must leave unrelated descriptors alone. */
	if (!ours) return 0;
	if (!prog) return 1;
	if (prog->type == BPF_PROG_TYPE_SYSCALL) return 0;
	return !prog->aux || !prog->aux->ebpfos_component ||
	       prog->type != BPF_PROG_TYPE_RAW_TRACEPOINT || prog->sleepable;
}

static int __init xadd_register(void)
{
	int err;
	struct btf *btf = bpf_get_btf_vmlinux();
	bool area = !IS_ERR_OR_NULL(btf) &&
		btf_find_by_name_kind(btf, "__percpu_area", BTF_KIND_VAR) > 0;
#define REGISTER(width, size) \
	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, \
	 area ? &percpu_area_xadd##width##_set : &percpu_xadd##width##_set); \
	if (err) return err;
	XADD_ROWS(REGISTER)
#undef REGISTER
	return 0;
}
late_initcall(xadd_register);
#endif
