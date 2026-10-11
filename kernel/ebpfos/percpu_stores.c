// SPDX-License-Identifier: GPL-2.0-only
/* An immediate GS store: stock selection and the same field store prove the
 * access. The returned scalar is ABI bookkeeping, never a pointer producer.
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
#define PERCPU_STORE_ROWS(X) \
 X(8, BPF_B) X(16, BPF_H) X(32, BPF_W) X(64, BPF_DW)

__bpf_kfunc_start_defs();
#define STORE_DECL(width, size) \
__bpf_kfunc u64 bpf_ebpfos_kop_percpu_store##width(void *template) { return 0; }
PERCPU_STORE_ROWS(STORE_DECL)
#undef STORE_DECL
__bpf_kfunc_end_defs();

/* payload = u32 source immediate << 16 | nonnegative signed-16 offset.
 * Width comes from the descriptor. A 64-bit MOV sign extends its imm32.
 */
static bool store_payload(u64 payload, unsigned width)
{
	return !(payload >> 48) && (payload & 0xffff) <= S16_MAX &&
	       (width >= 32 || (payload >> 16) < (1ULL << width));
}

static int store_requirements(u64 payload, unsigned width, u64 *cap,
			      u64 *effects, u8 digest[SHA256_DIGEST_SIZE])
{
	/* sha256("percpu-store-v1:stock-template-selection;exact-field-write;"
	 * "immediate-by-payload;width-by-descriptor;single-GS-MOV;scalar-return") */
	static const u8 semantics[SHA256_DIGEST_SIZE] = {
		0xc3,0x8e,0xf9,0x7e,0x12,0x2b,0xd7,0x62,0x9e,0x95,0x8e,0xd5,0xdf,0xec,0x6b,0x0c,
		0xb1,0xe3,0xfb,0x61,0x85,0xa7,0x62,0x80,0x0a,0x46,0x6f,0xcc,0x45,0xc6,0xe2,0x04 };
	if (!cap || !effects || !digest || !store_payload(payload, width))
		return -EINVAL;
	*cap = 0;
	*effects = 0;
	memcpy(digest, semantics, sizeof(semantics));
	return 0;
}

static int store_emit(u8 *image, u32 *offset, bool emit, u64 payload,
		      unsigned width)
{
	u8 native[20];
	u32 immediate = payload >> 16;
	unsigned n = 0;

	if (!offset || (emit && !image) || !store_payload(payload, width))
		return -EINVAL;
	native[n++] = 0x65;
	if (width == 16) native[n++] = 0x66;
	if (width == 64) native[n++] = 0x48;
	native[n++] = width == 8 ? 0xc6 : 0xc7;
	native[n++] = 0x87; /* imm, disp32(rdi), with GS selection */
	put_unaligned_le32(payload & 0xffff, native + n); n += 4;
	if (width == 8) native[n++] = immediate;
	else if (width == 16) { put_unaligned_le16(immediate, native + n); n += 2; }
	else { put_unaligned_le32(immediate, native + n); n += 4; }
	/* Preserve arithmetic flags. This MOV supplies the proof's scalar return;
	 * there is still exactly one native access to the selected CPU object.
	 */
	if (width == 64) {
		native[n++] = 0x48; native[n++] = 0xc7; native[n++] = 0xc0;
	} else native[n++] = 0xb8;
	put_unaligned_le32(immediate, native + n); n += 4;
	if (emit) memcpy(image + *offset, native, n);
	*offset += n;
	return n;
}

static int store_component_filter(const struct bpf_prog *prog, u32 id)
{
	return !prog || !prog->aux || !prog->aux->ebpfos_component ||
	       prog->type != BPF_PROG_TYPE_RAW_TRACEPOINT || prog->sleepable;
}

#define STORE_DEFINE(width, size) \
BTF_KFUNCS_START(percpu_store##width##_ids) \
BTF_ID_FLAGS(func, bpf_ebpfos_kop_percpu_store##width) \
BTF_KFUNCS_END(percpu_store##width##_ids) \
static int percpu_store##width##_proof(u64 payload, struct bpf_insn *insns) \
{ \
 if (!insns || !store_payload(payload, width)) return -EINVAL; \
 insns[0] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_this_cpu_ptr); \
 insns[1] = BPF_ST_MEM(size, BPF_REG_0, payload & 0xffff, (u32)(payload >> 16)); \
 insns[2] = width == 64 ? BPF_MOV64_IMM(BPF_REG_0, (u32)(payload >> 16)) : \
                         BPF_MOV32_IMM(BPF_REG_0, (u32)(payload >> 16)); \
 return 3; \
} \
static int percpu_store##width##_requirements(u64 p, u64 *c, u64 *e, u8 d[SHA256_DIGEST_SIZE]) \
{ return store_requirements(p, width, c, e, d); } \
static int percpu_store##width##_emit(u8 *i, u32 *o, bool emit, u64 p, \
 const struct bpf_prog *prog, const u8 *ip) \
{ return store_emit(i, o, emit, p, width); } \
static const struct bpf_kop percpu_store##width##_desc = { \
 .max_insn_cnt = 3, .max_emit_bytes = 20, \
 .requirements = percpu_store##width##_requirements, .instantiate_insn = percpu_store##width##_proof, \
 .emit_x86 = percpu_store##width##_emit }; \
static const struct bpf_kop * const percpu_store##width##_descs[] = { &percpu_store##width##_desc }; \
static const struct btf_kfunc_id_set percpu_store##width##_set = { \
 .set = &percpu_store##width##_ids, .kop_descs = percpu_store##width##_descs }; \
static const struct btf_kfunc_id_set percpu_store##width##_component_set = { \
 .set = &percpu_store##width##_ids, .kop_descs = percpu_store##width##_descs, \
 .filter = store_component_filter };
PERCPU_STORE_ROWS(STORE_DEFINE)
#undef STORE_DEFINE

static int __init percpu_stores_init(void)
{
	int err;
#define STORE_REGISTER(width, size) \
 err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &percpu_store##width##_set); \
 if (err) return err; \
 err = register_btf_kfunc_id_set(BPF_PROG_TYPE_RAW_TRACEPOINT, &percpu_store##width##_component_set); \
 if (err) return err;
	PERCPU_STORE_ROWS(STORE_REGISTER)
#undef STORE_REGISTER
	return 0;
}
late_initcall(percpu_stores_init);
#endif
