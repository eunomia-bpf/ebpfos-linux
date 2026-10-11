/* SPDX-License-Identifier: GPL-2.0-only */
#ifdef CONFIG_X86_64
/* A source GS load remains a single instruction, including in preemptible
 * code. Its proof selects the original per-CPU symbol with the stock helper
 * and checks the same constant field offset/width with an ordinary load.
 * The helper rejects non-root template pointers. No scalar becomes a pointer.
 */
#define EBPFOS_PERCPU_READ_ROWS(X) \
 X(8, BPF_B, 0x0f, 0xb6, 0) \
 X(16, BPF_H, 0x0f, 0xb7, 0) \
 X(32, BPF_W, 0x8b, 0, 0) \
 X(64, BPF_DW, 0x8b, 0, 1)

__bpf_kfunc_start_defs();
#define EBPFOS_PERCPU_READ_DECL(width, size, opcode, second, wide) \
__bpf_kfunc u64 bpf_ebpfos_kop_percpu_read##width(void *template) { return 0; }
EBPFOS_PERCPU_READ_ROWS(EBPFOS_PERCPU_READ_DECL)
#undef EBPFOS_PERCPU_READ_DECL
__bpf_kfunc_end_defs();

#define EBPFOS_PERCPU_READ_DEFINE(width, size, opcode, second, wide) \
BTF_KFUNCS_START(ebpfos_kprog_percpu_read##width##_ids) \
BTF_ID_FLAGS(func, bpf_ebpfos_kop_percpu_read##width) \
BTF_KFUNCS_END(ebpfos_kprog_percpu_read##width##_ids) \
static bool ebpfos_kop_percpu_read##width##_payload(u64 payload) \
{ \
 return ebpfos_kprog_percpu_read##width##_ids.cnt == 1 && \
  (payload >> 16) == ebpfos_kprog_percpu_read##width##_ids.pairs[0].id && \
  (payload & 0xffff) <= S16_MAX; \
} \
static int ebpfos_kop_percpu_read##width##_instantiate(u64 payload, struct bpf_insn *insns) \
{ \
 if (!insns || !ebpfos_kop_percpu_read##width##_payload(payload)) return -EINVAL; \
 insns[0] = BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_this_cpu_ptr); \
 insns[1] = BPF_LDX_MEM(size, BPF_REG_0, BPF_REG_0, payload & 0xffff); \
 return 2; \
} \
static int ebpfos_kop_percpu_read##width##_requirements(u64 payload, u64 *cap, u64 *effects, \
 u8 semantic_sha256[SHA256_DIGEST_SIZE]) \
{ \
 /* sha256("ebpfos-percpu-read-v1:original-template;root-only;GS-load;" \
  * "payload=id<<16|nonnegative-s16-offset;width-by-descriptor;stock-helper-and-load-proof") */ \
 static const u8 digest[SHA256_DIGEST_SIZE] = { \
  0x34,0xd8,0x50,0x90,0x49,0xe7,0x48,0x69,0x9d,0x2d,0xde,0x43,0x92,0xbd,0x32,0xca, \
  0x4c,0xdd,0x47,0xde,0xf4,0x15,0x36,0x00,0x0a,0xdb,0xc4,0xca,0x8c,0x3a,0x1d,0xfa }; \
 if (!cap || !effects || !semantic_sha256 || !ebpfos_kop_percpu_read##width##_payload(payload)) return -EINVAL; \
 *cap = 0; *effects = 0; memcpy(semantic_sha256,digest,sizeof(digest)); return 0; \
} \
static int ebpfos_kop_percpu_read##width##_emit_x86(u8 *image, u32 *offset, bool emit, \
 u64 payload, const struct bpf_prog *prog, const u8 *final_ip) \
{ \
 u8 native[9]; unsigned n = 0; \
 if (!offset || (emit && !image) || !ebpfos_kop_percpu_read##width##_payload(payload)) return -EINVAL; \
 native[n++] = 0x65; \
 if (wide) native[n++] = 0x48; \
 native[n++] = opcode; \
 if (second) native[n++] = second; \
 native[n++] = 0x87; /* rax/eax, disp32(rdi), with GS selection */ \
 put_unaligned_le32((u32)(payload & 0xffff),native+n); n += 4; \
 if (emit) memcpy(image+*offset,native,n); \
 *offset += n; return n; \
} \
static struct bpf_kop ebpfos_kop_percpu_read##width = { \
 .max_insn_cnt = 2, .max_emit_bytes = 9, \
 .requirements = ebpfos_kop_percpu_read##width##_requirements, \
 .instantiate_insn = ebpfos_kop_percpu_read##width##_instantiate, \
 .emit_x86 = ebpfos_kop_percpu_read##width##_emit_x86 }; \
static const struct bpf_kop * const ebpfos_kprog_percpu_read##width##_descs[] = { \
 &ebpfos_kop_percpu_read##width }; \
static const struct btf_kfunc_id_set ebpfos_kprog_percpu_read##width##_set = { \
 .set = &ebpfos_kprog_percpu_read##width##_ids, \
 .kop_descs = ebpfos_kprog_percpu_read##width##_descs };
EBPFOS_PERCPU_READ_ROWS(EBPFOS_PERCPU_READ_DEFINE)
#undef EBPFOS_PERCPU_READ_DEFINE
#endif
