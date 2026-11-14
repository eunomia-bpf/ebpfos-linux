/* SPDX-License-Identifier: GPL-2.0-only */
#include "koperation_frame_addresses.generated.h"

#define EBPFOS_FRAME_ADDRESS_ROWS(X) \
 X(return_address0, RETURN_ADDRESS0, __builtin_return_address(0)) \
 X(frame_address0, FRAME_ADDRESS0, __builtin_frame_address(0))

/* The proof service's unsigned return gives the stock verifier an unknown
 * scalar. Its frame is not the descriptor's frame: no address equality,
 * bound, trust, refcount or pointer capability is asserted by the proof.
 * The bound instruction reads the compiled invocation's actual frame.
 */
__bpf_kfunc_start_defs();
#define EBPFOS_FRAME_ADDRESS_DECL(name, upper, value) \
__bpf_kfunc u64 bpf_ebpfos_x86_##name(void) { return (u64)(value); } \
__bpf_kfunc __attribute__((btf_decl_tag("bpf_kop_payload_id:0"))) u64 bpf_ebpfos_kop_##name(void) { return 0; }
EBPFOS_FRAME_ADDRESS_ROWS(EBPFOS_FRAME_ADDRESS_DECL)
#undef EBPFOS_FRAME_ADDRESS_DECL
__bpf_kfunc_end_defs();

#define EBPFOS_FRAME_ADDRESS_DEFINE(name, upper, value) \
BTF_KFUNCS_START(ebpfos_kprog_##name##_ids) \
BTF_ID_FLAGS(func, bpf_ebpfos_kop_##name) \
BTF_KFUNCS_END(ebpfos_kprog_##name##_ids) \
BTF_KFUNCS_START(ebpfos_kprog_##name##_service_ids) \
BTF_ID_FLAGS(func, bpf_ebpfos_x86_##name) \
BTF_KFUNCS_END(ebpfos_kprog_##name##_service_ids) \
static bool ebpfos_kop_##name##_payload(u64 payload) \
{ return ebpfos_kprog_##name##_ids.cnt == 1 && \
 ebpfos_kprog_##name##_service_ids.cnt == 1 && \
 payload == ebpfos_kprog_##name##_ids.pairs[0].id; } \
static int ebpfos_kop_##name##_instantiate(u64 payload, struct bpf_insn *insns) \
{ \
 insns[0] = (struct bpf_insn) { .code = BPF_JMP | BPF_CALL, \
  .src_reg = BPF_PSEUDO_KFUNC_CALL, .imm = ebpfos_kprog_##name##_service_ids.pairs[0].id }; \
 return 1; \
} \
static int ebpfos_kop_##name##_emit_x86(u8 *image, u32 *offset, bool emit, \
 u64 payload, const struct bpf_prog *prog, const u8 *final_ip) \
{ \
 static const u8 native[] = EBPFOS_KOP_##upper##_NATIVE_BYTES; \
 /* emit_prologue establishes RBP even with a private BPF data stack. \
  * Tail calls and exception callbacks reuse a frame, so are excluded. */ \
 if (emit) memcpy(image + *offset, native, sizeof(native)); \
 *offset += sizeof(native); return sizeof(native); \
} \
static struct bpf_kop ebpfos_kop_##name = { .max_insn_cnt = 1, .max_emit_bytes = 8, \
 .instantiate_insn = ebpfos_kop_##name##_instantiate, .emit_x86 = ebpfos_kop_##name##_emit_x86, }; \
static const struct bpf_kop * const ebpfos_kprog_##name##_descs[] = { &ebpfos_kop_##name }; \
static const struct btf_kfunc_id_set ebpfos_kprog_##name##_set = { \
 .set = &ebpfos_kprog_##name##_ids, .kop_descs = ebpfos_kprog_##name##_descs }; \
static const struct btf_kfunc_id_set ebpfos_kprog_##name##_service_set = { \
 .set = &ebpfos_kprog_##name##_service_ids };
EBPFOS_FRAME_ADDRESS_ROWS(EBPFOS_FRAME_ADDRESS_DEFINE)
#undef EBPFOS_FRAME_ADDRESS_DEFINE
