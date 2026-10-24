/* SPDX-License-Identifier: GPL-2.0-only */
#include "koperation_native_arguments.generated.h"

#define EBPFOS_NATIVE_ARGUMENT_ROWS(X) \
 X(native_argument6, NATIVE_ARGUMENT6, 0)

/* Snapshot the sixth x86 C argument as an unknown scalar, without a pointer
 * capability. The compiler captures it before any source call. The x86 JIT
 * must retain the native argument register: private stacks use R9 instead.
 */
__bpf_kfunc_start_defs();
#define EBPFOS_NATIVE_ARGUMENT_DECL(name, upper, value) \
__bpf_kfunc u64 bpf_ebpfos_x86_##name(void) { return (u64)(value); } \
__bpf_kfunc u64 bpf_ebpfos_kop_##name(void) { return 0; }
EBPFOS_NATIVE_ARGUMENT_ROWS(EBPFOS_NATIVE_ARGUMENT_DECL)
#undef EBPFOS_NATIVE_ARGUMENT_DECL
__bpf_kfunc_end_defs();

#define EBPFOS_NATIVE_ARGUMENT_DEFINE(name, upper, value) \
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
 if (!insns || !ebpfos_kop_##name##_payload(payload)) return -EINVAL; \
 insns[0] = (struct bpf_insn) { .code = BPF_JMP | BPF_CALL, \
  .src_reg = BPF_PSEUDO_KFUNC_CALL, .imm = ebpfos_kprog_##name##_service_ids.pairs[0].id }; \
 return 1; \
} \
static int ebpfos_kop_##name##_requirements(u64 payload, u64 *cap, u64 *effects, \
 u8 semantic_sha256[SHA256_DIGEST_SIZE]) \
{ \
 static const u8 digest[] = EBPFOS_KOP_##upper##_SEMANTIC_SHA256; \
 if (!cap || !effects || !semantic_sha256 || !ebpfos_kop_##name##_payload(payload)) return -EINVAL; \
 *cap = 0; *effects = 0; memcpy(semantic_sha256, digest, sizeof(digest)); return 0; \
} \
static struct bpf_kop ebpfos_kop_##name; \
static int ebpfos_kop_##name##_emit_x86(u8 *image, u32 *offset, bool emit, \
 u64 payload, const struct bpf_prog *prog, const u8 *final_ip) \
{ \
 static const u8 native[] = EBPFOS_KOP_##upper##_NATIVE_BYTES; \
 /* Private stacks overwrite R9 before the first BPF instruction. \
  * FineIBT's optional BHI call also has no six-argument contract. */ \
 if (!prog || !prog->aux || prog->aux->tail_call_reachable || \
     prog->aux->exception_cb || prog->aux->jits_use_priv_stack || prog->aux->priv_stack_ptr || \
     IS_ENABLED(CONFIG_FINEIBT)) return -EOPNOTSUPP; \
 if (!offset || (emit && !image) || !ebpfos_kop_##name##_payload(payload)) return -EINVAL; \
 /* Calls can overwrite R9; require one capture before other calls. \
  * Branches after it may loop, but cannot re-enter the capture. */ \
 { \
  u32 capture = U32_MAX; \
  for (u32 i = 0; i < prog->len; ++i) { \
   const struct bpf_insn *insn = &prog->insnsi[i]; \
   const struct bpf_kop *found; u64 found_payload; \
   bool snapshot; \
   if (BPF_CLASS(insn->code) != BPF_JMP || BPF_OP(insn->code) != BPF_CALL) continue; \
   snapshot = insn->code == (BPF_JMP | BPF_CALL) && \
       !bpf_jit_get_kop_payload(prog, insn, &found, &found_payload) && \
       found == &ebpfos_kop_##name && found_payload == payload; \
   if (snapshot) { \
    if (capture != U32_MAX) return -EOPNOTSUPP; \
    capture = i; \
   } else if (capture == U32_MAX) return -EOPNOTSUPP; \
  } \
  if (capture == U32_MAX) return -EOPNOTSUPP; \
  for (u32 i = 0; i < prog->len; ++i) { \
   const struct bpf_insn *insn = &prog->insnsi[i]; \
   u8 cls = BPF_CLASS(insn->code), op = BPF_OP(insn->code); \
   s64 displacement; \
   if ((cls != BPF_JMP && cls != BPF_JMP32) || op == BPF_CALL || op == BPF_EXIT) continue; \
   displacement = cls == BPF_JMP32 && op == BPF_JA ? insn->imm : insn->off; \
   if (i > capture && (s64)i + 1 + displacement <= capture) return -EOPNOTSUPP; \
  } \
 } \
 if (emit) memcpy(image + *offset, native, sizeof(native)); \
 *offset += sizeof(native); return sizeof(native); \
} \
static struct bpf_kop ebpfos_kop_##name = { .max_insn_cnt = 1, .max_emit_bytes = 8, \
 .requirements = ebpfos_kop_##name##_requirements, \
 .instantiate_insn = ebpfos_kop_##name##_instantiate, .emit_x86 = ebpfos_kop_##name##_emit_x86, }; \
static const struct bpf_kop * const ebpfos_kprog_##name##_descs[] = { &ebpfos_kop_##name }; \
static const struct btf_kfunc_id_set ebpfos_kprog_##name##_set = { \
 .set = &ebpfos_kprog_##name##_ids, .kop_descs = ebpfos_kprog_##name##_descs }; \
static const struct btf_kfunc_id_set ebpfos_kprog_##name##_service_set = { \
 .set = &ebpfos_kprog_##name##_service_ids };
EBPFOS_NATIVE_ARGUMENT_ROWS(EBPFOS_NATIVE_ARGUMENT_DEFINE)
#undef EBPFOS_NATIVE_ARGUMENT_DEFINE
