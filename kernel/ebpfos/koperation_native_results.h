/* SPDX-License-Identifier: GPL-2.0-only */
#include "koperation_native_results.generated.h"
#include "native_result_abi.h"

#define EBPFOS_NATIVE_RESULT_ROWS(X) X(native_result2, NATIVE_RESULT2, 0)

__bpf_kfunc_start_defs();
__bpf_kfunc u64 bpf_ebpfos_x86_native_result2(u64 value, u64 first) { return 0; }
__bpf_kfunc u64 bpf_ebpfos_kop_native_result2(u64 value, u64 first) { return 0; }
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(ebpfos_kprog_native_result2_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_native_result2)
BTF_KFUNCS_END(ebpfos_kprog_native_result2_ids)
BTF_KFUNCS_START(ebpfos_kprog_native_result2_service_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_native_result2)
BTF_KFUNCS_END(ebpfos_kprog_native_result2_service_ids)

static struct bpf_kop ebpfos_kop_native_result2;
static bool ebpfos_result2_call(const struct bpf_prog *prog, const struct bpf_insn *insn)
{
 /* kfunc_tab is temporary and is freed after JIT. These immutable builtin
  * descriptor IDs and the retained instruction pair survive that teardown.
  */
 return insn > prog->insnsi && insn < prog->insnsi + prog->len &&
  insn->code == (BPF_JMP | BPF_CALL) && insn->src_reg == BPF_PSEUDO_KOP_CALL &&
  !insn->off && insn->imm == ebpfos_kprog_native_result2_ids.pairs[0].id &&
  bpf_kop_is_sidecar_insn(insn - 1) &&
  bpf_kop_sidecar_payload(insn - 1) == ebpfos_kprog_native_result2_ids.pairs[0].id;
}
#include "native_result_returns.h"

static bool ebpfos_result2_payload(u64 payload)
{
 return ebpfos_kprog_native_result2_ids.cnt == 1 &&
  ebpfos_kprog_native_result2_service_ids.cnt == 1 &&
  payload == ebpfos_kprog_native_result2_ids.pairs[0].id;
}
static int ebpfos_result2_instantiate(u64 payload, struct bpf_insn *insns)
{
 if (!insns || !ebpfos_result2_payload(payload)) return -EINVAL;
 insns[0] = (struct bpf_insn) { .code = BPF_JMP | BPF_CALL,
  .src_reg = BPF_PSEUDO_KFUNC_CALL, .imm = ebpfos_kprog_native_result2_service_ids.pairs[0].id };
 return 1;
}
static int ebpfos_result2_requirements(u64 payload, u64 *cap, u64 *effects,
 u8 semantic_sha256[SHA256_DIGEST_SIZE])
{
 static const u8 digest[] = EBPFOS_KOP_NATIVE_RESULT2_SEMANTIC_SHA256;
 if (!cap || !effects || !semantic_sha256 || !ebpfos_result2_payload(payload)) return -EINVAL;
 *cap = 0; *effects = 0; memcpy(semantic_sha256, digest, sizeof(digest)); return 0;
}
static int ebpfos_result2_emit_x86(u8 *image, u32 *offset, bool emit,
 u64 payload, const struct bpf_prog *prog, const u8 *final_ip)
{
 static const u8 native[] = EBPFOS_KOP_NATIVE_RESULT2_NATIVE_BYTES;
 if (!prog || !prog->aux || prog->aux->tail_call_reachable ||
     prog->aux->exception_cb || prog->aux->exception_boundary ||
     prog->aux->jits_use_priv_stack || prog->aux->priv_stack_ptr ||
     !ebpfos_result2_returns(prog)) return -EOPNOTSUPP;
 if (!offset || (emit && !image) || !ebpfos_result2_payload(payload)) return -EINVAL;
 if (emit) memcpy(image + *offset, native, sizeof(native));
 *offset += sizeof(native); return sizeof(native);
}
static struct bpf_kop ebpfos_kop_native_result2 = {
 .max_insn_cnt = 1, .max_emit_bytes = 8,
 .requirements = ebpfos_result2_requirements, .instantiate_insn = ebpfos_result2_instantiate,
 .emit_x86 = ebpfos_result2_emit_x86,
};
static const struct bpf_kop * const ebpfos_kprog_native_result2_descs[] = { &ebpfos_kop_native_result2 };
static const struct btf_kfunc_id_set ebpfos_kprog_native_result2_set = {
 .set = &ebpfos_kprog_native_result2_ids, .kop_descs = ebpfos_kprog_native_result2_descs };
static const struct btf_kfunc_id_set ebpfos_kprog_native_result2_service_set = {
 .set = &ebpfos_kprog_native_result2_service_ids };

bool ebpfos_prog_native_result2(const struct bpf_prog *prog)
{
 u32 i;
 if (!prog || !prog->jited) return false;
 /* JIT admission already checked every return block. Look at this exact
  * subprogram, not a BTF claim or a flag inherited from its parent graph.
  */
 for (i = 0; i < prog->len; i++) if (ebpfos_result2_call(prog, &prog->insnsi[i])) return true;
 return false;
}
