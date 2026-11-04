// SPDX-License-Identifier: GPL-2.0-only
/* Single REP MOVS opcodes, retaining Linux's element progress on faults. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <asm/asm.h>
#include <asm/extable.h>
#include "koperation_fault_rep.generated.h"
#include "component_context.h"

__bpf_kfunc_start_defs();
#define REP_SERVICE(name, type, instruction, shift) \
__bpf_kfunc u64 name(void *destination__nullable __attribute__((btf_decl_tag("arg:nonnull-size"))), u64 destination__sz, \
                    const void *source__nullable __attribute__((btf_decl_tag("arg:readonly"), btf_decl_tag("arg:nonnull-size"))), u64 source__sz) \
{ \
 u64 remaining = destination__sz >> (shift); \
 /* Direct proof-service calls must not copy beyond either checked range. */ \
 if (destination__sz != source__sz) return remaining; \
 asm volatile("1: " instruction "\n2:\n" _ASM_EXTABLE_TYPE(1b, 2b, type) \
              : "+D"(destination__nullable), "+S"(source__nullable), "+c"(remaining) : : "memory"); \
 return remaining; \
}
REP_SERVICE(bpf_ebpfos_x86_fault_rep_movsb, EX_TYPE_UACCESS, "rep movsb", 0)
REP_SERVICE(bpf_ebpfos_x86_fault_rep_movsb_mc, EX_TYPE_DEFAULT_MCE_SAFE, "rep movsb", 0)
REP_SERVICE(bpf_ebpfos_x86_fault_rep_movsq, EX_TYPE_UACCESS, "rep movsq", 3)
REP_SERVICE(bpf_ebpfos_x86_fault_rep_movsq_mc, EX_TYPE_DEFAULT_MCE_SAFE, "rep movsq", 3)
#undef REP_SERVICE
__bpf_kfunc __attribute__((btf_decl_tag("bpf_kop_payload_id:8"))) u64 bpf_ebpfos_kop_fault_rep_movsb(void *destination, void *source, u64 count)
{
 return 0; /* Only the checked proof or bound instruction emission runs. */
}
__bpf_kfunc __attribute__((btf_decl_tag("bpf_kop_payload_id:8"))) u64 bpf_ebpfos_kop_fault_rep_movsq(void *destination, void *source, u64 count)
{
 return 0; /* Logical result is RCX (BPF r4), not the C return register. */
}
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(rep_services3)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_fault_rep_movsb)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_fault_rep_movsq)
BTF_KFUNCS_END(rep_services3)
BTF_KFUNCS_START(rep_services14)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_fault_rep_movsb_mc)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_fault_rep_movsq_mc)
BTF_KFUNCS_END(rep_services14)
BTF_KFUNCS_START(rep_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_fault_rep_movsb)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_fault_rep_movsq)
BTF_KFUNCS_END(rep_ids)
static const u8 rep_native[] = EBPFOS_FAULT_REP_MOVSB_NATIVE;
static bool rep_valid(u64 payload)
{
 return (payload >> 8) == rep_ids.pairs[0].id &&
        ((payload & 255) == EX_TYPE_UACCESS || (payload & 255) == EX_TYPE_DEFAULT_MCE_SAFE);
}
static u32 rep_service(u64 payload)
{
 if (!rep_valid(payload)) return 0;
 return (payload & 255) == EX_TYPE_UACCESS ? rep_services3.pairs[0].id : rep_services14.pairs[0].id;
}
static int rep_proof(u64 payload, struct bpf_insn *insns)
{
 u32 service = rep_service(payload);
 unsigned n = 0;
 
 /* Native inputs: r1=RDI/destination, r2=RSI/source, r4=RCX/elements.
  * Only this proof uses the C service ABI; none of it runs at runtime.
  */
 insns[n++] = BPF_MOV64_REG(BPF_REG_3, BPF_REG_2);
 insns[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_4);
 insns[n++] = BPF_MOV64_REG(BPF_REG_4, BPF_REG_2);
 insns[n++] = BPF_CALL_KFUNC(0, service);
 insns[n++] = BPF_MOV64_REG(BPF_REG_4, BPF_REG_0);
 return n;
}
static int rep_exception(u64 payload, unsigned int index, struct bpf_kop_exception *entry)
{
 *entry = (struct bpf_kop_exception) {
  .insn_offset = EBPFOS_FAULT_REP_MOVSB_INSN,
  .fixup_offset = EBPFOS_FAULT_REP_MOVSB_FIXUP, .data = payload & 255 };
 return 0;
}
static int rep_requirements(u64 payload, u64 *capability, u64 *effect, u8 sha[32])
{
 static const u8 ordinary[] = EBPFOS_FAULT_REP_MOVSB_SHA256_3;
 static const u8 machine_check[] = EBPFOS_FAULT_REP_MOVSB_SHA256_14;
 *capability = 0; *effect = 0;
 memcpy(sha, (payload & 255) == EX_TYPE_UACCESS ? ordinary : machine_check, 32);
 return 0;
}
static int rep_emit(u8 *image, u32 *offset, bool emit, u64 payload,
                    const struct bpf_prog *prog, const u8 *final_ip)
{
 if (emit) memcpy(image + *offset, rep_native, sizeof(rep_native));
 *offset += sizeof(rep_native); return sizeof(rep_native);
}
static struct bpf_kop rep_kop = {
 .max_insn_cnt = 5, .max_emit_bytes = sizeof(rep_native),
 .num_exentries = 1, .exception_entry = rep_exception,
 .instantiate_insn = rep_proof, .emit_x86 = rep_emit,
 .requirements = rep_requirements, .proof_kfunc_id_for_payload = rep_service,
 .semantic_sha256 = EBPFOS_FAULT_REP_MOVSB_SHA256_3,
};
static const u8 repq_native[] = EBPFOS_FAULT_REP_MOVSQ_NATIVE;
static bool repq_valid(u64 payload)
{
 return (payload >> 8) == rep_ids.pairs[1].id &&
        ((payload & 255) == EX_TYPE_UACCESS || (payload & 255) == EX_TYPE_DEFAULT_MCE_SAFE);
}
static u32 repq_service(u64 payload)
{
 if (!repq_valid(payload)) return 0;
 return (payload & 255) == EX_TYPE_UACCESS ? rep_services3.pairs[1].id : rep_services14.pairs[1].id;
}
static int repq_proof(u64 payload, struct bpf_insn *insns)
{
 u32 service = repq_service(payload);
 unsigned n = 0;
 
 /* Native inputs: r1=RDI/destination, r2=RSI/source, r4=RCX/elements.
  * Only this proof uses the C service ABI; none of it runs at runtime.
  */
 insns[n++] = BPF_MOV64_REG(BPF_REG_3, BPF_REG_2);
 insns[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_4);
 /* Saturate overflowing byte footprints instead of wrapping them into
  * a small object. Valid element counts keep the exact count*8 span.
  */
 insns[n++] = BPF_MOV64_REG(BPF_REG_5, BPF_REG_2);
 insns[n++] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_5, 61);
 insns[n++] = BPF_ALU64_IMM(BPF_NEG, BPF_REG_5, 0);
 insns[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_2, 3);
 insns[n++] = BPF_ALU64_REG(BPF_OR, BPF_REG_2, BPF_REG_5);
 insns[n++] = BPF_MOV64_REG(BPF_REG_4, BPF_REG_2);
 insns[n++] = BPF_CALL_KFUNC(0, service);
 insns[n++] = BPF_MOV64_REG(BPF_REG_4, BPF_REG_0);
 return n;
}
static int repq_exception(u64 payload, unsigned int index, struct bpf_kop_exception *entry)
{
 *entry = (struct bpf_kop_exception) {
  .insn_offset = EBPFOS_FAULT_REP_MOVSQ_INSN,
  .fixup_offset = EBPFOS_FAULT_REP_MOVSQ_FIXUP, .data = payload & 255 };
 return 0;
}
static int repq_requirements(u64 payload, u64 *capability, u64 *effect, u8 sha[32])
{
 static const u8 ordinary[] = EBPFOS_FAULT_REP_MOVSQ_SHA256_3;
 static const u8 machine_check[] = EBPFOS_FAULT_REP_MOVSQ_SHA256_14;
 *capability = 0; *effect = 0;
 memcpy(sha, (payload & 255) == EX_TYPE_UACCESS ? ordinary : machine_check, 32);
 return 0;
}
static int repq_emit(u8 *image, u32 *offset, bool emit, u64 payload,
                    const struct bpf_prog *prog, const u8 *final_ip)
{
 if (emit) memcpy(image + *offset, repq_native, sizeof(repq_native));
 *offset += sizeof(repq_native); return sizeof(repq_native);
}
static struct bpf_kop repq_kop = {
 .max_insn_cnt = 10, .max_emit_bytes = sizeof(repq_native),
 .num_exentries = 1, .exception_entry = repq_exception,
 .instantiate_insn = repq_proof, .emit_x86 = repq_emit,
 .requirements = repq_requirements, .proof_kfunc_id_for_payload = repq_service,
 .semantic_sha256 = EBPFOS_FAULT_REP_MOVSQ_SHA256_3,
};
static const struct bpf_kop * const rep_descs[] = { &rep_kop, &repq_kop };
static const struct btf_kfunc_id_set rep_service_set3 = { .set = &rep_services3 };
static const struct btf_kfunc_id_set rep_service_set14 = { .set = &rep_services14 };
static const struct btf_kfunc_id_set rep_set = { .set = &rep_ids, .kop_descs = rep_descs };
static int rep_component_filter(const struct bpf_prog *prog, u32 id)
{
 if (btf_id_set8_contains(&rep_ids, id) ||
     btf_id_set8_contains(&rep_services3, id) ||
     btf_id_set8_contains(&rep_services14, id))
  return !ebpfos_non_sleepable_component(prog);
 return 0;
}
static const struct btf_kfunc_id_set rep_component_services3 = {
 .set = &rep_services3, .filter = rep_component_filter };
static const struct btf_kfunc_id_set rep_component_services14 = {
 .set = &rep_services14, .filter = rep_component_filter };
static const struct btf_kfunc_id_set rep_component_set = {
 .set = &rep_ids, .filter = rep_component_filter, .kop_descs = rep_descs };
static int __init rep_register(void)
{
 const struct btf_kfunc_id_set *syscall_sets[] = {
  &rep_service_set3, &rep_service_set14, &rep_set };
 const struct btf_kfunc_id_set *component_sets[] = {
  &rep_component_services3, &rep_component_services14, &rep_component_set };
 unsigned i;
 int error;
 for (i = 0; i < ARRAY_SIZE(syscall_sets); i++) {
  error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, syscall_sets[i]);
  if (error) return error;
  error = register_btf_kfunc_id_set(BPF_PROG_TYPE_RAW_TRACEPOINT, component_sets[i]);
  if (error) return error;
 }
 return 0;
}
late_initcall(rep_register);
