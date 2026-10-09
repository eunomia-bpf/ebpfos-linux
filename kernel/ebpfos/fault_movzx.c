// SPDX-License-Identifier: GPL-2.0-only
/* Exact MOVZX opcodes, typed source footprints and Linux uaccess recovery. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <asm/asm.h>
#include <asm/extable.h>
#include "koperation_fault_load.generated.h"

#define MOVZX_ROWS(X) \
 X(movzx16rm8, MOVZX16rm8, 8, "movzbw", "w") \
 X(movzx32rm8, MOVZX32rm8, 8, "movzbl", "k") \
 X(movzx32rm16, MOVZX32rm16, 16, "movzwl", "k") \
 X(movzx64rm8, MOVZX64rm8, 8, "movzbq", "q") \
 X(movzx64rm16, MOVZX64rm16, 16, "movzwq", "q")
__bpf_kfunc_start_defs();
#define MOVZX_FUNCTIONS(name, stem, width, opcode, part) \
__bpf_kfunc u64 bpf_ebpfos_x86_fault_##name(u##width *source, u32 *status) \
{ \
 u64 value = 0; u32 fault = 1; \
 asm volatile("1: " opcode " %2,%" part "0\nmovl $0,%1\n2:\n" \
              _ASM_EXTABLE_TYPE(1b, 2b, EX_TYPE_UACCESS) \
              : "+r"(value), "+r"(fault) : "m"(*source) : "memory"); \
 *status = fault; return value; \
} \
__bpf_kfunc u64 bpf_ebpfos_kop_fault_##name(u64 ignored, void *source, u32 *status) \
{ return 0; /* Only checked proof or instruction emission executes. */ }
MOVZX_ROWS(MOVZX_FUNCTIONS)
__bpf_kfunc_end_defs();

#define MOVZX_DESCRIPTOR(name, stem, width, opcode, part) \
BTF_KFUNCS_START(name##_services) \
BTF_ID_FLAGS(func, bpf_ebpfos_x86_fault_##name) \
BTF_KFUNCS_END(name##_services) \
BTF_KFUNCS_START(name##_ids) \
BTF_ID_FLAGS(func, bpf_ebpfos_kop_fault_##name) \
BTF_KFUNCS_END(name##_ids) \
static const u8 name##_native[] = EBPFOS_FAULT_##stem##_NATIVE; \
static bool name##_valid(u64 payload) \
{ return (payload >> 8) == name##_ids.pairs[0].id && (payload & 255) == EX_TYPE_UACCESS; } \
static u32 name##_service(u64 payload) \
{ return name##_valid(payload) ? name##_services.pairs[0].id : 0; } \
static int name##_proof(u64 payload, struct bpf_insn *insns) \
{ \
 if (!insns || !name##_valid(payload)) return -EINVAL; \
 insns[0] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_2); \
 insns[1] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_3); \
 insns[2] = BPF_CALL_KFUNC(0, name##_services.pairs[0].id); return 3; \
} \
static int name##_exception(u64 payload, unsigned int index, struct bpf_kop_exception *entry) \
{ \
 if (!entry || index || !name##_valid(payload)) return -EINVAL; \
 *entry = (struct bpf_kop_exception) { .insn_offset = EBPFOS_FAULT_##stem##_INSN, \
  .fixup_offset = EBPFOS_FAULT_##stem##_FIXUP, .data = EX_TYPE_UACCESS }; return 0; \
} \
static int name##_requirements(u64 payload, u64 *capability, u64 *effect, u8 sha[32]) \
{ \
 static const u8 digest[] = EBPFOS_FAULT_##stem##_SHA256; \
 if (!capability || !effect || !sha || !name##_valid(payload)) return -EINVAL; \
 *capability = 0; *effect = 0; memcpy(sha, digest, 32); return 0; \
} \
static int name##_emit(u8 *image, u32 *offset, bool emit, u64 payload, \
                     const struct bpf_prog *prog, const u8 *final_ip) \
{ \
 if (!offset || (emit && !image) || !name##_valid(payload)) return -EINVAL; \
 if (emit) memcpy(image + *offset, name##_native, sizeof(name##_native)); \
 *offset += sizeof(name##_native); return sizeof(name##_native); \
} \
static struct bpf_kop name##_kop = { .max_insn_cnt = 3, .max_emit_bytes = sizeof(name##_native), \
 .num_exentries = 1, .exception_entry = name##_exception, .instantiate_insn = name##_proof, \
 .emit_x86 = name##_emit, .requirements = name##_requirements, \
 .proof_kfunc_id_for_payload = name##_service, \
 .semantic_sha256 = EBPFOS_FAULT_##stem##_SHA256 }; \
static const struct bpf_kop * const name##_descs[] = { &name##_kop }; \
static const struct btf_kfunc_id_set name##_service_set = { .set = &name##_services }; \
static const struct btf_kfunc_id_set name##_set = { .set = &name##_ids, .kop_descs = name##_descs };
MOVZX_ROWS(MOVZX_DESCRIPTOR)
static int __init fault_movzx_register(void)
{
 int error;
#define MOVZX_REGISTER(name, stem, width, opcode, part) \
 error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &name##_service_set); if (error) return error; \
 error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &name##_set); if (error) return error;
 MOVZX_ROWS(MOVZX_REGISTER)
 return 0;
}
late_initcall(fault_movzx_register);
