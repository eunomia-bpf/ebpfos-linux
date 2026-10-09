// SPDX-License-Identifier: GPL-2.0-only
/* One faulting MOV per descriptor; the records use Linux's own handler. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <asm/asm.h>
#include <asm/extable.h>
#include "koperation_fault_load.generated.h"

#define FAULT_MOV_ROWS(X) \
 X(8, "b", "b") X(16, "w", "w") X(32, "l", "k") X(64, "q", "q")

__bpf_kfunc_start_defs();
#define FAULT_MOV_FUNCTIONS(width, suffix, part) \
__bpf_kfunc u64 bpf_ebpfos_x86_fault_mov##width(u##width *source, u32 *status) \
{ \
 u64 value = 0; u32 fault = 1; \
 asm volatile("1: mov" suffix " %2,%" part "0\n" \
              "movl $0,%1\n2:\n" \
              _ASM_EXTABLE_TYPE(1b, 2b, EX_TYPE_UACCESS) \
              : "+r"(value), "+r"(fault) : "m"(*source) : "memory"); \
 *status = fault; return value; \
} \
__bpf_kfunc u64 bpf_ebpfos_kop_fault_mov##width(u64 address, u64 *source, u32 *status) \
{ \
 return 0; /* Only the checked proof or bound instruction emission runs. */ \
}
FAULT_MOV_ROWS(FAULT_MOV_FUNCTIONS)
#undef FAULT_MOV_FUNCTIONS
__bpf_kfunc u64 bpf_ebpfos_x86_zeropad_mov64(u64 *source, u32 *status)
{
 u64 value;
 asm volatile("1: movq %1,%0\n2:\n"
              _ASM_EXTABLE_TYPE(1b, 2b, EX_TYPE_ZEROPAD)
              : "=r"(value) : "m"(*source) : "memory");
 *status = 0; return value;
}
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(zeropad_mov64_services)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_zeropad_mov64)
BTF_KFUNCS_END(zeropad_mov64_services)
static const u8 zeropad_mov64_native[] = EBPFOS_FAULT_MOV64_ZEROPAD_NATIVE;
static const u8 zeropad_mov64_sha256[] = EBPFOS_FAULT_MOV64_ZEROPAD_SHA256;
static const struct btf_kfunc_id_set zeropad_mov64_service_set = { .set = &zeropad_mov64_services };


#define FAULT_MOV_DESCRIPTOR(width, suffix, part) \
BTF_KFUNCS_START(fault_mov##width##_services) \
BTF_ID_FLAGS(func, bpf_ebpfos_x86_fault_mov##width) \
BTF_KFUNCS_END(fault_mov##width##_services) \
BTF_KFUNCS_START(fault_mov##width##_ids) \
BTF_ID_FLAGS(func, bpf_ebpfos_kop_fault_mov##width) \
BTF_KFUNCS_END(fault_mov##width##_ids) \
static const u8 fault_mov##width##_native[] = EBPFOS_FAULT_MOV##width##_NATIVE; \
static bool fault_mov##width##_valid(u64 payload) \
{ \
 return (payload >> 8) == fault_mov##width##_ids.pairs[0].id && \
   ((payload & 255) == EX_TYPE_UACCESS || (width == 64 && (payload & 255) == EX_TYPE_ZEROPAD)); \
} \
static u32 fault_mov##width##_service(u64 payload) \
{ \
 if (!fault_mov##width##_valid(payload)) return 0; \
 return (payload & 255) == EX_TYPE_ZEROPAD ? zeropad_mov64_services.pairs[0].id : \
   fault_mov##width##_services.pairs[0].id; \
} \
static int fault_mov##width##_proof(u64 payload, struct bpf_insn *insns) \
{ \
 u32 service = fault_mov##width##_service(payload); \
 if (!insns || !service) return -EINVAL; \
 insns[0] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_2); \
 insns[1] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_3); \
 insns[2] = BPF_CALL_KFUNC(0, service); \
 return 3; \
} \
static int fault_mov##width##_exception(u64 payload, unsigned int index, \
                                      struct bpf_kop_exception *entry) \
{ \
 if (!entry || index || !fault_mov##width##_valid(payload)) return -EINVAL; \
 *entry = (struct bpf_kop_exception) { \
  .insn_offset = EBPFOS_FAULT_MOV##width##_INSN, \
  .fixup_offset = EBPFOS_FAULT_MOV##width##_FIXUP, .data = EX_TYPE_UACCESS }; \
 if ((payload & 255) == EX_TYPE_ZEROPAD) { \
  entry->insn_offset = EBPFOS_FAULT_MOV64_ZEROPAD_INSN; \
  entry->fixup_offset = EBPFOS_FAULT_MOV64_ZEROPAD_FIXUP; entry->data = EX_TYPE_ZEROPAD; \
 } \
 return 0; \
} \
static int fault_mov##width##_requirements(u64 payload, u64 *capability, u64 *effect, u8 sha[32]) \
{ \
 static const u8 ordinary_sha[] = EBPFOS_FAULT_MOV##width##_SHA256; \
 if (!capability || !effect || !sha || !fault_mov##width##_valid(payload)) return -EINVAL; \
 *capability = 0; *effect = 0; \
 memcpy(sha, (payload & 255) == EX_TYPE_ZEROPAD ? zeropad_mov64_sha256 : ordinary_sha, 32); \
 return 0; \
} \
static int fault_mov##width##_emit(u8 *image, u32 *offset, bool emit, \
                    u64 payload, const struct bpf_prog *prog, const u8 *final_ip) \
{ \
 const u8 *bytes = fault_mov##width##_native; unsigned int size = sizeof(fault_mov##width##_native); \
 if (!offset || (emit && !image) || !fault_mov##width##_valid(payload)) return -EINVAL; \
 if ((payload & 255) == EX_TYPE_ZEROPAD) { bytes = zeropad_mov64_native; size = sizeof(zeropad_mov64_native); } \
 if (emit) memcpy(image + *offset, bytes, size); \
 *offset += size; return size; \
} \
static struct bpf_kop fault_mov##width##_kop = { \
 .max_insn_cnt = 3, .max_emit_bytes = sizeof(fault_mov##width##_native), \
 .num_exentries = 1, .exception_entry = fault_mov##width##_exception, \
 .instantiate_insn = fault_mov##width##_proof, .emit_x86 = fault_mov##width##_emit, \
 .requirements = fault_mov##width##_requirements, .proof_kfunc_id_for_payload = fault_mov##width##_service, \
 .semantic_sha256 = EBPFOS_FAULT_MOV##width##_SHA256, \
}; \
static const struct bpf_kop * const fault_mov##width##_descs[] = { &fault_mov##width##_kop }; \
static const struct btf_kfunc_id_set fault_mov##width##_service_set = { .set = &fault_mov##width##_services }; \
static const struct btf_kfunc_id_set fault_mov##width##_set = { \
 .set = &fault_mov##width##_ids, .kop_descs = fault_mov##width##_descs };
FAULT_MOV_ROWS(FAULT_MOV_DESCRIPTOR)
#undef FAULT_MOV_DESCRIPTOR

static int __init fault_mov_register(void)
{
 int error;
 error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &zeropad_mov64_service_set);
 if (error) return error;
#define FAULT_MOV_REGISTER(width, suffix, part) \
 if (fault_mov##width##_ids.cnt != 1 || fault_mov##width##_services.cnt != 1) return -EINVAL; \
 error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &fault_mov##width##_service_set); \
 if (error) return error; \
 error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &fault_mov##width##_set); \
 if (error) return error;
 FAULT_MOV_ROWS(FAULT_MOV_REGISTER)
#undef FAULT_MOV_REGISTER
 return 0;
}
late_initcall(fault_mov_register);
