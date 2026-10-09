// SPDX-License-Identifier: GPL-2.0-only
/* One MOV/MOVNTI store; retain Linux's original exception handler. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <asm/asm.h>
#include <asm/extable.h>
#include "koperation_fault_store.generated.h"

#define STORE_ROWS(X) \
 X(store, STORE, 8, "movb", "b") X(store, STORE, 16, "movw", "w") \
 X(store, STORE, 32, "movl", "k") X(store, STORE, 64, "movq", "q") \
 X(ntstore, NTSTORE, 32, "movnti", "k") X(ntstore, NTSTORE, 64, "movnti", "q")
__bpf_kfunc_start_defs();
#define STORE_SERVICE(family, stem, width, opcode, part, kind) \
__bpf_kfunc u64 bpf_ebpfos_x86_fault_##family##width##_##kind(u64 value, u##width *destination, u32 *status) \
{ \
 u32 fault = 1; \
 asm volatile("1: " opcode " %" part "1,%0\nmovl $0,%2\n2:\n" \
              _ASM_EXTABLE_TYPE(1b, 2b, kind) \
              : "=m"(*destination), "+r"(value), "+r"(fault) : : "memory"); \
 *status = fault; return 0; \
}
#define STORE_FUNCTIONS(family, stem, width, opcode, part) \
 STORE_SERVICE(family, stem, width, opcode, part, 1) \
 STORE_SERVICE(family, stem, width, opcode, part, 3) \
 __bpf_kfunc u64 bpf_ebpfos_kop_fault_##family##width(u64 value, void *destination, u32 *status) \
 { return 0; /* Only the checked proof or bound instruction emission runs. */ }
STORE_ROWS(STORE_FUNCTIONS)
__bpf_kfunc_end_defs();

#define STORE_DESCRIPTOR(family, stem, width, opcode, part) \
BTF_KFUNCS_START(family##width##_services1) \
BTF_ID_FLAGS(func, bpf_ebpfos_x86_fault_##family##width##_1) \
BTF_KFUNCS_END(family##width##_services1) \
BTF_KFUNCS_START(family##width##_services3) \
BTF_ID_FLAGS(func, bpf_ebpfos_x86_fault_##family##width##_3) \
BTF_KFUNCS_END(family##width##_services3) \
BTF_KFUNCS_START(family##width##_ids) \
BTF_ID_FLAGS(func, bpf_ebpfos_kop_fault_##family##width) \
BTF_KFUNCS_END(family##width##_ids) \
static const u8 family##width##_native[] = EBPFOS_FAULT_##stem##width##_NATIVE; \
static bool family##width##_valid(u64 payload) \
{ return (payload >> 8) == family##width##_ids.pairs[0].id && ((payload & 255) == 1 || (payload & 255) == 3); } \
static u32 family##width##_service(u64 payload) \
{ \
 if (!family##width##_valid(payload)) return 0; \
 return (payload & 255) == 1 ? family##width##_services1.pairs[0].id : family##width##_services3.pairs[0].id; \
} \
static int family##width##_proof(u64 payload, struct bpf_insn *insns) \
{ \
 u32 service = family##width##_service(payload); \
 if (!insns || !service) return -EINVAL; \
 insns[0] = BPF_CALL_KFUNC(0, service); return 1; \
} \
static int family##width##_exception(u64 payload, unsigned int index, struct bpf_kop_exception *entry) \
{ \
 if (!entry || index || !family##width##_valid(payload)) return -EINVAL; \
 *entry = (struct bpf_kop_exception) { .insn_offset = EBPFOS_FAULT_##stem##width##_INSN, \
  .fixup_offset = EBPFOS_FAULT_##stem##width##_FIXUP, .data = payload & 255 }; return 0; \
} \
static int family##width##_requirements(u64 payload, u64 *capability, u64 *effect, u8 sha[32]) \
{ \
 static const u8 ordinary[] = EBPFOS_FAULT_##stem##width##_SHA256_1; \
 static const u8 uaccess[] = EBPFOS_FAULT_##stem##width##_SHA256_3; \
 if (!capability || !effect || !sha || !family##width##_valid(payload)) return -EINVAL; \
 *capability = 0; *effect = 0; memcpy(sha, (payload & 255) == 1 ? ordinary : uaccess, 32); return 0; \
} \
static int family##width##_emit(u8 *image, u32 *offset, bool emit, u64 payload, \
                              const struct bpf_prog *prog, const u8 *final_ip) \
{ \
 if (!offset || (emit && !image) || !family##width##_valid(payload)) return -EINVAL; \
 if (emit) memcpy(image + *offset, family##width##_native, sizeof(family##width##_native)); \
 *offset += sizeof(family##width##_native); return sizeof(family##width##_native); \
} \
static struct bpf_kop family##width##_kop = { .max_insn_cnt = 1, .max_emit_bytes = sizeof(family##width##_native), \
 .num_exentries = 1, .exception_entry = family##width##_exception, .instantiate_insn = family##width##_proof, \
 .emit_x86 = family##width##_emit, .requirements = family##width##_requirements, \
 .proof_kfunc_id_for_payload = family##width##_service, .semantic_sha256 = EBPFOS_FAULT_##stem##width##_SHA256_3 }; \
static const struct bpf_kop * const family##width##_descs[] = { &family##width##_kop }; \
static const struct btf_kfunc_id_set family##width##_set1 = { .set = &family##width##_services1 }; \
static const struct btf_kfunc_id_set family##width##_set3 = { .set = &family##width##_services3 }; \
static const struct btf_kfunc_id_set family##width##_set = { .set = &family##width##_ids, .kop_descs = family##width##_descs };
STORE_ROWS(STORE_DESCRIPTOR)
static int __init fault_store_register(void)
{
 int error;
#define STORE_REGISTER(family, stem, width, opcode, part) \
 error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &family##width##_set1); if (error) return error; \
 error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &family##width##_set3); if (error) return error; \
 error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &family##width##_set); if (error) return error;
 STORE_ROWS(STORE_REGISTER)
 return 0;
}
late_initcall(fault_store_register);
