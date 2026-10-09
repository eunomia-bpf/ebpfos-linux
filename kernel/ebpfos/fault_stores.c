// SPDX-License-Identifier: GPL-2.0-only
/* One MOV store; retain Linux's original exception handler. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <asm/asm.h>
#include <asm/extable.h>
#include "koperation_fault_store.generated.h"

#define STORE_ROWS(X) X(8, "b", "b") X(16, "w", "w") X(32, "l", "k") X(64, "q", "q")
__bpf_kfunc_start_defs();
#define STORE_SERVICE(width, suffix, part, kind) \
__bpf_kfunc u64 bpf_ebpfos_x86_fault_store##width##_##kind(u64 value, u##width *destination, u32 *status) \
{ \
 u32 fault = 1; \
 asm volatile("1: mov" suffix " %" part "1,%0\nmovl $0,%2\n2:\n" \
              _ASM_EXTABLE_TYPE(1b, 2b, kind) \
              : "=m"(*destination), "+r"(value), "+r"(fault) : : "memory"); \
 *status = fault; return 0; \
}
#define STORE_FUNCTIONS(width, suffix, part) \
 STORE_SERVICE(width, suffix, part, 1) \
 STORE_SERVICE(width, suffix, part, 3) \
 __bpf_kfunc u64 bpf_ebpfos_kop_fault_store##width(u64 value, void *destination, u32 *status) \
 { return 0; /* Only the checked proof or bound instruction emission runs. */ }
STORE_ROWS(STORE_FUNCTIONS)
__bpf_kfunc_end_defs();

#define STORE_DESCRIPTOR(width, suffix, part) \
BTF_KFUNCS_START(store##width##_services1) \
BTF_ID_FLAGS(func, bpf_ebpfos_x86_fault_store##width##_1) \
BTF_KFUNCS_END(store##width##_services1) \
BTF_KFUNCS_START(store##width##_services3) \
BTF_ID_FLAGS(func, bpf_ebpfos_x86_fault_store##width##_3) \
BTF_KFUNCS_END(store##width##_services3) \
BTF_KFUNCS_START(store##width##_ids) \
BTF_ID_FLAGS(func, bpf_ebpfos_kop_fault_store##width) \
BTF_KFUNCS_END(store##width##_ids) \
static const u8 store##width##_native[] = EBPFOS_FAULT_STORE##width##_NATIVE; \
static bool store##width##_valid(u64 payload) \
{ return (payload >> 8) == store##width##_ids.pairs[0].id && ((payload & 255) == 1 || (payload & 255) == 3); } \
static u32 store##width##_service(u64 payload) \
{ \
 if (!store##width##_valid(payload)) return 0; \
 return (payload & 255) == 1 ? store##width##_services1.pairs[0].id : store##width##_services3.pairs[0].id; \
} \
static int store##width##_proof(u64 payload, struct bpf_insn *insns) \
{ \
 u32 service = store##width##_service(payload); \
 if (!insns || !service) return -EINVAL; \
 insns[0] = BPF_CALL_KFUNC(0, service); return 1; \
} \
static int store##width##_exception(u64 payload, unsigned int index, struct bpf_kop_exception *entry) \
{ \
 if (!entry || index || !store##width##_valid(payload)) return -EINVAL; \
 *entry = (struct bpf_kop_exception) { .insn_offset = EBPFOS_FAULT_STORE##width##_INSN, \
  .fixup_offset = EBPFOS_FAULT_STORE##width##_FIXUP, .data = payload & 255 }; return 0; \
} \
static int store##width##_requirements(u64 payload, u64 *capability, u64 *effect, u8 sha[32]) \
{ \
 static const u8 ordinary[] = EBPFOS_FAULT_STORE##width##_SHA256_1; \
 static const u8 uaccess[] = EBPFOS_FAULT_STORE##width##_SHA256_3; \
 if (!capability || !effect || !sha || !store##width##_valid(payload)) return -EINVAL; \
 *capability = 0; *effect = 0; memcpy(sha, (payload & 255) == 1 ? ordinary : uaccess, 32); return 0; \
} \
static int store##width##_emit(u8 *image, u32 *offset, bool emit, u64 payload, \
                              const struct bpf_prog *prog, const u8 *final_ip) \
{ \
 if (!offset || (emit && !image) || !store##width##_valid(payload)) return -EINVAL; \
 if (emit) memcpy(image + *offset, store##width##_native, sizeof(store##width##_native)); \
 *offset += sizeof(store##width##_native); return sizeof(store##width##_native); \
} \
static struct bpf_kop store##width##_kop = { .max_insn_cnt = 1, .max_emit_bytes = sizeof(store##width##_native), \
 .num_exentries = 1, .exception_entry = store##width##_exception, .instantiate_insn = store##width##_proof, \
 .emit_x86 = store##width##_emit, .requirements = store##width##_requirements, \
 .proof_kfunc_id_for_payload = store##width##_service, .semantic_sha256 = EBPFOS_FAULT_STORE##width##_SHA256_3 }; \
static const struct bpf_kop * const store##width##_descs[] = { &store##width##_kop }; \
static const struct btf_kfunc_id_set store##width##_set1 = { .set = &store##width##_services1 }; \
static const struct btf_kfunc_id_set store##width##_set3 = { .set = &store##width##_services3 }; \
static const struct btf_kfunc_id_set store##width##_set = { .set = &store##width##_ids, .kop_descs = store##width##_descs };
STORE_ROWS(STORE_DESCRIPTOR)
static int __init fault_store_register(void)
{
 int error;
#define STORE_REGISTER(width, suffix, part) \
 error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &store##width##_set1); if (error) return error; \
 error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &store##width##_set3); if (error) return error; \
 error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &store##width##_set); if (error) return error;
 STORE_ROWS(STORE_REGISTER)
 return 0;
}
late_initcall(fault_store_register);
