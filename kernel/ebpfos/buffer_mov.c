// SPDX-License-Identifier: GPL-2.0-only
/* Single MOV operands inside a checked byte-buffer window. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <asm/asm.h>
#include <asm/extable.h>
#include "koperation_buffer_mov.generated.h"
#include "syscall_kfuncs.h"

#define WIDTHS(X) X(8, b, b, 1) X(16, w, w, 2) X(32, l, k, 4) X(64, q, q, 8)
static int buffer_context_filter(const struct bpf_prog *prog, u32 id);
__bpf_kfunc_start_defs();
#define LOAD_SERVICE(bits, suffix, part, bytes, seed, tail) \
__bpf_kfunc u64 bpf_ebpfos_x86_buffer_fault_load##bits##tail( \
 const void *source__nullable __attribute__((btf_decl_tag("arg:readonly"), btf_decl_tag("arg:nonnull-size"))), \
 u64 source__sz, u64 offset, u32 *status) \
{ \
 u64 value = 0; u32 fault = 1; const u##bits *selected; \
 if (offset > source__sz || bytes > source__sz - offset) { \
  *status = fault; return value; \
 } \
 asm volatile("lfence" : : : "memory"); \
 selected = (const u##bits *)((const u8 *)source__nullable + offset); \
 if (seed) value = (u64)selected; \
 asm volatile("1: mov" #suffix " %2,%" #part "0\nmovl $0,%1\n2:\n" \
              _ASM_EXTABLE_TYPE(1b, 2b, EX_TYPE_UACCESS) \
              : "+r"(value), "+r"(fault) : "m"(*selected) : "memory"); \
 *status = fault; return value; \
} \
__bpf_kfunc u64 bpf_ebpfos_kop_buffer_fault_load##bits##tail( \
 const void *source, u64 size, u64 offset, u32 *status) \
{ return 0; }
#define SERVICES(bits, suffix, part, bytes) \
 LOAD_SERVICE(bits, suffix, part, bytes, 0, ) \
 LOAD_SERVICE(bits, suffix, part, bytes, 1, _address_seed) \
 __bpf_kfunc u64 bpf_ebpfos_x86_buffer_store##bits( \
 void *destination__nullable __attribute__((btf_decl_tag("arg:nonnull-size"))), \
 u64 destination__sz, u64 offset, u64 value) \
 { \
  u##bits *selected; \
  if (offset > destination__sz || bytes > destination__sz - offset) return ~0ULL; \
  asm volatile("lfence" : : : "memory"); \
  selected = (u##bits *)((u8 *)destination__nullable + offset); \
  asm volatile("mov" #suffix " %" #part "1,%0" : "=m"(*selected) : "r"(value) : "memory"); \
  return 0; \
 } \
 __bpf_kfunc u64 bpf_ebpfos_kop_buffer_store##bits( \
 void *destination, u64 size, u64 offset, u64 value) { return 0; }
WIDTHS(SERVICES)
#undef SERVICES
#undef LOAD_SERVICE
__bpf_kfunc_end_defs();

#define DESCRIPTOR(name, exceptions, insn, fixup) \
 BTF_KFUNCS_START(name##_services) \
 BTF_ID_FLAGS(func, bpf_ebpfos_x86_##name) \
 BTF_KFUNCS_END(name##_services) \
 BTF_KFUNCS_START(name##_ids) \
 BTF_ID_FLAGS(func, bpf_ebpfos_kop_##name) \
 BTF_KFUNCS_END(name##_ids) \
 static const u8 name##_native[] = EBPFOS_##name##_NATIVE; \
 static bool name##_valid(u64 payload) { return payload == ((u64)name##_ids.pairs[0].id << 8); } \
 static u32 name##_service(u64 payload) { return name##_valid(payload) ? name##_services.pairs[0].id : 0; } \
 static int name##_proof(u64 payload, struct bpf_insn *insns) \
 { \
  u32 service = name##_service(payload); \
  if (!insns || !service) return -EINVAL; \
  insns[0] = BPF_CALL_KFUNC(0, service); return 1; \
 } \
 static int name##_exception(u64 payload, unsigned int index, struct bpf_kop_exception *entry) \
 { \
  if (!entry || index || !exceptions || !name##_valid(payload)) return -EINVAL; \
  *entry = (struct bpf_kop_exception) { .insn_offset = insn, .fixup_offset = fixup, .data = EX_TYPE_UACCESS }; \
  return 0; \
 } \
 static int name##_requirements(u64 payload, u64 *capability, u64 *effect, u8 sha[32]) \
 { \
  static const u8 digest[] = EBPFOS_##name##_SHA256; \
  if (!capability || !effect || !sha || !name##_valid(payload)) return -EINVAL; \
  *capability = 0; *effect = 0; memcpy(sha, digest, 32); return 0; \
 } \
 static int name##_emit(u8 *image, u32 *offset, bool emit, u64 payload, const struct bpf_prog *prog, const u8 *final_ip) \
 { \
  if (!offset || (emit && !image) || !name##_valid(payload)) return -EINVAL; \
  if (emit) memcpy(image + *offset, name##_native, sizeof(name##_native)); \
  *offset += sizeof(name##_native); return sizeof(name##_native); \
 } \
 static struct bpf_kop name##_kop = { \
  .max_insn_cnt = 1, .max_emit_bytes = sizeof(name##_native), \
  .num_exentries = exceptions, .exception_entry = name##_exception, \
  .instantiate_insn = name##_proof, .emit_x86 = name##_emit, \
  .requirements = name##_requirements, .proof_kfunc_id_for_payload = name##_service, \
  .semantic_sha256 = EBPFOS_##name##_SHA256, \
 }; \
 static const struct bpf_kop * const name##_descs[] = { &name##_kop }; \
 static const struct btf_kfunc_id_set name##_service_set = { .set = &name##_services, .filter = buffer_context_filter }; \
 static const struct btf_kfunc_id_set name##_set = { .set = &name##_ids, .kop_descs = name##_descs, .filter = buffer_context_filter };
#define DESCRIPTORS(bits, suffix, part, bytes) \
 DESCRIPTOR(buffer_fault_load##bits, 1, EBPFOS_buffer_fault_load##bits##_INSN, EBPFOS_buffer_fault_load##bits##_FIXUP) \
 DESCRIPTOR(buffer_fault_load##bits##_address_seed, 1, EBPFOS_buffer_fault_load##bits##_address_seed_INSN, EBPFOS_buffer_fault_load##bits##_address_seed_FIXUP) \
 DESCRIPTOR(buffer_store##bits, 0, 0, 0)
WIDTHS(DESCRIPTORS)
#undef DESCRIPTORS
#undef DESCRIPTOR

static const struct btf_kfunc_id_set * const buffer_sets[] = {
#define SETS(name) &name##_service_set, &name##_set,
#define WIDTH_SETS(bits, suffix, part, bytes) \
 SETS(buffer_fault_load##bits) \
 SETS(buffer_fault_load##bits##_address_seed) \
 SETS(buffer_store##bits)
 WIDTHS(WIDTH_SETS)
#undef WIDTH_SETS
#undef SETS
};
static int buffer_context_filter(const struct bpf_prog *prog, u32 id)
{
 return ebpfos_syscall_kfunc_filter(prog, id, buffer_sets,
                                    ARRAY_SIZE(buffer_sets));
}
static int __init buffer_mov_register(void)
{
 return ebpfos_register_syscall_kfuncs(buffer_sets, ARRAY_SIZE(buffer_sets));
}
late_initcall(buffer_mov_register);
