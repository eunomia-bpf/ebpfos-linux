// SPDX-License-Identifier: GPL-2.0-only
/* One REP STOSB with a checked byte-buffer operand window. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include "koperation_buffer_stos.generated.h"

__bpf_kfunc_start_defs();
__bpf_kfunc u64 bpf_ebpfos_x86_buffer_stosb(
 void *destination__nullable __attribute__((btf_decl_tag("arg:nonnull-size"))),
 u64 destination__sz, u64 offset, u64 count, u64 value)
{
 void *selected;

 /* Subtraction after the offset check avoids an overflowing offset+count. */
 if (offset > destination__sz || count > destination__sz - offset)
  return ~0ULL;
 if (!count)
  return 0;
 /* The scalar window is untrusted until both bounds checks have completed. */
 asm volatile("lfence" : : : "memory");
 selected = (u8 *)destination__nullable + offset;
 asm volatile("pushfq\ncld\nrep stosb\npopfq"
              : "+D"(selected), "+c"(count) : "a"(value) : "memory");
 return 0;
}
__bpf_kfunc u64 bpf_ebpfos_kop_buffer_stosb(void *destination, u64 size,
                                         u64 offset, u64 count, u64 value)
{
 return 0; /* The checked proof or bound instruction emission runs. */
}
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(stos_services)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_buffer_stosb)
BTF_KFUNCS_END(stos_services)
BTF_KFUNCS_START(stos_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_buffer_stosb)
BTF_KFUNCS_END(stos_ids)
static const u8 stos_native[] = EBPFOS_BUFFER_STOSB_NATIVE;
static bool stos_valid(u64 payload)
{
 return payload == ((u64)stos_ids.pairs[0].id << 8);
}
static u32 stos_service(u64 payload)
{
 return stos_valid(payload) ? stos_services.pairs[0].id : 0;
}
static int stos_proof(u64 payload, struct bpf_insn *insns)
{
 u32 service = stos_service(payload);
 if (!insns || !service)
  return -EINVAL;
 insns[0] = BPF_CALL_KFUNC(0, service);
 return 1;
}
static int stos_requirements(u64 payload, u64 *capability, u64 *effect, u8 sha[32])
{
 static const u8 digest[] = EBPFOS_BUFFER_STOSB_SHA256;
 if (!capability || !effect || !sha || !stos_valid(payload))
  return -EINVAL;
 *capability = 0;
 *effect = 0;
 memcpy(sha, digest, 32);
 return 0;
}
static int stos_emit(u8 *image, u32 *offset, bool emit, u64 payload,
                     const struct bpf_prog *prog, const u8 *final_ip)
{
 if (!offset || (emit && !image) || !stos_valid(payload))
  return -EINVAL;
 if (emit)
  memcpy(image + *offset, stos_native, sizeof(stos_native));
 *offset += sizeof(stos_native);
 return sizeof(stos_native);
}
static struct bpf_kop stos_kop = {
 .max_insn_cnt = 1, .max_emit_bytes = sizeof(stos_native),
 .instantiate_insn = stos_proof, .emit_x86 = stos_emit,
 .requirements = stos_requirements, .proof_kfunc_id_for_payload = stos_service,
 .semantic_sha256 = EBPFOS_BUFFER_STOSB_SHA256,
};
static const struct bpf_kop * const stos_descs[] = { &stos_kop };
static const struct btf_kfunc_id_set stos_service_set = { .set = &stos_services };
static const struct btf_kfunc_id_set stos_set = {
 .set = &stos_ids, .kop_descs = stos_descs,
};
static int __init stos_register(void)
{
 int error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &stos_service_set);
 return error ? error : register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &stos_set);
}
late_initcall(stos_register);
