// SPDX-License-Identifier: GPL-2.0-only
/* One RDMSR with Linux's safe exception result; no warning policy. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <asm/asm.h>
#include <asm/extable.h>
#include "koperation_rdmsr.generated.h"

__bpf_kfunc_start_defs();
__bpf_kfunc u64 bpf_ebpfos_x86_rdmsr(u32 index, u32 *status)
{
 u32 low, high;
 int error;
 asm volatile("1: rdmsr\nxor %0,%0\n2:\n"
              _ASM_EXTABLE_TYPE_REG(1b, 2b, EX_TYPE_RDMSR_SAFE, %0)
              : "=r"(error), "=a"(low), "=d"(high) : "c"(index));
 *status = error;
 return ((u64)high << 32) | low;
}
__bpf_kfunc u64 bpf_ebpfos_kop_rdmsr(u32 index, u32 *status)
{
 return 0; /* Only checked proof or instruction emission executes. */
}
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(rdmsr_services)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_rdmsr)
BTF_KFUNCS_END(rdmsr_services)
BTF_KFUNCS_START(rdmsr_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_rdmsr)
BTF_KFUNCS_END(rdmsr_ids)
static const u8 rdmsr_native[] = EBPFOS_RDMSR_NATIVE;
static bool rdmsr_valid(u64 payload) { return payload == rdmsr_ids.pairs[0].id; }
static u32 rdmsr_service(u64 payload)
{ return rdmsr_valid(payload) ? rdmsr_services.pairs[0].id : 0; }
static int rdmsr_proof(u64 payload, struct bpf_insn *insns)
{
 if (!insns || !rdmsr_valid(payload)) return -EINVAL;
 insns[0] = BPF_CALL_KFUNC(0, rdmsr_services.pairs[0].id);
 return 1;
}
static int rdmsr_exception(u64 payload, unsigned int index, struct bpf_kop_exception *entry)
{
 if (!entry || index || !rdmsr_valid(payload)) return -EINVAL;
 *entry = (struct bpf_kop_exception) { .insn_offset = EBPFOS_RDMSR_INSN,
  .fixup_offset = EBPFOS_RDMSR_FIXUP, .data = EX_TYPE_RDMSR_SAFE | (8 << 8) };
 return 0;
}
static int rdmsr_requirements(u64 payload, u64 *capability, u64 *effect, u8 sha[32])
{
 static const u8 digest[] = EBPFOS_RDMSR_SHA256;
 if (!capability || !effect || !sha || !rdmsr_valid(payload)) return -EINVAL;
 *capability = 0; *effect = 0; memcpy(sha, digest, 32);
 return 0;
}
static int rdmsr_emit(u8 *image, u32 *offset, bool emit, u64 payload,
                     const struct bpf_prog *prog, const u8 *final_ip)
{
 if (!offset || (emit && !image) || !rdmsr_valid(payload)) return -EINVAL;
 if (emit) memcpy(image + *offset, rdmsr_native, sizeof(rdmsr_native));
 *offset += sizeof(rdmsr_native); return sizeof(rdmsr_native);
}
static struct bpf_kop rdmsr_kop = { .max_insn_cnt = 1,
 .max_emit_bytes = sizeof(rdmsr_native), .num_exentries = 1,
 .exception_entry = rdmsr_exception, .instantiate_insn = rdmsr_proof,
 .emit_x86 = rdmsr_emit, .requirements = rdmsr_requirements,
 .proof_kfunc_id_for_payload = rdmsr_service, .semantic_sha256 = EBPFOS_RDMSR_SHA256 };
static const struct bpf_kop * const rdmsr_descs[] = { &rdmsr_kop };
static const struct btf_kfunc_id_set rdmsr_service_set = { .set = &rdmsr_services };
static const struct btf_kfunc_id_set rdmsr_set = { .set = &rdmsr_ids, .kop_descs = rdmsr_descs };
static int __init rdmsr_register(void)
{
 int error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &rdmsr_service_set);
 if (error) return error;
 return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &rdmsr_set);
}
late_initcall(rdmsr_register);
