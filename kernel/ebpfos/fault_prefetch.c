// SPDX-License-Identifier: GPL-2.0-only
/* A protected cache hint, including Linux's intentional unmapped addresses. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <asm/asm.h>
#include <asm/extable.h>
#include "koperation_fault_prefetch.generated.h"
#include "fault_prefetch.h"

__bpf_kfunc_start_defs();
__bpf_kfunc u64 bpf_ebpfos_x86_prefetcht0_protected(void *address__ign)
{
 /* No architectural memory access. Linux's type-1 fixup skips this hint
  * even for an address that faults; no object is read or written. */
 asm volatile("1: prefetcht0 (%0)\n2:\n" _ASM_EXTABLE(1b, 2b)
              : : "r"(address__ign) : "memory");
 return 0;
}
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(prefetch_services)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_prefetcht0_protected)
BTF_KFUNCS_END(prefetch_services)
static u32 prefetch_id, prefetch_typed_service;
static u8 prefetch_typed_sha[32];
static u64 prefetch_capability, prefetch_effect;
static const u8 prefetch_native[] = EBPFOS_FAULT_PREFETCHT0_NATIVE;
static u32 prefetch_service(u64 payload)
{
 if (payload==prefetch_id) return prefetch_typed_service;
 if (payload==((u64)prefetch_id<<8 | 1)) return prefetch_services.pairs[0].id;
 return 0;
}
static int prefetch_proof(u64 payload, struct bpf_insn *insns)
{
 u32 service=prefetch_service(payload);
 if (!insns || !service) return -EINVAL;
 insns[0]=BPF_CALL_KFUNC(0,service); return 1;
}
static int prefetch_exception(u64 payload, unsigned int index, struct bpf_kop_exception *entry)
{
 if (!entry || index || !prefetch_service(payload)) return -EINVAL;
 *entry=(struct bpf_kop_exception) { .insn_offset=0,
  .fixup_offset=EBPFOS_FAULT_PREFETCHT0_FIXUP, .data=EX_TYPE_DEFAULT }; return 0;
}
static int prefetch_requirements(u64 payload, u64 *capability, u64 *effect, u8 sha[32])
{
 static const u8 digest[]=EBPFOS_FAULT_PREFETCHT0_SHA256;
 if (!capability || !effect || !sha || !prefetch_service(payload)) return -EINVAL;
 *capability=prefetch_capability; *effect=prefetch_effect;
 memcpy(sha,payload==prefetch_id ? prefetch_typed_sha : digest,32); return 0;
}
static int prefetch_emit(u8 *image, u32 *offset, bool emit, u64 payload,
                        const struct bpf_prog *prog, const u8 *final_ip)
{
 if (!offset || (emit && !image) || !prefetch_service(payload)) return -EINVAL;
 if (emit) memcpy(image+*offset,prefetch_native,sizeof(prefetch_native));
 *offset+=sizeof(prefetch_native); return sizeof(prefetch_native);
}
static const struct btf_kfunc_id_set prefetch_service_set={ .set=&prefetch_services };
int ebpfos_prefetcht0_initialize(struct bpf_kop *kop, u32 id, u32 typed_service)
{
 prefetch_id=id; prefetch_typed_service=typed_service;
 prefetch_capability=kop->capability_mask; prefetch_effect=kop->effect_mask;
 memcpy(prefetch_typed_sha,kop->semantic_sha256,32);
 /* One opcode descriptor. Plain hints keep their existing typed proof;
  * only an explicit protected payload accepts arbitrary addresses. The
  * extra fixup is unreachable for the plain proof's valid mapped objects. */
 kop->max_insn_cnt=1; kop->max_emit_bytes=sizeof(prefetch_native);
 kop->num_exentries=1; kop->exception_entry=prefetch_exception;
 kop->instantiate_insn=prefetch_proof; kop->emit_x86=prefetch_emit;
 kop->requirements=prefetch_requirements;
 kop->proof_kfunc_id_for_payload=prefetch_service;
 return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,&prefetch_service_set);
}
