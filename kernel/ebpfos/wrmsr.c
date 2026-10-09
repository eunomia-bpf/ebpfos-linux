// SPDX-License-Identifier: GPL-2.0-only
/* One WRMSR with Linux's safe exception result; no warning policy. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <asm/asm.h>
#include <asm/extable.h>
#include "koperation_wrmsr.generated.h"

__bpf_kfunc_start_defs();
__bpf_kfunc u32 bpf_ebpfos_x86_wrmsr(u32 index, u64 value)
{
 int error;
 asm volatile("1: wrmsr\nxor %0,%0\n2:\n"
              _ASM_EXTABLE_TYPE_REG(1b, 2b, EX_TYPE_WRMSR_SAFE, %0)
              : "=r"(error) : "c"(index), "a"((u32)value), "d"((u32)(value >> 32)));
 return error;
}
__bpf_kfunc u32 bpf_ebpfos_kop_wrmsr(u32 index, u64 value)
{
 return 0; /* Only checked proof or instruction emission executes. */
}
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(wrmsr_services)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_wrmsr)
BTF_KFUNCS_END(wrmsr_services)
BTF_KFUNCS_START(wrmsr_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_wrmsr)
BTF_KFUNCS_END(wrmsr_ids)
static const u8 wrmsr_native[] = EBPFOS_WRMSR_NATIVE;
static bool wrmsr_valid(u64 payload) { return payload == wrmsr_ids.pairs[0].id; }
static u32 wrmsr_service(u64 payload)
{ return wrmsr_valid(payload) ? wrmsr_services.pairs[0].id : 0; }
static int wrmsr_proof(u64 payload, struct bpf_insn *insns)
{
 if (!insns || !wrmsr_valid(payload)) return -EINVAL;
 insns[0] = BPF_CALL_KFUNC(0, wrmsr_services.pairs[0].id);
 return 1;
}
static int wrmsr_exception(u64 payload, unsigned int index, struct bpf_kop_exception *entry)
{
 if (!entry || index || !wrmsr_valid(payload)) return -EINVAL;
 *entry = (struct bpf_kop_exception) { .insn_offset = EBPFOS_WRMSR_INSN,
  .fixup_offset = EBPFOS_WRMSR_FIXUP, .data = EX_TYPE_WRMSR_SAFE | (8 << 8) };
 return 0;
}
static int wrmsr_requirements(u64 payload, u64 *capability, u64 *effect, u8 sha[32])
{
 static const u8 digest[] = EBPFOS_WRMSR_SHA256;
 if (!capability || !effect || !sha || !wrmsr_valid(payload)) return -EINVAL;
 *capability = 0; *effect = 0; memcpy(sha, digest, 32);
 return 0;
}
static int wrmsr_emit(u8 *image, u32 *offset, bool emit, u64 payload,
                     const struct bpf_prog *prog, const u8 *final_ip)
{
 if (!offset || (emit && !image) || !wrmsr_valid(payload)) return -EINVAL;
 if (emit) memcpy(image + *offset, wrmsr_native, sizeof(wrmsr_native));
 *offset += sizeof(wrmsr_native); return sizeof(wrmsr_native);
}
static struct bpf_kop wrmsr_kop = { .max_insn_cnt = 1,
 .max_emit_bytes = sizeof(wrmsr_native), .num_exentries = 1,
 .exception_entry = wrmsr_exception, .instantiate_insn = wrmsr_proof,
 .emit_x86 = wrmsr_emit, .requirements = wrmsr_requirements,
 .proof_kfunc_id_for_payload = wrmsr_service, .semantic_sha256 = EBPFOS_WRMSR_SHA256 };
static const struct bpf_kop * const wrmsr_descs[] = { &wrmsr_kop };
static const struct btf_kfunc_id_set wrmsr_service_set = { .set = &wrmsr_services };
static const struct btf_kfunc_id_set wrmsr_set = { .set = &wrmsr_ids, .kop_descs = wrmsr_descs };
static int __init wrmsr_register(void)
{
 int error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &wrmsr_service_set);
 if (error) return error;
 return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &wrmsr_set);
}
late_initcall(wrmsr_register);
