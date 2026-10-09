// SPDX-License-Identifier: GPL-2.0-only
/* Single source SFENCE, including ordering of non-temporal stores. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include "koperation_sfence.generated.h"

__bpf_kfunc_start_defs();
__bpf_kfunc u64 bpf_ebpfos_x86_sfence(void)
{
	asm volatile("sfence" : : : "memory");
	return 0;
}
__bpf_kfunc u64 bpf_ebpfos_kop_sfence(void)
{
	return 0; /* Only the checked proof or bound instruction emission runs. */
}
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(sfence_services)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_sfence)
BTF_KFUNCS_END(sfence_services)
BTF_KFUNCS_START(sfence_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_sfence)
BTF_KFUNCS_END(sfence_ids)
static const u8 sfence_native[] = EBPFOS_SFENCE_NATIVE;
static int sfence_proof(u64 payload, struct bpf_insn *insns)
{
	if (!insns || payload != sfence_ids.pairs[0].id)
		return -EINVAL;
	insns[0] = BPF_CALL_KFUNC(0, sfence_services.pairs[0].id);
	return 1;
}
static int sfence_requirements(u64 payload, u64 *capability, u64 *effect, u8 sha[32])
{
	static const u8 semantics[] = EBPFOS_SFENCE_SHA256;
	if (!capability || !effect || !sha || payload != sfence_ids.pairs[0].id)
		return -EINVAL;
	*capability = 0; *effect = 0;
	memcpy(sha, semantics, sizeof(semantics));
	return 0;
}
static int sfence_emit(u8 *image, u32 *offset, bool emit, u64 payload,
		      const struct bpf_prog *prog, const u8 *final_ip)
{
	if (!offset || (emit && !image) || payload != sfence_ids.pairs[0].id)
		return -EINVAL;
	if (emit) memcpy(image + *offset, sfence_native, sizeof(sfence_native));
	*offset += sizeof(sfence_native);
	return sizeof(sfence_native);
}
static struct bpf_kop sfence_kop = {
	.max_insn_cnt = 1, .max_emit_bytes = sizeof(sfence_native),
	.instantiate_insn = sfence_proof, .emit_x86 = sfence_emit,
	.requirements = sfence_requirements, .semantic_sha256 = EBPFOS_SFENCE_SHA256,
};
static const struct bpf_kop * const sfence_descs[] = { &sfence_kop };
static const struct btf_kfunc_id_set sfence_service_set = { .set = &sfence_services };
static const struct btf_kfunc_id_set sfence_set = { .set = &sfence_ids, .kop_descs = sfence_descs };
static int __init sfence_register(void)
{
	int error;
	sfence_kop.proof_kfunc_id = sfence_services.pairs[0].id;
	error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &sfence_service_set);
	if (error) return error;
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &sfence_set);
}
late_initcall(sfence_register);
