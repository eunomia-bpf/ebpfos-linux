// SPDX-License-Identifier: GPL-2.0-only
/* Source local_irq_restore: enable IF only when the saved word had IF set. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include "koperation_irq_restore_if.generated.h"

__bpf_kfunc_start_defs();
__bpf_kfunc void bpf_ebpfos_kop_irq_restore_if(unsigned long *flags)
{
	/* Only the stock IRQ-token proof or bound instruction emission runs. */
}
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(irq_restore_if_services)
BTF_ID_FLAGS(func, bpf_local_irq_restore)
BTF_KFUNCS_END(irq_restore_if_services)
BTF_KFUNCS_START(irq_restore_if_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_irq_restore_if)
BTF_KFUNCS_END(irq_restore_if_ids)

static const u8 irq_restore_if_native[] = EBPFOS_IRQ_RESTORE_IF_NATIVE;
static int irq_restore_if_proof(u64 payload, struct bpf_insn *insns)
{
	if (!insns || payload != irq_restore_if_ids.pairs[0].id)
		return -EINVAL;
	insns[0] = BPF_CALL_KFUNC(0, irq_restore_if_services.pairs[0].id);
	return 1;
}
static int irq_restore_if_requirements(u64 payload, u64 *capability,
				       u64 *effect, u8 sha[32])
{
	static const u8 semantics[] = EBPFOS_IRQ_RESTORE_IF_SHA256;
	if (!capability || !effect || !sha || payload != irq_restore_if_ids.pairs[0].id)
		return -EINVAL;
	*capability = 0;
	*effect = 0;
	memcpy(sha, semantics, sizeof(semantics));
	return 0;
}
static int irq_restore_if_emit(u8 *image, u32 *offset, bool emit, u64 payload,
			      const struct bpf_prog *prog, const u8 *final_ip)
{
	if (!offset || (emit && !image) || payload != irq_restore_if_ids.pairs[0].id)
		return -EINVAL;
	if (emit)
		memcpy(image + *offset, irq_restore_if_native, sizeof(irq_restore_if_native));
	*offset += sizeof(irq_restore_if_native);
	return sizeof(irq_restore_if_native);
}
static struct bpf_kop irq_restore_if_kop = {
	.max_insn_cnt = 1, .max_emit_bytes = sizeof(irq_restore_if_native),
	.instantiate_insn = irq_restore_if_proof, .emit_x86 = irq_restore_if_emit,
	.requirements = irq_restore_if_requirements,
	.semantic_sha256 = EBPFOS_IRQ_RESTORE_IF_SHA256,
};
static const struct bpf_kop * const irq_restore_if_descs[] = { &irq_restore_if_kop };
static const struct btf_kfunc_id_set irq_restore_if_service_set = {
	.set = &irq_restore_if_services,
};
static const struct btf_kfunc_id_set irq_restore_if_set = {
	.set = &irq_restore_if_ids, .kop_descs = irq_restore_if_descs,
};
static int __init irq_restore_if_register(void)
{
	int error;
	irq_restore_if_kop.proof_kfunc_id = irq_restore_if_services.pairs[0].id;
	error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &irq_restore_if_service_set);
	if (error)
		return error;
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &irq_restore_if_set);
}
late_initcall(irq_restore_if_register);
