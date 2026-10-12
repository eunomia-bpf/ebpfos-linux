// SPDX-License-Identifier: GPL-2.0-only
/* Single direct CALL with an ordinary, stock-verified exception continuation. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <asm/extable_fixup_types.h>

__bpf_kfunc_start_defs();
__bpf_kfunc void bpf_ebpfos_kop_fault_call(u64 carrier)
{
	/* Non-callable descriptor; only its proof and adjacent real CALL run. */
}
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(fault_call_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_fault_call)
BTF_KFUNCS_END(fault_call_ids)

static bool fault_call_valid(u64 payload)
{
	return payload == ((u64)fault_call_ids.pairs[0].id << 8 |
			   EX_TYPE_UACCESS);
}

static int fault_call_proof(u64 payload, struct bpf_insn *insns)
{
	if (!insns || !fault_call_valid(payload))
		return -EINVAL;
	/* Require the real R1 argument to be initialized and preserve it. */
	insns[0] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_1);
	return 1;
}

static int fault_call_emit(u8 *image, u32 *offset, bool emit, u64 payload,
			   const struct bpf_prog *prog, const u8 *final_ip)
{
	if (!offset || !fault_call_valid(payload))
		return -EINVAL;
	/* The normal direct CALL emitter owns its one opcode and extable. */
	return 0;
}

static struct bpf_kop fault_call_kop = {
	.call_exception_annotation = true,
	.max_insn_cnt = 1,
	.max_emit_bytes = 0,
	.num_exentries = 1,
	.instantiate_insn = fault_call_proof,
	.emit_x86 = fault_call_emit,
	.semantic_sha256 = { 0x5b, 0x4b, 0x65, 0x64, 0x02, 0xcc, 0x82, 0x88, 0xc6, 0xb8, 0x21, 0xda, 0x98, 0xb4, 0x14, 0x9e, 0xfc, 0xbe, 0x6b, 0x96, 0x86, 0x70, 0x9b, 0xf9, 0x30, 0xe7, 0x55, 0xb3, 0x4a, 0x08, 0x7a, 0x28 },
};
static const struct bpf_kop * const fault_call_descs[] = { &fault_call_kop };
static const struct btf_kfunc_id_set fault_call_set = {
	.set = &fault_call_ids,
	.kop_descs = fault_call_descs,
};

static int __init fault_call_register(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &fault_call_set);
}
late_initcall(fault_call_register);
