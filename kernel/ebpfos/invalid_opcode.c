// SPDX-License-Identifier: GPL-2.0-only
/* Exact terminal UD2. Linux's exception entry and handler are separate code. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include "koperation_ud2_terminal.generated.h"
#include "component_context.h"

/* Returning BUG/WARN/CFI traps require their source tables and continuation. */
#if defined(CONFIG_X86_64) && !defined(CONFIG_BUG) && !defined(CONFIG_CFI) && \
    !defined(CONFIG_X86_FRED)
__bpf_kfunc_start_defs();
__bpf_kfunc __attribute__((btf_decl_tag("bpf_kop_payload_id:0"))) void bpf_ebpfos_kop_ud2_terminal(void)
{
	/* Only the checked proof or exact instruction emission executes. */
}
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(ud2_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_ud2_terminal, KF_NORETURN)
BTF_KFUNCS_END(ud2_ids)

static bool ud2_valid(u64 payload)
{
	return payload == ud2_ids.pairs[0].id;
}
static int ud2_proof(u64 payload, struct bpf_insn *insns)
{
	if (!insns || !ud2_valid(payload))
		return -EINVAL;
	/* The existing KF_NORETURN protocol marks this final scalar instruction
	 * terminal. No source output or local continuation survives the #UD.
	 * Its Linux entry/handler remain separate compiled-code dependencies.
	 */
	insns[0] = BPF_MOV64_IMM(BPF_REG_0, 6); /* X86_TRAP_UD */
	return 1;
}
static int ud2_emit(u8 *image, u32 *offset, bool emit, u64 payload,
		    const struct bpf_prog *prog, const u8 *final_ip)
{
	static const u8 native[] = EBPFOS_UD2_TERMINAL_NATIVE;

	if (!offset || (emit && !image) || !ud2_valid(payload))
		return -EINVAL;
	if (emit)
		memcpy(image + *offset, native, sizeof(native));
	*offset += sizeof(native);
	return sizeof(native);
}
static struct bpf_kop ud2_kop = {
	.max_insn_cnt = 1,
	.max_emit_bytes = 2,
	.instantiate_insn = ud2_proof,
	.emit_x86 = ud2_emit,
	.semantic_sha256 = EBPFOS_UD2_TERMINAL_SHA256,
};
static const struct bpf_kop * const ud2_descs[] = { &ud2_kop };
static const struct btf_kfunc_id_set ud2_set = {
	.set = &ud2_ids, .kop_descs = ud2_descs,
};
static int ud2_component_filter(const struct bpf_prog *prog, u32 id)
{
 if (!btf_id_set8_contains(&ud2_ids, id)) return 0;
 return !ebpfos_non_sleepable_component(prog) || prog->type != BPF_PROG_TYPE_TRACING;
}
static const struct btf_kfunc_id_set ud2_component_set = {
 .set = &ud2_ids, .kop_descs = ud2_descs, .filter = ud2_component_filter,
};
static int __init ud2_register(void)
{
 int error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &ud2_set);
 return error ? error : register_btf_kfunc_id_set(BPF_PROG_TYPE_RAW_TRACEPOINT, &ud2_component_set);
}
late_initcall(ud2_register);
#endif
