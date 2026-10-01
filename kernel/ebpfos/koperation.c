// SPDX-License-Identifier: GPL-2.0-only
/* A verifier-checked terminal effect with no machine-root controls. */
#include <crypto/sha2.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/ebpfos.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/unaligned.h>

__bpf_kfunc_start_defs();
__bpf_kfunc void bpf_ebpfos_kprog_terminal_effect(void) { }
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(ebpfos_kprog_terminal_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kprog_terminal_effect, KF_NORETURN)
BTF_KFUNCS_END(ebpfos_kprog_terminal_ids)

/* sha256("ebpfos-koperation-terminal-effect-v2:x86_64:f390:verified-native-backedge:verifier-noreturn") */
static const u8 ebpfos_kprog_terminal_semantic_sha256[SHA256_DIGEST_SIZE] = {
	0xf4, 0xae, 0x65, 0xa5, 0x34, 0xd1, 0xa6, 0xb0,
	0x5d, 0xae, 0x97, 0x22, 0xcd, 0xad, 0xaa, 0x25,
	0xa3, 0xf0, 0x97, 0x01, 0x75, 0x51, 0x85, 0x69,
	0x37, 0x5c, 0x2b, 0xf2, 0x70, 0x71, 0x62, 0x93,
};

static bool ebpfos_kprog_terminal_payload(u64 payload)
{
	return ebpfos_kprog_terminal_ids.cnt == 1 &&
	       payload == ebpfos_kprog_terminal_ids.pairs[0].id;
}

static int ebpfos_kprog_terminal_instantiate(u64 payload,
					      struct bpf_insn *insns)
{
	u32 effect_tag;

	if (!insns || !ebpfos_kprog_terminal_payload(payload))
		return -EINVAL;
	effect_tag = get_unaligned_le32(
		ebpfos_kprog_terminal_semantic_sha256) & S32_MAX;
	insns[0] = BPF_MOV64_IMM(BPF_REG_0, effect_tag);
	return 1;
}

static int ebpfos_kprog_terminal_requirements(
	u64 payload, u64 *capability_mask, u64 *effect_mask,
	u8 semantic_sha256[SHA256_DIGEST_SIZE])
{
	if (!capability_mask || !effect_mask || !semantic_sha256 ||
	    !ebpfos_kprog_terminal_payload(payload))
		return -EINVAL;
	*capability_mask = EBPFOS_CAP_KPROG_TERMINAL_ROOT;
	*effect_mask = EBPFOS_EFFECT_KPROG_TERMINAL_WAIT;
	memcpy(semantic_sha256, ebpfos_kprog_terminal_semantic_sha256,
	       SHA256_DIGEST_SIZE);
	return 0;
}

static int ebpfos_kprog_terminal_emit_x86(
	u8 *image, u32 *offset, bool emit, u64 payload,
	const struct bpf_prog *prog, const u8 *final_ip)
{
	static const u8 terminal[] = { 0xf3, 0x90 };

	(void)prog;
	(void)final_ip;
	if (!offset || (emit && !image) ||
	    !ebpfos_kprog_terminal_payload(payload))
		return -EINVAL;
	if (emit)
		memcpy(image + *offset, terminal, sizeof(terminal));
	*offset += sizeof(terminal);
	return sizeof(terminal);
}

static struct bpf_kop ebpfos_kprog_terminal = {
	.max_insn_cnt = 1,
	.max_emit_bytes = 2,
	.noreturn_native_backedge = true,
	.capability_mask = EBPFOS_CAP_KPROG_TERMINAL_ROOT,
	.effect_mask = EBPFOS_EFFECT_KPROG_TERMINAL_WAIT,
	.semantic_sha256 = {
		0xf4, 0xae, 0x65, 0xa5, 0x34, 0xd1, 0xa6, 0xb0,
		0x5d, 0xae, 0x97, 0x22, 0xcd, 0xad, 0xaa, 0x25,
		0xa3, 0xf0, 0x97, 0x01, 0x75, 0x51, 0x85, 0x69,
		0x37, 0x5c, 0x2b, 0xf2, 0x70, 0x71, 0x62, 0x93,
	},
	.requirements = ebpfos_kprog_terminal_requirements,
	.instantiate_insn = ebpfos_kprog_terminal_instantiate,
	.emit_x86 = ebpfos_kprog_terminal_emit_x86,
};

static const struct bpf_kop * const ebpfos_kprog_terminal_descs[] = {
	&ebpfos_kprog_terminal,
};

static int ebpfos_kprog_terminal_filter(const struct bpf_prog *prog,
					u32 kfunc_id)
{
	if (!btf_id_set8_contains(&ebpfos_kprog_terminal_ids, kfunc_id))
		return 0;
	if (!prog || !prog->aux)
		return 1;
	if (prog->aux->ebpfos_component)
		return 0;
	return prog->type != BPF_PROG_TYPE_SYSCALL || !prog->sleepable;
}

static const struct btf_kfunc_id_set ebpfos_kprog_terminal_set = {
	.set = &ebpfos_kprog_terminal_ids,
	.filter = ebpfos_kprog_terminal_filter,
	.kop_descs = ebpfos_kprog_terminal_descs,
};

static int __init ebpfos_kprog_register(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					 &ebpfos_kprog_terminal_set);
}
late_initcall(ebpfos_kprog_register);
