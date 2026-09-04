// SPDX-License-Identifier: GPL-2.0-only
/* Generic generated KOperation verifier-to-native execution cell. */
#include <crypto/sha2.h>
#include <linux/atomic.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/ebpfos.h>
#include <linux/err.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/preempt.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#include <linux/uaccess.h>

#include <asm/page.h>
#include <asm/desc.h>
#include <asm/msr.h>
#include <asm/processor-flags.h>
#include <asm/special_insns.h>

struct ebpfos_koperation_descriptor {
	u32 operation_id;
	u32 architecture_requirements;
	u8 kprog_machine_form;
	u8 kprog_machine_selector;
	u8 kprog_machine_action;
	u8 kprog_normalize_bits;
	u32 kprog_machine_register;
	u8 kprog_operand_policy;
	u8 kprog_readback_required;
	u64 kprog_operand_required;
	u64 kprog_operand_variable_mask;
	const struct bpf_insn *proof_insns;
	u32 proof_insn_count;
	u32 proof_imm64_insn;
	u32 shadow_source;
	u64 (*native_emit)(u64 operand);
	const u32 *native_body_end_delta;
	u32 native_body_size;
	u8 semantic_sha256[SHA256_DIGEST_SIZE];
	u8 proof_template_sha256[SHA256_DIGEST_SIZE];
	u8 native_sha256[SHA256_DIGEST_SIZE];
	u8 equivalence_sha256[SHA256_DIGEST_SIZE];
};

#define EBPFOS_KOPERATION_SHADOW_CURRENT_MM_PGD 1U
#define EBPFOS_KOPERATION_SHADOW_CURRENT_CR4 2U
#define EBPFOS_KOPERATION_SHADOW_CURRENT_LSTAR 3U
#define EBPFOS_KOPERATION_SHADOW_UNAVAILABLE 4U
#define EBPFOS_KOPERATION_SHADOW_CURRENT_IDTR 5U
#define EBPFOS_KOPERATION_REQUIRE_CR3_NOFLUSH_CLEAR (1U << 0)

#include "koperation-generated.h"

static const struct ebpfos_koperation_descriptor *
ebpfos_koperation_find(u32 operation_id);

/*
 * Donor structure: bpf-benchmark@5b130b6ec8c44006fd7768acb7b2c8b506ea038b
 * module/include/kop_common.h and module/include/kop_x86_emit.h.  The payload
 * decoder, descriptor callbacks, and bounded byte emitter are mechanically
 * adapted here.  The benchmark loader and bpf_x86_native_lab.c verifier
 * bypass are deliberately excluded.
 */
#define EBPFOS_KPROG_FORM_CONTROL_REGISTER 1U
#define EBPFOS_KPROG_FORM_MODEL_SPECIFIC_REGISTER 2U
#define EBPFOS_KPROG_FORM_DESCRIPTOR_TABLE_REGISTER 3U
#define EBPFOS_KPROG_FORM_IO_PORT 4U
#define EBPFOS_KPROG_CONTROL_CR3 3U
#define EBPFOS_KPROG_CONTROL_CR4 4U
#define EBPFOS_KPROG_MSR_LSTAR 1U
#define EBPFOS_KPROG_MSR_X2APIC_LVTT 2U
#define EBPFOS_KPROG_MSR_X2APIC_TMICT 3U
#define EBPFOS_KPROG_MSR_X2APIC_TMCCT 4U
#define EBPFOS_KPROG_MSR_X2APIC_ICR_SELF 5U
#define EBPFOS_KPROG_MSR_X2APIC_EOI 6U
#define EBPFOS_KPROG_DESCRIPTOR_IDTR 1U
#define EBPFOS_KPROG_IO_PORT_UART8250_TX 1U
#define EBPFOS_KPROG_ACTION_RELOAD 1U
#define EBPFOS_KPROG_ACTION_OBSERVE 2U
#define EBPFOS_KPROG_ACTION_INSTALL 3U
#define EBPFOS_KPROG_OPERAND_NONE 0U
#define EBPFOS_KPROG_OPERAND_CANONICAL_ADDRESS 1U
#define EBPFOS_KPROG_OPERAND_MASKED_VALUE 2U

static bool ebpfos_kprog_payload_escaped(u64 payload)
{
	u8 marker = payload & 0xf;
	u8 original_low = (payload >> 4) & 0xf;

	return marker == BPF_REG_10 && original_low >= 11 && original_low <= 15;
}

static u64 ebpfos_kprog_payload_decode(u64 payload)
{
	if (!ebpfos_kprog_payload_escaped(payload))
		return payload;
	return ((payload >> 8) << 4) | ((payload >> 4) & 0xf);
}

struct ebpfos_kprog_machine_payload {
	u8 input_reg;
	u8 output_reg;
	u8 form;
	u8 selector;
	u8 action;
};

static int ebpfos_kprog_machine_decode(
	u64 payload, struct ebpfos_kprog_machine_payload *decoded)
{
	payload = ebpfos_kprog_payload_decode(payload);
	decoded->form = payload & 0xf;
	if ((decoded->form != EBPFOS_KPROG_FORM_CONTROL_REGISTER &&
	     decoded->form != EBPFOS_KPROG_FORM_MODEL_SPECIFIC_REGISTER &&
	     decoded->form != EBPFOS_KPROG_FORM_DESCRIPTOR_TABLE_REGISTER &&
	     decoded->form != EBPFOS_KPROG_FORM_IO_PORT) ||
	    payload >> 24)
		return -EINVAL;
	decoded->input_reg = (payload >> 4) & 0xf;
	decoded->output_reg = (payload >> 8) & 0xf;
	decoded->selector = (payload >> 12) & 0xff;
	decoded->action = (payload >> 20) & 0xf;
	if (decoded->input_reg < BPF_REG_6 ||
	    decoded->input_reg > BPF_REG_9 ||
	    decoded->output_reg != BPF_REG_0)
		return -EINVAL;
	if (decoded->form == EBPFOS_KPROG_FORM_CONTROL_REGISTER) {
		if ((decoded->selector != EBPFOS_KPROG_CONTROL_CR3 &&
		     decoded->selector != EBPFOS_KPROG_CONTROL_CR4) ||
		    (decoded->action != EBPFOS_KPROG_ACTION_RELOAD &&
		     decoded->action != EBPFOS_KPROG_ACTION_OBSERVE))
			return -EINVAL;
	} else if (decoded->form == EBPFOS_KPROG_FORM_MODEL_SPECIFIC_REGISTER &&
		   (decoded->action != EBPFOS_KPROG_ACTION_INSTALL &&
		    decoded->action != EBPFOS_KPROG_ACTION_OBSERVE)) {
		return -EINVAL;
	} else if (decoded->form == EBPFOS_KPROG_FORM_DESCRIPTOR_TABLE_REGISTER &&
		   (decoded->selector != EBPFOS_KPROG_DESCRIPTOR_IDTR ||
		    (decoded->action != EBPFOS_KPROG_ACTION_INSTALL &&
		     decoded->action != EBPFOS_KPROG_ACTION_OBSERVE))) {
		return -EINVAL;
	} else if (decoded->form == EBPFOS_KPROG_FORM_IO_PORT &&
		   (decoded->selector != EBPFOS_KPROG_IO_PORT_UART8250_TX ||
		    decoded->action != EBPFOS_KPROG_ACTION_INSTALL)) {
		return -EINVAL;
	}
	return 0;
}

static const struct ebpfos_koperation_descriptor *
ebpfos_koperation_find_machine(u8 form, u8 selector, u8 action)
{
	unsigned int index;

	for (index = 0; index < ARRAY_SIZE(ebpfos_koperation_descriptors);
	     index++) {
		const struct ebpfos_koperation_descriptor *descriptor =
			&ebpfos_koperation_descriptors[index];

		if (descriptor->kprog_machine_form == form &&
		    descriptor->kprog_machine_selector == selector &&
		    descriptor->kprog_machine_action == action)
			return descriptor;
	}
	return NULL;
}

static int ebpfos_kprog_machine_instantiate(u64 payload,
				    struct bpf_insn *insns)
{
	const struct ebpfos_koperation_descriptor *operation;
	struct ebpfos_kprog_machine_payload decoded;
	u32 effect_tag;
	int error;

	if (!insns)
		return -EINVAL;
	error = ebpfos_kprog_machine_decode(payload, &decoded);
	if (error)
		return error;
	operation = ebpfos_koperation_find_machine(decoded.form, decoded.selector,
						     decoded.action);
	if (!operation)
		return -ENOENT;
	/* The canonical BPF model preserves the declared root while committing
	 * the effect identity twice so the full 64-bit result remains exact. */
	effect_tag = get_unaligned_le32(operation->semantic_sha256) & S32_MAX;
	insns[0] = BPF_MOV64_REG(decoded.output_reg, decoded.input_reg);
	insns[1] = BPF_ALU64_IMM(BPF_XOR, decoded.output_reg, effect_tag);
	insns[2] = BPF_ALU64_IMM(BPF_XOR, decoded.output_reg, effect_tag);
	return 3;
}

static int ebpfos_kprog_machine_requirements(
	u64 payload, u64 *capability_mask, u64 *effect_mask,
	u8 semantic_sha256[SHA256_DIGEST_SIZE])
{
	const struct ebpfos_koperation_descriptor *operation;
	struct ebpfos_kprog_machine_payload decoded;
	int error;

	if (!capability_mask || !effect_mask || !semantic_sha256)
		return -EINVAL;
	error = ebpfos_kprog_machine_decode(payload, &decoded);
	if (error)
		return error;
	operation = ebpfos_koperation_find_machine(decoded.form, decoded.selector,
						     decoded.action);
	if (!operation)
		return -ENOENT;
	*capability_mask = EBPFOS_CAP_KPROG_MACHINE_ROOT;
	*effect_mask = EBPFOS_EFFECT_KPROG_MACHINE_STATE;
	memcpy(semantic_sha256, operation->semantic_sha256,
	       SHA256_DIGEST_SIZE);
	return 0;
}

static u8 ebpfos_kprog_x86_reg_code(u8 reg)
{
	static const u8 codes[] = {
		[BPF_REG_6] = 3, /* RBX */
		[BPF_REG_7] = 5, /* R13 */
		[BPF_REG_8] = 6, /* R14 */
		[BPF_REG_9] = 7, /* R15 */
	};

	return reg < ARRAY_SIZE(codes) ? codes[reg] : 0xff;
}

static bool ebpfos_kprog_x86_reg_extended(u8 reg)
{
	return reg == BPF_REG_7 || reg == BPF_REG_8 || reg == BPF_REG_9;
}

static int ebpfos_kprog_machine_emit_x86(
	u8 *image, u32 *offset, bool emit, u64 payload,
	const struct bpf_prog *prog, const u8 *final_ip)
{
	const struct ebpfos_koperation_descriptor *operation;
	struct ebpfos_kprog_machine_payload decoded;
	u8 code[96];
	u8 *cursor = code;
	u8 *first_mismatch = NULL;
	u8 *second_mismatch = NULL;
	u8 *third_mismatch = NULL;
	u8 *success_jump;
	u8 input_code;
	s32 normalize_mask;
	u32 size;
	int error;

	(void)prog;
	(void)final_ip;
	if (!offset || (emit && !image))
		return -EINVAL;
	error = ebpfos_kprog_machine_decode(payload, &decoded);
	if (error)
		return error;
	operation = ebpfos_koperation_find_machine(decoded.form, decoded.selector,
						     decoded.action);
	if (!operation || operation->kprog_normalize_bits > 31)
		return -ENOENT;
	input_code = ebpfos_kprog_x86_reg_code(decoded.input_reg);
	if (input_code == 0xff)
		return -EINVAL;
#define EMIT(_byte) (*cursor++ = (_byte))
	if (decoded.form == EBPFOS_KPROG_FORM_CONTROL_REGISTER) {
		/* Observe and validate the exact normalized control root. */
		EMIT(0x0f); EMIT(0x20);
		EMIT(0xc0 | (decoded.selector << 3));
		if (decoded.action == EBPFOS_KPROG_ACTION_RELOAD) {
			/* Preserve raw CR3, including PCID, for same-root reload. */
			EMIT(0x49); EMIT(0x89); EMIT(0xc3);
		}
		normalize_mask = (s32)(~0U << operation->kprog_normalize_bits);
		EMIT(0x48); EMIT(0x25);
		put_unaligned_le32((u32)normalize_mask, cursor);
		cursor += sizeof(normalize_mask);
		EMIT(0x48 | (ebpfos_kprog_x86_reg_extended(decoded.input_reg) << 2));
		EMIT(0x39); EMIT(0xc0 | (input_code << 3));
		EMIT(0x75); first_mismatch = cursor++;
		if (decoded.action == EBPFOS_KPROG_ACTION_RELOAD) {
			/* Clear CR3.NOFLUSH before the unique privileged write. */
			EMIT(0x49); EMIT(0x0f); EMIT(0xba); EMIT(0xf3); EMIT(0x3f);
			EMIT(0x41); EMIT(0x0f); EMIT(0x22); EMIT(0xdb);
			/* Read back and require the same normalized root. */
			EMIT(0x0f); EMIT(0x20); EMIT(0xd8);
			EMIT(0x48); EMIT(0x25); EMIT(0x00); EMIT(0xf0); EMIT(0xff); EMIT(0xff);
			EMIT(0x48 | (ebpfos_kprog_x86_reg_extended(decoded.input_reg) << 2));
			EMIT(0x39); EMIT(0xc0 | (input_code << 3));
			EMIT(0x75); second_mismatch = cursor++;
		}
	} else if (decoded.form == EBPFOS_KPROG_FORM_DESCRIPTOR_TABLE_REGISTER) {
		/* IDTR is a 10-byte architectural value.  The generated ABI binds
		 * its base in the BPF u64 operand and fixes the x86-64 IDT limit to
		 * 256 descriptors.  Both observe and install verify limit and base. */
		if (decoded.action == EBPFOS_KPROG_ACTION_INSTALL) {
			EMIT(0x49 | (ebpfos_kprog_x86_reg_extended(decoded.input_reg) << 2));
			EMIT(0x89); EMIT(0xc0 | (input_code << 3) | 3); /* input -> r11 */
			/* Reject a non-canonical component-owned table base. */
			EMIT(0x4c); EMIT(0x89); EMIT(0xd8);
			EMIT(0x48); EMIT(0xc1); EMIT(0xe0); EMIT(0x10);
			EMIT(0x48); EMIT(0xc1); EMIT(0xf8); EMIT(0x10);
			EMIT(0x49); EMIT(0x39); EMIT(0xc3);
			EMIT(0x75); first_mismatch = cursor++;
		}
		EMIT(0x48); EMIT(0x83); EMIT(0xec); EMIT(0x10);
		if (decoded.action == EBPFOS_KPROG_ACTION_INSTALL) {
			EMIT(0x66); EMIT(0xc7); EMIT(0x04); EMIT(0x24);
			EMIT(0xff); EMIT(0x0f); /* 256 * 16 - 1 */
			EMIT(0x4c); EMIT(0x89); EMIT(0x5c); EMIT(0x24); EMIT(0x02);
			EMIT(0x0f); EMIT(0x01); EMIT(0x1c); EMIT(0x24); /* lidt */
		}
		EMIT(0x0f); EMIT(0x01); EMIT(0x0c); EMIT(0x24); /* sidt */
		EMIT(0x48); EMIT(0x8b); EMIT(0x44); EMIT(0x24); EMIT(0x02);
		EMIT(0x0f); EMIT(0xb7); EMIT(0x14); EMIT(0x24);
		EMIT(0x48); EMIT(0x83); EMIT(0xc4); EMIT(0x10);
		EMIT(0x81); EMIT(0xfa); EMIT(0xff); EMIT(0x0f); EMIT(0x00); EMIT(0x00);
		EMIT(0x75);
		if (!first_mismatch)
			first_mismatch = cursor++;
		else
			second_mismatch = cursor++;
		EMIT(0x48 | (ebpfos_kprog_x86_reg_extended(decoded.input_reg) << 2));
		EMIT(0x39); EMIT(0xc0 | (input_code << 3));
		EMIT(0x75);
		if (!first_mismatch)
			first_mismatch = cursor++;
		else if (!second_mismatch)
			second_mismatch = cursor++;
		else
			third_mismatch = cursor++;
	} else if (decoded.form == EBPFOS_KPROG_FORM_IO_PORT) {
		u32 mask = ~(u32)operation->kprog_operand_variable_mask;

		if (operation->kprog_operand_policy !=
		    EBPFOS_KPROG_OPERAND_MASKED_VALUE ||
		    operation->kprog_operand_required > S32_MAX ||
		    operation->kprog_operand_variable_mask > U32_MAX ||
		    operation->kprog_machine_register > U16_MAX)
			return -ERANGE;
		/* Stage the component byte in r11 and reject non-byte authority. */
		EMIT(0x49 | (ebpfos_kprog_x86_reg_extended(decoded.input_reg) << 2));
		EMIT(0x89); EMIT(0xc0 | (input_code << 3) | 3);
		EMIT(0x4c); EMIT(0x89); EMIT(0xd8);
		EMIT(0x48); EMIT(0x25);
		put_unaligned_le32(mask, cursor); cursor += 4;
		EMIT(0x48); EMIT(0x3d);
		put_unaligned_le32((u32)operation->kprog_operand_required, cursor);
		cursor += 4;
		EMIT(0x75); first_mismatch = cursor++;
		/* Unique generated PIO execution point: out %al,(%dx). */
		EMIT(0x4c); EMIT(0x89); EMIT(0xd8);
		EMIT(0xba);
		put_unaligned_le32(operation->kprog_machine_register, cursor);
		cursor += 4;
		EMIT(0xee);
		EMIT(0x4c); EMIT(0x89); EMIT(0xd8);
	} else if (decoded.action == EBPFOS_KPROG_ACTION_INSTALL) {
		/*
		 * Stage and constrain the component-owned operand before the unique
		 * WRMSR execution point selected by generated operation metadata.
		 */
		EMIT(0x49 | (ebpfos_kprog_x86_reg_extended(decoded.input_reg) << 2));
		EMIT(0x89); EMIT(0xc0 | (input_code << 3) | 3);
		if (operation->kprog_operand_policy ==
		    EBPFOS_KPROG_OPERAND_CANONICAL_ADDRESS) {
			EMIT(0x4c); EMIT(0x89); EMIT(0xd8);
			EMIT(0x48); EMIT(0xc1); EMIT(0xe0); EMIT(0x10);
			EMIT(0x48); EMIT(0xc1); EMIT(0xf8); EMIT(0x10);
			EMIT(0x49); EMIT(0x39); EMIT(0xc3);
			EMIT(0x75); first_mismatch = cursor++;
		} else if (operation->kprog_operand_policy ==
			   EBPFOS_KPROG_OPERAND_MASKED_VALUE) {
			u32 mask = ~(u32)operation->kprog_operand_variable_mask;

			if (operation->kprog_operand_required > S32_MAX ||
			    operation->kprog_operand_variable_mask > U32_MAX)
				return -ERANGE;
			EMIT(0x4c); EMIT(0x89); EMIT(0xd8);
			EMIT(0x48); EMIT(0x25);
			put_unaligned_le32(mask, cursor); cursor += 4;
			EMIT(0x48); EMIT(0x3d);
			put_unaligned_le32((u32)operation->kprog_operand_required,
					   cursor);
			cursor += 4;
			EMIT(0x75); first_mismatch = cursor++;
		} else if (operation->kprog_operand_policy !=
			   EBPFOS_KPROG_OPERAND_NONE) {
			return -EINVAL;
		}
		EMIT(0x4c); EMIT(0x89); EMIT(0xd8);
		EMIT(0x4c); EMIT(0x89); EMIT(0xda);
		EMIT(0x48); EMIT(0xc1); EMIT(0xea); EMIT(0x20);
		EMIT(0xb9);
		put_unaligned_le32(operation->kprog_machine_register, cursor);
		cursor += 4;
		EMIT(0x0f); EMIT(0x30);
		if (operation->kprog_readback_required) {
			EMIT(0xb9);
			put_unaligned_le32(operation->kprog_machine_register,
					   cursor);
			cursor += 4;
			EMIT(0x0f); EMIT(0x32);
			EMIT(0x48); EMIT(0xc1); EMIT(0xe2); EMIT(0x20);
			EMIT(0x48); EMIT(0x09); EMIT(0xd0);
			EMIT(0x49); EMIT(0x39); EMIT(0xc3);
			EMIT(0x75); second_mismatch = cursor++;
		} else {
			EMIT(0x4c); EMIT(0x89); EMIT(0xd8);
		}
	} else {
		/* Observe the generated MSR and require the verifier-visible value. */
		EMIT(0xb9);
		put_unaligned_le32(operation->kprog_machine_register, cursor);
		cursor += 4;
		EMIT(0x0f); EMIT(0x32);
		EMIT(0x48); EMIT(0xc1); EMIT(0xe2); EMIT(0x20);
		EMIT(0x48); EMIT(0x09); EMIT(0xd0);
		EMIT(0x48 | (ebpfos_kprog_x86_reg_extended(decoded.input_reg) << 2));
		EMIT(0x39); EMIT(0xc0 | (input_code << 3));
		EMIT(0x75); first_mismatch = cursor++;
	}
	EMIT(0xeb); success_jump = cursor++;
	/* -ESTALE is a fail-closed precondition/readback result. */
	*first_mismatch = cursor - (first_mismatch + 1);
	if (second_mismatch)
		*second_mismatch = cursor - (second_mismatch + 1);
	if (third_mismatch)
		*third_mismatch = cursor - (third_mismatch + 1);
	EMIT(0x48); EMIT(0xc7); EMIT(0xc0);
	EMIT(0x8c); EMIT(0xff); EMIT(0xff); EMIT(0xff);
	*success_jump = cursor - (success_jump + 1);
#undef EMIT
	size = cursor - code;
	if (size > sizeof(code))
		return -E2BIG;
	if (emit)
		memcpy(image + *offset, code, size);
	*offset += size;
	return size;
}

__bpf_kfunc_start_defs();
__bpf_kfunc void bpf_ebpfos_kprog_machine_register(void) { }
__bpf_kfunc void bpf_ebpfos_kprog_terminal_effect(void) { }
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(ebpfos_kprog_machine_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kprog_machine_register)
BTF_KFUNCS_END(ebpfos_kprog_machine_ids)

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

static struct bpf_kop ebpfos_kprog_machine = {
	.max_insn_cnt = 3,
	.max_emit_bytes = 96,
	.capability_mask = EBPFOS_CAP_KPROG_MACHINE_ROOT,
	.effect_mask = EBPFOS_EFFECT_KPROG_MACHINE_STATE,
	.requirements = ebpfos_kprog_machine_requirements,
	.instantiate_insn = ebpfos_kprog_machine_instantiate,
	.emit_x86 = ebpfos_kprog_machine_emit_x86,
};

static const struct bpf_kop * const ebpfos_kprog_machine_descs[] = {
	&ebpfos_kprog_machine,
};

int ebpfos_kprog_domain_filter(const struct bpf_prog *prog,
			       bool own_koperation_id)
{
	if (!own_koperation_id)
		return 0;
	return !prog || !prog->aux || !prog->aux->ebpfos_component;
}

static int ebpfos_kprog_filter(const struct bpf_prog *prog, u32 kfunc_id)
{
	/* Hook filters are shared by every kfunc set for the program type. */
	return ebpfos_kprog_domain_filter(
		prog, btf_id_set8_contains(&ebpfos_kprog_machine_ids, kfunc_id));
}

static const struct btf_kfunc_id_set ebpfos_kprog_machine_set = {
	.set = &ebpfos_kprog_machine_ids,
	.filter = ebpfos_kprog_filter,
	.kop_descs = ebpfos_kprog_machine_descs,
};

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
	bool own_id = btf_id_set8_contains(&ebpfos_kprog_terminal_ids,
					 kfunc_id);

	if (!own_id)
		return 0;
	if (!prog || !prog->aux)
		return 1;
	/* Admitted components may execute this root capability.  An ordinary
	 * sleepable syscall program may only freeze verifier/JIT output; the
	 * generic test-run paths reject it through kop_terminal_effect.
	 */
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
	int error;

	if (!ebpfos_koperation_find_machine(EBPFOS_KPROG_FORM_CONTROL_REGISTER,
					    EBPFOS_KPROG_CONTROL_CR3,
					    EBPFOS_KPROG_ACTION_RELOAD) ||
	    !ebpfos_koperation_find_machine(EBPFOS_KPROG_FORM_CONTROL_REGISTER,
					    EBPFOS_KPROG_CONTROL_CR3,
					    EBPFOS_KPROG_ACTION_OBSERVE) ||
	    !ebpfos_koperation_find_machine(EBPFOS_KPROG_FORM_CONTROL_REGISTER,
					    EBPFOS_KPROG_CONTROL_CR4,
					    EBPFOS_KPROG_ACTION_OBSERVE) ||
	    !ebpfos_koperation_find_machine(
			EBPFOS_KPROG_FORM_MODEL_SPECIFIC_REGISTER,
			EBPFOS_KPROG_MSR_LSTAR, EBPFOS_KPROG_ACTION_OBSERVE) ||
	    !ebpfos_koperation_find_machine(
			EBPFOS_KPROG_FORM_MODEL_SPECIFIC_REGISTER,
			EBPFOS_KPROG_MSR_LSTAR, EBPFOS_KPROG_ACTION_INSTALL) ||
	    !ebpfos_koperation_find_machine(
			EBPFOS_KPROG_FORM_DESCRIPTOR_TABLE_REGISTER,
			EBPFOS_KPROG_DESCRIPTOR_IDTR, EBPFOS_KPROG_ACTION_OBSERVE) ||
	    !ebpfos_koperation_find_machine(
			EBPFOS_KPROG_FORM_DESCRIPTOR_TABLE_REGISTER,
			EBPFOS_KPROG_DESCRIPTOR_IDTR, EBPFOS_KPROG_ACTION_INSTALL) ||
	    !ebpfos_koperation_find_machine(
			EBPFOS_KPROG_FORM_MODEL_SPECIFIC_REGISTER,
			EBPFOS_KPROG_MSR_X2APIC_LVTT,
			EBPFOS_KPROG_ACTION_OBSERVE) ||
	    !ebpfos_koperation_find_machine(
			EBPFOS_KPROG_FORM_MODEL_SPECIFIC_REGISTER,
			EBPFOS_KPROG_MSR_X2APIC_LVTT,
			EBPFOS_KPROG_ACTION_INSTALL) ||
	    !ebpfos_koperation_find_machine(
			EBPFOS_KPROG_FORM_MODEL_SPECIFIC_REGISTER,
			EBPFOS_KPROG_MSR_X2APIC_TMCCT,
			EBPFOS_KPROG_ACTION_OBSERVE) ||
	    !ebpfos_koperation_find_machine(
			EBPFOS_KPROG_FORM_MODEL_SPECIFIC_REGISTER,
			EBPFOS_KPROG_MSR_X2APIC_TMICT,
			EBPFOS_KPROG_ACTION_INSTALL) ||
	    !ebpfos_koperation_find_machine(
			EBPFOS_KPROG_FORM_MODEL_SPECIFIC_REGISTER,
			EBPFOS_KPROG_MSR_X2APIC_ICR_SELF,
			EBPFOS_KPROG_ACTION_INSTALL) ||
	    !ebpfos_koperation_find_machine(
			EBPFOS_KPROG_FORM_MODEL_SPECIFIC_REGISTER,
			EBPFOS_KPROG_MSR_X2APIC_EOI,
			EBPFOS_KPROG_ACTION_INSTALL) ||
	    !ebpfos_koperation_find_machine(
			EBPFOS_KPROG_FORM_IO_PORT,
			EBPFOS_KPROG_IO_PORT_UART8250_TX,
			EBPFOS_KPROG_ACTION_INSTALL))
		return -ENOENT;
	error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					  &ebpfos_kprog_machine_set);
	if (error)
		return error;
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					 &ebpfos_kprog_terminal_set);
}
late_initcall(ebpfos_kprog_register);

struct ebpfos_koperation_txn {
	const struct ebpfos_koperation_descriptor *descriptor;
	u64 transaction_id;
	u64 staged_shadow;
	u64 native_result;
	u64 native_operand_before;
	u64 architecture_flags;
	u32 cpu_before;
	u32 cpu_after;
	u32 status;
	int error;
	u8 proof_program_sha256[SHA256_DIGEST_SIZE];
};

static atomic64_t ebpfos_koperation_next_transaction = ATOMIC64_INIT(0);
static atomic64_t ebpfos_koperation_attempts = ATOMIC64_INIT(0);
static atomic64_t ebpfos_koperation_commits = ATOMIC64_INIT(0);
static atomic64_t ebpfos_koperation_rejects = ATOMIC64_INIT(0);

static const struct ebpfos_koperation_descriptor *
ebpfos_koperation_find(u32 operation_id)
{
	unsigned int index;

	for (index = 0; index < ARRAY_SIZE(ebpfos_koperation_descriptors);
	     index++) {
		if (ebpfos_koperation_descriptors[index].operation_id ==
		    operation_id)
			return &ebpfos_koperation_descriptors[index];
	}
	return NULL;
}

static int
ebpfos_koperation_shadow(const struct ebpfos_koperation_descriptor *descriptor,
			 u64 *shadow)
{
	/*
	 * This is donor-observed input state, not the operation implementation.
	 * The generated native sequence independently reads the bound register.
	 */
	switch (descriptor->shadow_source) {
	case EBPFOS_KOPERATION_SHADOW_CURRENT_MM_PGD:
		if (!current->mm)
			return -EOPNOTSUPP;
		*shadow = __pa(current->mm->pgd) & CR3_ADDR_MASK;
		return 0;
	case EBPFOS_KOPERATION_SHADOW_CURRENT_CR4:
		*shadow = __read_cr4();
		return 0;
	case EBPFOS_KOPERATION_SHADOW_CURRENT_LSTAR:
		rdmsrl(MSR_LSTAR, *shadow);
		return 0;
	case EBPFOS_KOPERATION_SHADOW_CURRENT_IDTR: {
		struct desc_ptr idtr;

		store_idt(&idtr);
		if (idtr.size != IDT_ENTRIES * sizeof(gate_desc) - 1)
			return -EOPNOTSUPP;
		*shadow = idtr.address;
		return 0;
	}
	case EBPFOS_KOPERATION_SHADOW_UNAVAILABLE:
		/* Component-owned operands are admitted through the verifier-visible
		 * KOperation payload, never through the experimental ioctl. */
		return -EOPNOTSUPP;
	default:
		return -EOPNOTSUPP;
	}
}

static void ebpfos_koperation_counters(u64 *attempts, u64 *commits,
				       u64 *rejects)
{
	*attempts = atomic64_read(&ebpfos_koperation_attempts);
	*commits = atomic64_read(&ebpfos_koperation_commits);
	*rejects = atomic64_read(&ebpfos_koperation_rejects);
}

static void ebpfos_koperation_burn(struct ebpfos_koperation_txn *txn,
				   int error)
{
	txn->status = EBPFOS_KOPERATION_STATUS_BURNED;
	txn->error = error;
	atomic64_inc(&ebpfos_koperation_rejects);
}

static bool ebpfos_koperation_native_matches(
	const struct ebpfos_koperation_descriptor *descriptor)
{
	u8 actual[SHA256_DIGEST_SIZE];
	const u8 *start = (const u8 *)descriptor->native_emit;
	unsigned long end;
	unsigned long start_address = (unsigned long)start;
	u32 linker_size;
	size_t size;

	size = descriptor->native_body_size;
	if (!size || !descriptor->native_body_end_delta)
		return false;
	linker_size = READ_ONCE(*descriptor->native_body_end_delta);
	if (linker_size != size || size > ULONG_MAX - start_address)
		return false;
	end = start_address + size;
	if (!core_kernel_text(start_address) ||
	    !core_kernel_text(end - 1))
		return false;
	sha256(start, size, actual);
	return !memcmp(actual, descriptor->native_sha256, sizeof(actual));
}

static bool ebpfos_koperation_proof_template_matches(
	const struct ebpfos_koperation_descriptor *descriptor)
{
	u8 actual[SHA256_DIGEST_SIZE];
	size_t size;

	if (!descriptor->proof_insn_count)
		return false;
	size = array_size(descriptor->proof_insn_count,
			  sizeof(struct bpf_insn));
	sha256((const u8 *)descriptor->proof_insns, size, actual);
	return !memcmp(actual, descriptor->proof_template_sha256,
		       sizeof(actual));
}

static int ebpfos_koperation_proof_matches(
	const struct ebpfos_koperation_descriptor *descriptor,
	const struct bpf_prog *prog, u64 staged_shadow,
	u8 program_sha256[SHA256_DIGEST_SIZE])
{
	struct bpf_insn *expected;
	u32 immediate;
	size_t size;
	int error = -EPROTO;

	if (prog->len != descriptor->proof_insn_count ||
	    descriptor->proof_imm64_insn + 1 >= descriptor->proof_insn_count)
		return -EPROTO;
	size = array_size(descriptor->proof_insn_count,
			  sizeof(struct bpf_insn));
	expected = kmemdup(descriptor->proof_insns, size, GFP_KERNEL);
	if (!expected)
		return -ENOMEM;
	immediate = descriptor->proof_imm64_insn;
	expected[immediate].imm = lower_32_bits(staged_shadow);
	expected[immediate + 1].imm = upper_32_bits(staged_shadow);
	if (!memcmp(expected, prog->insnsi, size)) {
		sha256((const u8 *)prog->insnsi, size, program_sha256);
		error = 0;
	}
	kfree(expected);
	return error;
}

long ebpfos_koperation_prepare_ioctl(void __user *argp, void **txn_slot)
{
	struct ebpfos_koperation_prepare request;
	const struct ebpfos_koperation_descriptor *descriptor;
	struct ebpfos_koperation_txn *old = *txn_slot;
	struct ebpfos_koperation_txn *txn;
	int error;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.version != EBPFOS_KOPERATION_ABI_VERSION || request.flags ||
	    request.reserved0)
		return -EINVAL;
	if (old && old->status == EBPFOS_KOPERATION_STATUS_STAGED)
		return -EBUSY;
	descriptor = ebpfos_koperation_find(request.operation_id);
	if (!descriptor)
		return -EOPNOTSUPP;
	txn = kzalloc_obj(*txn, GFP_KERNEL);
	if (!txn)
		return -ENOMEM;
	txn->descriptor = descriptor;
	txn->transaction_id =
		atomic64_inc_return(&ebpfos_koperation_next_transaction);
	error = ebpfos_koperation_shadow(descriptor, &txn->staged_shadow);
	if (error) {
		kfree(txn);
		return error;
	}
	txn->status = EBPFOS_KOPERATION_STATUS_STAGED;

	request.transaction_id = txn->transaction_id;
	request.staged_shadow = txn->staged_shadow;
	memcpy(request.semantic_sha256, descriptor->semantic_sha256,
	       sizeof(request.semantic_sha256));
	memcpy(request.proof_template_sha256,
	       descriptor->proof_template_sha256,
	       sizeof(request.proof_template_sha256));
	memcpy(request.native_sha256, descriptor->native_sha256,
	       sizeof(request.native_sha256));
	memcpy(request.equivalence_sha256, descriptor->equivalence_sha256,
	       sizeof(request.equivalence_sha256));
	ebpfos_koperation_counters(&request.attempts,
				     &request.commits, &request.rejects);
	/* A failed reply cannot leave a hidden staged operation. */
	if (copy_to_user(argp, &request, sizeof(request))) {
		kfree(txn);
		return -EFAULT;
	}
	kfree(old);
	*txn_slot = txn;
	return 0;
}

long ebpfos_koperation_execute_ioctl(void __user *argp, void **txn_slot)
{
	struct ebpfos_koperation_execute request;
	struct ebpfos_koperation_txn *txn = *txn_slot;
	struct bpf_prog *prog;
	u64 trusted_shadow;
	u64 native_result;
	unsigned long cr4;
	int error;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (!txn || txn->status != EBPFOS_KOPERATION_STATUS_STAGED)
		return -EINVAL;
	if (request.version != EBPFOS_KOPERATION_ABI_VERSION || request.flags) {
		ebpfos_koperation_burn(txn, -EINVAL);
		return -EINVAL;
	}
	if (request.operation_id != txn->descriptor->operation_id ||
	    request.transaction_id != txn->transaction_id ||
	    request.expected_shadow != txn->staged_shadow) {
		ebpfos_koperation_burn(txn, -ESTALE);
		return -ESTALE;
	}
	/*
	 * These commitments come from the independently generated component
	 * manifest embedded in the boot image, never from PREPARE's reply.
	 */
	if (memcmp(request.expected_semantic_sha256,
		   txn->descriptor->semantic_sha256,
		   sizeof(request.expected_semantic_sha256)) ||
	    memcmp(request.expected_proof_template_sha256,
		   txn->descriptor->proof_template_sha256,
		   sizeof(request.expected_proof_template_sha256)) ||
	    memcmp(request.expected_native_sha256,
		   txn->descriptor->native_sha256,
		   sizeof(request.expected_native_sha256)) ||
	    memcmp(request.expected_equivalence_sha256,
		   txn->descriptor->equivalence_sha256,
		   sizeof(request.expected_equivalence_sha256))) {
		ebpfos_koperation_burn(txn, -EKEYREJECTED);
		return -EKEYREJECTED;
	}
	error = ebpfos_koperation_shadow(txn->descriptor, &trusted_shadow);
	if (error || trusted_shadow != txn->staged_shadow) {
		error = error ?: -ESTALE;
		ebpfos_koperation_burn(txn, error);
		return error;
	}
	if (!ebpfos_koperation_proof_template_matches(txn->descriptor)) {
		ebpfos_koperation_burn(txn, -EKEYREJECTED);
		return -EKEYREJECTED;
	}
	prog = bpf_prog_get_type_dev(request.proof_prog_fd,
				     BPF_PROG_TYPE_SOCKET_FILTER, false);
	if (IS_ERR(prog)) {
		error = PTR_ERR(prog);
		ebpfos_koperation_burn(txn, error);
		return error;
	}
	error = ebpfos_koperation_proof_matches(txn->descriptor, prog,
						txn->staged_shadow,
						txn->proof_program_sha256);
	bpf_prog_put(prog);
	if (error) {
		ebpfos_koperation_burn(txn, error);
		return error;
	}
	if (!ebpfos_koperation_native_matches(txn->descriptor)) {
		ebpfos_koperation_burn(txn, -EKEYREJECTED);
		return -EKEYREJECTED;
	}

	/*
	 * Unique execution point: the exact verifier-admitted expansion and the
	 * generated text hash have passed.  No fallible user copy follows it.
	 */
	preempt_disable();
	txn->cpu_before = raw_smp_processor_id();
	if (txn->descriptor->shadow_source ==
	    EBPFOS_KOPERATION_SHADOW_CURRENT_MM_PGD) {
		txn->native_operand_before = __read_cr3();
		cr4 = __read_cr4();
		if (cr4 & X86_CR4_PCIDE)
			txn->architecture_flags |= EBPFOS_KOPERATION_ARCH_CR4_PCIDE;
		if (cr4 & X86_CR4_PGE)
			txn->architecture_flags |= EBPFOS_KOPERATION_ARCH_CR4_PGE;
		if (txn->native_operand_before & (1ULL << 63))
			txn->architecture_flags |= EBPFOS_KOPERATION_ARCH_CR3_NOFLUSH;
	} else {
		txn->native_operand_before = trusted_shadow;
	}
	/*
	 * All generated architectural preconditions must close before attempts
	 * changes and before native_emit.  A post-execution check cannot restore
	 * an architectural side effect.
	 */
	if ((txn->descriptor->architecture_requirements &
	     EBPFOS_KOPERATION_REQUIRE_CR3_NOFLUSH_CLEAR) &&
	    (txn->architecture_flags & EBPFOS_KOPERATION_ARCH_CR3_NOFLUSH)) {
		preempt_enable();
		ebpfos_koperation_burn(txn, -EOPNOTSUPP);
		return -EOPNOTSUPP;
	}
	atomic64_inc(&ebpfos_koperation_attempts);
	native_result = txn->descriptor->native_emit(txn->staged_shadow);
	txn->cpu_after = raw_smp_processor_id();
	preempt_enable();
	txn->native_result = native_result;
	if (native_result != txn->staged_shadow) {
		ebpfos_koperation_burn(txn, -EREMOTEIO);
		return -EREMOTEIO;
	}
	txn->status = EBPFOS_KOPERATION_STATUS_COMPLETE;
	txn->error = 0;
	atomic64_inc(&ebpfos_koperation_commits);
	return 0;
}

long ebpfos_koperation_result_ioctl(void __user *argp, void **txn_slot)
{
	struct ebpfos_koperation_txn *txn = *txn_slot;
	struct ebpfos_koperation_result result = { 0 };

	if (!txn)
		return -ENOENT;
	result.version = EBPFOS_KOPERATION_ABI_VERSION;
	result.operation_id = txn->descriptor->operation_id;
	result.status = txn->status;
	result.error = txn->error;
	result.transaction_id = txn->transaction_id;
	result.staged_shadow = txn->staged_shadow;
	result.native_result = txn->native_result;
	result.native_operand_before = txn->native_operand_before;
	result.architecture_flags = txn->architecture_flags;
	result.cpu_before = txn->cpu_before;
	result.cpu_after = txn->cpu_after;
	memcpy(result.semantic_sha256, txn->descriptor->semantic_sha256,
	       sizeof(result.semantic_sha256));
	memcpy(result.proof_program_sha256, txn->proof_program_sha256,
	       sizeof(result.proof_program_sha256));
	memcpy(result.native_sha256, txn->descriptor->native_sha256,
	       sizeof(result.native_sha256));
	memcpy(result.equivalence_sha256,
	       txn->descriptor->equivalence_sha256,
	       sizeof(result.equivalence_sha256));
	ebpfos_koperation_counters(&result.attempts,
				     &result.commits, &result.rejects);
	return copy_to_user(argp, &result, sizeof(result)) ? -EFAULT : 0;
}

void ebpfos_koperation_release(void **txn_slot)
{
	kfree(*txn_slot);
	*txn_slot = NULL;
}
