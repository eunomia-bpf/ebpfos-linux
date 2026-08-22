// SPDX-License-Identifier: GPL-2.0
/*
 * Test-only KOperation descriptor adapted from bpf-benchmark rotate lowering:
 *   module/x86/bpf_x86_rotate.c
 *   module/include/kop_common.h
 *   module/include/kop_x86_emit.h
 * donor: eunomia-bpf/bpf-benchmark@5b130b6ec8c44006fd7768acb7b2c8b506ea038b
 *
 * This descriptor exercises the generic verifier/JIT path.  It owns no OS
 * role and is unavailable when CONFIG_EBPFOS_KUNIT_TEST is disabled.
 */

#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/ebpfos.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/bpf_verifier.h>
#include <kunit/test.h>

#define EBPFOS_KOP_TEST_FORM_IMMEDIATE 2U
#define EBPFOS_KOP_TEST_FORM_FORWARD_ESCAPE 3U
#define EBPFOS_KOP_TEST_FORM_BACKWARD_ESCAPE 4U
#define EBPFOS_KOP_TEST_SCRATCH0 BPF_REG_6
#define EBPFOS_KOP_TEST_SCRATCH1 BPF_REG_7
#define EBPFOS_KOP_TEST_SCRATCH0_OFF (-40)
#define EBPFOS_KOP_TEST_SCRATCH1_OFF (-32)

struct ebpfos_kop_test_rotate {
	u8 dst;
	u8 src;
	u8 shift;
};

static atomic64_t ebpfos_kop_test_emit_attempts = ATOMIC64_INIT(0);

static int ebpfos_kop_test_decode(u64 payload,
				  struct ebpfos_kop_test_rotate *rotate)
{
	if ((payload & 0xf) != EBPFOS_KOP_TEST_FORM_IMMEDIATE || payload >> 20)
		return -EINVAL;
	rotate->dst = (payload >> 4) & 0xf;
	rotate->src = (payload >> 8) & 0xf;
	rotate->shift = ((payload >> 12) & 0xff) & 63;
	if (rotate->dst >= BPF_REG_10 || rotate->src >= BPF_REG_10 ||
	    rotate->dst == EBPFOS_KOP_TEST_SCRATCH0 ||
	    rotate->dst == EBPFOS_KOP_TEST_SCRATCH1 ||
	    rotate->src == EBPFOS_KOP_TEST_SCRATCH0 ||
	    rotate->src == EBPFOS_KOP_TEST_SCRATCH1 || !rotate->shift)
		return -EINVAL;
	return 0;
}

static int ebpfos_kop_test_instantiate(u64 payload, struct bpf_insn *insns)
{
	struct ebpfos_kop_test_rotate rotate;
	int err;
	u8 form = payload & 0xf;

	if (form == EBPFOS_KOP_TEST_FORM_FORWARD_ESCAPE) {
		if (payload >> 4)
			return -EINVAL;
		insns[0] = BPF_JMP_A(1);
		insns[1] = BPF_MOV64_IMM(BPF_REG_0, 1);
		return 2;
	}
	if (form == EBPFOS_KOP_TEST_FORM_BACKWARD_ESCAPE) {
		if (payload >> 4)
			return -EINVAL;
		insns[0] = BPF_JMP_A(-2);
		insns[1] = BPF_MOV64_IMM(BPF_REG_0, 1);
		return 2;
	}

	err = ebpfos_kop_test_decode(payload, &rotate);
	if (err)
		return err;
	insns[0] = BPF_STX_MEM(BPF_DW, BPF_REG_10,
				EBPFOS_KOP_TEST_SCRATCH0,
				EBPFOS_KOP_TEST_SCRATCH0_OFF);
	insns[1] = BPF_STX_MEM(BPF_DW, BPF_REG_10,
				EBPFOS_KOP_TEST_SCRATCH1,
				EBPFOS_KOP_TEST_SCRATCH1_OFF);
	insns[2] = BPF_MOV64_REG(EBPFOS_KOP_TEST_SCRATCH0, rotate.src);
	insns[3] = BPF_MOV64_REG(EBPFOS_KOP_TEST_SCRATCH1,
				 EBPFOS_KOP_TEST_SCRATCH0);
	insns[4] = BPF_ALU64_IMM(BPF_LSH, EBPFOS_KOP_TEST_SCRATCH0,
				  rotate.shift);
	insns[5] = BPF_ALU64_IMM(BPF_RSH, EBPFOS_KOP_TEST_SCRATCH1,
				  64 - rotate.shift);
	insns[6] = BPF_ALU64_REG(BPF_OR, EBPFOS_KOP_TEST_SCRATCH0,
				  EBPFOS_KOP_TEST_SCRATCH1);
	insns[7] = BPF_MOV64_REG(rotate.dst, EBPFOS_KOP_TEST_SCRATCH0);
	insns[8] = BPF_LDX_MEM(BPF_DW, EBPFOS_KOP_TEST_SCRATCH1, BPF_REG_10,
				EBPFOS_KOP_TEST_SCRATCH1_OFF);
	insns[9] = BPF_LDX_MEM(BPF_DW, EBPFOS_KOP_TEST_SCRATCH0, BPF_REG_10,
				EBPFOS_KOP_TEST_SCRATCH0_OFF);
	return 10;
}

static u8 ebpfos_kop_test_x86_reg(u8 reg)
{
	switch (reg) {
	case BPF_REG_0:
	case BPF_REG_5:
		return 0;
	case BPF_REG_4:
		return 1;
	case BPF_REG_3:
		return 2;
	case BPF_REG_6:
		return 3;
	case BPF_REG_7:
		return 5;
	case BPF_REG_2:
	case BPF_REG_8:
		return 6;
	case BPF_REG_1:
	case BPF_REG_9:
		return 7;
	default:
		return 0xff;
	}
}

static bool ebpfos_kop_test_x86_extended(u8 reg)
{
	return reg == BPF_REG_5 || reg == BPF_REG_7 ||
	       reg == BPF_REG_8 || reg == BPF_REG_9;
}

static int ebpfos_kop_test_emit_x86(u8 *image, u32 *off, bool emit,
				    u64 payload, const struct bpf_prog *prog,
				    const u8 *final_ip)
{
	struct ebpfos_kop_test_rotate rotate;
	u8 bytes[4], code;
	int err;

	(void)prog;
	(void)final_ip;
	if (!off || (emit && !image))
		return -EINVAL;
	atomic64_inc(&ebpfos_kop_test_emit_attempts);
	err = ebpfos_kop_test_decode(payload, &rotate);
	if (err)
		return err;
	if (rotate.dst != rotate.src)
		return -EINVAL;
	code = ebpfos_kop_test_x86_reg(rotate.dst);
	if (code == 0xff)
		return -EINVAL;
	bytes[0] = 0x48 | ebpfos_kop_test_x86_extended(rotate.dst);
	bytes[1] = 0xc1;
	bytes[2] = 0xc0 | code;
	bytes[3] = rotate.shift;
	if (emit)
		memcpy(image + *off, bytes, sizeof(bytes));
	*off += sizeof(bytes);
	return sizeof(bytes);
}

__bpf_kfunc_start_defs();
__bpf_kfunc void bpf_ebpfos_kop_test_rol64(void) { }
__bpf_kfunc u64 bpf_ebpfos_kop_test_emit_attempts(void)
{
	return atomic64_read(&ebpfos_kop_test_emit_attempts);
}
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(ebpfos_kop_test_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_test_rol64)
BTF_KFUNCS_END(ebpfos_kop_test_ids)

BTF_KFUNCS_START(ebpfos_kop_test_counter_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_test_emit_attempts)
BTF_KFUNCS_END(ebpfos_kop_test_counter_ids)

static const struct bpf_kop ebpfos_kop_test_rol64 = {
	.max_insn_cnt = 10,
	.max_emit_bytes = 4,
	.instantiate_insn = ebpfos_kop_test_instantiate,
	.emit_x86 = ebpfos_kop_test_emit_x86,
};

static const struct bpf_kop * const ebpfos_kop_test_descs[] = {
	&ebpfos_kop_test_rol64,
};

static const struct btf_kfunc_id_set ebpfos_kop_test_set = {
	.owner = THIS_MODULE,
	.set = &ebpfos_kop_test_ids,
	.kop_descs = ebpfos_kop_test_descs,
};

static const struct btf_kfunc_id_set ebpfos_kop_test_counter_set = {
	.owner = THIS_MODULE,
	.set = &ebpfos_kop_test_counter_ids,
};

static int __init ebpfos_kop_test_register(void)
{
	int err;

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_SOCKET_FILTER,
					       &ebpfos_kop_test_set);
	if (err)
		return err;
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SOCKET_FILTER,
					 &ebpfos_kop_test_counter_set);
}
late_initcall(ebpfos_kop_test_register);

static u64 ebpfos_kop_test_payload(u8 dst, u8 src, u8 shift)
{
	return EBPFOS_KOP_TEST_FORM_IMMEDIATE | ((u64)dst << 4) |
	       ((u64)src << 8) | ((u64)shift << 12);
}

static void ebpfos_kop_descriptor_test(struct kunit *test)
{
	const u8 expected[] = { 0x48, 0xc1, 0xc0, 8 };
	struct bpf_insn proof[10];
	u8 native[4] = {};
	u64 payload = ebpfos_kop_test_payload(BPF_REG_0, BPF_REG_0, 8);
	u32 off = 0;

	KUNIT_EXPECT_EQ(test, ebpfos_kop_test_instantiate(payload, proof), 10);
	KUNIT_EXPECT_EQ(test,
		ebpfos_kop_test_emit_x86(native, &off, true, payload, NULL, NULL), 4);
	KUNIT_EXPECT_EQ(test, off, (u32)sizeof(expected));
	KUNIT_EXPECT_MEMEQ(test, native, expected, sizeof(expected));
	KUNIT_EXPECT_EQ(test,
		ebpfos_kop_test_instantiate(
			ebpfos_kop_test_payload(BPF_REG_0, BPF_REG_0, 0), proof),
		-EINVAL);
	KUNIT_EXPECT_EQ(test,
		ebpfos_kop_test_emit_x86(
			native, &off, false,
			ebpfos_kop_test_payload(BPF_REG_0, BPF_REG_1, 8),
			NULL, NULL),
		-EINVAL);
}

static struct bpf_insn ebpfos_kop_test_sidecar(void)
{
	return (struct bpf_insn) {
		.code = BPF_ALU64 | BPF_MOV | BPF_K,
		.src_reg = BPF_PSEUDO_KOP_SIDECAR,
	};
}

static void ebpfos_kop_proof_cfg_test(struct kunit *test)
{
	const struct bpf_kop kop = { .max_insn_cnt = 3 };
	struct bpf_insn forward_boundary[] = {
		BPF_JMP_A(1), BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_MOV64_IMM(BPF_REG_0, 1),
	};
	struct bpf_insn forward_escape[] = {
		BPF_JMP_A(1), BPF_MOV64_IMM(BPF_REG_0, 0),
	};
	struct bpf_insn backward_boundary[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0), BPF_JMP_A(-2),
	};
	struct bpf_insn backward_escape[] = {
		BPF_JMP_A(-2), BPF_MOV64_IMM(BPF_REG_0, 0),
	};
	struct bpf_insn jump_to_sidecar[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0), BPF_JMP_A(0),
		ebpfos_kop_test_sidecar(),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_KOP_CALL,
			     0, 1),
		BPF_EXIT_INSN(),
	};
	struct bpf_insn jump_to_call[] = {
		BPF_MOV64_IMM(BPF_REG_0, 0),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
		ebpfos_kop_test_sidecar(),
		BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, BPF_PSEUDO_KOP_CALL,
			     0, 1),
		BPF_EXIT_INSN(),
	};
	struct bpf_kfunc_desc_tab *tab;
	struct bpf_prog_aux *aux;
	struct bpf_prog prog = {};

	tab = kunit_kzalloc(test, sizeof(*tab), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, tab);
	aux = kunit_kzalloc(test, sizeof(*aux), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, aux);
	tab->nr_descs = 1;
	tab->descs[0].kop = &kop;
	aux->kfunc_tab = tab;
	prog.aux = aux;
	KUNIT_EXPECT_EQ(test, bpf_validate_kop_proof_seq(
		NULL, &kop, forward_boundary, ARRAY_SIZE(forward_boundary)), 0);
	KUNIT_EXPECT_EQ(test, bpf_validate_kop_proof_seq(
		NULL, &kop, forward_escape, ARRAY_SIZE(forward_escape)), -EINVAL);
	KUNIT_EXPECT_EQ(test, bpf_validate_kop_proof_seq(
		NULL, &kop, backward_boundary, ARRAY_SIZE(backward_boundary)), 0);
	KUNIT_EXPECT_EQ(test, bpf_validate_kop_proof_seq(
		NULL, &kop, backward_escape, ARRAY_SIZE(backward_escape)), -EINVAL);
	KUNIT_EXPECT_EQ(test, bpf_validate_kop_single_entry(
		NULL, jump_to_sidecar, ARRAY_SIZE(jump_to_sidecar)), 0);
	KUNIT_EXPECT_EQ(test, bpf_validate_kop_single_entry(
		NULL, jump_to_call, ARRAY_SIZE(jump_to_call)), -EINVAL);
	/* This is the config-independent fail-closed predicate used when a
	 * requested native JIT later fails: the descriptor remains recorded and
	 * the pseudo-call cannot fall back to the interpreter.  The current
	 * non-JIT path rejects the load; it does not retire the descriptor and
	 * execute an expanded proof.
	 */
	KUNIT_EXPECT_TRUE(test, bpf_prog_has_kop_call(&prog));
}

static void ebpfos_kop_component_identity_test(struct kunit *test)
{
	const struct bpf_kop first = {
		.capability_mask = BIT_ULL(3),
		.effect_mask = BIT_ULL(6),
		.semantic_sha256 = { 1 },
	};
	const struct bpf_kop second = {
		.capability_mask = BIT_ULL(4),
		.effect_mask = BIT_ULL(7),
		.semantic_sha256 = { 2 },
	};
	const struct bpf_kop unbound = {};
	struct bpf_kfunc_desc_tab *tab;
	struct bpf_prog_aux *aux;
	struct bpf_prog prog = {};
	u8 one[SHA256_DIGEST_SIZE];
	u8 two[SHA256_DIGEST_SIZE];
	u64 capabilities;
	u64 effects;

	tab = kunit_kzalloc(test, sizeof(*tab), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, tab);
	aux = kunit_kzalloc(test, sizeof(*aux), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, aux);
	aux->kfunc_tab = tab;
	prog.aux = aux;

	tab->nr_descs = 1;
	tab->descs[0].kop = &first;
	KUNIT_ASSERT_EQ(test, bpf_prog_kop_requirements(
		&prog, &capabilities, &effects, one), 0);
	KUNIT_EXPECT_EQ(test, capabilities, BIT_ULL(3));
	KUNIT_EXPECT_EQ(test, effects, BIT_ULL(6));

	tab->nr_descs = 2;
	tab->descs[1].kop = &second;
	KUNIT_ASSERT_EQ(test, bpf_prog_kop_requirements(
		&prog, &capabilities, &effects, two), 0);
	KUNIT_EXPECT_EQ(test, capabilities, BIT_ULL(3) | BIT_ULL(4));
	KUNIT_EXPECT_EQ(test, effects, BIT_ULL(6) | BIT_ULL(7));
	KUNIT_EXPECT_MEMNEQ(test, one, two, sizeof(one));

	/* JIT completion frees kfunc_tab.  Admission must still observe the
	 * exact verifier-sealed identity and the presence of KOperations.
	 */
	aux->ebpfos_kop_count = tab->nr_descs;
	aux->ebpfos_kop_capability_mask = capabilities;
	aux->ebpfos_kop_effect_mask = effects;
	memcpy(aux->ebpfos_kop_semantic_set_sha256, two, sizeof(two));
	aux->ebpfos_kop_requirements_valid = true;
	aux->kfunc_tab = NULL;
	KUNIT_EXPECT_TRUE(test, bpf_prog_has_kop_call(&prog));
	memset(one, 0, sizeof(one));
	KUNIT_ASSERT_EQ(test, bpf_prog_kop_requirements(
		&prog, &capabilities, &effects, one), 0);
	KUNIT_EXPECT_EQ(test, capabilities, BIT_ULL(3) | BIT_ULL(4));
	KUNIT_EXPECT_EQ(test, effects, BIT_ULL(6) | BIT_ULL(7));
	KUNIT_EXPECT_MEMEQ(test, one, two, sizeof(one));
	aux->kfunc_tab = tab;
	aux->ebpfos_kop_requirements_valid = false;

	tab->descs[1].kop = &unbound;
	KUNIT_EXPECT_EQ(test, bpf_prog_kop_requirements(
		&prog, &capabilities, &effects, two), -EPROTO);
	tab->descs[1].kop = NULL;
	KUNIT_EXPECT_EQ(test, bpf_prog_kop_requirements(
		&prog, &capabilities, &effects, two), -EACCES);
}

static void ebpfos_kop_domain_filter_test(struct kunit *test)
{
	struct bpf_prog_aux *aux;
	struct bpf_prog prog = {};

	aux = kunit_kzalloc(test, sizeof(*aux), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, aux);
	prog.aux = aux;

	/* A hook filter must not affect kfunc IDs owned by another set. */
	KUNIT_EXPECT_EQ(test, ebpfos_kprog_domain_filter(&prog, false), 0);
	KUNIT_EXPECT_EQ(test, ebpfos_kprog_domain_filter(&prog, true), 1);
	aux->ebpfos_provider = true;
	KUNIT_EXPECT_EQ(test, ebpfos_kprog_domain_filter(&prog, true), 1);
	aux->ebpfos_provider = false;
	aux->ebpfos_meta = true;
	KUNIT_EXPECT_EQ(test, ebpfos_kprog_domain_filter(&prog, true), 1);
	aux->ebpfos_meta = false;
	aux->ebpfos_component = true;
	KUNIT_EXPECT_EQ(test, ebpfos_kprog_domain_filter(&prog, true), 0);
}

static struct kunit_case ebpfos_kop_test_cases[] = {
	KUNIT_CASE(ebpfos_kop_descriptor_test),
	KUNIT_CASE(ebpfos_kop_proof_cfg_test),
	KUNIT_CASE(ebpfos_kop_component_identity_test),
	KUNIT_CASE(ebpfos_kop_domain_filter_test),
	{}
};

static struct kunit_suite ebpfos_kop_test_suite = {
	.name = "ebpfos-kop-donor",
	.test_cases = ebpfos_kop_test_cases,
};
kunit_test_suite(ebpfos_kop_test_suite);
