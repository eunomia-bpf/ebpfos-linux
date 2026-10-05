// SPDX-License-Identifier: GPL-2.0-only
/* Preserve pointer provenance while masking the separate scalar tag half. */
#include <crypto/sha2.h>
#include <linux/bpf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <linux/string.h>
#include "pointer_tag.generated.h"

__bpf_kfunc_start_defs();
__bpf_kfunc void *bpf_ebpfos_kop_ptr_tag_parts(void *pointer, u64 flags,
					    u64 *flags_out)
{
	return NULL; /* Only the verified proof or its bound JIT sequence executes. */
}
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(ebpfos_ptr_tag_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_ptr_tag_parts)
BTF_KFUNCS_END(ebpfos_ptr_tag_ids)

static const struct ebpfos_ptr_tag_spec *ptr_tag_spec(u64 payload)
{
	u32 i;

	if (ebpfos_ptr_tag_ids.cnt != 1 ||
	    payload >> 8 != ebpfos_ptr_tag_ids.pairs[0].id)
		return NULL;
	for (i = 0; i < ARRAY_SIZE(ebpfos_ptr_tag_specs); i++)
		if ((payload & 0xff) == ebpfos_ptr_tag_specs[i].mask)
			return &ebpfos_ptr_tag_specs[i];
	return NULL;
}

static int ptr_tag_instantiate(u64 payload, struct bpf_insn *insns)
{
	const struct ebpfos_ptr_tag_spec *spec = ptr_tag_spec(payload);

	if (!spec || !insns)
		return -EINVAL;
	memcpy(insns, spec->proof, sizeof(spec->proof));
	return ARRAY_SIZE(spec->proof);
}

static int ptr_tag_requirements(u64 payload, u64 *capabilities, u64 *effects,
			       u8 digest[SHA256_DIGEST_SIZE])
{
	const struct ebpfos_ptr_tag_spec *spec = ptr_tag_spec(payload);

	if (!spec || !capabilities || !effects || !digest)
		return -EINVAL;
	*capabilities = 0;
	*effects = 0;
	memcpy(digest, spec->digest, sizeof(spec->digest));
	return 0;
}

static int ptr_tag_emit_x86(u8 *image, u32 *offset, bool emit, u64 payload,
			   const struct bpf_prog *prog, const u8 *final_ip)
{
	const struct ebpfos_ptr_tag_spec *spec = ptr_tag_spec(payload);

	if (!spec || !offset || (emit && !image))
		return -EINVAL;
	if (emit)
		memcpy(image + *offset, spec->native, spec->native_len);
	*offset += spec->native_len;
	return spec->native_len;
}

static struct bpf_kop ptr_tag_kop = {
	.max_insn_cnt = 4,
	.max_emit_bytes = 15,
	.requirements = ptr_tag_requirements,
	.instantiate_insn = ptr_tag_instantiate,
	.emit_x86 = ptr_tag_emit_x86,
};

static const struct bpf_kop * const ptr_tag_descriptors[] = { &ptr_tag_kop };
static const struct btf_kfunc_id_set ptr_tag_set = {
	.set = &ebpfos_ptr_tag_ids,
	.kop_descs = ptr_tag_descriptors,
};

static int __init ptr_tag_register(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &ptr_tag_set);
}
late_initcall(ptr_tag_register);
