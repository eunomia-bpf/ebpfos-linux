// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/init.h>

BTF_KFUNCS_START(ebpfos_native_ids)
#define NATIVE_FUNCTION(source, native, flags) BTF_ID_FLAGS(func, native, flags)
#define NATIVE_INLINE_FUNCTION(source, native, flags) BTF_ID_FLAGS(func, native, flags)
#define NATIVE_STATIC_CALL(source, native, record, field, flags) BTF_ID_FLAGS(func, native, flags)
#define NATIVE_ALIAS(source, native)
#define NATIVE_ARG(native, index, tag)
#define NATIVE_ENUM_MAX(native, index, record, sentinel)
#define NATIVE_POINTEE_TAG(native, index, tag)
#include <linux/ebpfos_native_set.def>
#undef NATIVE_FUNCTION
#undef NATIVE_INLINE_FUNCTION
#undef NATIVE_STATIC_CALL
#undef NATIVE_ALIAS
#undef NATIVE_ARG
#undef NATIVE_ENUM_MAX
#undef NATIVE_POINTEE_TAG
BTF_KFUNCS_END(ebpfos_native_ids)

static int ebpfos_native_filter(const struct bpf_prog *prog, u32 id)
{
	if (!btf_id_set8_contains(&ebpfos_native_ids, id))
		return 0;
	return !prog || prog->type != BPF_PROG_TYPE_SYSCALL ||
	       !prog->aux || !prog->aux->ebpfos_component;
}

static const struct btf_kfunc_id_set ebpfos_native_set = {
	.set = &ebpfos_native_ids,
	.filter = ebpfos_native_filter,
};

static int __init ebpfos_native_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &ebpfos_native_set);
}
late_initcall(ebpfos_native_init);
