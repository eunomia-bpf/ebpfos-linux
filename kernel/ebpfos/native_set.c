// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/init.h>
#include <linux/threads.h>
#include <asm/apicdef.h>

/* Carry configured scalar counts into the same BTF used for registration.
 * The resolver consumes these actual C values, rather than guessing a build
 * configuration or substituting a count from another image.
 */
enum ebpfos_native_scalar_counts {
	__native_count_none = 0,
#define NATIVE_FUNCTION(source, native, flags)
#define NATIVE_PROTOTYPE(source)
#define NATIVE_INLINE_FUNCTION(source, native, flags)
#define NATIVE_ALIAS(source, native)
#define NATIVE_ARG(native, index, tag)
#define NATIVE_ENUM_MAX(native, index, record, sentinel)
#define NATIVE_COUNT_MAX(native, index, count) __native_count_##native##_##index = (count),
#define NATIVE_POINTEE_TAG(native, index, tag)
#include <linux/ebpfos_native_set.def>
#undef NATIVE_FUNCTION
#undef NATIVE_PROTOTYPE
#undef NATIVE_INLINE_FUNCTION
#undef NATIVE_ALIAS
#undef NATIVE_ARG
#undef NATIVE_ENUM_MAX
#undef NATIVE_COUNT_MAX
#undef NATIVE_POINTEE_TAG
};
static enum ebpfos_native_scalar_counts __used native_scalar_count_btf;

BTF_KFUNCS_START(ebpfos_native_ids)
#define NATIVE_FUNCTION(source, native, flags) BTF_ID_FLAGS(func, native, flags)
#define NATIVE_PROTOTYPE(source)
#define NATIVE_INLINE_FUNCTION(source, native, flags) BTF_ID_FLAGS(func, native, flags)
#define NATIVE_ALIAS(source, native)
#define NATIVE_ARG(native, index, tag)
#define NATIVE_ENUM_MAX(native, index, record, sentinel)
#define NATIVE_COUNT_MAX(native, index, count)
#define NATIVE_POINTEE_TAG(native, index, tag)
#include <linux/ebpfos_native_set.def>
#undef NATIVE_FUNCTION
#undef NATIVE_PROTOTYPE
#undef NATIVE_INLINE_FUNCTION
#undef NATIVE_ALIAS
#undef NATIVE_ARG
#undef NATIVE_ENUM_MAX
#undef NATIVE_COUNT_MAX
#undef NATIVE_POINTEE_TAG
BTF_KFUNCS_END(ebpfos_native_ids)

static int ebpfos_native_filter(const struct bpf_prog *prog, u32 id)
{
	if (!btf_id_set8_contains(&ebpfos_native_ids, id))
		return 0;
	if (!prog || !prog->aux || !prog->aux->ebpfos_component)
		return 1;
	if (prog->type == BPF_PROG_TYPE_SYSCALL)
		return 0;
	/* Replacement keeps the original Linux call context. Ordinary tracing
	 * observers cannot acquire the component's native dependency boundary.
	 * The kfunc's argument, reference and sleepability checks still apply.
	 */
	return prog->type != BPF_PROG_TYPE_TRACING || prog->sleepable ||
	       prog->expected_attach_type != BPF_TRACE_REPLACE;
}

static const struct btf_kfunc_id_set ebpfos_native_set = {
	.set = &ebpfos_native_ids,
	.filter = ebpfos_native_filter,
};

static int __init ebpfos_native_init(void)
{
	int ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &ebpfos_native_set);
	int tracing = ret ? ret :
		register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &ebpfos_native_set);

	pr_info("native kfunc set: count=%u registration=%d replacement=%d\n",
		ebpfos_native_ids.cnt, ret, tracing);
	return ret ? ret : tracing;
}
late_initcall(ebpfos_native_init);
