// SPDX-License-Identifier: GPL-2.0-only
/* Internal guard for compiler-generated, individually typed native entries.
 * This is not a kfunc: exposing (address, type) as a BPF-callable interface
 * would lose the dispatch entry's ordinary pointer argument checks.
 */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/string.h>
#include "checked_dispatch_types.h"

static struct btf *checked_btf;
bool ebpfos_native_plain_call(u32 id);

/* P's native-IR producer replaces these together, after checking each real
 * definition's C calling convention and full physical ABI against its BTF.
 * BTF alone can retain an optimized-away formal and does not encode fastcc.
 * This is one image-wide callable registry, not a closed per-call target set.
 * Without a producer every target refuses; no arbitrary text becomes callable.
 */
const unsigned long * const ebpfos_checked_native_functions __weak;
const unsigned int ebpfos_checked_native_function_count __weak;

static bool checked_native_entry(unsigned long target)
{
	unsigned int i;

	if (!ebpfos_checked_native_functions)
		return false;
	for (i = 0; i < ebpfos_checked_native_function_count; i++)
		if (ebpfos_checked_native_functions[i] == target)
			return true;
	return false;
}

static int __init checked_dispatch_init(void)
{
	struct btf *btf = bpf_get_btf_vmlinux();

	if (!IS_ERR_OR_NULL(btf))
		checked_btf = btf;
	return 0;
}
late_initcall(checked_dispatch_init);

static const struct btf_type *checked_type(const void *btf, unsigned int id)
{
	return btf_type_by_id(btf, id);
}

static const char *checked_name(const void *btf, unsigned int offset)
{
	return btf_name_by_offset(btf, offset);
}

static u32 checked_function_type(struct btf *btf, unsigned long address)
{
	struct ebpfos_checked_types types = { btf, checked_type, checked_name };
	char buffer[KSYM_NAME_LEN], *module = NULL;
	unsigned long size, offset;
	const char *name;
	u32 id, prototype = 0;

	/* Core text has the kernel's lifetime. A raw JIT/module address has no
	 * such lease; refuse it until publication supplies a pinned ABI entry.
	 * Calls to an original symbol already replaced through the component
	 * publication machinery still enter through that same permanent symbol.
	 */
	if (!address || !core_kernel_text(address))
		return 0;
	name = kallsyms_lookup(address, &size, &offset, &module, buffer);
	if (!name || module || offset || !size || kallsyms_lookup_name(name) != address)
		return 0;
	/* Duplicate local names are not an address-to-type proof. Accept only
	 * when every matching FUNC has the same complete source prototype.
	 */
	for (id = 1; id < btf_nr_types(btf); id++) {
		const struct btf_type *f = btf_type_by_id(btf, id);
		const struct btf_type *p;

		if (!f || !btf_type_is_func(f) || strcmp(name, btf_name_by_offset(btf, f->name_off)))
			continue;
		if (!ebpfos_native_plain_call(id))
			return 0;
		p = btf_type_by_id(btf, f->type);
		if (!p || !btf_type_is_func_proto(p))
			return 0;
		if (prototype && !ebpfos_checked_type_equal(&types, prototype, f->type, 0))
			return 0;
		prototype = f->type;
	}
	return prototype;
}

bool ebpfos_checked_function(u64 target, u64 witness);
bool ebpfos_checked_function(u64 target, u64 witness)
{
	struct btf *btf = READ_ONCE(checked_btf);
	struct ebpfos_checked_types types = { btf, checked_type, checked_name };
	u32 actual, expected;

	if (IS_ERR_OR_NULL(btf))
		return false;
	if (!checked_native_entry(target))
		return false;
	actual = checked_function_type(btf, target);
	expected = checked_function_type(btf, witness);
	return actual && expected && ebpfos_checked_type_equal(&types, actual, expected, 0);
}
