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
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/string.h>
#include "checked_dispatch_types.h"
#include "checked_dispatch_index.h"

static struct btf *checked_btf __ro_after_init;
static struct ebpfos_checked_index_entry *checked_index __ro_after_init;
static unsigned int checked_index_count __ro_after_init;
bool ebpfos_native_plain_call(u32 id);

/* P's native-IR producer replaces these together, after checking each real
 * definition's C calling convention and full physical ABI against its BTF.
 * BTF alone can retain an optimized-away formal and does not encode fastcc.
 * This is one image-wide callable registry, not a closed per-call target set.
 * Without a producer every target refuses; no arbitrary text becomes callable.
 */
const unsigned long * const ebpfos_checked_native_functions __weak;
const unsigned int ebpfos_checked_native_function_count __weak;

static const struct btf_type *checked_type(const void *btf, unsigned int id)
{
	return btf_type_by_id(btf, id);
}

static const char *checked_name(const void *btf, unsigned int offset)
{
	return btf_name_by_offset(btf, offset);
}

static int __init checked_dispatch_init(void)
{
	struct btf *btf = bpf_get_btf_vmlinux();
	struct ebpfos_checked_types types = { btf, checked_type, checked_name };
	struct ebpfos_checked_index_entry *entries, *entry;
	unsigned int id, capacity = 0, count = 0, callable = 0;
	char buffer[KSYM_NAME_LEN], *module = NULL;
	unsigned long size, offset;

	if (IS_ERR_OR_NULL(btf) || !ebpfos_checked_native_functions ||
	    !ebpfos_checked_native_function_count)
		return 0;
	for (id = 1; id < btf_nr_types(btf); id++) {
		const struct btf_type *f = btf_type_by_id(btf, id);

		if (f && btf_type_is_func(f))
			capacity++;
	}
	entries = kvcalloc(capacity, sizeof(*entries), GFP_KERNEL);
	if (!entries)
		return -ENOMEM;
	/* Resolve immutable symbol/type metadata once, not at each call. Looking
	 * up a BTF name first selects exactly the canonical name the old reverse
	 * lookup accepted. Same-name FUNC records are then merged in BTF order.
	 */
	for (id = 1; id < btf_nr_types(btf); id++) {
		const struct btf_type *f = btf_type_by_id(btf, id);
		const struct btf_type *p;
		const char *name, *canonical;
		unsigned long address;

		if (!f || !btf_type_is_func(f))
			continue;
		name = btf_name_by_offset(btf, f->name_off);
		address = kallsyms_lookup_name(name);
		if (!address || !core_kernel_text(address))
			continue;
		module = NULL;
		canonical = kallsyms_lookup(address, &size, &offset, &module, buffer);
		if (!canonical || module || offset || !size || strcmp(canonical, name))
			continue;
		p = btf_type_by_id(btf, f->type);
		entries[count++] = (struct ebpfos_checked_index_entry) {
			.address = address,
			.prototype = p && btf_type_is_func_proto(p) &&
				ebpfos_native_plain_call(id) ? f->type : 0,
			.state = id,
		};
	}
	sort(entries, count, sizeof(*entries), ebpfos_checked_index_compare, NULL);
	count = ebpfos_checked_index_compact(entries, count, &types);
	for (id = 0; id < ebpfos_checked_native_function_count; id++) {
		entry = ebpfos_checked_index_find(entries, count, ebpfos_checked_native_functions[id]);
		if (entry && entry->prototype && !entry->state) {
			entry->state = 1;
			callable++;
		}
	}
	checked_btf = btf;
	checked_index_count = count;
	/* No reader can observe a partial index. There are no later writers. */
	smp_store_release(&checked_index, entries);
	pr_info("checked dispatch: metadata=%u callable=%u bytes=%zu\n",
		count, callable, capacity * sizeof(*entries));
	return 0;
}
late_initcall(checked_dispatch_init);

bool ebpfos_checked_function(u64 target, u64 witness);
bool ebpfos_checked_function(u64 target, u64 witness)
{
	struct ebpfos_checked_index_entry *entries = smp_load_acquire(&checked_index);
	struct btf *btf;
	struct ebpfos_checked_index_entry *actual, *expected;
	struct ebpfos_checked_types types;

	if (!entries || !core_kernel_text(target) || !core_kernel_text(witness))
		return false;
	/* core_kernel_text also accepts init text before FREEING_INITMEM. Keep
	 * this live check: metadata collected during init cannot pin freed code.
	 * Raw module/JIT pointers still lack a permanent published ABI lifetime.
	 */
	btf = checked_btf;
	actual = ebpfos_checked_index_find(entries, checked_index_count, target);
	expected = ebpfos_checked_index_find(entries, checked_index_count, witness);
	if (!actual || !actual->state || !actual->prototype || !expected || !expected->prototype)
		return false;
	types = (struct ebpfos_checked_types) { btf, checked_type, checked_name };
	return ebpfos_checked_type_equal(&types, actual->prototype, expected->prototype, 0);
}
