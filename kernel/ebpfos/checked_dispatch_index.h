/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _EBPFOS_CHECKED_DISPATCH_INDEX_H
#define _EBPFOS_CHECKED_DISPATCH_INDEX_H

/* Metadata only. During preparation state is the FUNC ID, preserving the BTF
 * iteration order for duplicate names. After compaction it is the callable
 * native-ABI bit. The destructive requirement is unioned across aliases and
 * checked separately by the plain/privileged guards. Neither code nor verifier
 * results are stored here.
 */
struct ebpfos_checked_index_entry {
	unsigned long address;
	unsigned int prototype;
	/* FUNC IDs are bounded by BTF_MAX_TYPE (20 bits); compacted state is 0/1. */
	unsigned int state:31;
	unsigned int destructive:1;
};

static inline int ebpfos_checked_index_compare(const void *left, const void *right)
{
	const struct ebpfos_checked_index_entry *a = (const struct ebpfos_checked_index_entry *)left;
	const struct ebpfos_checked_index_entry *b = (const struct ebpfos_checked_index_entry *)right;

	if (a->address != b->address)
		return a->address < b->address ? -1 : 1;
	return a->state < b->state ? -1 : a->state != b->state;
}

static inline struct ebpfos_checked_index_entry *ebpfos_checked_index_find(
	struct ebpfos_checked_index_entry *entries, unsigned int count,
	unsigned long address)
{
	unsigned int low = 0, high = count;

	while (low < high) {
		unsigned int middle = low + (high - low) / 2;

		if (entries[middle].address < address)
			low = middle + 1;
		else
			high = middle;
	}
	return low < count && entries[low].address == address ? entries + low : 0;
}

/* Input is sorted by exact address, then original BTF FUNC ID. A refusal in
 * any same-name definition stays a refusal for the whole address. Keep the
 * last compatible prototype, exactly as the original linear reader did.
 */
static inline unsigned int ebpfos_checked_index_compact(
	struct ebpfos_checked_index_entry *entries, unsigned int count,
	const struct ebpfos_checked_types *types)
{
	unsigned int read, written = 0;

	for (read = 0; read < count; read++) {
		struct ebpfos_checked_index_entry value = entries[read];
		struct ebpfos_checked_index_entry *previous = written ? entries + written - 1 : 0;

		if (previous && previous->address == value.address) {
			/* Every same-address declaration contributes its requirements. */
			previous->destructive |= value.destructive;
			if (!previous->prototype || !value.prototype ||
			    !ebpfos_checked_type_equal(types, previous->prototype, value.prototype, 0))
				previous->prototype = 0;
			else
				previous->prototype = value.prototype;
		} else {
			value.state = 0;
			entries[written++] = value;
		}
	}
	return written;
}

#endif
