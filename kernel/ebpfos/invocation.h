/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _EBPFOS_INVOCATION_H
#define _EBPFOS_INVOCATION_H

#include <linux/ebpfos.h>

#define EBPFOS_BINDING_ACTIVE_BITS 16
#define EBPFOS_BINDING_ACTIVE_MASK ((1ULL << EBPFOS_BINDING_ACTIVE_BITS) - 1)
#define EBPFOS_BINDING_ENTRY_ONE (1ULL << EBPFOS_BINDING_ACTIVE_BITS)
#define EBPFOS_BINDING_ENTRY_BITS 47
#define EBPFOS_BINDING_ENTRY_MASK \
	(((1ULL << EBPFOS_BINDING_ENTRY_BITS) - 1) << \
	 EBPFOS_BINDING_ACTIVE_BITS)
#define EBPFOS_BINDING_RETIRED BIT_ULL(63)

/* Internal callers already hold a non-NULL binding under its RCU epoch.
 * Keep the acquisition in the entry path, without an extra function call.
 * The public API checks NULL before using this same implementation.
 */
static __always_inline int
ebpfos_binding_acquire_invocation(struct ebpfos_binding *binding)
{
	u64 old, new;

	do {
		old = atomic64_read(&binding->invocation_state);
		if (old & EBPFOS_BINDING_RETIRED)
			return -ESHUTDOWN;
		new = old + EBPFOS_BINDING_ENTRY_ONE + 1;
		/* With retirement clear, this increment cannot wrap the word.
		 * An exhausted active field wraps to zero; an exhausted entry
		 * field carries into retirement. Reject both before the CAS.
		 */
		if (!(new & EBPFOS_BINDING_ACTIVE_MASK) ||
		    (new & EBPFOS_BINDING_RETIRED))
			return -EOVERFLOW;
	} while (atomic64_cmpxchg(&binding->invocation_state, old, new) != old);
	return 0;
}

/* A paired private exit owns one active count, even after retirement. Other
 * paired exits cannot consume that count, so subtraction cannot borrow into
 * the cumulative entry field. Keep a fully ordered RMW without requesting
 * the unused counter word; dec_and_test has full ordering on every arch.
 * Public exit retains its defensive zero-count check.
 */
static __always_inline void
ebpfos_binding_release_invocation(struct ebpfos_binding *binding)
{
	(void)atomic64_dec_and_test(&binding->invocation_state);
}

#endif
