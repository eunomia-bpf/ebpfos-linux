/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_EBPFOS_LOCKED_SECTION_H
#define _UAPI_LINUX_EBPFOS_LOCKED_SECTION_H

#include <linux/types.h>

/*
 * One linearizable scalar update on a component-owned object handle.
 * The caller supplies this request on the BPF stack, computes the next value
 * outside the lock, and retries on a mismatch. No BPF code or sleepable
 * effect executes while L1 holds the IRQ-safe lock.
 *
 * A return of 0 commits desired, 1 reports a mismatch, and a negative value
 * reports an invalid scope or slot. observed is set on either valid outcome.
 * The slot starts at zero when the handle's L1 effect object is created.
 *
 * BPF import declaration (the caller adds its normal .ksyms annotation):
 * int bpf_ebpfos_effect_locked_u64_irqsave(__u64 handle, __u32 slot,
 *                                          void *request, __u32 request__sz);
 * request__sz must be sizeof(struct ebpfos_locked_u64_request).
 */
struct ebpfos_locked_u64_request {
	__u64 expected;
	__u64 desired;
	__u64 observed;
};

#define EBPFOS_LOCKED_U64_SLOTS 8

#endif
