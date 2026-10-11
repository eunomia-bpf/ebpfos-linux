/* SPDX-License-Identifier: GPL-2.0-only */
/* Read visible selectors; these scalar values convey no address authority. */
#ifndef EBPFOS_KOPERATION_SELECTOR_READ_H
#define EBPFOS_KOPERATION_SELECTOR_READ_H
#ifdef CONFIG_X86_64
#define EBPFOS_SELECTOR_READ(segment) \
__bpf_kfunc u64 bpf_ebpfos_x86_read_selector_##segment(void) \
{ \
	u32 value; \
	asm volatile("movl %%" #segment ", %0" : "=r" (value)); \
	return value; \
} \
__bpf_kfunc u64 bpf_ebpfos_kop_read_selector_##segment(void) \
{ \
	return 0; /* Only the checked proof or bound instruction executes. */ \
}
EBPFOS_SELECTOR_READ(cs)
EBPFOS_SELECTOR_READ(ss)
EBPFOS_SELECTOR_READ(ds)
EBPFOS_SELECTOR_READ(es)
EBPFOS_SELECTOR_READ(fs)
EBPFOS_SELECTOR_READ(gs)
#undef EBPFOS_SELECTOR_READ
#endif
#endif
