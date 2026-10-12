/* SPDX-License-Identifier: GPL-2.0-only */
/* Raw architectural writes. Linux pinning/retry policy stays compiled code. */
#ifdef CONFIG_X86
#define EBPFOS_CONTROL_WRITE(number) \
__bpf_kfunc u64 bpf_ebpfos_x86_write_cr##number(u64 value) \
{ \
 if (!IS_ENABLED(CONFIG_X86_64)) return -EOPNOTSUPP; \
 asm volatile("mov %0,%%cr" #number : : "r"((unsigned long)value) : "memory"); \
 return 0; \
} \
__bpf_kfunc u64 bpf_ebpfos_kop_write_cr##number(u64 value) \
{ return 0; /* Only the typed proof or bound instruction executes. */ }
EBPFOS_CONTROL_WRITE(0)
EBPFOS_CONTROL_WRITE(4)
#undef EBPFOS_CONTROL_WRITE
#endif
