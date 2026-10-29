/* SPDX-License-Identifier: GPL-2.0-only */
/* Architectural transfers only. Linux constructs and owns the descriptor tables. */
#ifdef CONFIG_X86
#include <asm/desc_defs.h>
__bpf_kfunc u64 bpf_ebpfos_x86_lidt64(const struct desc_ptr *table)
{
 if (!IS_ENABLED(CONFIG_X86_64)) return -EOPNOTSUPP;
 asm volatile("lidt %0" : : "m"(*table) : "memory");
 return 0;
}
__bpf_kfunc __attribute__((btf_decl_tag("bpf_kop_payload_id:0"))) u64 bpf_ebpfos_kop_lidt64(const struct desc_ptr *table)
{ return 0; /* Only the typed proof or bound instruction executes. */ }
__bpf_kfunc u64 bpf_ebpfos_x86_sidt64(struct desc_ptr *table)
{
 if (!IS_ENABLED(CONFIG_X86_64)) return -EOPNOTSUPP;
 asm volatile("sidt %0" : "=m"(*table) : : "memory");
 return 0;
}
__bpf_kfunc __attribute__((btf_decl_tag("bpf_kop_payload_id:0"))) u64 bpf_ebpfos_kop_sidt64(struct desc_ptr *table)
{ return 0; /* Only the typed proof or bound instruction executes. */ }
__bpf_kfunc u64 bpf_ebpfos_x86_sgdt64(struct desc_ptr *table)
{
 if (!IS_ENABLED(CONFIG_X86_64)) return -EOPNOTSUPP;
 asm volatile("sgdt %0" : "=m"(*table) : : "memory");
 return 0;
}
__bpf_kfunc __attribute__((btf_decl_tag("bpf_kop_payload_id:0"))) u64 bpf_ebpfos_kop_sgdt64(struct desc_ptr *table)
{ return 0; /* Only the typed proof or bound instruction executes. */ }
__bpf_kfunc u64 bpf_ebpfos_x86_lgdt64(const struct desc_ptr *table)
{
 if (!IS_ENABLED(CONFIG_X86_64)) return -EOPNOTSUPP;
 asm volatile("lgdt %0" : : "m"(*table) : "memory");
 return 0;
}
__bpf_kfunc __attribute__((btf_decl_tag("bpf_kop_payload_id:0"))) u64 bpf_ebpfos_kop_lgdt64(const struct desc_ptr *table)
{ return 0; /* Only the typed proof or bound instruction executes. */ }
#endif
