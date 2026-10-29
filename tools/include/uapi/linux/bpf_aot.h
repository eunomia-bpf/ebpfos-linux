/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_BPF_AOT_H
#define _UAPI_LINUX_BPF_AOT_H
#include <linux/types.h>

/* Build artifact export through BPF_OBJ_GET_INFO_BY_FD. This does not change
 * the loaded program, its verification tier, or any live call binding.
 */
#define BPF_AOT_SYMBOL_LEN 256
#define BPF_AOT_F_PATCHABLE_JUMPS (1U << 0)
struct bpf_aot_request {
	__u32 func_index;
	__u32 nr_relocs;
	__aligned_u64 relocs;
	__u32 flags;
	__u32 reserved;
};

/* Optional symbolic operands in verifier-rewritten instruction coordinates.
 * Useful for scalar BTF IDs, per-CPU symbols, and relocated non-kallsyms data.
 * The symbol/addend replaces an immediate only in the exported object.
 */
struct bpf_aot_reloc {
	__u32 insn;
	__u32 type;
	__s64 addend;
	char symbol[BPF_AOT_SYMBOL_LEN];
};
#endif
