/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LINUX_BPF_NATIVE_ABI_H
#define LINUX_BPF_NATIVE_ABI_H
#include <linux/bpf.h>
enum bpf_native_class { BPF_NC_NONE, BPF_NC_SSE, BPF_NC_INTEGER, BPF_NC_MEMORY };
struct bpf_native_arg {
 u32 type_id, size, stack_offset;
 s8 reg;
 u8 words;
 bool result_buffer;
};
struct bpf_native_abi {
 u32 stack_size;
 u8 nr_args;
 bool result_buffer;
 struct bpf_native_arg args[MAX_BPF_FUNC_ARGS + 1];
};
struct btf;
struct btf_type;
bool btf_native_scalar_storage(struct btf *btf, u32 id, u32 depth);
int bpf_native_abi_plan(struct btf *btf, const struct btf_type *proto,
                       struct bpf_native_abi *abi);
#endif
