/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LINUX_BPF_NATIVE_ABI_H
#define LINUX_BPF_NATIVE_ABI_H
#include <linux/bpf.h>
enum bpf_native_class { BPF_NC_NONE, BPF_NC_SSE, BPF_NC_INTEGER, BPF_NC_MEMORY };
struct bpf_native_arg {
 u32 type_id, size, stack_offset;
 s8 reg;
 u8 words, word_mask;
 bool result_buffer;
};
struct bpf_native_abi {
 u32 stack_size;
 u8 nr_args, result_words, result_word_mask;
 bool result_buffer;
 struct bpf_native_arg args[MAX_BPF_FUNC_ARGS + 1];
};
struct btf;
struct bpf_subprog_arg_info;
struct bpf_verifier_log;
struct btf_type;
bool btf_native_scalar_storage(struct btf *btf, u32 id, u32 depth);
int btf_native_pointer_word(struct btf *btf, u32 id, u32 offset, u32 *pointer);
int btf_native_pointer_arg(struct btf *btf, u32 id, struct bpf_subprog_arg_info *arg,
                           struct bpf_verifier_log *log);
bool btf_native_value_storage(struct btf *btf, u32 id);
bool btf_native_record_entry_contract(struct btf *btf, u32 id);
int btf_native_record_ro_size(struct btf *btf, const struct btf_type *fn,
                              u32 word, u32 *bytes, struct bpf_verifier_log *log);
int bpf_native_abi_plan(struct btf *btf, const struct btf_type *proto,
                       struct bpf_native_abi *abi, bool allow_variadic_prefix);
#endif
