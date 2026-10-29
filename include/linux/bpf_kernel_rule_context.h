/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_BPF_KERNEL_RULE_CONTEXT_H
#define _LINUX_BPF_KERNEL_RULE_CONTEXT_H
#include <linux/types.h>
struct bpf_kernel_rule_ctx;
#ifdef CONFIG_EBPFOS_ENTRY_LINK
bool bpf_kernel_rule_context_kfunc(u32 id, s16 offset);
u64 bpf_kernel_rule_task_under(const struct bpf_kernel_rule_ctx *, u64 root);
u64 bpf_kernel_rule_cgroup_under(const struct bpf_kernel_rule_ctx *, u64 root);
#else
static inline bool bpf_kernel_rule_context_kfunc(u32 id, s16 offset) { return false; }
#endif
#endif
