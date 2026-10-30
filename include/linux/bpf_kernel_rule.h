/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_BPF_KERNEL_RULE_H
#define _LINUX_BPF_KERNEL_RULE_H
#include <linux/bpf.h>
#include <linux/gfp_types.h>
#include <uapi/linux/bpf_kernel_rule.h>

struct ebpfos_operations;
struct ebpfos_rule_decision;

#ifdef CONFIG_EBPFOS_ENTRY_LINK
int bpf_kernel_rule_link_create(const union bpf_attr *attr);
/* Resolve at the outermost binding point. Pass the retained decision to
 * inner bindings and queued work; they must not rerun the rule. A decision
 * holds the exact rule generation and every selected table until put. */
struct ebpfos_rule_decision *ebpfos_rule_resolve(const struct bpf_kernel_rule_ctx *, gfp_t);
struct ebpfos_rule_decision *ebpfos_rule_decision_get(struct ebpfos_rule_decision *);
void ebpfos_rule_decision_put(struct ebpfos_rule_decision *);
struct ebpfos_operations *ebpfos_rule_operations(struct ebpfos_rule_decision *,
 const void *original, u32 type, size_t size);
u64 ebpfos_rule_epoch(void);
bool ebpfos_rule_active(void);
void ebpfos_rule_context(struct bpf_kernel_rule_ctx *, u64 object, u64 binding);
#ifdef CONFIG_EBPFOS_AUTOBIND
int ebpfos_rule_bind_view(struct ebpfos_rule_decision *);
#endif
#else
static inline int bpf_kernel_rule_link_create(const union bpf_attr *attr) { return -EOPNOTSUPP; }
#endif
#endif
