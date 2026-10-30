/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_TASK_RULE_H
#define _LINUX_EBPFOS_TASK_RULE_H
#include <linux/types.h>
struct task_struct;
struct ebpfos_rule_decision;
struct ebpfos_task_view_request;
struct bpf_kernel_rule_version;
struct bpf_operations_set;
#ifdef CONFIG_EBPFOS_ENTRY_LINK
void ebpfos_task_rule_claim(void);
void ebpfos_task_rule_unclaim(void);
void ebpfos_task_rule_mark(struct task_struct *);
void ebpfos_task_rules_changed(void);
void ebpfos_task_rule_resume(void);
void ebpfos_task_rule_fork(struct task_struct *);
void ebpfos_task_rule_free(struct task_struct *);
struct ebpfos_rule_decision *ebpfos_task_rule_decision(void);
struct ebpfos_task_view_request *ebpfos_rule_task_prepare(const struct bpf_kernel_rule_version *);
void ebpfos_rule_task_put(struct ebpfos_task_view_request *);
struct ebpfos_task_view_request *ebpfos_rule_task_get(struct ebpfos_task_view_request *);
bool ebpfos_rule_task_overlap(struct ebpfos_task_view_request *, struct ebpfos_task_view_request *);
int ebpfos_rule_task_operations_check(struct ebpfos_task_view_request *, const struct bpf_operations_set *);
void ebpfos_rule_task_copy(struct ebpfos_task_view_request *, void *);
bool ebpfos_rule_task_choices(struct ebpfos_rule_decision *);
void ebpfos_rule_task_table(struct ebpfos_rule_decision *, void *);
#else
static inline void ebpfos_task_rule_mark(struct task_struct *task) {}
static inline void ebpfos_task_rules_changed(void) {}
static inline void ebpfos_task_rule_resume(void) {}
static inline void ebpfos_task_rule_fork(struct task_struct *task) {}
static inline void ebpfos_task_rule_free(struct task_struct *task) {}
#endif
#endif
