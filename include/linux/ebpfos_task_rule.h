/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_TASK_RULE_H
#define _LINUX_EBPFOS_TASK_RULE_H
#include <linux/types.h>
struct task_struct;
struct ebpfos_rule_decision;
struct ebpfos_task_view_request;
#ifdef CONFIG_EBPFOS_ENTRY_LINK
/* These claims serialize the transition from the old cgroup owner. There
 * cannot be two independent publishers of a task's complete syscall table. */
int ebpfos_task_rule_claim(bool legacy);
void ebpfos_task_rule_unclaim(bool legacy);
void ebpfos_task_rule_mark(struct task_struct *);
void ebpfos_task_rules_changed(void);
void ebpfos_task_rule_resume(void);
void ebpfos_task_rule_fork(struct task_struct *);
void ebpfos_task_rule_free(struct task_struct *);
struct ebpfos_rule_decision *ebpfos_task_rule_decision(void);
struct ebpfos_task_view_request *ebpfos_rule_task_prepare(const u32 *, const u32 *, u32);
void ebpfos_rule_task_put(struct ebpfos_task_view_request *);
struct ebpfos_task_view_request *ebpfos_rule_task_get(struct ebpfos_task_view_request *);
bool ebpfos_rule_task_overlap(struct ebpfos_task_view_request *, struct ebpfos_task_view_request *);
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
