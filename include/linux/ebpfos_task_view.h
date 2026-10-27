/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LINUX_EBPFOS_TASK_VIEW_H
#define LINUX_EBPFOS_TASK_VIEW_H
struct task_struct;
struct ebpfos_task_view_request;
#if defined(CONFIG_EBPFOS) && defined(CONFIG_X86_64)
void ebpfos_task_view_fork(struct task_struct *task);
void ebpfos_task_view_free(struct task_struct *task);
void ebpfos_task_view_resume(void);
#else
static inline void ebpfos_task_view_fork(struct task_struct *task) { }
static inline void ebpfos_task_view_free(struct task_struct *task) { }
static inline void ebpfos_task_view_resume(void) { }
#endif
struct cgroup;
#if defined(CONFIG_EBPFOS_ENTRY_LINK) && defined(CONFIG_CGROUP_BPF)
/* Membership and fork callers already hold css_set_lock. */
void ebpfos_cgroup_task_move(struct task_struct *task);
void ebpfos_cgroup_exec(void);
void ebpfos_cgroup_offline(struct cgroup *group);
#else
static inline void ebpfos_cgroup_task_move(struct task_struct *task) {}
static inline void ebpfos_cgroup_exec(void) {}
static inline void ebpfos_cgroup_offline(struct cgroup *group) {}
#endif
#endif
