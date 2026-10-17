/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LINUX_EBPFOS_TASK_VIEW_H
#define LINUX_EBPFOS_TASK_VIEW_H
struct task_struct;
#if defined(CONFIG_EBPFOS) && defined(CONFIG_X86_64)
void ebpfos_task_view_fork(struct task_struct *task);
void ebpfos_task_view_free(struct task_struct *task);
#else
static inline void ebpfos_task_view_fork(struct task_struct *task) { }
static inline void ebpfos_task_view_free(struct task_struct *task) { }
#endif
#endif
