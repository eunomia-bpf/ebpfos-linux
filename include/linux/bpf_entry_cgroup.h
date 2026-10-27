/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_BPF_ENTRY_CGROUP_H
#define _LINUX_BPF_ENTRY_CGROUP_H
#include <linux/bpf.h>
struct ebpfos_cgroup_view;
struct bpf_operations_set;
struct ebpfos_task_view_request;
struct bpf_entry_target {
 u32 function;
 struct bpf_prog *program;
 unsigned long address;
};
#if defined(CONFIG_EBPFOS_ENTRY_LINK) && defined(CONFIG_CGROUP_BPF)
struct ebpfos_task_view_request *ebpfos_cgroup_prepare(
 const struct bpf_entry_target *, u32 count, u64 generation, struct bpf_operations_set *);
void ebpfos_cgroup_request_put(struct ebpfos_task_view_request *);
struct ebpfos_cgroup_view *ebpfos_cgroup_view_create(int fd,
 struct ebpfos_task_view_request *);
int ebpfos_cgroup_view_attach(struct ebpfos_cgroup_view *);
int ebpfos_cgroup_view_update(struct ebpfos_cgroup_view *, struct ebpfos_task_view_request *);
void ebpfos_cgroup_view_detach(struct ebpfos_cgroup_view *);
void ebpfos_cgroup_view_put(struct ebpfos_cgroup_view *);
u64 ebpfos_cgroup_view_id(const struct ebpfos_cgroup_view *);
bool ebpfos_cgroup_view_active(const struct ebpfos_cgroup_view *);
#else
static inline struct ebpfos_task_view_request *ebpfos_cgroup_prepare(
 const struct bpf_entry_target *targets, u32 count, u64 generation, struct bpf_operations_set *operations)
{ return ERR_PTR(-EOPNOTSUPP); }
static inline void ebpfos_cgroup_request_put(struct ebpfos_task_view_request *request) {}
static inline struct ebpfos_cgroup_view *ebpfos_cgroup_view_create(int fd,
 struct ebpfos_task_view_request *request) { return ERR_PTR(-EOPNOTSUPP); }
static inline int ebpfos_cgroup_view_attach(struct ebpfos_cgroup_view *view) { return -EOPNOTSUPP; }
static inline int ebpfos_cgroup_view_update(struct ebpfos_cgroup_view *view,
 struct ebpfos_task_view_request *request) { return -EOPNOTSUPP; }
static inline void ebpfos_cgroup_view_detach(struct ebpfos_cgroup_view *view) {}
static inline void ebpfos_cgroup_view_put(struct ebpfos_cgroup_view *view) {}
static inline u64 ebpfos_cgroup_view_id(const struct ebpfos_cgroup_view *view) { return 0; }
static inline bool ebpfos_cgroup_view_active(const struct ebpfos_cgroup_view *view) { return false; }
#endif
#endif
