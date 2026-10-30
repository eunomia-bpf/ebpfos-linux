/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_BPF_OPERATIONS_H
#define _LINUX_BPF_OPERATIONS_H
#include <linux/bpf.h>
struct bpf_operations_set;
struct ebpfos_operations;
typedef int (*bpf_operations_visit_change)(unsigned long, const void *, size_t, void *);
#ifdef CONFIG_EBPFOS_ENTRY_LINK
u32 btf_module_type_id(const struct module *, u32);
long bpf_operations_update(struct bpf_map *, void *, void *, u64);
struct bpf_operations_set *bpf_operations_prepare(const u32 *fds, u32 count);
struct bpf_operations_set *bpf_operations_set_get(struct bpf_operations_set *set);
void bpf_operations_set_put(struct bpf_operations_set *set);
u32 bpf_operations_set_count(const struct bpf_operations_set *set);
int bpf_operations_visit_programs(const struct bpf_operations_set *,int (*visit)(struct bpf_prog *,void *),void *);
int bpf_operations_visit_changes(const struct bpf_operations_set *, bpf_operations_visit_change, void *);
u32 bpf_operations_set_id(const struct bpf_operations_set *set, u32 index);
bool bpf_operations_set_targets(const struct bpf_operations_set *, const struct bpf_operations_set *);
bool bpf_operations_overlap(const struct bpf_operations_set *, const struct bpf_operations_set *);
bool bpf_operations_set_same(const struct bpf_operations_set *a, const struct bpf_operations_set *b);
struct bpf_operations_set *bpf_operations_compose(struct bpf_operations_set *active,
 struct bpf_operations_set *next, struct bpf_operations_set *old);
struct bpf_operations_global_update {
 struct bpf_operations_set *before, *after;
};
int bpf_operations_global_prepare(struct bpf_operations_global_update *,
 struct bpf_operations_set *next, struct bpf_operations_set *old);
void bpf_operations_global_publish(struct bpf_operations_global_update *);
void bpf_operations_global_undo(struct bpf_operations_global_update *);
void bpf_operations_global_release(struct bpf_operations_global_update *);
struct ebpfos_operations *bpf_operations_find(struct bpf_operations_set *, const void *, u32, size_t);
void bpf_operations_info(struct bpf_map *, struct bpf_map_info *);
#else
static inline long bpf_operations_update(struct bpf_map *map, void *key, void *value, u64 flags) { return -EOPNOTSUPP; }
static inline void bpf_operations_set_put(struct bpf_operations_set *set) {}
#endif
#endif
