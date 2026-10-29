/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_RULE_CACHE_H
#define _LINUX_EBPFOS_RULE_CACHE_H
#include <linux/bpf_kernel_rule.h>

/* The owner uses its existing publication lock and operation boundary.
 * Neither this record nor its epoch is examined by a cached call. The
 * resolver table has the original BTF type and typed resolver methods. */
struct ebpfos_rule_cache {
 void **slot;
 const void *original, *resolver;
 struct bpf_kernel_rule_ctx context;
 struct ebpfos_rule_decision *decision;
 struct ebpfos_operations *operations;
 u64 epoch;
 u32 type, size, member;
};

void ebpfos_rule_cache_init(struct ebpfos_rule_cache *, void **slot,
 const void *original, const void *resolver, u32 type, u32 size,
 const struct bpf_kernel_rule_ctx *);
/* A generated binding can instead cache one typed function-pointer member
 * directly in work->func, timer->function, bi_end_io or another existing slot.
 * member is the compiler's constant offsetof in the admitted original table.
 * The owner supplies a resolver with that member's exact C prototype. */
void ebpfos_rule_cache_init_member(struct ebpfos_rule_cache *, void **slot,
 const void *original, const void *resolver, u32 type, u32 size, u32 member,
 const struct bpf_kernel_rule_ctx *);
/* Only the typed first-use resolver calls this, under the owner's lock.
 * An inherited decision belongs to the outer operation, even if rules have
 * changed since it started. NULL starts an operation from this context. */
int ebpfos_rule_cache_resolve(struct ebpfos_rule_cache *, struct ebpfos_rule_decision *, gfp_t);
/* Call only when the owner has no operation in flight. Queued work retains
 * its separate decision until its callback and all work it queues finish. */
void ebpfos_rule_cache_quiescent(struct ebpfos_rule_cache *);
void ebpfos_rule_cache_destroy(struct ebpfos_rule_cache *);
#endif
