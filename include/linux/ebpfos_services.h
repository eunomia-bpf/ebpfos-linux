/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_SERVICES_H
#define _LINUX_EBPFOS_SERVICES_H

#include <linux/types.h>

struct file;
struct bio;
struct iov_iter;
struct poll_table_struct;
struct net_device;
struct rtnl_link_stats64;
struct sk_buff;
struct ebpfos_effect_scope;
struct ebpfos_effect_wait_ref;

/* Provider kfuncs must belong to the ebpfos_l1_services BTF set. */
#ifdef CONFIG_EBPFOS
bool ebpfos_effect_kfunc_allowed(u32 btf_id);
#else
static inline bool ebpfos_effect_kfunc_allowed(u32 btf_id)
{
	return false;
}
#endif

/* Native route owns one handle reference from attach through detach. */
int ebpfos_effect_handle_get(u64 handle);
void ebpfos_effect_handle_put(u64 handle);

/* Enter around a synchronous, sleepable component invocation. */
struct ebpfos_effect_scope *ebpfos_effect_scope_enter(u64 handle,
					     struct file *file,
					     struct iov_iter *iter,
					     struct poll_table_struct *table);
struct ebpfos_effect_scope *ebpfos_effect_scope_enter_bio(u64 handle,
						   struct bio *bio);
int ebpfos_effect_scope_exit(struct ebpfos_effect_scope *scope);
struct ebpfos_effect_scope *ebpfos_effect_net_scope_enter(u64 handle,
					 struct net_device *dev,
					 struct sk_buff *skb);
struct ebpfos_effect_scope *ebpfos_effect_net_config_scope_enter(u64 handle,
		struct net_device *dev, void *addr,
		struct rtnl_link_stats64 *stats);
bool ebpfos_effect_net_skb_pending(struct ebpfos_effect_scope *scope);

/* Native fops can attach poll/fasync to an effect object. */
void ebpfos_effect_poll(u64 handle, u32 slot, struct file *file,
			struct poll_table_struct *table);
int ebpfos_effect_fasync(u64 handle, int fd, struct file *file, int on);

/* Persistent per-handle wait queue shared by routed native and BPF calls. */
struct ebpfos_effect_wait_ref *ebpfos_effect_wait_ref_get(u64 handle,
						       u32 slot);
void ebpfos_effect_wait_ref_put(struct ebpfos_effect_wait_ref *ref);
u64 ebpfos_effect_wait_ref_sequence(struct ebpfos_effect_wait_ref *ref);
int ebpfos_effect_wait_ref_wait(struct ebpfos_effect_wait_ref *ref, u64 seen);
void ebpfos_effect_wait_ref_wake(struct ebpfos_effect_wait_ref *ref, u32 mask);

#endif
