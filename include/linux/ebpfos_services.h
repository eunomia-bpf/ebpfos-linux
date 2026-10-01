/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_SERVICES_H
#define _LINUX_EBPFOS_SERVICES_H

#include <linux/types.h>

struct file;
struct iov_iter;
struct poll_table_struct;
struct ebpfos_effect_scope;

/* The component verifier may admit only kfunc IDs in this L1 service set. */
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
int ebpfos_effect_scope_exit(struct ebpfos_effect_scope *scope);

/* Native fops can attach poll/fasync to an effect object. */
void ebpfos_effect_poll(u64 handle, u32 slot, struct file *file,
			struct poll_table_struct *table);
int ebpfos_effect_fasync(u64 handle, int fd, struct file *file, int on);

#endif
