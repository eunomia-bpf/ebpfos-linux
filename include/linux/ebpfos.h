/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_H
#define _LINUX_EBPFOS_H

#include <linux/errno.h>
#include <linux/types.h>
#include <uapi/linux/ebpfos.h>

struct file;

#ifdef CONFIG_EBPFOS
/* Public dispatch selects typed struct_ops first and raw graph as fallback. */
u32 ebpfos_run_hook(enum ebpfos_hook_id hook, const u64 *args, u32 nr_args);
u32 ebpfos_run_raw_hook(enum ebpfos_hook_id hook, const u64 *args, u32 nr_args);
bool ebpfos_hook_enabled(enum ebpfos_hook_id hook);
long ebpfos_object_create_ioctl(void __user *argp);
#else
static inline u32 ebpfos_run_hook(enum ebpfos_hook_id hook,
				  const u64 *args, u32 nr_args)
{
	return EBPFOS_ACTION(EBPFOS_VERDICT_CONTINUE, 0);
}

static inline u32 ebpfos_run_raw_hook(enum ebpfos_hook_id hook,
				      const u64 *args, u32 nr_args)
{
	return EBPFOS_ACTION(EBPFOS_VERDICT_CONTINUE, 0);
}

static inline bool ebpfos_hook_enabled(enum ebpfos_hook_id hook)
{
	return false;
}

static inline long ebpfos_object_create_ioctl(void __user *argp)
{
	return -EOPNOTSUPP;
}
#endif

static inline bool ebpfos_action_is(u32 action, enum ebpfos_verdict verdict)
{
	return EBPFOS_ACTION_VERDICT(action) == verdict;
}

static inline int ebpfos_action_error(u32 action)
{
	u32 error = EBPFOS_ACTION_PAYLOAD(action);

	return error ? -(int)error : -EPERM;
}
#endif
