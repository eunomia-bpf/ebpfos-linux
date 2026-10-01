/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_FOPS_ROUTE_H
#define _LINUX_EBPFOS_FOPS_ROUTE_H

#include <linux/types.h>

struct file;

#define EBPFOS_FOPS_ROUTE_FRAME_VERSION 1U
struct ebpfos_fops_route_frame {
	u32 version;
	u32 method;
	u64 handle;
	u64 epoch;
	u64 requested;
	s64 result;
	u64 effect_token;
};

/* Native object boundary for a published executor-root provider. The caller
 * owns the typed frame and the object-specific method contract. */
int ebpfos_fops_route_call(u64 handle, u64 role, void *frame,
			  u64 *epoch, u32 *provider_id, u32 *status);

/* Attach/detach require a closed object gate and drained VFS calls. */
int ebpfos_fops_route_attach(struct file *file, u64 handle, u64 role);
int ebpfos_fops_route_detach(struct file *file);
int ebpfos_fops_route_quiesce(struct file *file);
int ebpfos_fops_route_switch(struct file *file, bool component);
void ebpfos_fops_route_resume(struct file *file);
u64 ebpfos_fops_route_linux_entries(struct file *file);

#endif
