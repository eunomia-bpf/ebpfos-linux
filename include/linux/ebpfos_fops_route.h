/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_FOPS_ROUTE_H
#define _LINUX_EBPFOS_FOPS_ROUTE_H

#include <linux/types.h>

struct file;

/* Native routes use struct ebpfos_component_call_frame: the verifier's
 * read-only input and writable output bounds must match the actual frame. */

/* Native object boundary for a published executor-root provider. The caller
 * owns the typed frame and the object-specific method contract. */
int ebpfos_fops_route_call(u64 handle, u64 role, void *frame,
			  u64 *epoch, u32 *provider_id, u32 *status);

/* The caller must exclude concurrent VFS acquisition while swapping f_op.
 * The E3 oracle attaches before publishing FDs and detaches after its child
 * exits. The gate drains calls before an implementation change. */
int ebpfos_fops_route_attach(struct file *file, u64 handle, u64 role);
int ebpfos_fops_route_detach(struct file *file);
int ebpfos_fops_route_quiesce(struct file *file);
int ebpfos_fops_route_switch(struct file *file, bool component);
void ebpfos_fops_route_resume(struct file *file);
u64 ebpfos_fops_route_linux_entries(struct file *file);

#endif
