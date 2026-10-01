/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_FOPS_ROUTE_H
#define _LINUX_EBPFOS_FOPS_ROUTE_H

#include <linux/types.h>

/* Native object boundary for a published executor-root provider. The caller
 * owns the typed frame and the object-specific method contract. */
int ebpfos_fops_route_call(u64 handle, u64 role, void *frame,
			  u64 *epoch, u32 *provider_id, u32 *status);

#endif
