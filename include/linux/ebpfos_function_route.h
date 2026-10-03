/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_FUNCTION_ROUTE_H
#define _LINUX_EBPFOS_FUNCTION_ROUTE_H

#include <linux/types.h>
#include <linux/errno.h>
#include <uapi/linux/ebpfos.h>

struct ebpfos_function_route;

/* Generated BTF-typed stubs register once at boot.  Only scalar arguments
 * and a <=32-bit scalar result use the non-sleepable call ABI today. */
int ebpfos_function_route_register(const char *symbol, void *stub,
				   struct ebpfos_function_route **route);
unsigned long ebpfos_function_route_native(struct ebpfos_function_route *route);
bool ebpfos_function_route_call(struct ebpfos_function_route *route,
				const u64 args[12], u32 *result);
#ifdef CONFIG_FUNCTION_TRACER
int ebpfos_function_route_ioctl(struct ebpfos_ioc_function_route *request);
#else
static inline int ebpfos_function_route_ioctl(
		struct ebpfos_ioc_function_route *request)
{
	return -EOPNOTSUPP;
}
#endif

#endif
