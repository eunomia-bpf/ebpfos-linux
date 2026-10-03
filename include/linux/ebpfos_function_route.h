/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_FUNCTION_ROUTE_H
#define _LINUX_EBPFOS_FUNCTION_ROUTE_H

#include <linux/types.h>
#include <linux/errno.h>
#include <uapi/linux/ebpfos.h>

struct ebpfos_function_route;

/* Generated BTF-typed stubs register once at boot. */
int ebpfos_function_route_register(const char *symbol, void *stub,
				   struct ebpfos_function_route **route);
unsigned long ebpfos_function_route_native(struct ebpfos_function_route *route);
void *ebpfos_function_route_pointer_arg(struct ebpfos_function_route *route,
					u64 token, u32 index);
void ebpfos_function_route_pointer_result(struct ebpfos_function_route *route,
					 u64 token, const void *value);
void ebpfos_function_route_identity_result(struct ebpfos_function_route *route,
					 u64 token, u32 arg, const void *value);
void ebpfos_function_route_writeback_word(struct ebpfos_function_route *route,
					 u64 token, u32 arg, u32 word, u64 value);
bool ebpfos_function_route_call(struct ebpfos_function_route *route,
				const u64 args[12], bool require_full_output,
				u64 *result);
bool ebpfos_function_route_call_writeback(struct ebpfos_function_route *route,
				const u64 args[12], u32 arg, u32 size, u64 *result);
bool ebpfos_function_route_call_inout(struct ebpfos_function_route *route,
				const u64 args[12], u32 arg, u32 size, u64 *result);
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
