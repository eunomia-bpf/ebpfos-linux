// SPDX-License-Identifier: GPL-2.0-only
/* Generated from this image's vmlinux BTF. Do not edit. */
#include <linux/compiler.h>
#include <linux/ebpfos_function_route.h>
#include <linux/init.h>

static struct ebpfos_function_route *route_0;
static noinline notrace u32 stub_0(u64 a0, u32 a1, u32 a2)
{
	u64 args[12] = { a0, a1, a2 };
	u64 result;
	if (ebpfos_function_route_call(route_0, args, false, &result))
		return (u32)result;
	result = ((u32 (*)(u64, u32, u32))ebpfos_function_route_native(route_0))(a0, a1, a2);
	/* Keep the fallback call site inside this stub for ftrace. */
	barrier();
	return (u32)result;
}
static int __init register_0(void)
{
	return ebpfos_function_route_register("__accumulate_pelt_segments", stub_0, &route_0);
}
late_initcall(register_0);
