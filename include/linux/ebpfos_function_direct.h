/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_FUNCTION_DIRECT_H
#define _LINUX_EBPFOS_FUNCTION_DIRECT_H
struct ebpfos_function_route;
int ebpfos_function_route_register_direct(const char *symbol, void *stub,
                void *direct, unsigned long *fallback_begin,
                unsigned long *fallback_end, struct ebpfos_function_route **route);
#endif
