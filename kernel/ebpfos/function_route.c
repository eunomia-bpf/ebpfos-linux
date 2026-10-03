// SPDX-License-Identifier: GPL-2.0-only
/* BTF-generated typed stubs enter the existing non-sleepable L1 route. */
#include <linux/atomic.h>
#include <linux/ebpfos.h>
#include <linux/ebpfos_function_route.h>
#include <linux/ebpfos_irq_route.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "component_graph.h"

struct ebpfos_function_route {
	struct list_head link;
	struct ftrace_ops fops;
	struct ebpfos_component_gate gate;
	char symbol[64];
	unsigned long native;
	unsigned long stub;
	unsigned long stub_size;
	u64 object_id;
	u64 role_type;
	u64 last_epoch;
	u32 last_provider_id;
	atomic64_t component_calls;
	atomic64_t native_fallbacks;
	bool enabled;
};

static LIST_HEAD(ebpfos_function_routes);
static DEFINE_MUTEX(ebpfos_function_routes_lock);

static void notrace ebpfos_function_ftrace(unsigned long ip,
		unsigned long parent_ip, struct ftrace_ops *ops,
		struct ftrace_regs *regs)
{
	struct ebpfos_function_route *route =
		container_of(ops, struct ebpfos_function_route, fops);

	/* Calling the original from the stub is the native fault path. */
	if (parent_ip >= route->stub &&
	    parent_ip - route->stub < route->stub_size)
		return;
	if (READ_ONCE(route->enabled))
		ftrace_regs_set_instruction_pointer(regs, route->stub);
}

int ebpfos_function_route_register(const char *symbol, void *stub,
				   struct ebpfos_function_route **out)
{
	struct ebpfos_function_route *route, *entry;
	unsigned long offset;

	if (!symbol || !stub || !out || !*symbol || strlen(symbol) >= 64)
		return -EINVAL;
	route = kzalloc(sizeof(*route), GFP_KERNEL);
	if (!route)
		return -ENOMEM;
	strscpy(route->symbol, symbol, sizeof(route->symbol));
	route->native = kallsyms_lookup_name(symbol);
	route->stub = (unsigned long)stub;
	if (!route->native || !ftrace_location(route->native) ||
	    !kallsyms_lookup_size_offset(route->stub, &route->stub_size,
					 &offset) || !route->stub_size) {
		kfree(route);
		return -ENOENT;
	}
	ebpfos_component_gate_init(&route->gate);
	route->fops.func = ebpfos_function_ftrace;
	route->fops.flags = FTRACE_OPS_FL_DYNAMIC |
#ifndef CONFIG_HAVE_DYNAMIC_FTRACE_WITH_ARGS
		FTRACE_OPS_FL_SAVE_REGS |
#endif
		FTRACE_OPS_FL_IPMODIFY | FTRACE_OPS_FL_PERMANENT;
	mutex_lock(&ebpfos_function_routes_lock);
	list_for_each_entry(entry, &ebpfos_function_routes, link) {
		if (!strcmp(entry->symbol, symbol)) {
			mutex_unlock(&ebpfos_function_routes_lock);
			kfree(route);
			return -EEXIST;
		}
	}
	list_add_tail(&route->link, &ebpfos_function_routes);
	mutex_unlock(&ebpfos_function_routes_lock);
	*out = route;
	return 0;
}

unsigned long ebpfos_function_route_native(struct ebpfos_function_route *route)
{
	return route->native;
}

bool ebpfos_function_route_call(struct ebpfos_function_route *route,
				const u64 args[12], u32 *result)
{
	struct ebpfos_component_irq_frame frame = {};
	u64 epoch = 0;
	u32 provider = 0, value = 0;
	int error;

	if (!READ_ONCE(route->enabled) ||
	    !ebpfos_component_gate_try_enter(&route->gate))
		goto fallback;
	memcpy(frame.args, args, sizeof(frame.args));
	error = ebpfos_irq_route_call(READ_ONCE(route->object_id),
		READ_ONCE(route->role_type), &frame, &epoch, &provider, &value);
	if (!error) {
		*result = value;
		WRITE_ONCE(route->last_epoch, epoch);
		WRITE_ONCE(route->last_provider_id, provider);
		atomic64_inc(&route->component_calls);
	}
	ebpfos_component_gate_exit(&route->gate);
	if (!error)
		return true;
fallback:
	atomic64_inc(&route->native_fallbacks);
	return false;
}

int ebpfos_function_route_ioctl(struct ebpfos_ioc_function_route *request)
{
	struct ebpfos_function_route *route;
	unsigned long location;
	int error = -ENOENT;

	mutex_lock(&ebpfos_function_routes_lock);
	list_for_each_entry(route, &ebpfos_function_routes, link) {
		if (!strcmp(route->symbol, request->symbol))
			goto found;
	}
	goto out;
found:
	location = ftrace_location(route->native);
	if (request->enable == 1 && !route->enabled) {
		if (!request->object_id || !request->role_type) {
			error = -EINVAL;
			goto out;
		}
		WRITE_ONCE(route->object_id, request->object_id);
		WRITE_ONCE(route->role_type, request->role_type);
		error = ftrace_set_filter_ip(&route->fops, location, 0, 0);
		if (error)
			goto out;
		error = register_ftrace_function(&route->fops);
		if (error) {
			ftrace_set_filter_ip(&route->fops, location, 1, 0);
			goto out;
		}
		WRITE_ONCE(route->enabled, true);
	} else if (request->enable == 0 && route->enabled) {
		WRITE_ONCE(route->enabled, false);
		unregister_ftrace_function(&route->fops);
		ftrace_set_filter_ip(&route->fops, location, 1, 0);
		error = ebpfos_component_gate_engage(&route->gate);
		if (!error)
			ebpfos_component_gate_abort(&route->gate);
		if (error)
			goto out;
	} else if (request->enable > 1) {
		error = -EINVAL;
		goto out;
	}
	request->object_id = READ_ONCE(route->object_id);
	request->role_type = READ_ONCE(route->role_type);
	request->component_calls = atomic64_read(&route->component_calls);
	request->native_fallbacks = atomic64_read(&route->native_fallbacks);
	request->last_epoch = READ_ONCE(route->last_epoch);
	request->last_provider_id = READ_ONCE(route->last_provider_id);
	error = 0;
out:
	mutex_unlock(&ebpfos_function_routes_lock);
	return error;
}
