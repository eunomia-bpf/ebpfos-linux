// SPDX-License-Identifier: GPL-2.0-only
/* BTF-generated typed stubs enter the existing non-sleepable L1 route. */
#include <linux/atomic.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/ebpfos.h>
#include <linux/ebpfos_function_route.h>
#include <linux/ebpfos_function_direct.h>
#include <linux/ebpfos_irq_route.h>
#include <linux/ftrace.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/ibt.h>
#include <asm/cpufeature.h>
#include "irq_route_dispatch.h"

struct ebpfos_function_counters {
	u64 component_calls;
	u64 native_fallbacks;
};

struct ebpfos_function_route {
	struct list_head link;
	struct ftrace_ops fops;
	char symbol[64];
	unsigned long native;
	unsigned long stub;
	unsigned long stub_size;
	unsigned long direct;
	bool direct_active;
	bool entry_active;
	unsigned long native_body;
	u64 object_id;
	struct ebpfos_executor_root_slot *root_slot;
	u64 role_type;
	u64 last_epoch;
	u32 last_provider_id;
	struct ebpfos_function_counters __percpu *counters;
	bool enabled;
};

static LIST_HEAD(ebpfos_function_routes);
static DEFINE_MUTEX(ebpfos_function_routes_lock);
static bool direct_calls;
module_param(direct_calls, bool, 0444);
MODULE_PARM_DESC(direct_calls, "Use generated direct-ftrace trampolines for function routes");
static bool own_entry;
module_param(own_entry, bool, 0444);
MODULE_PARM_DESC(own_entry, "Jump directly to the BTF-generated component entry");
static atomic64_t ebpfos_function_token = ATOMIC64_INIT(0);

struct ebpfos_function_result_scope {
	struct ebpfos_function_result_scope *previous;
	struct ebpfos_function_route *route;
	const u64 *args;
	u64 token;
	u64 value;
	u64 writeback[4];
	u32 writeback_arg;
	u32 writeback_size;
	u32 writeback_mask;
	u64 field_value;
	u32 field_arg;
	u32 field_offset;
	u32 field_size;
	bool field_written;
	bool written;
};

static DEFINE_PER_CPU(struct ebpfos_function_result_scope *, ebpfos_function_result);

__bpf_kfunc_start_defs();

/* A non-sleepable provider returns its full-width value to its own call. */
__bpf_kfunc void bpf_ebpfos_function_output(u64 token, u64 value)
{
	struct ebpfos_function_result_scope *scope = this_cpu_read(ebpfos_function_result);

	if (scope && scope->token == token) {
		scope->value = value;
		scope->written = true;
	}
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(ebpfos_function_output_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_function_output)
BTF_KFUNCS_END(ebpfos_function_output_ids)

static int ebpfos_function_output_filter(const struct bpf_prog *prog, u32 id)
{
	if (!btf_id_set8_contains(&ebpfos_function_output_ids, id))
		return 0;
	return !prog || !prog->aux || !prog->aux->ebpfos_component ||
	       prog->type != BPF_PROG_TYPE_RAW_TRACEPOINT || prog->sleepable;
}

static const struct btf_kfunc_id_set ebpfos_function_output_set = {
	.owner = THIS_MODULE,
	.set = &ebpfos_function_output_ids,
	.filter = ebpfos_function_output_filter,
};

static int __init ebpfos_function_output_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_RAW_TRACEPOINT,
					 &ebpfos_function_output_set);
}
late_initcall(ebpfos_function_output_init);

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
	/* A replacement enters before the native prologue, as does -mfentry.
	 * Fallback must resume beyond the patched slot, without entering us again.
	 */
	offset = ftrace_location(route->native);
	if (offset == route->native ||
	    (IS_ENABLED(CONFIG_X86_KERNEL_IBT) &&
	     offset == route->native + ENDBR_INSN_SIZE))
		route->native_body = offset + MCOUNT_INSN_SIZE;
	route->counters = alloc_percpu(struct ebpfos_function_counters);
	if (!route->counters) {
		kfree(route);
		return -ENOMEM;
	}
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
			free_percpu(route->counters);
			kfree(route);
			return -EEXIST;
		}
	}
	list_add_tail(&route->link, &ebpfos_function_routes);
	mutex_unlock(&ebpfos_function_routes_lock);
	*out = route;
	return 0;
}

int ebpfos_function_route_register_direct(const char *symbol, void *stub,
				void *direct, unsigned long *fallback_begin,
				unsigned long *fallback_end,
				struct ebpfos_function_route **out)
{
	int error;

	/* x86 reserves the low address bit for another direct-entry ABI. */
	if (!direct || ((unsigned long)direct & 1) ||
	    !fallback_begin || !fallback_end)
		return -EINVAL;
	error = ebpfos_function_route_register(symbol, stub, out);
	if (error)
		return error;
	*fallback_begin = (*out)->stub;
	*fallback_end = (*out)->stub + (*out)->stub_size;
	(*out)->direct = (unsigned long)direct;
	return 0;
}

unsigned long ebpfos_function_route_native(struct ebpfos_function_route *route)
{
	return route->entry_active ? route->native_body : route->native;
}

void *ebpfos_function_route_pointer_arg(struct ebpfos_function_route *route,
					u64 token, u32 index)
{
	struct ebpfos_function_result_scope *scope = this_cpu_read(ebpfos_function_result);

	if (!scope || scope->token != token || scope->route != route || index >= 11)
		return NULL;
	return (void *)(unsigned long)scope->args[index];
}

void ebpfos_function_route_pointer_result(struct ebpfos_function_route *route,
					 u64 token, const void *value)
{
	struct ebpfos_function_result_scope *scope = this_cpu_read(ebpfos_function_result);

	if (scope && scope->token == token && scope->route == route) {
		scope->value = (u64)(unsigned long)value;
		scope->written = true;
	}
}

void ebpfos_function_route_identity_result(struct ebpfos_function_route *route,
					 u64 token, u32 arg, const void *value)
{
	struct ebpfos_function_result_scope *scope = this_cpu_read(ebpfos_function_result);

	if (scope && scope->token == token && scope->route == route &&
	    arg < 11 && (u64)(unsigned long)value == scope->args[arg]) {
		scope->value = (u64)(unsigned long)value;
		scope->written = true;
	}
}

void ebpfos_function_route_writeback_word(struct ebpfos_function_route *route,
					 u64 token, u32 arg, u32 word, u64 value)
{
	struct ebpfos_function_result_scope *scope = this_cpu_read(ebpfos_function_result);

	if (!scope || scope->token != token || scope->route != route ||
	    !scope->writeback_size || arg != scope->writeback_arg ||
	    word >= (scope->writeback_size + sizeof(u64) - 1) / sizeof(u64))
		return;
	scope->writeback[word] = value;
	scope->writeback_mask |= 1U << word;
}

void ebpfos_function_route_field_writeback(struct ebpfos_function_route *route,
					   u64 value)
{
	struct ebpfos_function_result_scope *scope = this_cpu_read(ebpfos_function_result);

	if (scope && scope->route == route && scope->field_size) {
		scope->field_value = value;
		scope->field_written = true;
	}
}

static __always_inline bool ebpfos_function_route_call_inner(struct ebpfos_function_route *route,
				u64 args[12], bool require_full_output,
				u32 writeback_arg, u32 writeback_size,
				bool copyin, u32 field_offset, u32 field_size,
				u64 *result)
{
	struct ebpfos_component_irq_frame *frame = (void *)args;
	struct ebpfos_function_result_scope scope __uninitialized;
	u64 before[4] __uninitialized;
	u64 epoch = 0;
	u32 provider = 0, value = 0;
	struct ebpfos_executor_root_slot *slot;
	int error;

	/*
	 * Control fields are assigned before exposing this scope to kfuncs.
	 * Writeback controls are accessed only when their assigned size is nonzero.
	 * Payloads are read only after their completion flag/full word mask.
	 * Copy-in snapshots are read only after the native bytes were copied.
	 */
	scope.written = false;
	if (field_size)
		scope.field_written = false;
	if (writeback_size)
		scope.writeback_mask = 0;
	/* Disable drains the entire call, including output commit, via RCU. */
	rcu_read_lock();
	if (!smp_load_acquire(&route->enabled))
		goto fallback;
	if (writeback_size && (writeback_arg >= 11 || !args[writeback_arg] ||
			       writeback_size > sizeof(scope.writeback) ||
			       (copyin && writeback_size > sizeof(before)))) {
		goto fallback;
	}
	if (field_size && (writeback_arg >= 11 || !args[writeback_arg] ||
			   field_size > sizeof(scope.field_value) ||
			   field_offset > 4096 - field_size)) {
		goto fallback;
	}
	if (copyin)
		memcpy(before, (void *)(unsigned long)args[writeback_arg],
		       writeback_size);
	scope.token = atomic64_inc_return(&ebpfos_function_token);
	scope.route = route;
	scope.args = frame->args;
	scope.writeback_size = writeback_size;
	if (writeback_size)
		scope.writeback_arg = writeback_arg;
	scope.field_size = field_size;
	if (field_size) {
		scope.field_arg = writeback_arg;
		scope.field_offset = field_offset;
	}
	frame->args[11] = scope.token;
	preempt_disable();
	scope.previous = this_cpu_read(ebpfos_function_result);
	this_cpu_write(ebpfos_function_result, &scope);
	slot = READ_ONCE(route->root_slot);
	if (unlikely(!slot)) {
		/* A route may be enabled before its root's first publication. */
		slot = ebpfos_executor_root_lookup(READ_ONCE(route->object_id));
		WRITE_ONCE(route->root_slot, slot);
	}
	error = ebpfos_irq_route_call_slot_rcu(slot,
		READ_ONCE(route->role_type), frame, &epoch, &provider, &value);
	this_cpu_write(ebpfos_function_result, scope.previous);
	preempt_enable();
	if (!error && require_full_output && !scope.written)
		error = -ENODATA;
	if (!error && writeback_size &&
	    scope.writeback_mask !=
	    (1U << ((writeback_size + sizeof(u64) - 1) / sizeof(u64))) - 1)
		error = -ENODATA;
	if (!error && copyin &&
	    memcmp((void *)(unsigned long)args[writeback_arg], before,
		   writeback_size))
		error = -EAGAIN;
	if (!error) {
		if (field_size && scope.field_written)
			memcpy((char *)(unsigned long)args[scope.field_arg] +
			       scope.field_offset, &scope.field_value, field_size);
		if (writeback_size &&
		    (!copyin || memcmp(scope.writeback, before, writeback_size)))
			memcpy((void *)(unsigned long)args[writeback_arg],
			       scope.writeback, writeback_size);
		*result = scope.written ? scope.value : value;
		if (READ_ONCE(route->last_epoch) != epoch)
			WRITE_ONCE(route->last_epoch, epoch);
		if (READ_ONCE(route->last_provider_id) != provider)
			WRITE_ONCE(route->last_provider_id, provider);
		this_cpu_inc(route->counters->component_calls);
	}
	if (!error) {
		rcu_read_unlock();
		return true;
	}
fallback:
	rcu_read_unlock();
	this_cpu_inc(route->counters->native_fallbacks);
	return false;
}

bool ebpfos_function_route_call(struct ebpfos_function_route *route,
				u64 args[12], bool require_full_output,
				u64 *result)
{
	return ebpfos_function_route_call_inner(route, args, require_full_output,
					 0, 0, false, 0, 0, result);
}

bool ebpfos_function_route_call_writeback(struct ebpfos_function_route *route,
				u64 args[12], u32 arg, u32 size, u64 *result)
{
	return ebpfos_function_route_call_inner(route, args, true, arg, size,
					 false, 0, 0, result);
}

bool ebpfos_function_route_call_inout(struct ebpfos_function_route *route,
				u64 args[12], u32 arg, u32 size, u64 *result)
{
	return ebpfos_function_route_call_inner(route, args, true, arg, size,
					 true, 0, 0, result);
}

bool ebpfos_function_route_call_field(struct ebpfos_function_route *route,
				u64 args[12], u32 arg, u32 offset, u32 size,
				u64 *result)
{
	return ebpfos_function_route_call_inner(route, args, true, arg, 0,
					 false, offset, size, result);
}

int ebpfos_function_route_ioctl(struct ebpfos_ioc_function_route *request)
{
	struct ebpfos_function_route *route;
	unsigned long location;
	int cpu, error = -ENOENT;

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
		/* The native continuation has no ENDBR. Do not disable CET or
		 * its checks to enter it on an IBT-enforcing machine.
		 */
		if (own_entry && (!IS_ENABLED(CONFIG_DYNAMIC_FTRACE_WITH_JMP) ||
				  IS_ENABLED(CONFIG_CFI) ||
				  cpu_feature_enabled(X86_FEATURE_IBT) ||
				  !route->native_body || (route->stub & 1))) {
			error = -EOPNOTSUPP;
			goto out;
		}
		WRITE_ONCE(route->object_id, request->object_id);
		WRITE_ONCE(route->root_slot,
			ebpfos_executor_root_lookup(request->object_id));
		WRITE_ONCE(route->role_type, request->role_type);
		error = ftrace_set_filter_ip(&route->fops, location, 0, 0);
		if (error)
			goto out;
		route->entry_active = own_entry;
		route->direct_active = own_entry || (direct_calls && route->direct);
		if (route->direct_active) {
			route->fops.func = NULL;
			route->fops.flags &= ~FTRACE_OPS_FL_IPMODIFY;
			error = register_ftrace_direct(&route->fops,
				route->entry_active ? ftrace_jmp_set(route->stub) : route->direct);
		} else {
			error = register_ftrace_function(&route->fops);
		}
		if (error) {
			ftrace_set_filter_ip(&route->fops, location, 1, 0);
			goto out;
		}
		smp_store_release(&route->enabled, true);
	} else if (request->enable == 0 && route->enabled) {
		smp_store_release(&route->enabled, false);
		/*
		 * Import bridges enter the stub without traversing ftrace. Drain
		 * their scopes as well before returning or reusing this route.
		 */
		synchronize_rcu();
		if (route->direct_active) {
			error = unregister_ftrace_direct(&route->fops,
				route->entry_active ? ftrace_jmp_set(route->stub) : route->direct,
				false);
			if (error)
				goto out;
		} else {
			unregister_ftrace_function(&route->fops);
		}
		ftrace_set_filter_ip(&route->fops, location, 1, 0);
	} else if (request->enable > 1) {
		error = -EINVAL;
		goto out;
	}
	request->object_id = READ_ONCE(route->object_id);
	request->role_type = READ_ONCE(route->role_type);
	request->component_calls = 0;
	request->native_fallbacks = 0;
	for_each_possible_cpu(cpu) {
		const struct ebpfos_function_counters *counters =
			per_cpu_ptr(route->counters, cpu);

		request->component_calls += READ_ONCE(counters->component_calls);
		request->native_fallbacks += READ_ONCE(counters->native_fallbacks);
	}
	request->last_epoch = READ_ONCE(route->last_epoch);
	request->last_provider_id = READ_ONCE(route->last_provider_id);
	error = 0;
out:
	mutex_unlock(&ebpfos_function_routes_lock);
	return error;
}
