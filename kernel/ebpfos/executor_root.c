// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/ebpfos.h>
#include <linux/ebpfos_typed.h>
#include <linux/errno.h>
#include <linux/filter.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <linux/xarray.h>
#include <uapi/linux/ebpfos_root.h>
#include "executor_root.h"
#include "step_scope.h"

/* Slots have stable lifetime; bundles own bindings until after an RCU grace period. */
static DEFINE_XARRAY(ebpfos_executor_roots);

static struct ebpfos_executor_root_slot *
ebpfos_executor_root_slot_get(u64 object_id)
{
	struct ebpfos_executor_root_slot *slot;
	int error;

	slot = xa_load(&ebpfos_executor_roots, object_id);
	if (slot)
		return slot;
	slot = kzalloc(sizeof(*slot), GFP_KERNEL);
	if (!slot)
		return ERR_PTR(-ENOMEM);
	spin_lock_init(&slot->lock);
	ebpfos_component_gate_init(&slot->gate);
	error = xa_insert(&ebpfos_executor_roots, object_id, slot, GFP_KERNEL);
	if (error) {
		kfree(slot);
		return ERR_PTR(error);
	}
	return slot;
}

static void ebpfos_executor_root_bundle_release(
	struct ebpfos_executor_root_bundle *bundle)
{
	u32 role;

	if (!bundle)
		return;
	for (role = 0; role < bundle->role_count; role++) {
		ebpfos_component_context_free(bundle->roles[role].context_image);
		ebpfos_binding_put(bundle->roles[role].binding);
		ebpfos_admission_put(bundle->roles[role].grant);
	}
	kfree(bundle);
}

static void ebpfos_executor_root_retire_work(struct work_struct *work)
{
	struct ebpfos_executor_root_bundle *bundle =
		container_of(work, struct ebpfos_executor_root_bundle, retire_work);

	ebpfos_executor_root_bundle_release(bundle);
}

static void ebpfos_executor_root_retire_rcu(struct rcu_head *rcu)
{
	struct ebpfos_executor_root_bundle *bundle =
		container_of(rcu, struct ebpfos_executor_root_bundle, rcu);

	schedule_work(&bundle->retire_work);
}

static bool ebpfos_pointer_result_tag(const struct bpf_map *map)
{
	u32 i;

	if (!map->btf)
		return false;
	for (i = 1; i < btf_nr_types(map->btf); i++) {
		const struct btf_type *type = btf_type_by_id(map->btf, i);

		if (type && BTF_INFO_KIND(type->info) == BTF_KIND_DECL_TAG &&
		    type->type == map->btf_value_type_id &&
		    btf_decl_tag(type)->component_idx == -1 &&
		    !strcmp(btf_name_by_offset(map->btf, type->name_off),
			    "ebpfos.component.pointer_result"))
			return true;
	}
	return false;
}

static int ebpfos_executor_root_pointer_result(struct bpf_prog *prog,
					    struct bpf_map **result)
{
	const struct btf_type *pointee;
	struct bpf_map *declared = NULL, *legacy = NULL;
	bool ambiguous = false;
	u32 id, index;

	*result = NULL;
	if (prog->type != BPF_PROG_TYPE_TRACING)
		return 0;
	pointee = btf_type_resolve_ptr(prog->aux->attach_btf,
				       prog->aux->attach_func_proto->type, &id);
	if (!pointee)
		return 0;
	if (!btf_type_is_struct(pointee))
		return -EOPNOTSUPP;
	for (index = 0; index < prog->aux->used_map_cnt; index++) {
		struct bpf_map *map = prog->aux->used_maps[index];
		const struct btf_field *field;
		bool tagged = ebpfos_pointer_result_tag(map);

		if (map->map_type != BPF_MAP_TYPE_PERCPU_ARRAY ||
		    map->max_entries != 1 || map->value_size != sizeof(void *) ||
		    IS_ERR_OR_NULL(map->record) || map->record->cnt != 1) {
			if (tagged)
				return -EPROTOTYPE;
			continue;
		}
		field = &map->record->fields[0];
		/* The native caller receives exactly the type stock verification
		 * checked at each kptr store. Never reinterpret another map field.
		 */
		if (field->offset ||
		    (field->type != BPF_KPTR_UNREF && field->type != BPF_KPTR_REF) ||
		    (field->type == BPF_KPTR_REF &&
		     (!btf_is_kernel(field->kptr.btf) || !field->kptr.dtor)) ||
		    !btf_types_are_same(prog->aux->attach_btf, id,
				field->kptr.btf, field->kptr.btf_id)) {
			if (tagged)
				return -EPROTOTYPE;
			continue;
		}
		/* Ordinary provider maps can have the same native kptr type.
		 * The compiler's declaration selects the return channel, never
		 * its authority: the stock field/type checks above still apply.
		 * Preserve unambiguous legacy producers without guessing a map.
		 */
		if (tagged) {
			if (declared)
				return -EPROTOTYPE;
			declared = map;
		} else {
			ambiguous |= legacy != NULL;
			legacy = map;
		}
	}
	*result = declared ?: (ambiguous ? NULL : legacy);
	return *result ? 0 : -EPROTOTYPE;
}

static int ebpfos_executor_root_role_fill(
	struct ebpfos_executor_root_role *role,
	const struct ebpfos_executor_root_role_request *request)
{
	struct ebpfos_binding *binding;
	struct ebpfos_admission *grant;
	int error;

	if (!role || !request || request->admission_fd < 0)
		return -EINVAL;
	grant = ebpfos_admission_get_from_fd(request->admission_fd);
	if (IS_ERR(grant))
		return PTR_ERR(grant);
	binding = ebpfos_admission_binding_get(grant);
	if (!binding) {
		ebpfos_admission_put(grant);
		return -EUCLEAN;
	}
	error = ebpfos_component_typed_export(binding->prog, &role->typed_entry);
	if (!error && role->typed_entry)
		error = ebpfos_component_typed_null_args(binding->prog,
						       role->typed_entry, &role->null_args);
	if (!error && !role->typed_entry)
		error = ebpfos_executor_root_pointer_result(binding->prog, &role->pointer_result);
	if (!error && !role->typed_entry)
		error = ebpfos_component_context_export(binding->prog, &role->typed_entry,
						&role->context_image);
	if (error) {
		ebpfos_binding_put(binding);
		ebpfos_admission_put(grant);
		return error;
	}
	role->snapshot.role_type = request->role_type;
	role->snapshot.prog_id = binding->prog_id;
	role->snapshot.map_id = binding->map_id;
	/* Only the verifier-checked context ABI is callable through this entry.
	 * Other root roles retain their existing execution mechanism. No address
	 * supplied by userspace is accepted as executable code.
	 */
	if (binding->prog->jited && !binding->prog->sleepable &&
	    binding->prog->aux->ebpfos_component &&
	    (binding->prog->type == BPF_PROG_TYPE_RAW_TRACEPOINT ||
	     (binding->prog->type == BPF_PROG_TYPE_TRACING &&
	      binding->prog->expected_attach_type == BPF_TRACE_FENTRY))) {
		role->entry = binding->prog->bpf_func;
		/* Checked context roots need their result scope even without a
		 * service call. A native global export returns directly; retain
		 * its scope only when the loaded call graph can reach a service.
		 */
		role->needs_steps = role->context_image ||
			ebpfos_step_program_needs_scope(binding->prog);
	}
	role->binding = binding;
	role->grant = grant;
	return 0;
}

static void ebpfos_executor_root_sort(
	struct ebpfos_executor_root_bundle *bundle)
{
	u32 index;

	for (index = 1; index < bundle->role_count; index++) {
		struct ebpfos_executor_root_role role = bundle->roles[index];
		u32 position = index;

		while (position && bundle->roles[position - 1].snapshot.role_type >
				   role.snapshot.role_type) {
			bundle->roles[position] = bundle->roles[position - 1];
			position--;
		}
		bundle->roles[position] = role;
	}
}

static int ebpfos_executor_root_prepare(
	const struct ebpfos_executor_root_publish_request *request,
	struct ebpfos_executor_root_bundle **result)
{
	struct ebpfos_executor_root_bundle *bundle;
	u32 role;

	bundle = kzalloc(struct_size(bundle, roles, request->role_count),
			 GFP_KERNEL);
	if (!bundle)
		return -ENOMEM;
	INIT_WORK(&bundle->retire_work, ebpfos_executor_root_retire_work);
	bundle->object_id = request->object_id;
	bundle->epoch = request->target_epoch;
	bundle->role_count = request->role_count;
	for (role = 0; role < bundle->role_count; role++) {
		int error = ebpfos_executor_root_role_fill(&bundle->roles[role],
							  &request->roles[role]);

		if (error) {
			ebpfos_executor_root_bundle_release(bundle);
			return error;
		}
	}
	ebpfos_executor_root_sort(bundle);
	for (role = 1; role < bundle->role_count; role++)
		if (bundle->roles[role - 1].snapshot.role_type ==
		    bundle->roles[role].snapshot.role_type) {
			ebpfos_executor_root_bundle_release(bundle);
			return -EUCLEAN;
		}
	*result = bundle;
	return 0;
}

static int ebpfos_executor_root_source_validate(
	const struct ebpfos_executor_root_publish_request *request,
	const struct ebpfos_executor_root_bundle *source,
	const struct ebpfos_executor_root_bundle *target)
{
	if (target->object_id != request->object_id ||
	    target->epoch != request->target_epoch ||
	    target->role_count != request->role_count)
		return -ESTALE;
	if (!source)
		return request->expected_epoch ? -ESTALE : 0;
	if (source->object_id != request->object_id ||
	    source->epoch != request->expected_epoch)
		return -ESTALE;
	return 0;
}

static bool ebpfos_executor_root_active_matches_locked(
	struct ebpfos_executor_root_slot *slot,
	const struct ebpfos_executor_root_bundle *expected, u64 expected_epoch)
{
	struct ebpfos_executor_root_bundle *active;

	lockdep_assert_held(&slot->lock);
	active = rcu_dereference_protected(slot->active,
					   lockdep_is_held(&slot->lock));
	return active == expected &&
	       ((!active && !expected_epoch) ||
		(active && active->epoch == expected_epoch));
}

static bool ebpfos_executor_root_retains_binding(
	const struct ebpfos_executor_root_bundle *target,
	const struct ebpfos_binding *binding)
{
	u32 role;

	for (role = 0; target && role < target->role_count; role++)
		if (target->roles[role].binding == binding)
			return true;
	return false;
}

static bool ebpfos_executor_root_binding_seen(
	const struct ebpfos_executor_root_bundle *source, u32 role)
{
	u32 previous;

	for (previous = 0; previous < role; previous++)
		if (source->roles[previous].binding ==
		    source->roles[role].binding)
			return true;
	return false;
}

static bool ebpfos_executor_root_can_retire(
	const struct ebpfos_executor_root_bundle *source,
	const struct ebpfos_executor_root_bundle *target)
{
	u32 role;

	for (role = 0; source && role < source->role_count; role++)
		if (!ebpfos_executor_root_binding_seen(source, role) &&
		    !ebpfos_executor_root_retains_binding(
				target, source->roles[role].binding) &&
		    ebpfos_binding_is_retired(source->roles[role].binding))
			return false;
	return true;
}

static void ebpfos_executor_root_retire_removed(
	const struct ebpfos_executor_root_bundle *source,
	const struct ebpfos_executor_root_bundle *target)
{
	u32 role;

	for (role = 0; source && role < source->role_count; role++)
		if (!ebpfos_executor_root_binding_seen(source, role) &&
		    !ebpfos_executor_root_retains_binding(
				target, source->roles[role].binding))
			ebpfos_binding_retire(source->roles[role].binding,
					      target->epoch);
}

static int ebpfos_executor_root_commit(
	struct ebpfos_executor_root_slot *slot,
	const struct ebpfos_executor_root_publish_request *request,
	struct ebpfos_executor_root_bundle *source,
	struct ebpfos_executor_root_bundle *target,
	struct ebpfos_admission **grants)
{
	int error;

	spin_lock(&slot->lock);
	if (!ebpfos_executor_root_active_matches_locked(
			slot, source, request->expected_epoch)) {
		error = -ESTALE;
		goto out_unlock;
	}
	if (!ebpfos_executor_root_can_retire(source, target)) {
		error = -ESTALE;
		goto out_unlock;
	}
	error = ebpfos_admission_consume_bundle_locked(grants,
						       target->role_count);
	if (error)
		goto out_unlock;
	/* Unique linearization point: one immutable finite-role bundle pointer. */
	rcu_assign_pointer(slot->active, target);
	/*
	 * While still holding the root lock, atomically close each removed old
	 * binding.  The pre-close word is the exact active/entry observation at
	 * publication: enter-before-close drains normally, close-before-enter
	 * rejects without advancing the entry sequence.  Retained bindings stay
	 * open.  No rollback reaches either the pointer store or these closes.
	 */
	ebpfos_executor_root_retire_removed(source, target);
	error = 0;
out_unlock:
	spin_unlock(&slot->lock);
	return error;
}

__bpf_kfunc_start_defs();

static int ebpfos_executor_root_publish_common(
	const struct ebpfos_executor_root_publish_request *request)
{
	struct ebpfos_executor_root_bundle *source;
	struct ebpfos_executor_root_bundle *target = NULL;
	struct ebpfos_executor_root_slot *slot;
	struct ebpfos_admission **grants = NULL;
	bool staged = false;
	u32 role;
	int error;

	if (!request->object_id || !request->role_count ||
	    request->role_count > EBPFOS_EXECUTOR_ROOT_MAX_ROLES ||
	    request->target_epoch <= request->expected_epoch)
		return -EINVAL;
	error = ebpfos_executor_root_prepare(request, &target);
	if (error)
		return error;
	grants = kcalloc(target->role_count, sizeof(*grants), GFP_KERNEL);
	if (!grants) {
		error = -ENOMEM;
		goto out;
	}
	for (role = 0; role < target->role_count; role++)
		grants[role] = target->roles[role].grant;

	ebpfos_admission_gate_lock();
	slot = ebpfos_executor_root_slot_get(request->object_id);
	if (IS_ERR(slot)) {
		error = PTR_ERR(slot);
		goto out_unlock_gate;
	}
	spin_lock(&slot->lock);
	source = rcu_dereference_protected(slot->active,
					    lockdep_is_held(&slot->lock));
	spin_unlock(&slot->lock);
	error = ebpfos_executor_root_source_validate(request, source, target);
	if (error)
		goto out_unlock_gate;
	error = ebpfos_admission_stage_bundle_locked(grants, target->role_count);
	if (error)
		goto out_unlock_gate;
	staged = true;
	error = ebpfos_executor_root_commit(slot, request,
					    source, target, grants);
	if (error)
		goto out_unlock_gate;
	for (role = 0; role < target->role_count; role++)
		target->roles[role].grant = NULL;
	ebpfos_admission_gate_unlock();
	for (role = 0; role < target->role_count; role++)
		ebpfos_admission_put(grants[role]);
	if (source)
		call_rcu(&source->rcu, ebpfos_executor_root_retire_rcu);
	kfree(grants);
	return 0;

out_unlock_gate:
	if (staged)
		ebpfos_admission_burn_set_locked(grants, target->role_count);
	ebpfos_admission_gate_unlock();
out:
	kfree(grants);
	ebpfos_executor_root_bundle_release(target);
	return error;
}

long ebpfos_executor_root_publish_ioctl(void __user *argp)
{
	struct ebpfos_ioc_root_publish *request;
	long error;

	static_assert(offsetof(struct ebpfos_ioc_root_publish, roles) ==
		      sizeof(struct ebpfos_executor_root_publish_request));
	static_assert(sizeof(struct ebpfos_ioc_root_role) ==
		      sizeof(struct ebpfos_executor_root_role_request));

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	request = memdup_user(argp, sizeof(*request));
	if (IS_ERR(request))
		return PTR_ERR(request);
	error = ebpfos_executor_root_publish_common((const void *)request);
	kfree(request);
	return error;
}

static int ebpfos_executor_call_size(struct ebpfos_executor_call *call,
				     u32 call_data__sz)
{
	size_t expected_size;

	if (!call || call_data__sz < sizeof(*call) ||
	    call->version != EBPFOS_EXECUTOR_ROOT_ABI_VERSION ||
	    !call->object_id ||
	    !call->context_size ||
	    call->context_size > EBPFOS_EXECUTOR_ROOT_MAX_CONTEXT_SIZE ||
	    check_add_overflow(sizeof(*call), (size_t)call->context_size,
			       &expected_size) || expected_size != call_data__sz)
		return -EINVAL;
	return 0;
}

static struct ebpfos_binding *ebpfos_executor_root_role_get(
	struct ebpfos_executor_root_slot *slot, u64 role_type, u64 *epoch,
	struct ebpfos_executor_root_role_snapshot *snapshot)
{
	struct ebpfos_binding *binding;

	rcu_read_lock();
	binding = ebpfos_executor_root_role_get_rcu(slot, role_type, epoch,
						      snapshot, true);
	rcu_read_unlock();
	return binding;
}

int ebpfos_executor_root_lease_begin(u64 object_id, u64 role_type,
	struct ebpfos_executor_root_lease *lease,
	struct ebpfos_executor_root_role_snapshot *snapshot)
{
	struct ebpfos_executor_root_slot *slot;

	if (!object_id || !lease || !snapshot)
		return -EINVAL;
	memset(lease, 0, sizeof(*lease));
	slot = xa_load(&ebpfos_executor_roots, object_id);
	if (!slot)
		return -ENOENT;
	ebpfos_component_gate_enter(&slot->gate);
	lease->binding = ebpfos_executor_root_role_get(
		slot, role_type, &lease->epoch, snapshot);
	if (!lease->binding) {
		ebpfos_component_gate_exit(&slot->gate);
		return -ENOENT;
	}
	lease->slot = slot;
	return 0;
}

struct ebpfos_executor_root_slot *ebpfos_executor_root_lookup(u64 object_id)
{
	return object_id ? xa_load(&ebpfos_executor_roots, object_id) : NULL;
}

int ebpfos_executor_root_lease_try_begin_slot(
	struct ebpfos_executor_root_slot *slot, u64 role_type,
	struct ebpfos_executor_root_lease *lease,
	struct ebpfos_executor_root_role_snapshot *snapshot)
{
	return ebpfos_executor_root_lease_try_begin_slot_inner(
		slot, role_type, lease, snapshot, false);
}

int ebpfos_executor_root_lease_try_begin_slot_rcu(
	struct ebpfos_executor_root_slot *slot, u64 role_type,
	struct ebpfos_executor_root_lease *lease,
	struct ebpfos_executor_root_role_snapshot *snapshot)
{
	return ebpfos_executor_root_lease_try_begin_slot_inner(
		slot, role_type, lease, snapshot, true);
}

int ebpfos_executor_root_lease_try_begin(u64 object_id, u64 role_type,
	struct ebpfos_executor_root_lease *lease,
	struct ebpfos_executor_root_role_snapshot *snapshot)
{
	if (!object_id)
		return -EINVAL;
	return ebpfos_executor_root_lease_try_begin_slot(
		ebpfos_executor_root_lookup(object_id), role_type, lease, snapshot);
}

void ebpfos_executor_root_lease_end(struct ebpfos_executor_root_lease *lease)
{
	if (!lease || !lease->slot)
		return;
	/*
	 * Non-sleepable leases use owned or caller-held RCU through invocation.
	 * A borrowed lease never releases its caller's hold.
	 * The bundle's owned reference is released only after that grace period.
	 * Sleepable leases drop RCU at acquisition and must own a reference.
	 */
	if (!lease->rcu_held) {
		ebpfos_binding_put(lease->binding);
		ebpfos_component_gate_exit(&lease->slot->gate);
	} else if (!lease->rcu_borrowed) {
		rcu_read_unlock();
	}
	lease->slot = NULL;
}

int ebpfos_executor_root_quiesce(u64 object_id, u64 expected_epoch)
{
	struct ebpfos_executor_root_slot *slot;
	struct ebpfos_executor_root_bundle *active;
	int error;

	if (!object_id)
		return -EINVAL;
	if (!expected_epoch) {
		/* A first publish can be gated before the root has a bundle. */
		ebpfos_admission_gate_lock();
		slot = ebpfos_executor_root_slot_get(object_id);
		ebpfos_admission_gate_unlock();
		if (IS_ERR(slot))
			return PTR_ERR(slot);
	} else {
		slot = xa_load(&ebpfos_executor_roots, object_id);
	}
	if (!slot)
		return -ENOENT;
	spin_lock(&slot->lock);
	active = rcu_dereference_protected(slot->active,
					   lockdep_is_held(&slot->lock));
	error = (!active && !expected_epoch) ||
		(active && active->epoch == expected_epoch) ? 0 : -ESTALE;
	spin_unlock(&slot->lock);
	if (error)
		return error;
	error = ebpfos_component_gate_engage(&slot->gate);
	if (error)
		return error;
	/*
	 * Counted sleepable leases are drained above. An RCU reader that saw
	 * the open gate before closure must finish before this grace period
	 * returns; readers observing closure never access the provider.
	 * The control session cannot resume its gate until quiesce returns.
	 */
	synchronize_rcu();
	spin_lock(&slot->lock);
	active = rcu_dereference_protected(slot->active,
					   lockdep_is_held(&slot->lock));
	error = (!active && !expected_epoch) ||
		(active && active->epoch == expected_epoch) ? 0 : -ESTALE;
	spin_unlock(&slot->lock);
	if (error)
		ebpfos_component_gate_abort(&slot->gate);
	return error;
}

void ebpfos_executor_root_resume(u64 object_id)
{
	struct ebpfos_executor_root_slot *slot;

	slot = xa_load(&ebpfos_executor_roots, object_id);
	if (slot)
		ebpfos_component_gate_abort(&slot->gate);
}

static int ebpfos_executor_frame_validate(
	const struct ebpfos_executor_call *call)
{
	const struct ebpfos_component_call_frame *frame =
		(const void *)call->context;

	if (call->context_size != sizeof(*frame) ||
	    frame->version != EBPFOS_COMPONENT_CALL_ABI_VERSION ||
	    frame->method_id != call->method_id ||
	    frame->object_id != call->object_id ||
	    frame->input_size > sizeof(frame->input) ||
	    frame->output_capacity > sizeof(frame->output))
		return -EPROTO;
	return 0;
}

static bool ebpfos_executor_provider_supported(const struct bpf_prog *provider)
{
	return provider && provider->aux && provider->aux->ebpfos_component &&
	       provider->type == BPF_PROG_TYPE_SYSCALL && provider->sleepable;
}

static int ebpfos_executor_provider_run(struct ebpfos_binding *binding,
		struct bpf_prog *provider, void *context, u32 *status)
{
	struct bpf_tramp_run_ctx run_ctx = {};
	u64 start;
	int error;

	if (!binding || !ebpfos_executor_provider_supported(provider) ||
	    !context || !status)
		return -EOPNOTSUPP;
	start = __bpf_prog_enter_sleepable_recur(provider, &run_ctx);
	if (!start) {
		__bpf_prog_exit_sleepable_recur(provider, 0, &run_ctx);
		return -EBUSY;
	}
	error = ebpfos_binding_invocation_enter(binding);
	if (error) {
		__bpf_prog_exit_sleepable_recur(provider, 0, &run_ctx);
		return error;
	}
	*status = bpf_prog_run(provider, context);
	__bpf_prog_exit_sleepable_recur(provider, 0, &run_ctx);
	ebpfos_binding_invocation_exit(binding);
	return 0;
}

noinline int bpf_ebpfos_executor_root_call_impl(
	void *call_data, u32 call_data__sz, struct bpf_prog_aux *aux)
{
	struct ebpfos_executor_call *call = call_data;
	struct ebpfos_executor_root_role_snapshot role = {};
	struct ebpfos_executor_root_lease lease = {};
	const struct ebpfos_component_desc_v1 *descriptor;
	struct ebpfos_binding *binding;
	struct bpf_prog *provider;
	u64 epoch = 0;
	u32 status;
	bool retried = false;
	int error;

	error = ebpfos_executor_call_size(call, call_data__sz);
	if (error)
		return error;
	call->observed_epoch = 0;
	call->provider_prog_id = 0;
	call->provider_status = 0;
retry_lookup:
	error = ebpfos_executor_root_lease_begin(call->object_id,
						call->role_type, &lease, &role);
	if (error)
		return error;
	binding = lease.binding;
	epoch = lease.epoch;
	descriptor = ebpfos_binding_descriptor(binding);
	provider = ebpfos_binding_prog(binding);
	if (!descriptor || !ebpfos_executor_provider_supported(provider)) {
		error = -EOPNOTSUPP;
		goto out_put;
	}
	if (provider->aux == aux) {
		error = -ELOOP;
		goto out_put;
	}
	if ((call->flags & EBPFOS_EXECUTOR_CALL_F_EXPECT_EPOCH) &&
	    call->expected_epoch != epoch) {
		error = -ESTALE;
		goto out_put;
	}
	if (call->context_size != le32_to_cpu(descriptor->context_size)) {
		error = -EMSGSIZE;
		goto out_put;
	}
	error = ebpfos_executor_frame_validate(call);
	if (error)
		goto out_put;
	/*
	 * The binding reference is the in-flight epoch pin.  Publication may
	 * replace and RCU-retire the old immutable bundle concurrently, but its
	 * program remains alive until this exact invocation has returned.
	 */
	error = ebpfos_executor_provider_run(binding, provider, call->context,
					     &status);
	if (error) {
		if (error == -ESHUTDOWN) {
			ebpfos_executor_root_lease_end(&lease);
			if (call->flags & EBPFOS_EXECUTOR_CALL_F_EXPECT_EPOCH)
				return -ESTALE;
			if (!retried) {
				retried = true;
				goto retry_lookup;
			}
			error = -EAGAIN;
			binding = NULL;
		}
		goto out_put;
	}
	call->observed_epoch = epoch;
	call->provider_prog_id = role.prog_id;
	call->provider_status = status;
	error = 0;
out_put:
	ebpfos_executor_root_lease_end(&lease);
	return error;
}

__bpf_kfunc int bpf_ebpfos_executor_root_call(
	void *call_data, u32 call_data__sz, struct bpf_prog_aux *aux)
{
	return bpf_ebpfos_executor_root_call_impl(call_data, call_data__sz, aux);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(ebpfos_executor_root_kfunc_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_executor_root_call,
		     KF_IMPLICIT_ARGS | KF_SLEEPABLE)
BTF_KFUNCS_END(ebpfos_executor_root_kfunc_ids)

static const struct btf_kfunc_id_set ebpfos_executor_root_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &ebpfos_executor_root_kfunc_ids,
};

static int __init ebpfos_executor_root_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL,
					 &ebpfos_executor_root_kfunc_set);
}
late_initcall(ebpfos_executor_root_init);
