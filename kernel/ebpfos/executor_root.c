// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/ebpfos.h>
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
#include "component_graph.h"
#if IS_ENABLED(CONFIG_EBPFOS_KUNIT_TEST)
#include <kunit/test.h>
#endif

struct ebpfos_executor_root_role {
	struct ebpfos_executor_root_role_snapshot snapshot;
	struct ebpfos_binding *binding;
	struct ebpfos_admission *grant;
};

struct ebpfos_executor_root_bundle {
	struct rcu_head rcu;
	struct work_struct retire_work;
	u64 object_id;
	u64 epoch;
	u32 role_count;
	struct ebpfos_executor_root_role roles[];
};

struct ebpfos_executor_root_slot {
	spinlock_t lock;
	struct ebpfos_component_gate gate;
	struct ebpfos_executor_root_bundle __rcu *active;
};

/* Slots have stable lifetime; readers find them under RCU and pin bindings. */
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

static int ebpfos_executor_root_request_size(
	const struct ebpfos_executor_root_publish_request *request,
	u32 request_size, size_t *expected_size)
{
	size_t capacity_size;
	size_t roles_size;

	if (!request || !expected_size ||
	    request_size < sizeof(*request) ||
	    request->version != EBPFOS_EXECUTOR_ROOT_ABI_VERSION ||
	    request->flags & ~EBPFOS_EXECUTOR_ROOT_F_TEST_FAIL_AFTER_STAGE ||
	    (request->flags && !IS_ENABLED(CONFIG_EBPFOS_KUNIT_TEST)) ||
	    request->reserved || !request->object_id ||
	    !request->role_count ||
	    request->role_count > EBPFOS_EXECUTOR_ROOT_MAX_ROLES ||
	    request->expected_epoch == U64_MAX ||
	    request->target_epoch != request->expected_epoch + 1)
		return -EINVAL;
	if (check_mul_overflow((size_t)request->role_count,
			       sizeof(request->roles[0]), &roles_size) ||
	    check_add_overflow(sizeof(*request), roles_size, expected_size) ||
	    request_size < *expected_size)
		return -E2BIG;
	capacity_size = request_size - sizeof(*request);
	if (capacity_size % sizeof(request->roles[0]) ||
	    capacity_size / sizeof(request->roles[0]) >
		EBPFOS_EXECUTOR_ROOT_MAX_ROLES ||
	    memchr_inv((const u8 *)request + *expected_size, 0,
		       request_size - *expected_size))
		return -E2BIG;
	return 0;
}

static int ebpfos_executor_root_role_fill(
	struct ebpfos_executor_root_role *role,
	const struct ebpfos_executor_root_role_request *request)
{
	const struct ebpfos_component_desc_v1 *descriptor;
	struct ebpfos_binding *binding;
	struct ebpfos_admission *grant;
	bool component;

	if (!role || !request || request->admission_fd < 0 ||
	    request->reserved || !request->role_type)
		return -EINVAL;
	grant = ebpfos_admission_get_from_fd(request->admission_fd);
	if (IS_ERR(grant))
		return PTR_ERR(grant);
	binding = ebpfos_admission_binding_get(grant);
	if (!binding) {
		ebpfos_admission_put(grant);
		return -EUCLEAN;
	}
	descriptor = ebpfos_binding_descriptor(binding);
	component = descriptor &&
		ebpfos_binding_prog(binding) &&
		ebpfos_binding_prog(binding)->aux->ebpfos_component;
	if (ebpfos_binding_kind(binding) != EBPFOS_ADMITTED_BINDING_BPF ||
	    !component) {
		ebpfos_binding_put(binding);
		ebpfos_admission_put(grant);
		return -EOPNOTSUPP;
	}
	role->snapshot.role_type = request->role_type;
	role->snapshot.prog_id = binding->prog_id;
	role->snapshot.map_id = binding->map_id;
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
	const void *request_data, u32 request_data__sz)
{
	const struct ebpfos_executor_root_publish_request *request = request_data;
	struct ebpfos_executor_root_bundle *source;
	struct ebpfos_executor_root_bundle *target = NULL;
	struct ebpfos_executor_root_slot *slot;
	struct ebpfos_admission **grants = NULL;
	size_t expected_size;
	bool staged = false;
	u32 role;
	int error;

	error = ebpfos_executor_root_request_size(request, request_data__sz,
						  &expected_size);
	if (error)
		return error;
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
	if (request->flags & EBPFOS_EXECUTOR_ROOT_F_TEST_FAIL_AFTER_STAGE) {
		error = -ECANCELED;
		goto out_unlock_gate;
	}
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
	size_t request_size;
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
	if (request->role_count > EBPFOS_ROOT_MAX_ROLES) {
		error = -EINVAL;
		goto out;
	}
	request_size = offsetof(struct ebpfos_ioc_root_publish, roles) +
		request->role_count * sizeof(request->roles[0]);
	error = ebpfos_executor_root_publish_common(
		(const void *)request, request_size);
out:
	kfree(request);
	return error;
}

static int ebpfos_executor_call_size(struct ebpfos_executor_call *call,
				     u32 call_data__sz)
{
	size_t expected_size;

	if (!call || call_data__sz < sizeof(*call) ||
	    call->version != EBPFOS_EXECUTOR_ROOT_ABI_VERSION ||
	    call->flags & ~EBPFOS_EXECUTOR_CALL_F_EXPECT_EPOCH ||
	    !call->method_id || !call->object_id || !call->role_type ||
	    !call->context_size ||
	    call->context_size > EBPFOS_EXECUTOR_ROOT_MAX_CONTEXT_SIZE ||
	    (!(call->flags & EBPFOS_EXECUTOR_CALL_F_EXPECT_EPOCH) &&
	     call->expected_epoch) ||
	    check_add_overflow(sizeof(*call), (size_t)call->context_size,
			       &expected_size) || expected_size != call_data__sz)
		return -EINVAL;
	return 0;
}

static struct ebpfos_binding *ebpfos_executor_root_role_get_rcu(
	struct ebpfos_executor_root_slot *slot, u64 role_type, u64 *epoch,
	struct ebpfos_executor_root_role_snapshot *snapshot)
{
	struct ebpfos_executor_root_bundle *bundle;
	struct ebpfos_binding *binding = NULL;
	u32 role;

	bundle = rcu_dereference(slot->active);
	if (!bundle)
		return NULL;
	for (role = 0; role < bundle->role_count; role++) {
		if (bundle->roles[role].snapshot.role_type < role_type)
			continue;
		if (bundle->roles[role].snapshot.role_type != role_type)
			break;
		binding = ebpfos_binding_get(bundle->roles[role].binding);
		if (binding) {
			*epoch = bundle->epoch;
			*snapshot = bundle->roles[role].snapshot;
		}
		break;
	}
	return binding;
}

static struct ebpfos_binding *ebpfos_executor_root_role_get(
	struct ebpfos_executor_root_slot *slot, u64 role_type, u64 *epoch,
	struct ebpfos_executor_root_role_snapshot *snapshot)
{
	struct ebpfos_binding *binding;

	rcu_read_lock();
	binding = ebpfos_executor_root_role_get_rcu(slot, role_type, epoch,
						      snapshot);
	rcu_read_unlock();
	return binding;
}

int ebpfos_executor_root_lease_begin(u64 object_id, u64 role_type,
	struct ebpfos_executor_root_lease *lease,
	struct ebpfos_executor_root_role_snapshot *snapshot)
{
	struct ebpfos_executor_root_slot *slot;

	if (!object_id || !role_type || !lease || !snapshot)
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

int ebpfos_executor_root_lease_try_begin(u64 object_id, u64 role_type,
	struct ebpfos_executor_root_lease *lease,
	struct ebpfos_executor_root_role_snapshot *snapshot)
{
	struct ebpfos_executor_root_slot *slot;

	if (!object_id || !role_type || !lease || !snapshot)
		return -EINVAL;
	memset(lease, 0, sizeof(*lease));
	slot = xa_load(&ebpfos_executor_roots, object_id);
	if (!slot)
		return -ENOENT;
	if (!ebpfos_component_gate_try_enter(&slot->gate))
		return -EAGAIN;
	rcu_read_lock();
	lease->binding = ebpfos_executor_root_role_get_rcu(
		slot, role_type, &lease->epoch, snapshot);
	if (!lease->binding) {
		rcu_read_unlock();
		ebpfos_component_gate_exit(&slot->gate);
		return -ENOENT;
	}
	lease->slot = slot;
	lease->rcu_held = true;
	return 0;
}

void ebpfos_executor_root_lease_end(struct ebpfos_executor_root_lease *lease)
{
	if (!lease || !lease->slot)
		return;
	ebpfos_binding_put(lease->binding);
	ebpfos_component_gate_exit(&lease->slot->gate);
	if (lease->rcu_held)
		rcu_read_unlock();
	memset(lease, 0, sizeof(*lease));
}

int ebpfos_executor_root_quiesce(u64 object_id, u64 expected_epoch)
{
	struct ebpfos_executor_root_slot *slot;
	struct ebpfos_executor_root_bundle *active;
	int error;

	if (!object_id)
		return -EINVAL;
	slot = xa_load(&ebpfos_executor_roots, object_id);
	if (!slot)
		return -ENOENT;
	spin_lock(&slot->lock);
	active = rcu_dereference_protected(slot->active,
					   lockdep_is_held(&slot->lock));
	error = !active || active->epoch != expected_epoch ? -ESTALE : 0;
	spin_unlock(&slot->lock);
	if (error)
		return error;
	error = ebpfos_component_gate_engage(&slot->gate);
	if (error)
		return error;
	spin_lock(&slot->lock);
	active = rcu_dereference_protected(slot->active,
					   lockdep_is_held(&slot->lock));
	error = !active || active->epoch != expected_epoch ? -ESTALE : 0;
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

#if IS_ENABLED(CONFIG_EBPFOS_KUNIT_TEST)
static void ebpfos_executor_root_compare_test(struct kunit *test)
{
	struct ebpfos_executor_root_slot slot = {};
	struct ebpfos_executor_root_bundle *source;
	struct ebpfos_executor_root_bundle *target;
	struct ebpfos_executor_root_bundle *acquired;
	struct ebpfos_executor_root_publish_request request = {
		.version = EBPFOS_EXECUTOR_ROOT_ABI_VERSION,
		.object_id = 7, .expected_epoch = 3, .target_epoch = 4,
		.role_count = 1,
	};

	source = kunit_kzalloc(test, struct_size(source, roles, 1), GFP_KERNEL);
	target = kunit_kzalloc(test, struct_size(target, roles, 1), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, source);
	KUNIT_ASSERT_NOT_NULL(test, target);
	spin_lock_init(&slot.lock);
	source->object_id = target->object_id = request.object_id;
	source->epoch = request.expected_epoch;
	target->epoch = request.target_epoch;
	source->role_count = target->role_count = 1;
	source->roles[0].snapshot.role_type = 9;
	target->roles[0].snapshot.role_type = 9;
	source->roles[0].binding = (void *)0x10UL;

	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_source_validate(
		&request, source, target), 0);
	request.expected_epoch--;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_source_validate(
		&request, source, target), -ESTALE);
	request.expected_epoch++;
	target->roles[0].snapshot.role_type++;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_source_validate(
		&request, source, target), 0);
	target->roles[0].snapshot.role_type--;
	target->role_count = 2;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_source_validate(
		&request, source, target), -ESTALE);
	target->role_count = 1;

	rcu_assign_pointer(slot.active, source);
	spin_lock(&slot.lock);
	KUNIT_EXPECT_TRUE(test, ebpfos_executor_root_active_matches_locked(
		&slot, source, request.expected_epoch));
	KUNIT_EXPECT_FALSE(test, ebpfos_executor_root_active_matches_locked(
		&slot, target, request.expected_epoch));
	KUNIT_EXPECT_FALSE(test, ebpfos_executor_root_active_matches_locked(
		&slot, source, request.expected_epoch - 1));
	KUNIT_EXPECT_PTR_EQ(test, rcu_dereference_protected(slot.active,
						lockdep_is_held(&slot.lock)),
			    source);
	spin_unlock(&slot.lock);
	/*
	 * A reader that acquired the old immutable bundle remains wholly old;
	 * readers acquiring after the one pointer publication see wholly new.
	 */
	rcu_read_lock();
	acquired = rcu_dereference(slot.active);
	KUNIT_EXPECT_PTR_EQ(test, acquired, source);
	spin_lock(&slot.lock);
	rcu_assign_pointer(slot.active, target);
	spin_unlock(&slot.lock);
	KUNIT_EXPECT_PTR_EQ(test, acquired, source);
	KUNIT_EXPECT_PTR_EQ(test, rcu_dereference(slot.active), target);
	rcu_read_unlock();
}

static void ebpfos_executor_root_retained_binding_test(struct kunit *test)
{
	struct ebpfos_executor_root_bundle *source;
	struct ebpfos_executor_root_bundle *target;
	struct ebpfos_executor_root_bundle *already_closed;
	struct ebpfos_binding retained = {};
	struct ebpfos_binding removed = {};
	struct ebpfos_binding rollback = {};

	source = kunit_kzalloc(test, struct_size(source, roles, 3), GFP_KERNEL);
	target = kunit_kzalloc(test, struct_size(target, roles, 1), GFP_KERNEL);
	already_closed = kunit_kzalloc(
		test, struct_size(already_closed, roles, 1), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, source);
	KUNIT_ASSERT_NOT_NULL(test, target);
	KUNIT_ASSERT_NOT_NULL(test, already_closed);
	source->role_count = 3;
	target->role_count = 1;
	target->epoch = 9;
	source->roles[0].binding = &retained;
	source->roles[1].binding = &removed;
	source->roles[2].binding = &removed;
	target->roles[0].binding = &retained;
	KUNIT_ASSERT_EQ(test, ebpfos_binding_invocation_enter(&removed), 0);
	KUNIT_EXPECT_TRUE(test,
		ebpfos_executor_root_retains_binding(target, &retained));
	KUNIT_EXPECT_FALSE(test,
		ebpfos_executor_root_retains_binding(target, &removed));
	KUNIT_EXPECT_TRUE(test, ebpfos_executor_root_can_retire(source, target));
	ebpfos_executor_root_retire_removed(source, target);
	KUNIT_EXPECT_FALSE(test, ebpfos_binding_is_retired(&retained));
	KUNIT_EXPECT_TRUE(test, ebpfos_binding_is_retired(&removed));
	KUNIT_EXPECT_EQ(test, READ_ONCE(removed.retired_epoch), 9ULL);
	KUNIT_EXPECT_EQ(test, removed.retirement_snapshot, (1ULL << 16) | 1);
	KUNIT_EXPECT_EQ(test, ebpfos_binding_invocation_enter(&removed),
		-ESHUTDOWN);
	ebpfos_binding_invocation_exit(&removed);
	KUNIT_EXPECT_EQ(test, ebpfos_binding_active_invocations(&removed), 0U);

	already_closed->role_count = 1;
	already_closed->roles[0].binding = &removed;
	KUNIT_EXPECT_FALSE(test,
		ebpfos_executor_root_can_retire(already_closed, NULL));
	/* A precommit rollback leaves its never-published candidate open. */
	KUNIT_EXPECT_FALSE(test, ebpfos_binding_is_retired(&rollback));
	KUNIT_EXPECT_EQ(test, READ_ONCE(rollback.retired_epoch), 0ULL);
}

static void ebpfos_executor_root_request_test(struct kunit *test)
{
	struct ebpfos_executor_root_publish_request *request;
	size_t request_size = sizeof(*request) + 2 * sizeof(request->roles[0]);
	size_t live_size = sizeof(*request) + sizeof(request->roles[0]);
	size_t expected_size = 0;

	request = kunit_kzalloc(test, request_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, request);
	request->version = EBPFOS_EXECUTOR_ROOT_ABI_VERSION;
	request->object_id = 1;
	request->target_epoch = 1;
	request->role_count = 1;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_request_size(
		request, live_size, &expected_size), 0);
	KUNIT_EXPECT_EQ(test, expected_size, live_size);
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_request_size(
		request, request_size, &expected_size), 0);
	KUNIT_EXPECT_EQ(test, expected_size, live_size);
	request->roles[1].role_type = 2;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_request_size(
		request, request_size, &expected_size), -E2BIG);
	request->roles[1].role_type = 0;
	request->role_count = EBPFOS_EXECUTOR_ROOT_MAX_ROLES + 1;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_request_size(
		request, request_size, &expected_size), -EINVAL);
	request->role_count = 1;
	request->expected_epoch = U64_MAX;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_request_size(
		request, request_size, &expected_size), -EINVAL);
}

static void ebpfos_executor_root_call_size_test(struct kunit *test)
{
	struct ebpfos_executor_call *call;
	size_t size = sizeof(*call) + 64;

	call = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, call);
	call->version = EBPFOS_EXECUTOR_ROOT_ABI_VERSION;
	call->object_id = 7;
	call->role_type = 9;
	call->method_id = 1;
	call->context_size = 64;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_call_size(call, size), 0);
	KUNIT_EXPECT_EQ(test, ebpfos_executor_call_size(call, size - 1), -EINVAL);
	call->flags = EBPFOS_EXECUTOR_CALL_F_EXPECT_EPOCH;
	call->expected_epoch = 3;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_call_size(call, size), 0);
	call->flags = 2;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_call_size(call, size), -EINVAL);
	call->flags = 0;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_call_size(call, size), -EINVAL);
}

static void ebpfos_executor_frame_test(struct kunit *test)
{
	struct ebpfos_executor_call *call;
	struct ebpfos_component_call_frame *frame;
	size_t size = sizeof(*call) + sizeof(*frame);

	call = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, call);
	frame = (void *)call->context;
	call->method_id = frame->method_id = 5;
	call->object_id = frame->object_id = 7;
	call->context_size = sizeof(*frame);
	frame->version = EBPFOS_COMPONENT_CALL_ABI_VERSION;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_frame_validate(call), 0);
	frame->method_id++;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_frame_validate(call), -EPROTO);
	frame->method_id--;
	frame->input_size = sizeof(frame->input) + 1;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_frame_validate(call), -EPROTO);
}

static unsigned int ebpfos_executor_test_provider(
	const void *context, const struct bpf_insn *insn)
{
	struct ebpfos_component_call_frame *frame = (void *)context;
	u64 input, output;

	memcpy(&input, frame->input, sizeof(input));
	output = input + 7;
	memcpy(frame->output, &output, sizeof(output));
	frame->status = 0;
	frame->output_size = sizeof(output);
	return 0x2a;
}

static void ebpfos_executor_test_prog_free(void *value)
{
	bpf_prog_free(value);
}

static void ebpfos_executor_provider_run_test(struct kunit *test)
{
	struct ebpfos_component_call_frame frame = {
		.version = EBPFOS_COMPONENT_CALL_ABI_VERSION,
		.input_size = sizeof(u64),
		.output_capacity = EBPFOS_COMPONENT_CALL_OUTPUT_SIZE,
	};
	struct ebpfos_binding binding = {};
	struct bpf_prog *provider;
	u64 input = 35, output = 0;
	u32 status = U32_MAX;

	provider = bpf_prog_alloc(bpf_prog_size(1), 0);
	KUNIT_ASSERT_NOT_NULL(test, provider);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(
		test, ebpfos_executor_test_prog_free, provider), 0);
	provider->type = BPF_PROG_TYPE_SYSCALL;
	provider->sleepable = true;
	provider->aux->ebpfos_component = true;
	provider->bpf_func = ebpfos_executor_test_provider;
	refcount_set(&binding.refs, 1);
	atomic64_set(&binding.invocation_state, 0);
	memcpy(frame.input, &input, sizeof(input));

	KUNIT_ASSERT_EQ(test, ebpfos_executor_provider_run(
		&binding, provider, &frame, &status), 0);
	memcpy(&output, frame.output, sizeof(output));
	KUNIT_EXPECT_EQ(test, status, (u32)0x2a);
	KUNIT_EXPECT_EQ(test, frame.output_size, (u32)sizeof(output));
	KUNIT_EXPECT_EQ(test, output, (u64)42);
	KUNIT_EXPECT_EQ(test, ebpfos_binding_active_invocations(&binding), 0U);
	KUNIT_EXPECT_EQ(test, ebpfos_binding_invocation_entries(&binding), 1ULL);

	/* An ordinary syscall program is not a component-call callee. */
	provider->aux->ebpfos_component = false;
	status = U32_MAX;
	memset(frame.output, 0, sizeof(frame.output));
	frame.output_size = 0;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_provider_run(
		&binding, provider, &frame, &status), -EOPNOTSUPP);
	KUNIT_EXPECT_EQ(test, status, U32_MAX);
	KUNIT_EXPECT_EQ(test, frame.output_size, 0U);
	KUNIT_EXPECT_EQ(test, ebpfos_binding_invocation_entries(&binding), 1ULL);
}

static struct kunit_case ebpfos_executor_root_cases[] = {
	KUNIT_CASE(ebpfos_executor_root_compare_test),
	KUNIT_CASE(ebpfos_executor_root_retained_binding_test),
	KUNIT_CASE(ebpfos_executor_root_request_test),
	KUNIT_CASE(ebpfos_executor_root_call_size_test),
	KUNIT_CASE(ebpfos_executor_frame_test),
	KUNIT_CASE(ebpfos_executor_provider_run_test),
	{}
};

static struct kunit_suite ebpfos_executor_root_suite = {
	.name = "ebpfos-executor-root",
	.test_cases = ebpfos_executor_root_cases,
};
kunit_test_suite(ebpfos_executor_root_suite);
#endif
