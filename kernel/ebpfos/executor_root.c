// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <crypto/sha2.h>
#include <linux/ebpfos.h>
#include <linux/errno.h>
#include <linux/filter.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/unaligned.h>
#include <linux/workqueue.h>
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
	u64 authority;
	u32 publisher_prog_id;
	u32 role_count;
	u8 publisher_digest[SHA256_DIGEST_SIZE];
	struct ebpfos_executor_root_role roles[];
};

struct ebpfos_executor_root_slot {
	spinlock_t lock;
	struct ebpfos_executor_root_bundle __rcu *active;
};

static struct ebpfos_executor_root_slot ebpfos_executor_root = {
	.lock = __SPIN_LOCK_UNLOCKED(ebpfos_executor_root.lock),
};

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

static int ebpfos_executor_root_snapshot_size(u32 role_count,
					       u32 snapshot_size,
					       size_t *expected_size)
{
	size_t capacity_size;
	size_t roles_size;

	if (!role_count || role_count > EBPFOS_EXECUTOR_ROOT_MAX_ROLES ||
	    !expected_size || snapshot_size <
		sizeof(struct ebpfos_executor_root_snapshot))
		return -EINVAL;
	if (check_mul_overflow((size_t)role_count,
			       sizeof(struct ebpfos_executor_root_role_snapshot),
			       &roles_size) ||
	    check_add_overflow(sizeof(struct ebpfos_executor_root_snapshot),
			       roles_size, expected_size) ||
	    snapshot_size < *expected_size)
		return -ENOSPC;
	capacity_size = snapshot_size -
		sizeof(struct ebpfos_executor_root_snapshot);
	if (capacity_size %
			sizeof(struct ebpfos_executor_root_role_snapshot) ||
	    capacity_size /
			sizeof(struct ebpfos_executor_root_role_snapshot) >
		EBPFOS_EXECUTOR_ROOT_MAX_ROLES)
		return -ENOSPC;
	return 0;
}

static int ebpfos_executor_root_role_fill(
	struct ebpfos_executor_root_role *role,
	const struct ebpfos_executor_root_role_request *request)
{
	const struct ebpfos_component_desc_v1 *descriptor;
	struct ebpfos_admission_identity_v1 identity = {};
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
		(le32_to_cpu(descriptor->resource_count) ==
		 !!ebpfos_binding_map(binding)) &&
		ebpfos_binding_prog(binding) &&
		ebpfos_binding_prog(binding)->aux->ebpfos_component;
	if (ebpfos_binding_kind(binding) != EBPFOS_ADMITTED_BINDING_BPF ||
	    !component) {
		ebpfos_binding_put(binding);
		ebpfos_admission_put(grant);
		return -EOPNOTSUPP;
	}
	ebpfos_binding_fill_identity(binding, &identity);
	role->snapshot.role_type = request->role_type;
	role->snapshot.authority = le64_to_cpu(descriptor->capability_mask);
	role->snapshot.provider_type_id =
		le64_to_cpu(descriptor->provider_type_id);
	role->snapshot.schema = le64_to_cpu(descriptor->runtime_schema_u64);
	role->snapshot.prog_id = identity.prog_id;
	role->snapshot.map_id = identity.map_id;
	memcpy(role->snapshot.content_digest, identity.content_digest,
	       SHA256_DIGEST_SIZE);
	memcpy(role->snapshot.contract_digest, descriptor->contract_sha256,
	       SHA256_DIGEST_SIZE);
	role->binding = binding;
	role->grant = grant;
	return 0;
}

static int ebpfos_executor_root_manifest_validate(
	const struct ebpfos_executor_root_manifest *manifest,
	const struct ebpfos_executor_root_bundle *target)
{
	u32 role;

	if (target->object_id != manifest->object_id ||
	    target->role_count != manifest->role_count ||
	    target->authority != manifest->authority_ceiling)
		return -EACCES;
	for (role = 0; role < target->role_count; role++) {
		const struct ebpfos_executor_root_role_snapshot *actual =
			&target->roles[role].snapshot;
		const struct ebpfos_executor_root_manifest_role *expected =
			&manifest->roles[role];

		if (actual->role_type != expected->role_type ||
		    actual->provider_type_id != expected->provider_type_id ||
		    actual->schema != expected->schema ||
		    actual->authority != expected->authority ||
		    memcmp(actual->content_digest, expected->content_digest,
			   SHA256_DIGEST_SIZE) ||
		    memcmp(actual->contract_digest, expected->contract_digest,
			   SHA256_DIGEST_SIZE))
			return -EPROTOTYPE;
	}
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
		bundle->authority |= bundle->roles[role].snapshot.authority;
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
	const struct ebpfos_executor_root_bundle *target,
	struct ebpfos_binding **predecessors)
{
	u32 role;

	if (target->object_id != request->object_id ||
	    target->epoch != request->target_epoch ||
	    target->role_count != request->role_count)
		return -ESTALE;
	if (!source)
		return request->expected_epoch ? -ESTALE : 0;
	if (source->object_id != request->object_id ||
	    source->epoch != request->expected_epoch ||
	    source->role_count != target->role_count)
		return -ESTALE;
	if (target->authority & ~source->authority)
		return -EACCES;
	for (role = 0; role < target->role_count; role++) {
		if (source->roles[role].snapshot.role_type !=
			    target->roles[role].snapshot.role_type ||
		    memcmp(source->roles[role].snapshot.contract_digest,
			   target->roles[role].snapshot.contract_digest,
			   SHA256_DIGEST_SIZE))
			return -EPROTOTYPE;
		if (target->roles[role].snapshot.authority &
		    ~source->roles[role].snapshot.authority)
			return -EACCES;
		predecessors[role] = source->roles[role].binding;
	}
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

noinline int bpf_ebpfos_executor_root_publish_impl(
	const void *request_data, u32 request_data__sz,
	struct bpf_prog_aux *aux)
{
	const struct ebpfos_executor_root_publish_request *request = request_data;
	struct ebpfos_executor_root_bundle *source;
	struct ebpfos_executor_root_bundle *target = NULL;
	struct ebpfos_binding **predecessors = NULL;
	struct ebpfos_admission **grants = NULL;
	struct ebpfos_executor_root_manifest *manifest = NULL;
	u8 publisher_digest[SHA256_DIGEST_SIZE];
	size_t expected_size;
	u32 publisher_prog_id;
	bool staged = false;
	u32 role;
	int error;

	/* Reject non-publisher meta programs before parsing request-owned FDs. */
	if (!aux || !ebpfos_admission_root_publisher_program(aux->prog))
		return -EACCES;
	error = ebpfos_executor_root_request_size(request, request_data__sz,
						  &expected_size);
	if (error)
		return error;
	error = ebpfos_executor_root_prepare(request, &target);
	if (error)
		return error;
	grants = kcalloc(target->role_count, sizeof(*grants), GFP_KERNEL);
	predecessors = kcalloc(target->role_count, sizeof(*predecessors),
			       GFP_KERNEL);
	manifest = kzalloc_obj(*manifest);
	if (!grants || !predecessors || !manifest) {
		error = -ENOMEM;
		goto out;
	}
	for (role = 0; role < target->role_count; role++)
		grants[role] = target->roles[role].grant;

	ebpfos_admission_gate_lock();
	error = ebpfos_admission_root_publisher_validate_locked(
		aux, &publisher_prog_id, publisher_digest, manifest);
	if (error)
		goto out_unlock_gate;
	error = ebpfos_executor_root_manifest_validate(manifest, target);
	if (error)
		goto out_unlock_gate;
	spin_lock(&ebpfos_executor_root.lock);
	source = rcu_dereference_protected(ebpfos_executor_root.active,
					    lockdep_is_held(&ebpfos_executor_root.lock));
	spin_unlock(&ebpfos_executor_root.lock);
	error = ebpfos_executor_root_source_validate(request, source, target,
						     predecessors);
	if (error)
		goto out_unlock_gate;
	error = ebpfos_admission_stage_bundle_locked(grants, predecessors,
						     target->role_count);
	if (error)
		goto out_unlock_gate;
	staged = true;
	if (request->flags & EBPFOS_EXECUTOR_ROOT_F_TEST_FAIL_AFTER_STAGE) {
		error = -ECANCELED;
		goto out_unlock_gate;
	}
	target->publisher_prog_id = publisher_prog_id;
	memcpy(target->publisher_digest, publisher_digest,
	       SHA256_DIGEST_SIZE);
	error = ebpfos_executor_root_commit(&ebpfos_executor_root, request,
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
	kfree(predecessors);
	kfree(grants);
	kfree(manifest);
	return 0;

out_unlock_gate:
	if (staged)
		ebpfos_admission_burn_set_locked(grants, target->role_count);
	ebpfos_admission_gate_unlock();
out:
	kfree(predecessors);
	kfree(grants);
	kfree(manifest);
	ebpfos_executor_root_bundle_release(target);
	return error;
}

/*
 * Keep the legacy _impl BTF counterpart explicit until the minimum supported
 * pahole can synthesize it for KF_IMPLICIT_ARGS.  The public symbol remains
 * the only registered/callable kfunc and receives aux from the verifier.
 */
__bpf_kfunc int bpf_ebpfos_executor_root_publish(
	const void *request_data, u32 request_data__sz,
	struct bpf_prog_aux *aux)
{
	return bpf_ebpfos_executor_root_publish_impl(request_data,
						     request_data__sz, aux);
}

noinline int bpf_ebpfos_executor_root_read_impl(
	u64 object_id, void *snapshot_data, u32 snapshot_data__sz,
	struct bpf_prog_aux *aux)
{
	struct ebpfos_executor_root_snapshot *snapshot = snapshot_data;
	struct ebpfos_executor_root_bundle *bundle;
	size_t expected_size;
	u32 role;
	int error = 0;

	if (!aux || !ebpfos_admission_root_publisher_program(aux->prog))
		return -EACCES;
	if (!object_id || !snapshot ||
	    snapshot_data__sz < sizeof(*snapshot))
		return -EINVAL;
	rcu_read_lock();
	bundle = rcu_dereference(ebpfos_executor_root.active);
	if (!bundle || bundle->object_id != object_id) {
		error = -ENOENT;
		goto out_unlock;
	}
	error = ebpfos_executor_root_snapshot_size(bundle->role_count,
						 snapshot_data__sz,
						 &expected_size);
	if (error)
		goto out_unlock;
	memset(snapshot, 0, snapshot_data__sz);
	snapshot->version = EBPFOS_EXECUTOR_ROOT_ABI_VERSION;
	snapshot->object_id = bundle->object_id;
	snapshot->epoch = bundle->epoch;
	snapshot->authority = bundle->authority;
	snapshot->publisher_prog_id = bundle->publisher_prog_id;
	snapshot->role_count = bundle->role_count;
	memcpy(snapshot->publisher_digest, bundle->publisher_digest,
	       SHA256_DIGEST_SIZE);
	for (role = 0; role < bundle->role_count; role++)
		snapshot->roles[role] = bundle->roles[role].snapshot;
out_unlock:
	rcu_read_unlock();
	return error;
}

__bpf_kfunc int bpf_ebpfos_executor_root_read(
	u64 object_id, void *snapshot_data, u32 snapshot_data__sz,
	struct bpf_prog_aux *aux)
{
	return bpf_ebpfos_executor_root_read_impl(object_id, snapshot_data,
						 snapshot_data__sz, aux);
}

static int ebpfos_executor_call_size(struct ebpfos_executor_call *call,
				     u32 call_data__sz)
{
	size_t expected_size;

	if (!call || call_data__sz < sizeof(*call) ||
	    call->version != EBPFOS_EXECUTOR_IMPORT_MANIFEST_VERSION ||
	    (call->flags & ~(EBPFOS_EXECUTOR_CALL_F_EXPECT_EPOCH |
			     EBPFOS_EXECUTOR_CALL_F_CONTINUATION)) ||
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

static struct ebpfos_binding *ebpfos_executor_root_role_get(
	u64 object_id, u64 role_type, u64 *epoch,
	struct ebpfos_executor_root_role_snapshot *snapshot)
{
	struct ebpfos_executor_root_bundle *bundle;
	struct ebpfos_binding *binding = NULL;
	u32 role;

	rcu_read_lock();
	bundle = rcu_dereference(ebpfos_executor_root.active);
	if (!bundle || bundle->object_id != object_id)
		goto out;
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
out:
	rcu_read_unlock();
	return binding;
}

static int ebpfos_executor_method_validate(
	const struct ebpfos_executor_call *call,
	const struct ebpfos_executor_import *import)
{
	const u8 *value;
	u64 discriminator;

	if (!call || !import || call->method_id != import->method_id ||
	    import->discriminator_offset > call->context_size ||
	    import->discriminator_size > call->context_size -
		import->discriminator_offset)
		return -EPROTO;
	value = call->context + import->discriminator_offset;
	switch (import->discriminator_size) {
	case 1:
		discriminator = *value;
		break;
	case 2:
		discriminator = get_unaligned_le16(value);
		break;
	case 4:
		discriminator = get_unaligned_le32(value);
		break;
	case 8:
		discriminator = get_unaligned_le64(value);
		break;
	default:
		return -EPROTO;
	}
	return (discriminator & import->discriminator_mask) ==
		import->discriminator_value ? 0 : -EACCES;
}

static bool ebpfos_executor_provider_supported(const struct bpf_prog *provider)
{
	return provider && provider->aux && provider->aux->ebpfos_component &&
	       provider->type == BPF_PROG_TYPE_SYSCALL && provider->sleepable;
}

/*
 * Run one admitted provider.  The lease is the caller's: an ordinary call takes
 * it here for the duration of this single invocation, while a continuation has
 * already taken it at session open and must not take it again, because a second
 * enter() would be a second lease that no retirement accounting expects.  The
 * two wrappers share this body so both paths run the provider identically.
 */
static int ebpfos_executor_provider_run_leased(struct bpf_prog *provider,
		void *context, u32 *status)
{
	struct bpf_tramp_run_ctx run_ctx = {};
	u64 start;

	if (!ebpfos_executor_provider_supported(provider) || !context || !status)
		return -EOPNOTSUPP;
	start = __bpf_prog_enter_sleepable_recur(provider, &run_ctx);
	if (!start) {
		__bpf_prog_exit_sleepable_recur(provider, 0, &run_ctx);
		return -EBUSY;
	}
	*status = bpf_prog_run(provider, context);
	__bpf_prog_exit_sleepable_recur(provider, 0, &run_ctx);
	return 0;
}

static int ebpfos_executor_provider_run(struct ebpfos_binding *binding,
		struct bpf_prog *provider, void *context, u32 *status)
{
	int error;

	/*
	 * A provider that cannot run must not consume an invocation entry: the
	 * lease is taken only once the call is known to be dispatchable, so a
	 * refused provider leaves the binding's counters exactly as it found
	 * them.
	 */
	if (!binding || !ebpfos_executor_provider_supported(provider) ||
	    !context || !status)
		return -EOPNOTSUPP;
	error = ebpfos_binding_invocation_enter(binding);
	if (error)
		return error;
	error = ebpfos_executor_provider_run_leased(provider, context, status);
	ebpfos_binding_invocation_exit(binding);
	return error;
}

/*
 * ---------------------------------------------------------------------------
 * Private continuation session.
 * ---------------------------------------------------------------------------
 *
 * A continuation is one logical operation spanning several independently
 * verified component programs.  The session that drives it is a value of one
 * top-level dispatcher call: never published, never reachable from a program or
 * from userspace, and holding no handle a caller could replay.  That is
 * deliberate.  A session a caller could name and re-enter would need a
 * registry, a lookup and a generation check, and each of those is attack
 * surface for forgeable authority; a value that lives and dies inside one call
 * has none.
 *
 * What the session does own is the epoch pin.  An ordinary call resolves one
 * role and runs it, and between two such calls publication may replace the
 * bundle and retire the bindings the first call used.  For a continuation that
 * is wrong: the operation may already have produced visible effects, so it must
 * finish wholly on the bundle it started on.  The session therefore acquires,
 * once and atomically under the root lock, a reference and an invocation lease
 * for every distinct binding it will need -- the entry binding included --
 * while the active bundle still matches the epoch the call named.  Those leases
 * are what make retirement wait: ebpfos_binding_retire() sets
 * EBPFOS_BINDING_RETIRED and a later enter() fails, but a lease taken here was
 * already counted, so the pinned provider stays runnable to the end.
 * ---------------------------------------------------------------------------
 */

/*
 * One pinned step: the binding, its snapshot, and the authenticated edge that
 * authorizes reaching it.
 */
struct ebpfos_continuation_step {
	struct ebpfos_binding *binding;
	struct ebpfos_executor_root_role_snapshot snapshot;
	struct ebpfos_continuation_edge edge;
	/* The lease is taken once per distinct binding, not once per edge. */
	bool lease_held;
	/*
	 * The import this step was authenticated against, kept from acquisition
	 * so the discriminator can be re-checked on the frame the provider
	 * actually receives without re-entering admission.  Re-validating
	 * against the same frozen import is the same decision, made once.
	 */
	struct ebpfos_executor_import import;
	/* The frame this step was addressed with, for its discriminator check. */
	const struct ebpfos_component_call_frame *frame;
};

/*
 * READY: the next ordinal may be claimed.
 * EXECUTING: exactly one claim is in flight.
 * CONSUMED: the chain reached a terminal disposition.
 * POISONED: a structural or provider failure made the session unusable.  A
 *           poisoned session is never resumed: the operation may have produced
 *           visible effects, so continuing it would make those ambiguous.
 */
enum ebpfos_continuation_state {
	EBPFOS_SESSION_READY = 1,
	EBPFOS_SESSION_EXECUTING = 2,
	EBPFOS_SESSION_CONSUMED = 3,
	EBPFOS_SESSION_POISONED = 4,
};

struct ebpfos_continuation_session {
	u64 object_id;
	u64 epoch;
	u8 component_id[16];
	/*
	 * The session's state, as one atomic word and nothing else.  A second,
	 * plain mirror would be a place for two writers to disagree, so the
	 * atomic word is the only source of truth and every transition is a
	 * single cmpxchg on it.
	 */
	atomic_t state;
	u32 step_count;
	struct ebpfos_continuation_step *steps;
	/*
	 * The generation is the chain's own counter, distinct from the epoch and
	 * from any ordinal: it is claimed with the ordinal so exactly one
	 * concurrent claimant can win, and it advances only after a
	 * structurally valid step completion.
	 */
	atomic64_t generation;
	u8 boundary_digest[32];
};

/*
 * Release every lease and reference the acquisition took, each exactly once.
 * The inverse of acquisition, in reverse order, so a session torn down for any
 * reason gives back exactly what it took.
 */
static bool ebpfos_continuation_nonzero(const u8 *data, size_t size)
{
	return memchr_inv(data, 0, size) != NULL;
}

/*
 * Make a session unusable, once and atomically.
 *
 * Every structural or provider failure funnels through here, so there is exactly
 * one place a session becomes poisoned and exactly one transition to reason
 * about.  A session that is already CONSUMED stays consumed: a terminal
 * completion is a different outcome from a failure, and the caller must be able
 * to tell which happened.
 */
static void ebpfos_continuation_poison(struct ebpfos_continuation_session *s)
{
	atomic_cmpxchg(&s->state, EBPFOS_SESSION_READY,
		       EBPFOS_SESSION_POISONED);
	atomic_cmpxchg(&s->state, EBPFOS_SESSION_EXECUTING,
		       EBPFOS_SESSION_POISONED);
}

static u32 ebpfos_continuation_state(
	const struct ebpfos_continuation_session *s)
{
	return (u32)atomic_read(&s->state);
}

static void ebpfos_continuation_release(struct ebpfos_continuation_session *s)
{
	u32 index;

	if (!s || !s->steps)
		return;
	for (index = 0; index < s->step_count; index++) {
		if (!s->steps[index].lease_held)
			continue;
		ebpfos_binding_invocation_exit(s->steps[index].binding);
		ebpfos_binding_put(s->steps[index].binding);
		s->steps[index].lease_held = false;
		s->steps[index].binding = NULL;
	}
}

/*
 * Resolve and lease every step of the chain, atomically, from one bundle.
 *
 * The lock is taken exactly once.  Under it the active pointer, object identity
 * and epoch are verified, every edge is resolved from *that* immutable bundle,
 * and a reference plus one invocation lease is taken for each distinct target
 * binding.  Two properties follow, and both are the point:
 *
 *   - Deduplication: several edges composed from one component resolve to one
 *     binding, and that binding is leased once.  Leasing it per edge would both
 *     violate "one lease per distinct binding" and burn the invocation counter.
 *   - Atomicity against publication: publication swaps the active pointer and
 *     retires removed bindings under this same lock, so either every lease is
 *     acquired here first and the chain runs wholly on the old epoch, or
 *     publication won and this open fails stale.  A mixed-epoch chain is not
 *     representable.  After this returns successfully the active root is never
 *     consulted again.
 */
static int ebpfos_continuation_acquire(
	struct bpf_prog_aux *aux, struct ebpfos_continuation_session *session,
	u32 edge_count)
{
	struct ebpfos_executor_root_bundle *bundle;
	unsigned long flags;
	u32 index, prior;
	int error = 0;

	spin_lock_irqsave(&ebpfos_executor_root.lock, flags);
	bundle = rcu_dereference_protected(
		ebpfos_executor_root.active,
		lockdep_is_held(&ebpfos_executor_root.lock));
	if (!bundle || bundle->object_id != session->object_id ||
	    bundle->epoch != session->epoch) {
		error = -ESTALE;
		goto out;
	}
	for (index = 0; index < edge_count; index++) {
		struct ebpfos_continuation_step *step = &session->steps[index];
		const struct ebpfos_continuation_edge *edge = &step->edge;
		const struct ebpfos_component_desc_v1 *descriptor;
		struct ebpfos_executor_import import = {};
		struct ebpfos_binding *binding = NULL;
		bool reused = false;
		u32 role;

		for (role = 0; role < bundle->role_count; role++) {
			if (bundle->roles[role].snapshot.role_type <
			    edge->destination_role_type)
				continue;
			if (bundle->roles[role].snapshot.role_type !=
			    edge->destination_role_type)
				break;
			binding = bundle->roles[role].binding;
			step->snapshot = bundle->roles[role].snapshot;
			break;
		}
		if (!binding || step->snapshot.role_type !=
				edge->destination_role_type ||
		    !step->snapshot.prog_id) {
			error = -ENOENT;
			goto out;
		}
		descriptor = ebpfos_binding_descriptor(binding);
		if (!descriptor || !ebpfos_executor_provider_supported(
			    ebpfos_binding_prog(binding))) {
			error = -EOPNOTSUPP;
			goto out;
		}
		if (ebpfos_binding_prog(binding)->aux == aux) {
			error = -ELOOP;
			goto out;
		}
		/*
		 * The destination is authenticated against the caller's frozen
		 * imports and the pinned provider, exactly as an ordinary call
		 * is: an edge can reach nowhere a direct call could not.  The
		 * content and contract digests the edge carries must be the ones
		 * that provider actually implements.
		 */
		error = ebpfos_admission_import_validate(
			aux, session->object_id, edge->destination_role_type,
			edge->destination_method_id, descriptor,
			&step->snapshot, &import);
		if (error)
			goto out;
		/*
		 * The dispatcher hands every continuation step the same fixed
		 * component frame, so a step whose import was admitted for a
		 * different context ABI cannot be driven by it.  The ordinary
		 * call path checks this against the entry provider; a chained
		 * step would otherwise skip the check entirely and receive a
		 * frame shaped for a different contract.  Refused before the
		 * import is cached or its lease taken.
		 */
		if (import.context_size !=
		    sizeof(struct ebpfos_component_call_frame)) {
			error = -EMSGSIZE;
			goto out;
		}
		step->import = import;
		if (memcmp(edge->destination_contract_digest,
			   import.contract_digest, SHA256_DIGEST_SIZE) ||
		    memcmp(edge->destination_content_digest,
			   step->snapshot.content_digest, SHA256_DIGEST_SIZE) ||
		    memcmp(edge->destination_component_id,
			   descriptor->component_id,
			   sizeof(edge->destination_component_id))) {
			error = -EPROTOTYPE;
			goto out;
		}
		/*
		 * Two edges may resolve to one binding.  Every step records the
		 * pointer so the driver can run it, but only one step owns the
		 * lease and the extra reference: a second enter() would be a
		 * second lease no retirement accounting expects, and a second
		 * get() would leak a reference on teardown.
		 */
		for (prior = 0; prior < index; prior++)
			reused |= session->steps[prior].binding == binding;
		step->binding = binding;
		if (reused)
			continue;
		error = ebpfos_binding_invocation_enter(binding);
		if (error) {
			step->binding = NULL;
			goto out;
		}
		ebpfos_binding_get(binding);
		step->lease_held = true;
	}
out:
	spin_unlock_irqrestore(&ebpfos_executor_root.lock, flags);
	return error;
}

/*
 * Loaded programs retain their maps and their used_maps lists are frozen.
 * An arena range is meaningful across a boundary only when the endpoints
 * share exactly one actual arena map covering the declared extent.
 */
static bool ebpfos_continuation_shared_arena(struct bpf_prog_aux *source,
					      struct bpf_prog_aux *target,
					      u64 extent)
{
	struct bpf_map *match = NULL, *map;
	u32 index, peer;

	if (!source || !target || !extent)
		return false;
	for (index = 0; index < source->used_map_cnt; index++) {
		map = source->used_maps[index];
		if (!map || map->map_type != BPF_MAP_TYPE_ARENA ||
		    (u64)map->max_entries * PAGE_SIZE < extent)
			continue;
		for (peer = 0; peer < target->used_map_cnt; peer++) {
			if (target->used_maps[peer] != map)
				continue;
			if (match && match != map)
				return false;
			match = map;
			break;
		}
	}
	return match != NULL;
}

static int ebpfos_continuation_arenas_validate(
	struct bpf_prog_aux *caller, struct ebpfos_continuation_session *session)
{
	struct bpf_prog_aux *source = caller, *target;
	const struct ebpfos_continuation_edge *edge;
	struct bpf_prog *prog;
	u32 index;

	for (index = 0; index < session->step_count; index++) {
		edge = &session->steps[index].edge;
		prog = ebpfos_binding_prog(session->steps[index].binding);
		if (!prog || !prog->aux)
			return -EOPNOTSUPP;
		target = prog->aux;
		if (edge->transport_kind ==
		    EBPFOS_CONTINUATION_TRANSPORT_ARENA_RANGE &&
		    !ebpfos_continuation_shared_arena(source, target,
						       edge->scalar_limit[0]))
			return -EACCES;
		source = target;
	}
	return 0;
}

static int ebpfos_continuation_transport_validate(
	const struct ebpfos_continuation_edge *edge,
	const struct ebpfos_continuation_transition *response)
{
	u32 slot = 0;

	if (edge->transport_kind ==
	    EBPFOS_CONTINUATION_TRANSPORT_ARENA_RANGE) {
		u64 offset = response->scalar[0];
		u64 length = response->scalar[1];
		u64 extent = edge->scalar_limit[0];

		if (!length || length > edge->scalar_limit[1] ||
		    offset >= extent || length > extent - offset)
			return -ERANGE;
		slot = 2;
	}
	for (; slot < EBPFOS_CONTINUATION_SCALAR_SLOTS; slot++) {
		u64 limit = edge->scalar_limit[slot];

		if (limit ? response->scalar[slot] > limit :
		    response->scalar[slot] != 0)
			return -ERANGE;
	}
	return 0;
}

/*
 * Claim the next transition.
 *
 * The session is confined to one dispatcher call and driven by one loop, so
 * there is no second thread to race; the claim is a single atomic
 * READY -> EXECUTING transition anyway, so the invariant does not depend on that
 * confinement staying true.  The claim captures the generation it will execute,
 * and the generation advances only on a valid completion, so an abandoned step
 * leaves the chain where it was rather than looking like a step that ran.
 */
static int ebpfos_continuation_claim(
	struct ebpfos_continuation_session *session,
	struct ebpfos_continuation_step **step, u64 *generation)
{
	u64 ordinal;

	if (!session || !step || !generation || !session->steps)
		return -EINVAL;
	/* One compare-and-swap is the whole claim: exactly one caller wins it. */
	if (atomic_cmpxchg(&session->state, EBPFOS_SESSION_READY,
			   EBPFOS_SESSION_EXECUTING) !=
	    EBPFOS_SESSION_READY)
		return ebpfos_continuation_state(session) ==
			       EBPFOS_SESSION_EXECUTING ? -EBUSY : -EALREADY;
	ordinal = atomic64_read(&session->generation);
	if (ordinal >= session->step_count) {
		ebpfos_continuation_poison(session);
		return -EPROTOTYPE;
	}
	*step = &session->steps[(u32)ordinal];
	*generation = ordinal;
	return 0;
}

/*
 * Complete a claimed step.  The generation advances only after a structurally
 * valid provider response, and a terminal disposition consumes the chain.
 */
static int ebpfos_continuation_complete(
	struct ebpfos_continuation_session *session, u64 generation,
	u32 disposition)
{
	switch (disposition) {
	case EBPFOS_CONTINUATION_DISPOSITION_CONTINUE:
		/*
		 * A continue past the last authenticated edge has nowhere to go,
		 * so the chain is poisoned rather than silently ending: the
		 * operation is incomplete and cannot be resumed.
		 */
		if (generation + 1 >= session->step_count) {
			ebpfos_continuation_poison(session);
			return -EPROTOTYPE;
		}
		atomic64_set(&session->generation, generation + 1);
		atomic_set(&session->state, EBPFOS_SESSION_READY);
		return 0;
	case EBPFOS_CONTINUATION_DISPOSITION_COMPLETE:
	case EBPFOS_CONTINUATION_DISPOSITION_ERROR:
		atomic_set(&session->state, EBPFOS_SESSION_CONSUMED);
		return 0;
	default:
		ebpfos_continuation_poison(session);
		return -EPROTO;
	}
}

/*
 * Whether a provider's response is a complete, well-formed answer for the step
 * it was given.
 *
 * A provider that writes nothing leaves the kernel's own prewritten request in
 * place, so the marker and the exact size are what distinguish a real answer
 * from silence.  The echoed ordinal and generation bind the answer to this step,
 * so a stale or duplicated response names a step that is not running.
 */
static bool ebpfos_executor_continuation_response_valid(
	const struct ebpfos_component_call_frame *frame, u64 ordinal,
	u64 generation)
{
	struct ebpfos_continuation_transition response = {};

	if (frame->output_size != EBPFOS_CONTINUATION_RESPONSE_SIZE)
		return false;
	memcpy(&response, frame->output, sizeof(response));
	if (response.magic != EBPFOS_CONTINUATION_RESPONSE_MAGIC ||
	    response.response_size != EBPFOS_CONTINUATION_RESPONSE_SIZE ||
	    response.ordinal != ordinal ||
	    response.generation != generation ||
	    response.reserved || response.reserved2)
		return false;
	return response.disposition == EBPFOS_CONTINUATION_DISPOSITION_CONTINUE ||
	       response.disposition == EBPFOS_CONTINUATION_DISPOSITION_COMPLETE ||
	       response.disposition == EBPFOS_CONTINUATION_DISPOSITION_ERROR;
}

/*
 * Apply one import's discriminator rule to a component frame.
 *
 * `ebpfos_executor_method_validate()` reads the discriminator out of an
 * `ebpfos_executor_call`'s trailing context.  A continuation step has no such
 * call: it has the component frame it just framed.  Rather than fabricate a call
 * with a flexible array, the same rule is applied to the frame's bytes, so both
 * paths decide the discriminator identically and neither silently skips it.
 */
static int ebpfos_continuation_discriminator_check(
	const struct ebpfos_component_call_frame *frame, u64 method_id,
	const struct ebpfos_executor_import *import)
{
	const u8 *value;
	u64 discriminator;

	if (!frame || !import || method_id != import->method_id ||
	    import->discriminator_offset > EBPFOS_COMPONENT_CALL_CONTEXT_SIZE ||
	    import->discriminator_size > EBPFOS_COMPONENT_CALL_CONTEXT_SIZE -
		import->discriminator_offset)
		return -EPROTO;
	value = (const u8 *)frame + import->discriminator_offset;
	switch (import->discriminator_size) {
	case 1:
		discriminator = *value;
		break;
	case 2:
		discriminator = get_unaligned_le16(value);
		break;
	case 4:
		discriminator = get_unaligned_le32(value);
		break;
	case 8:
		discriminator = get_unaligned_le64(value);
		break;
	default:
		return -EPROTO;
	}
	return (discriminator & import->discriminator_mask) ==
		import->discriminator_value ? 0 : -EACCES;
}

/*
 * Validate the frame and the request before either is used.
 *
 * Everything here is untrusted input.  The context size is checked first because
 * reading the frame at all is only sound once the admitted context is known to
 * be a whole frame; the frame's own version, flags, object, epoch and method are
 * then checked against what the caller was admitted for, so a caller cannot name
 * one object or method in the call and another in the frame.
 */
static int ebpfos_executor_continuation_frame_validate(
	const struct ebpfos_executor_call *call, u64 epoch,
	struct ebpfos_component_call_frame *frame,
	struct ebpfos_continuation_request *request)
{
	if (call->context_size != sizeof(*frame))
		return -EMSGSIZE;
	if (frame->version != EBPFOS_COMPONENT_CALL_ABI_VERSION ||
	    frame->flags ||
	    frame->object_id != call->object_id ||
	    frame->epoch != epoch ||
	    frame->method_id != call->method_id ||
	    frame->input_size != sizeof(*request) ||
	    frame->output_capacity < EBPFOS_CONTINUATION_RESPONSE_SIZE)
		return -EINVAL;
	memcpy(request, frame->input, sizeof(*request));
	if (request->reserved ||
	    !ebpfos_continuation_nonzero(request->component_id,
					 sizeof(request->component_id)) ||
	    !ebpfos_continuation_nonzero(request->boundary_digest,
					 sizeof(request->boundary_digest)) ||
	    (request->requested_disposition !=
			EBPFOS_CONTINUATION_DISPOSITION_CONTINUE &&
	     request->requested_disposition !=
			EBPFOS_CONTINUATION_DISPOSITION_COMPLETE &&
	     request->requested_disposition !=
			EBPFOS_CONTINUATION_DISPOSITION_ERROR))
		return -EINVAL;
	return 0;
}

/*
 * Validate one step's method against the discriminant in the context actually
 * sent to it.
 *
 * The step's import was authenticated at acquisition, but the import only says
 * which method this step is *allowed* to serve.  A context naming a different
 * method would make the provider act on one identity while the session believes
 * another, so the discriminator is re-checked on the frame the provider is about
 * to receive, using the same rule an ordinary call uses.
 */
static int ebpfos_continuation_step_method(
	struct ebpfos_continuation_step *step)
{
	return ebpfos_continuation_discriminator_check(
		step->frame, step->edge.destination_method_id, &step->import);
}

/*
 * Drive one top-level call's continuation.
 *
 * The order is the whole point, and it is the reverse of trusting the caller.
 * The frame and request are validated before either is used.  The first
 * authenticated edge must then agree with the entry the ordinary call path
 * already admitted, and the chain must be continuous: every step starts from the
 * component identity the previous step produced, so edges from unrelated
 * operations cannot be spliced into one sequence.
 *
 * Every provider runs under a frame built for *its* step -- destination object,
 * epoch, method and the record it is admitted for -- and its discriminator is
 * re-checked after that framing, so a step cannot be sent a context that names
 * a different method than the one its import authorized.  A response is
 * accepted only if the provider produced one.
 *
 * Three status layers stay distinct.  A negative return here is a dispatcher or
 * session failure: routing, epoch, replay, identity, structure.  `*status` is
 * the program-level result of the last provider that actually entered.  The
 * frame's `status` and `result` are what that provider's own logic reported, and
 * are never overwritten to mean something else.
 */
/*
 * Drive the authenticated chain to completion, one pinned step at a time.
 *
 * This is the whole execution path of a continuation: claim the next
 * generation, frame the step, check its discriminator, run its provider, and
 * validate what that provider reported.  It is a separate function so it can be
 * exercised end to end with real provider entry rather than only through its
 * validators, which is where the defects this replaced were hiding.
 *
 * Frames are staged in temporary storage and committed only when the step's
 * provider is about to enter, so a pre-entry refusal leaves the last executed
 * provider's frame status and result exactly as that provider left them.  The
 * scalars a step reports are carried into the next step's request, since those
 * values are the continuation's state.  Identity and status are attributed to a
 * provider only once it actually ran.
 */
static int ebpfos_continuation_drive(
	struct bpf_prog_aux *aux, struct ebpfos_continuation_session *session,
	struct ebpfos_component_call_frame *frame, u32 *status, u32 *prog_id)
{
	struct ebpfos_continuation_transition response = {};
	int error;

	(void)aux;
	*status = 0;
	/*
	 * The scalars one step reports are the next step's input, so they are
	 * carried forward explicitly: only the ordinal, generation and step
	 * identity are refreshed per iteration, and the values a provider
	 * validated survive into the request the next provider receives.
	 */
	memset(&response, 0, sizeof(response));
	for (;;) {
		struct ebpfos_continuation_step *step = NULL;
		struct bpf_prog *provider;
		struct ebpfos_component_call_frame staged = {};
		u32 step_status = 0;
		u64 generation = 0;

		error = ebpfos_continuation_claim(session, &step, &generation);
		if (error)
			break;
		staged.version = EBPFOS_COMPONENT_CALL_ABI_VERSION;
		staged.object_id = session->object_id;
		staged.epoch = session->epoch;
		staged.method_id = step->edge.destination_method_id;
		staged.input_size = sizeof(response);
		staged.output_capacity = EBPFOS_CONTINUATION_RESPONSE_SIZE;
		response.ordinal = step->edge.ordinal;
		response.generation = generation;
		response.magic = 0;
		response.response_size = 0;
		response.disposition = 0;
		response.transport_kind = step->edge.transport_kind;
		response.result = 0;
		response.reserved = 0;
		response.reserved2 = 0;
		memcpy(staged.input, &response, sizeof(response));
		step->frame = &staged;
		error = ebpfos_continuation_step_method(step);
		if (error) {
			ebpfos_continuation_poison(session);
			break;
		}
		provider = ebpfos_binding_prog(step->binding);
		if (!provider) {
			ebpfos_continuation_poison(session);
			error = -ENOENT;
			break;
		}
		/*
		 * The provider runs against the staged frame, and the live frame
		 * is written only once the runner confirms the provider actually
		 * entered.  A pre-entry refusal -- a recursion-busy enter, an
		 * unsupported provider -- therefore leaves the previous
		 * provider's frame status, result and output exactly as that
		 * provider left them.
		 */
		error = ebpfos_executor_provider_run_leased(provider, &staged,
							    &step_status);
		if (error) {
			ebpfos_continuation_poison(session);
			break;
		}
		memcpy(frame, &staged, sizeof(*frame));
		*status = step_status;
		*prog_id = step->snapshot.prog_id;
		if (!ebpfos_executor_continuation_response_valid(
				frame, step->edge.ordinal, generation)) {
			ebpfos_continuation_poison(session);
			error = -EPROTO;
			break;
		}
		memcpy(&response, frame->output, sizeof(response));
		if (response.disposition != step->edge.disposition ||
		    response.transport_kind != step->edge.transport_kind) {
			ebpfos_continuation_poison(session);
			error = -EPROTOTYPE;
			break;
		}
		error = ebpfos_continuation_transport_validate(
			&step->edge, &response);
		if (error) {
			ebpfos_continuation_poison(session);
			break;
		}
		error = ebpfos_continuation_complete(session, generation,
						     response.disposition);
		if (error)
			break;
		if (ebpfos_continuation_state(session) != EBPFOS_SESSION_READY)
			break;
	}
	if (ebpfos_continuation_state(session) == EBPFOS_SESSION_POISONED &&
	    !error)
		error = -EPROTO;
	return error;
}

static int ebpfos_executor_continuation_call(
	struct bpf_prog_aux *aux, const struct ebpfos_executor_call *call,
	u64 epoch, u32 *status, u32 *prog_id)
{
	struct ebpfos_component_call_frame *frame = (void *)call->context;
	struct ebpfos_continuation_session session = {};
	struct ebpfos_continuation_edge edge = {};
	struct ebpfos_continuation_request request = {};
	u32 count = 0, index;
	int error;

	error = ebpfos_executor_continuation_frame_validate(call, epoch, frame,
							    &request);
	if (error)
		return error;
	error = ebpfos_admission_continuation_count(aux, &count);
	if (error)
		return error;
	/*
	 * No authenticated edges is a refusal, not an empty success: a caller
	 * that asks to continue something it never declared must be told so.
	 */
	if (!count || request.requested_disposition !=
			EBPFOS_CONTINUATION_DISPOSITION_CONTINUE)
		return -EKEYREJECTED;
	session.steps = kcalloc(count, sizeof(*session.steps), GFP_KERNEL);
	if (!session.steps)
		return -ENOMEM;
	session.object_id = call->object_id;
	session.epoch = epoch;
	memcpy(session.component_id, request.component_id,
	       sizeof(session.component_id));
	session.step_count = count;
	memcpy(session.boundary_digest, request.boundary_digest,
	       sizeof(session.boundary_digest));
	atomic_set(&session.state, EBPFOS_SESSION_READY);
	atomic64_set(&session.generation, 0);
	for (index = 0; index < count; index++) {
		error = ebpfos_admission_continuation_edge(aux, index, &edge);
		if (error)
			goto out_free;
		if (memcmp(edge.boundary_digest, session.boundary_digest,
			   sizeof(edge.boundary_digest))) {
			error = -EPROTOTYPE;
			goto out_free;
		}
		session.steps[index].edge = edge;
	}
	/*
	 * The chain must begin at the component the caller named and be
	 * continuous thereafter, so a manifest cannot splice unrelated edges.
	 */
	if (memcmp(session.steps[0].edge.source_component_id,
		   session.component_id, sizeof(session.component_id))) {
		error = -EPROTOTYPE;
		goto out_free;
	}
	for (index = 1; index < count; index++)
		if (memcmp(session.steps[index].edge.source_component_id,
			   session.steps[index - 1].edge.destination_component_id,
			   sizeof(session.steps[index].edge.source_component_id))) {
			error = -EPROTOTYPE;
			goto out_free;
		}
	/*
	 * The first destination must be the entry the caller was already
	 * admitted to, or the chain would start somewhere the ordinary call path
	 * never validated.  Its disposition must be the one the caller asked
	 * for, or the request and the manifest disagree about what this call is.
	 */
	if (session.steps[0].edge.destination_role_type != call->role_type ||
	    session.steps[0].edge.destination_method_id != call->method_id ||
	    session.steps[0].edge.disposition != request.requested_disposition) {
		error = -EPROTOTYPE;
		goto out_free;
	}
	error = ebpfos_continuation_acquire(aux, &session, count);
	if (error) {
		/*
		 * A partial acquisition must give back what it took, or a
		 * refused open would strand leases on bindings the caller never
		 * reached -- including a retired one, which would then never
		 * become collectable.
		 */
		ebpfos_continuation_release(&session);
		goto out_free;
	}
	error = ebpfos_continuation_arenas_validate(aux, &session);
	if (!error)
		error = ebpfos_continuation_drive(aux, &session, frame, status,
						  prog_id);
	ebpfos_continuation_release(&session);
out_free:
	kfree(session.steps);
	return error;
}

noinline int bpf_ebpfos_executor_root_call_impl(
	void *call_data, u32 call_data__sz, struct bpf_prog_aux *aux)
{
	struct ebpfos_executor_call *call = call_data;
	struct ebpfos_executor_root_role_snapshot role = {};
	struct ebpfos_executor_import import = {};
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
	binding = ebpfos_executor_root_role_get(call->object_id,
						call->role_type, &epoch, &role);
	if (!binding)
		return -ENOENT;
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
	error = ebpfos_admission_import_validate(aux, call->object_id,
					 call->role_type, call->method_id, descriptor,
					 &role, &import);
	if (error)
		goto out_put;
	if ((call->flags & EBPFOS_EXECUTOR_CALL_F_EXPECT_EPOCH) &&
	    call->expected_epoch != epoch) {
		error = -ESTALE;
		goto out_put;
	}
	if (call->context_size != import.context_size) {
		error = -EMSGSIZE;
		goto out_put;
	}
	/*
	 * The discriminator check is not optional on either path: it is what
	 * stops a caller naming one method and sending another.  A
	 * continuation call is admitted exactly as an ordinary one is, then
	 * drives a private session rather than this single provider.
	 */
	error = ebpfos_executor_method_validate(call, &import);
	if (error)
		goto out_put;
	/*
	 * A continuation call drives a private session rather than this one
	 * provider.  The role the caller named is the entry step, so it is
	 * validated exactly as above first; the session then pins every
	 * further step on this same epoch.
	 */
	if (call->flags & EBPFOS_EXECUTOR_CALL_F_CONTINUATION) {
		u32 continuation_prog_id = 0;

		error = ebpfos_executor_continuation_call(
			aux, call, epoch, &status, &continuation_prog_id);
		/*
		 * A dispatcher or session failure before any provider ran leaves
		 * all three reports zero, so a caller cannot mistake a protocol
		 * failure for a provider result.  Once a provider did run, its
		 * own status and identity are reported even though the call
		 * still returns the structural error.
		 */
		if (continuation_prog_id) {
			call->observed_epoch = epoch;
			call->provider_prog_id = continuation_prog_id;
			call->provider_status = status;
		}
		goto out_put;
	}
	/*
	 * The binding reference is the in-flight epoch pin.  Publication may
	 * replace and RCU-retire the old immutable bundle concurrently, but its
	 * program remains alive until this exact invocation has returned.
	 */
	error = ebpfos_executor_provider_run(binding, provider, call->context,
					     &status);
	if (error) {
		if (error == -ESHUTDOWN) {
			ebpfos_binding_put(binding);
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
	ebpfos_binding_put(binding);
	return error;
}

__bpf_kfunc int bpf_ebpfos_executor_root_call(
	void *call_data, u32 call_data__sz, struct bpf_prog_aux *aux)
{
	return bpf_ebpfos_executor_root_call_impl(call_data, call_data__sz, aux);
}

__bpf_kfunc_end_defs();

struct ebpfos_binding *ebpfos_executor_root_binding_get(
	u64 object_id, u64 role_type, u64 *epoch)
{
	struct ebpfos_executor_root_role_snapshot snapshot;
	u64 observed_epoch;

	if (!object_id || !role_type)
		return NULL;
	if (!epoch)
		epoch = &observed_epoch;
	return ebpfos_executor_root_role_get(object_id, role_type, epoch,
					     &snapshot);
}

BTF_KFUNCS_START(ebpfos_executor_root_kfunc_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_executor_root_publish,
		     KF_IMPLICIT_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_executor_root_read,
		     KF_IMPLICIT_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_executor_root_call,
		     KF_IMPLICIT_ARGS | KF_SLEEPABLE)
BTF_KFUNCS_END(ebpfos_executor_root_kfunc_ids)

bool ebpfos_executor_root_kfunc_allowed(u32 btf_id)
{
	return btf_id_set8_contains(&ebpfos_executor_root_kfunc_ids, btf_id);
}

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
	struct ebpfos_binding *predecessors[1] = {};
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
	source->authority = target->authority = 3;
	source->role_count = target->role_count = 1;
	source->roles[0].snapshot.role_type = 9;
	target->roles[0].snapshot.role_type = 9;
	source->roles[0].snapshot.authority = 3;
	target->roles[0].snapshot.authority = 3;
	source->roles[0].snapshot.contract_digest[0] = 0xaa;
	target->roles[0].snapshot.contract_digest[0] = 0xaa;
	source->roles[0].binding = (void *)0x10UL;

	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_source_validate(
		&request, source, target, predecessors), 0);
	KUNIT_EXPECT_PTR_EQ(test, predecessors[0], source->roles[0].binding);
	request.expected_epoch--;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_source_validate(
		&request, source, target, predecessors), -ESTALE);
	request.expected_epoch++;
	target->roles[0].snapshot.role_type++;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_source_validate(
		&request, source, target, predecessors), -EPROTOTYPE);
	target->roles[0].snapshot.role_type--;
	target->roles[0].snapshot.contract_digest[0]++;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_source_validate(
		&request, source, target, predecessors), -EPROTOTYPE);
	target->roles[0].snapshot.contract_digest[0]--;
	target->authority = 7;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_source_validate(
		&request, source, target, predecessors), -EACCES);
	target->authority = source->authority;
	target->roles[0].snapshot.authority = 7;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_source_validate(
		&request, source, target, predecessors), -EACCES);
	target->roles[0].snapshot.authority = 3;
	target->role_count = 2;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_source_validate(
		&request, source, target, predecessors), -ESTALE);
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
	size_t snapshot_size = sizeof(struct ebpfos_executor_root_snapshot) +
		2 * sizeof(struct ebpfos_executor_root_role_snapshot);
	size_t live_snapshot_size = sizeof(struct ebpfos_executor_root_snapshot) +
		sizeof(struct ebpfos_executor_root_role_snapshot);
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
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_snapshot_size(
		1, snapshot_size, &expected_size), 0);
	KUNIT_EXPECT_EQ(test, expected_size, live_snapshot_size);
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_snapshot_size(
		2, live_snapshot_size, &expected_size), -ENOSPC);
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_snapshot_size(
		1, snapshot_size - 1, &expected_size), -ENOSPC);
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
	call->version = EBPFOS_EXECUTOR_IMPORT_MANIFEST_VERSION;
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

static void ebpfos_executor_method_test(struct kunit *test)
{
	struct ebpfos_executor_import import = {
		.method_id = 5,
		.context_size = 16,
		.discriminator_offset = 3,
		.discriminator_size = 4,
		.discriminator_value = 0x11223344,
		.discriminator_mask = U32_MAX,
	};
	struct ebpfos_executor_call *call;
	size_t size = sizeof(*call) + import.context_size;

	call = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, call);
	call->method_id = import.method_id;
	call->context_size = import.context_size;
	put_unaligned_le32(import.discriminator_value, call->context + 3);
	KUNIT_EXPECT_EQ(test, ebpfos_executor_method_validate(call, &import), 0);
	call->context[3]++;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_method_validate(call, &import),
			-EACCES);
	call->context[3]--;
	import.discriminator_size = 3;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_method_validate(call, &import),
			-EPROTO);
	import.discriminator_size = 4;
	import.discriminator_offset = 14;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_method_validate(call, &import),
			-EPROTO);
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

static void ebpfos_executor_root_manifest_test(struct kunit *test)
{
	struct ebpfos_executor_root_manifest *manifest;
	struct ebpfos_executor_root_bundle *target;
	struct ebpfos_executor_root_role_snapshot *actual;

	manifest = kunit_kzalloc(test, sizeof(*manifest), GFP_KERNEL);
	target = kunit_kzalloc(test, struct_size(target, roles, 1), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, manifest);
	KUNIT_ASSERT_NOT_NULL(test, target);
	manifest->version = EBPFOS_EXECUTOR_ROOT_ABI_VERSION;
	manifest->role_count = 1;
	manifest->object_id = 7;
	manifest->authority_ceiling = 3;
	manifest->roles[0].role_type = 9;
	manifest->roles[0].provider_type_id = 11;
	manifest->roles[0].schema = 13;
	manifest->roles[0].authority = 3;
	target->object_id = manifest->object_id;
	target->role_count = manifest->role_count;
	target->authority = manifest->authority_ceiling;
	actual = &target->roles[0].snapshot;
	actual->role_type = manifest->roles[0].role_type;
	actual->provider_type_id = manifest->roles[0].provider_type_id;
	actual->schema = manifest->roles[0].schema;
	actual->authority = manifest->roles[0].authority;
	actual->content_digest[0] = manifest->roles[0].content_digest[0] = 0xaa;
	actual->contract_digest[0] = manifest->roles[0].contract_digest[0] = 0xbb;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_manifest_validate(
		manifest, target), 0);
	actual->role_type++;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_manifest_validate(
		manifest, target), -EPROTOTYPE);
	actual->role_type--;
	actual->provider_type_id++;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_manifest_validate(
		manifest, target), -EPROTOTYPE);
	actual->provider_type_id--;
	actual->schema++;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_manifest_validate(
		manifest, target), -EPROTOTYPE);
	actual->schema--;
	actual->authority = 1;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_manifest_validate(
		manifest, target), -EPROTOTYPE);
	actual->authority = manifest->roles[0].authority;
	actual->content_digest[0]++;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_manifest_validate(
		manifest, target), -EPROTOTYPE);
}


/*
 * A continuation session pinned to a published bundle.
 *
 * The session is a value of one call's frame, so these tests drive the state
 * machine directly.  The honest questions are whether the state transition, the
 * generation, the lease accounting and the response validation behave under
 * replay, skipping, abandonment, concurrency and retirement.
 */
static void ebpfos_continuation_generation_test(struct kunit *test)
{
	struct ebpfos_continuation_step steps[3] = {};
	struct ebpfos_continuation_session session = {};
	struct ebpfos_continuation_step *step = NULL;
	u64 generation = 0;

	steps[0].edge.ordinal = 10;
	steps[1].edge.ordinal = 20;
	steps[2].edge.ordinal = 30;
	session.step_count = 3;
	session.steps = steps;
	atomic_set(&session.state, EBPFOS_SESSION_READY);
	atomic64_set(&session.generation, 0);

	KUNIT_ASSERT_EQ(test,
			ebpfos_continuation_claim(&session, &step, &generation), 0);
	KUNIT_EXPECT_PTR_EQ(test, step, &steps[0]);
	KUNIT_EXPECT_EQ(test, generation, 0ULL);
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_state(&session),
			EBPFOS_SESSION_EXECUTING);
	/* A claim while one is in flight is refused as busy. */
	KUNIT_EXPECT_EQ(test,
			ebpfos_continuation_claim(&session, &step, &generation),
			-EBUSY);
	/*
	 * The generation advances only on a valid completion, so an abandoned
	 * step leaves the chain where it was.
	 */
	KUNIT_EXPECT_EQ(test, (u64)atomic64_read(&session.generation), 0ULL);
	KUNIT_ASSERT_EQ(test, ebpfos_continuation_complete(
		&session, 0, EBPFOS_CONTINUATION_DISPOSITION_CONTINUE), 0);
	KUNIT_EXPECT_EQ(test, (u64)atomic64_read(&session.generation), 1ULL);
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_state(&session),
			EBPFOS_SESSION_READY);
	/* Replaying a completed generation must fail. */
	KUNIT_ASSERT_EQ(test,
			ebpfos_continuation_claim(&session, &step, &generation), 0);
	KUNIT_EXPECT_EQ(test, generation, 1ULL);
	KUNIT_EXPECT_PTR_EQ(test, step, &steps[1]);
	KUNIT_ASSERT_EQ(test, ebpfos_continuation_complete(
		&session, 1, EBPFOS_CONTINUATION_DISPOSITION_CONTINUE), 0);
	KUNIT_ASSERT_EQ(test,
			ebpfos_continuation_claim(&session, &step, &generation), 0);
	KUNIT_EXPECT_PTR_EQ(test, step, &steps[2]);
	/* A terminal disposition consumes the chain on completion. */
	KUNIT_ASSERT_EQ(test, ebpfos_continuation_complete(
		&session, 2, EBPFOS_CONTINUATION_DISPOSITION_COMPLETE), 0);
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_state(&session),
			EBPFOS_SESSION_CONSUMED);
	/* Use after terminal completion stays refused. */
	KUNIT_EXPECT_EQ(test,
			ebpfos_continuation_claim(&session, &step, &generation),
			-EALREADY);
}

/*
 * A continue past the last authenticated edge has nowhere to go, so the chain
 * is poisoned rather than silently ending: the operation is incomplete and must
 * not be resumable.
 */
static void ebpfos_continuation_terminal_boundary_test(struct kunit *test)
{
	struct ebpfos_continuation_step steps[1] = {};
	struct ebpfos_continuation_session session = {};
	struct ebpfos_continuation_step *step = NULL;
	u64 generation = 0;

	steps[0].edge.ordinal = 5;
	session.step_count = 1;
	session.steps = steps;
	atomic_set(&session.state, EBPFOS_SESSION_READY);
	atomic64_set(&session.generation, 0);
	KUNIT_ASSERT_EQ(test,
			ebpfos_continuation_claim(&session, &step, &generation), 0);
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_complete(
		&session, 0, EBPFOS_CONTINUATION_DISPOSITION_CONTINUE),
		-EPROTOTYPE);
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_state(&session),
			EBPFOS_SESSION_POISONED);
	KUNIT_EXPECT_EQ(test,
			ebpfos_continuation_claim(&session, &step, &generation),
			-EALREADY);
}

/* An out-of-vocabulary disposition poisons rather than advancing. */
static void ebpfos_continuation_disposition_test(struct kunit *test)
{
	struct ebpfos_continuation_step steps[2] = {};
	struct ebpfos_continuation_session session = {};
	struct ebpfos_continuation_step *step = NULL;
	u64 generation = 0;

	steps[0].edge.ordinal = 1;
	steps[1].edge.ordinal = 2;
	session.step_count = 2;
	session.steps = steps;
	atomic_set(&session.state, EBPFOS_SESSION_READY);
	atomic64_set(&session.generation, 0);
	KUNIT_ASSERT_EQ(test,
			ebpfos_continuation_claim(&session, &step, &generation), 0);
	KUNIT_EXPECT_EQ(test,
			ebpfos_continuation_complete(&session, 0, 0), -EPROTO);
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_state(&session),
			EBPFOS_SESSION_POISONED);
	/* A poisoned session never becomes usable again. */
	KUNIT_EXPECT_EQ(test,
			ebpfos_continuation_claim(&session, &step, &generation),
			-EALREADY);
}

/*
 * A response is accepted only when the provider actually produced one, at the
 * exact size and for this step.  Silence must not read as success, which is why
 * the marker and the echoed ordinal/generation are required.
 */
static void ebpfos_continuation_response_validity_test(struct kunit *test)
{
	struct ebpfos_component_call_frame frame = {};
	struct ebpfos_continuation_transition response = {};

	KUNIT_EXPECT_FALSE(test, ebpfos_executor_continuation_response_valid(
		&frame, 1, 0));
	response.magic = EBPFOS_CONTINUATION_RESPONSE_MAGIC;
	response.response_size = EBPFOS_CONTINUATION_RESPONSE_SIZE;
	response.ordinal = 1;
	response.generation = 0;
	response.disposition = EBPFOS_CONTINUATION_DISPOSITION_CONTINUE;
	memcpy(frame.output, &response, sizeof(response));
	frame.output_size = 0;
	KUNIT_EXPECT_FALSE(test, ebpfos_executor_continuation_response_valid(
		&frame, 1, 0));
	frame.output_size = sizeof(response) - 1;
	KUNIT_EXPECT_FALSE(test, ebpfos_executor_continuation_response_valid(
		&frame, 1, 0));
	frame.output_size = sizeof(response) + 1;
	KUNIT_EXPECT_FALSE(test, ebpfos_executor_continuation_response_valid(
		&frame, 1, 0));
	frame.output_size = EBPFOS_CONTINUATION_RESPONSE_SIZE;
	KUNIT_EXPECT_TRUE(test, ebpfos_executor_continuation_response_valid(
		&frame, 1, 0));
	/* A response for another step is stale, not valid. */
	KUNIT_EXPECT_FALSE(test, ebpfos_executor_continuation_response_valid(
		&frame, 2, 0));
	KUNIT_EXPECT_FALSE(test, ebpfos_executor_continuation_response_valid(
		&frame, 1, 1));
	response.reserved = 1;
	memcpy(frame.output, &response, sizeof(response));
	KUNIT_EXPECT_FALSE(test, ebpfos_executor_continuation_response_valid(
		&frame, 1, 0));
	response.reserved = 0;
	response.disposition = 0;
	memcpy(frame.output, &response, sizeof(response));
	KUNIT_EXPECT_FALSE(test, ebpfos_executor_continuation_response_valid(
		&frame, 1, 0));
}

/*
 * Releasing gives back exactly the leases taken.  A step that shared another
 * step's binding holds the pointer but owns no lease, so it must not release
 * one: that is what keeps the accounting exactly-once.
 */
static void ebpfos_continuation_release_test(struct kunit *test)
{
	struct ebpfos_continuation_session session = {};
	struct ebpfos_continuation_step steps[3] = {};
	struct ebpfos_binding binding = {};

	refcount_set(&binding.refs, 2);
	atomic64_set(&binding.invocation_state, 0);
	steps[0].binding = &binding;
	steps[0].lease_held = true;
	/* A reused step holds the pointer but no lease of its own. */
	steps[1].binding = &binding;
	steps[1].lease_held = false;
	KUNIT_ASSERT_EQ(test, ebpfos_binding_invocation_enter(&binding), 0);
	session.steps = steps;
	session.step_count = 3;
	KUNIT_EXPECT_EQ(test, ebpfos_binding_active_invocations(&binding), 1U);
	ebpfos_continuation_release(&session);
	/* Exactly one lease was given back, not two. */
	KUNIT_EXPECT_EQ(test, ebpfos_binding_active_invocations(&binding), 0U);
	KUNIT_EXPECT_FALSE(test, steps[0].lease_held);
	KUNIT_EXPECT_NULL(test, steps[0].binding);
	KUNIT_EXPECT_EQ(test, refcount_read(&binding.refs), 1);
}

/*
 * A retired binding cannot be leased.  This is the publication-before-open
 * direction: once publication retires a removed binding, a session that did not
 * already hold its lease cannot take one.
 */
static void ebpfos_continuation_retired_binding_test(struct kunit *test)
{
	struct ebpfos_binding binding = {};

	refcount_set(&binding.refs, 1);
	atomic64_set(&binding.invocation_state, 0);
	ebpfos_binding_retire(&binding, 9);
	KUNIT_EXPECT_EQ(test, ebpfos_binding_invocation_enter(&binding),
			-ESHUTDOWN);
	KUNIT_EXPECT_TRUE(test, ebpfos_binding_is_retired(&binding));
}

/*
 * A lease taken before retirement still counts, which is how a continuation that
 * opened first completes wholly on its own epoch.
 */
static void ebpfos_continuation_lease_before_retirement_test(struct kunit *test)
{
	struct ebpfos_binding binding = {};

	refcount_set(&binding.refs, 1);
	atomic64_set(&binding.invocation_state, 0);
	KUNIT_ASSERT_EQ(test, ebpfos_binding_invocation_enter(&binding), 0);
	ebpfos_binding_retire(&binding, 9);
	KUNIT_EXPECT_EQ(test, ebpfos_binding_active_invocations(&binding), 1U);
	KUNIT_EXPECT_EQ(test, ebpfos_binding_invocation_enter(&binding),
			-ESHUTDOWN);
	ebpfos_binding_invocation_exit(&binding);
	KUNIT_EXPECT_EQ(test, ebpfos_binding_active_invocations(&binding), 0U);
}

static void ebpfos_executor_continuation_call_size_test(struct kunit *test)
{
	struct ebpfos_executor_call *call;
	size_t size = sizeof(*call) + 64;

	call = kunit_kzalloc(test, size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, call);
	call->version = EBPFOS_EXECUTOR_IMPORT_MANIFEST_VERSION;
	call->object_id = 7;
	call->role_type = 9;
	call->method_id = 1;
	call->context_size = 64;
	call->flags = EBPFOS_EXECUTOR_CALL_F_CONTINUATION;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_call_size(call, size), 0);
	/* The epoch expectation composes with the continuation flag. */
	call->flags = EBPFOS_EXECUTOR_CALL_F_CONTINUATION |
		      EBPFOS_EXECUTOR_CALL_F_EXPECT_EPOCH;
	call->expected_epoch = 3;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_call_size(call, size), 0);
	/* An unknown flag is still refused. */
	call->flags = BIT(3);
	KUNIT_EXPECT_EQ(test, ebpfos_executor_call_size(call, size), -EINVAL);
	call->flags = EBPFOS_EXECUTOR_CALL_F_CONTINUATION | BIT(3);
	KUNIT_EXPECT_EQ(test, ebpfos_executor_call_size(call, size), -EINVAL);
	/* A continuation call must still declare its method and object. */
	call->flags = EBPFOS_EXECUTOR_CALL_F_CONTINUATION;
	call->method_id = 0;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_call_size(call, size), -EINVAL);
}

/*
 * The frame and request are validated before either is used.
 *
 * Everything here is untrusted input, so a malformed frame must fail before a
 * value is read out of it: a context too small to hold a frame, or a frame whose
 * version, flags, object, epoch or method disagrees with the call, is refused
 * rather than partially consumed.
 */
static void ebpfos_executor_continuation_frame_test(struct kunit *test)
{
	struct ebpfos_executor_call *call;
	struct ebpfos_component_call_frame *frame;
	struct ebpfos_continuation_request request = {};
	size_t size = sizeof(*call) + sizeof(*frame);
	u64 epoch = 5;

	call = kunit_kzalloc(test, size, GFP_KERNEL);
	frame = kunit_kzalloc(test, sizeof(*frame), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, call);
	KUNIT_ASSERT_NOT_NULL(test, frame);
	call->object_id = 7;
	call->method_id = 1;
	call->context_size = sizeof(*frame);
	frame->version = EBPFOS_COMPONENT_CALL_ABI_VERSION;
	frame->object_id = call->object_id;
	frame->epoch = epoch;
	frame->method_id = call->method_id;
	memset(request.component_id, 0x11, sizeof(request.component_id));
	memset(request.boundary_digest, 0x22, sizeof(request.boundary_digest));
	request.requested_disposition = EBPFOS_CONTINUATION_DISPOSITION_CONTINUE;
	frame->input_size = sizeof(request);
	frame->output_capacity = EBPFOS_CONTINUATION_RESPONSE_SIZE;
	memcpy(frame->input, &request, sizeof(request));
	KUNIT_EXPECT_EQ(test, ebpfos_executor_continuation_frame_validate(
		call, epoch, frame, &request), 0);
	call->context_size = sizeof(*frame) - 1;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_continuation_frame_validate(
		call, epoch, frame, &request), -EMSGSIZE);
	call->context_size = sizeof(*frame);
	frame->object_id = call->object_id + 1;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_continuation_frame_validate(
		call, epoch, frame, &request), -EINVAL);
	frame->object_id = call->object_id;
	frame->epoch = epoch + 1;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_continuation_frame_validate(
		call, epoch, frame, &request), -EINVAL);
	frame->epoch = epoch;
	frame->method_id = call->method_id + 1;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_continuation_frame_validate(
		call, epoch, frame, &request), -EINVAL);
	frame->method_id = call->method_id;
	frame->version = EBPFOS_COMPONENT_CALL_ABI_VERSION + 1;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_continuation_frame_validate(
		call, epoch, frame, &request), -EINVAL);
	frame->version = EBPFOS_COMPONENT_CALL_ABI_VERSION;
	frame->flags = 1;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_continuation_frame_validate(
		call, epoch, frame, &request), -EINVAL);
	frame->flags = 0;
	frame->input_size = sizeof(request) + 1;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_continuation_frame_validate(
		call, epoch, frame, &request), -EINVAL);
	frame->input_size = sizeof(request);
	frame->output_capacity = EBPFOS_CONTINUATION_RESPONSE_SIZE - 1;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_continuation_frame_validate(
		call, epoch, frame, &request), -EINVAL);
	frame->output_capacity = EBPFOS_CONTINUATION_RESPONSE_SIZE;
	request.reserved = 1;
	memcpy(frame->input, &request, sizeof(request));
	KUNIT_EXPECT_EQ(test, ebpfos_executor_continuation_frame_validate(
		call, epoch, frame, &request), -EINVAL);
	request.reserved = 0;
	request.requested_disposition = 0;
	memcpy(frame->input, &request, sizeof(request));
	KUNIT_EXPECT_EQ(test, ebpfos_executor_continuation_frame_validate(
		call, epoch, frame, &request), -EINVAL);
	request.requested_disposition = EBPFOS_CONTINUATION_DISPOSITION_CONTINUE;
	memset(request.component_id, 0, sizeof(request.component_id));
	memcpy(frame->input, &request, sizeof(request));
	KUNIT_EXPECT_EQ(test, ebpfos_executor_continuation_frame_validate(
		call, epoch, frame, &request), -EINVAL);
	memset(request.component_id, 0x11, sizeof(request.component_id));
	memset(request.boundary_digest, 0, sizeof(request.boundary_digest));
	memcpy(frame->input, &request, sizeof(request));
	KUNIT_EXPECT_EQ(test, ebpfos_executor_continuation_frame_validate(
		call, epoch, frame, &request), -EINVAL);
}

/*
 * A step's discriminator is checked against the frame it was actually addressed
 * with.  The import says which method the step may serve; a frame that names
 * another one would have the provider act on a different identity than the
 * session believes, so it is refused before the provider runs.
 */
static void ebpfos_executor_continuation_step_method_test(struct kunit *test)
{
	struct ebpfos_executor_import import = {
		.method_id = 5,
		.context_size = EBPFOS_COMPONENT_CALL_CONTEXT_SIZE,
		.discriminator_offset = 8,
		.discriminator_size = 8,
		.discriminator_value = 5,
		.discriminator_mask = U64_MAX,
	};
	struct ebpfos_component_call_frame *frame;

	frame = kunit_kzalloc(test, sizeof(*frame), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, frame);
	frame->method_id = import.method_id;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_discriminator_check(
		frame, import.method_id, &import), 0);
	frame->method_id = import.method_id + 1;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_discriminator_check(
		frame, import.method_id, &import), -EACCES);
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_discriminator_check(
		frame, import.method_id + 1, &import), -EPROTO);
	import.discriminator_size = 3;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_discriminator_check(
		frame, import.method_id, &import), -EPROTO);
	import.discriminator_size = 8;
	import.discriminator_offset = EBPFOS_COMPONENT_CALL_CONTEXT_SIZE;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_discriminator_check(
		frame, import.method_id, &import), -EPROTO);
}

/*
 * End-to-end continuation chain, driven through the real execution path.
 *
 * The validators and the isolated state helpers are tested above, but those
 * cannot catch a defect that only appears when a provider actually runs: a NULL
 * step frame, a response that never arrives, scalars that fail to cross a step
 * boundary, or a failure that overwrites the reports of the provider that did
 * run.  These cases drive `ebpfos_continuation_drive()` with real fake
 * providers, so the whole path is exercised rather than its pieces.
 */
struct ebpfos_continuation_test_plan {
	/* What step n reports back. */
	u32 disposition;
	u64 scalar0;
	u32 frame_status;
	/* Whether the provider writes a response at all. */
	bool respond;
};

static struct ebpfos_continuation_test_plan *ebpfos_continuation_test_state;
/* What each step actually observed in its request, for cross-step assertions. */
static u64 ebpfos_continuation_test_observed[2];
static u32 ebpfos_continuation_test_observed_count;

/*
 * Hold a program's recursion slot for the duration of one drive, and give it
 * back on every exit path.
 *
 * `__bpf_prog_enter_sleepable_recur()` takes this per-CPU slot and refuses with
 * -EBUSY when it is already held -- the genuine pre-entry refusal path, taken
 * when the same program is already running here.  Holding it from the test
 * produces a real pre-entry -EBUSY without a mock.
 *
 * The counter is per-CPU, so the hold, the drive and the release must all run on
 * one CPU or the release would decrement a different CPU's counter and leave
 * the held one permanently raised.  `migrate_disable()` is the right primitive
 * for that: it pins the task to its CPU without disabling preemption, which is
 * exactly what the production sleepable path relies on when it calls
 * `might_fault()` after `migrate_disable()`.  `guard(migrate)()` scopes it to
 * this function, so cleanup is structural and cannot be skipped by an early
 * return or an error path.
 *
 * The caller's regions are pinned the same way; see the per-test `guard(migrate)()`.
 */
static void ebpfos_continuation_test_hold_recursion(struct bpf_prog *provider)
{
	guard(migrate)();
	this_cpu_inc(*(int __percpu *)provider->active);
}

static void ebpfos_continuation_test_release_recursion(
	struct bpf_prog *provider)
{
	guard(migrate)();
	this_cpu_dec(*(int __percpu *)provider->active);
}

/*
 * The provider's own recursion counter on this CPU.
 *
 * A per-CPU value is only meaningful while the task cannot migrate, so the
 * caller must already be inside a migration-pinned region: this asserts that
 * rather than taking its own nested guard, which would silently read whichever
 * CPU the task happened to be on.  A non-zero value after a release is a leak
 * that would refuse every later entry of that program; a negative one is the
 * underflow a release on a different CPU produces.
 */
static int ebpfos_continuation_test_recursion_count(
	struct bpf_prog *provider)
{
	lockdep_assert_preemption_enabled();
	/*
	 * `migration_disabled` is the task-level pin `migrate_disable()` sets, so
	 * this both documents and enforces the caller's obligation: a read
	 * outside a pinned region would be a per-CPU value of unknown CPU.
	 */
	WARN_ON_ONCE(!current->migration_disabled);
	return this_cpu_read(*(int __percpu *)provider->active);
}

static unsigned int ebpfos_continuation_test_provider(
	const void *context, const struct bpf_insn *insn)
{
	const struct ebpfos_component_call_frame *in = context;
	struct ebpfos_component_call_frame *frame = (void *)context;
	struct ebpfos_continuation_transition request = {};
	struct ebpfos_continuation_transition response = {};
	u64 index;

	memcpy(&request, in->input, sizeof(request));
	/*
	 * Record what this step actually received, so a test can prove the
	 * previous step's scalar really crossed the boundary into this one.
	 */
	index = request.generation > 1 ? 1 : request.generation;
	if (ebpfos_continuation_test_observed_count < 2)
		ebpfos_continuation_test_observed[
			ebpfos_continuation_test_observed_count++] =
			request.scalar[0];
	/*
	 * The provider answers the step it was given: it echoes the ordinal and
	 * generation it received, so a response can never be mistaken for
	 * another step's.
	 */
	response.ordinal = request.ordinal;
	response.generation = request.generation;
	response.transport_kind = request.transport_kind;
	if (!ebpfos_continuation_test_state)
		return 0;
	(void)index;
	response.disposition =
		ebpfos_continuation_test_state[index].disposition;
	response.scalar[0] = ebpfos_continuation_test_state[index].scalar0;
	/*
	 * A provider that does not answer leaves the frame untouched, which is
	 * exactly the silence the driver must not read as success.
	 */
	if (!ebpfos_continuation_test_state[index].respond)
		return 0x11;
	response.magic = EBPFOS_CONTINUATION_RESPONSE_MAGIC;
	response.response_size = EBPFOS_CONTINUATION_RESPONSE_SIZE;
	memcpy(frame->output, &response, sizeof(response));
	frame->status = ebpfos_continuation_test_state[index].frame_status;
	frame->output_size = EBPFOS_CONTINUATION_RESPONSE_SIZE;
	return 0x22;
}

static struct bpf_prog *ebpfos_continuation_test_prog(struct kunit *test)
{
	struct bpf_prog *provider;

	provider = bpf_prog_alloc(bpf_prog_size(1), 0);
	KUNIT_ASSERT_NOT_NULL(test, provider);
	KUNIT_ASSERT_EQ(test, kunit_add_action_or_reset(
		test, ebpfos_executor_test_prog_free, provider), 0);
	provider->type = BPF_PROG_TYPE_SYSCALL;
	provider->sleepable = true;
	provider->aux->ebpfos_component = true;
	provider->bpf_func = ebpfos_continuation_test_provider;
	return provider;
}

/*
 * Build a two-step session and bind one fake provider to both steps, so the
 * chain genuinely runs: step one continues and step two terminates.
 */
static void ebpfos_continuation_chain_setup(
	struct kunit *test, struct ebpfos_continuation_session *session,
	struct ebpfos_continuation_step *steps,
	struct ebpfos_binding *binding, struct bpf_prog *provider)
{
	steps[0].binding = binding;
	steps[1].binding = binding;
	binding->prog = provider;
	refcount_set(&binding->refs, 1);
	atomic64_set(&binding->invocation_state, 0);
	session->step_count = 2;
	session->steps = steps;
	atomic_set(&session->state, EBPFOS_SESSION_READY);
	atomic64_set(&session->generation, 0);
	steps[0].edge.ordinal = 1;
	steps[0].edge.destination_method_id = 5;
	steps[0].edge.disposition = EBPFOS_CONTINUATION_DISPOSITION_CONTINUE;
	steps[0].edge.transport_kind = EBPFOS_CONTINUATION_TRANSPORT_SCALAR;
	/*
	 * A real bound, not zero: a zero limit means the slot must be returned
	 * as zero, so a chain that carries a cursor needs the edge to declare
	 * the range it admits.  Step two inherits this through the copy below.
	 */
	steps[0].edge.scalar_limit[0] = 65536;
	steps[0].import.method_id = 5;
	steps[0].import.discriminator_offset = offsetof(
		struct ebpfos_component_call_frame, method_id);
	steps[0].import.discriminator_size = 8;
	steps[0].import.discriminator_value = 5;
	steps[0].import.discriminator_mask = U64_MAX;
	steps[0].snapshot.prog_id = 11;
	steps[1].edge = steps[0].edge;
	steps[1].import = steps[0].import;
	steps[1].snapshot = steps[0].snapshot;
	steps[1].edge.ordinal = 2;
	steps[1].edge.disposition = EBPFOS_CONTINUATION_DISPOSITION_COMPLETE;
	steps[1].snapshot.prog_id = 12;
}

/*
 * The chain completes and step two receives step one's scalar.
 *
 * This is the cross-step assertion: the fake provider records the input each
 * step was actually given, so a chain that silently dropped the carried scalar
 * would fail here even though every per-step validator passed.
 */
static void ebpfos_continuation_chain_test(struct kunit *test)
{
	struct ebpfos_continuation_test_plan plan[2] = {
		{ .disposition = EBPFOS_CONTINUATION_DISPOSITION_CONTINUE,
		  .scalar0 = 7, .frame_status = 0x100, .respond = true },
		{ .disposition = EBPFOS_CONTINUATION_DISPOSITION_COMPLETE,
		  .scalar0 = 9, .frame_status = 0x200, .respond = true },
	};
	struct ebpfos_continuation_step steps[2] = {};
	struct ebpfos_continuation_session session = {};
	struct ebpfos_component_call_frame frame = {};
	struct ebpfos_binding binding = {};
	struct bpf_prog *provider;
	u32 status = 0, prog_id = 0;

	provider = ebpfos_continuation_test_prog(test);
	ebpfos_continuation_chain_setup(test, &session, steps, &binding,
					provider);
	ebpfos_continuation_test_state = plan;
	ebpfos_continuation_test_observed_count = 0;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_drive(
		NULL, &session, &frame, &status, &prog_id), 0);
	ebpfos_continuation_test_state = NULL;
	/* Both steps ran, and the second saw the first step's scalar. */
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_test_observed_count, 2U);
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_test_observed[0], 0ULL);
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_test_observed[1], 7ULL);
	KUNIT_EXPECT_EQ(test, status, 0x22U);
	KUNIT_EXPECT_EQ(test, prog_id, 12U);
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_state(&session),
			EBPFOS_SESSION_CONSUMED);
	KUNIT_EXPECT_EQ(test, frame.status, 0x200);
	KUNIT_EXPECT_EQ(test, (u64)atomic64_read(&session.generation), 1ULL);
}

/* A provider that writes nothing must not be read as a completed step. */
static void ebpfos_continuation_silence_test(struct kunit *test)
{
	struct ebpfos_continuation_test_plan plan[2] = {
		{ .disposition = EBPFOS_CONTINUATION_DISPOSITION_CONTINUE,
		  .respond = false },
		{ .disposition = EBPFOS_CONTINUATION_DISPOSITION_COMPLETE,
		  .respond = true },
	};
	struct ebpfos_continuation_step steps[2] = {};
	struct ebpfos_continuation_session session = {};
	struct ebpfos_component_call_frame frame = {};
	struct ebpfos_binding binding = {};
	struct bpf_prog *provider;
	u32 status = 0, prog_id = 0;

	provider = ebpfos_continuation_test_prog(test);
	ebpfos_continuation_chain_setup(test, &session, steps, &binding,
					provider);
	ebpfos_continuation_test_state = plan;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_drive(
		NULL, &session, &frame, &status, &prog_id), -EPROTO);
	ebpfos_continuation_test_state = NULL;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_state(&session),
			EBPFOS_SESSION_POISONED);
	KUNIT_EXPECT_EQ(test, prog_id, 11U);
}

/* A scalar beyond its edge's limit is refused, whatever the disposition. */
static void ebpfos_continuation_scalar_bound_test(struct kunit *test)
{
	struct ebpfos_continuation_test_plan plan[2] = {
		{ .disposition = EBPFOS_CONTINUATION_DISPOSITION_CONTINUE,
		  .scalar0 = 1000, .respond = true },
		{ .disposition = EBPFOS_CONTINUATION_DISPOSITION_COMPLETE,
		  .respond = true },
	};
	struct ebpfos_continuation_step steps[2] = {};
	struct ebpfos_continuation_session session = {};
	struct ebpfos_component_call_frame frame = {};
	struct ebpfos_binding binding = {};
	struct bpf_prog *provider;
	u32 status = 0, prog_id = 0;

	provider = ebpfos_continuation_test_prog(test);
	ebpfos_continuation_chain_setup(test, &session, steps, &binding,
					provider);
	steps[0].edge.scalar_limit[0] = 100;
	ebpfos_continuation_test_state = plan;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_drive(
		NULL, &session, &frame, &status, &prog_id), -ERANGE);
	ebpfos_continuation_test_state = NULL;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_state(&session),
			EBPFOS_SESSION_POISONED);
}

/* A disposition the edge does not admit is a wrong answer, not accepted. */
static void ebpfos_continuation_disposition_mismatch_test(struct kunit *test)
{
	struct ebpfos_continuation_test_plan plan[2] = {
		{ .disposition = EBPFOS_CONTINUATION_DISPOSITION_COMPLETE,
		  .respond = true },
		{ .disposition = EBPFOS_CONTINUATION_DISPOSITION_COMPLETE,
		  .respond = true },
	};
	struct ebpfos_continuation_step steps[2] = {};
	struct ebpfos_continuation_session session = {};
	struct ebpfos_component_call_frame frame = {};
	struct ebpfos_binding binding = {};
	struct bpf_prog *provider;
	u32 status = 0, prog_id = 0;

	provider = ebpfos_continuation_test_prog(test);
	ebpfos_continuation_chain_setup(test, &session, steps, &binding,
					provider);
	ebpfos_continuation_test_state = plan;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_drive(
		NULL, &session, &frame, &status, &prog_id), -EPROTOTYPE);
	ebpfos_continuation_test_state = NULL;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_state(&session),
			EBPFOS_SESSION_POISONED);
}

/*
 * A second step refused before entry preserves everything the first reported.
 *
 * Two distinct providers are used so the refusal is genuinely a *second* step:
 * the first runs and succeeds, the second's recursion slot is held so its entry
 * refuses, and the caller must still see the first provider's frame status,
 * result, output and identity exactly as that provider left them.  Sharing one
 * provider could not express this, because holding its slot would refuse the
 * first step too.
 */
static void ebpfos_continuation_pre_entry_preservation_test(struct kunit *test)
{
	/*
	 * The plan, the steps, the frame and the bindings are all large, so they
	 * are allocated rather than stacked: a kernel stack frame this size is a
	 * defect in itself, and the other continuation cases already keep theirs
	 * within the limit.
	 */
	struct ebpfos_continuation_test_plan *plan;
	struct ebpfos_continuation_step *steps;
	struct ebpfos_continuation_session *session;
	struct ebpfos_component_call_frame *frame;
	struct ebpfos_binding *first_binding, *second_binding;
	struct bpf_prog *first, *second;
	u32 status = 0, prog_id = 0;
	u64 output_after_first;
	int error, held = 0, released = -1;

	plan = kunit_kzalloc(test, sizeof(*plan) * 2, GFP_KERNEL);
	steps = kunit_kzalloc(test, sizeof(*steps) * 2, GFP_KERNEL);
	session = kunit_kzalloc(test, sizeof(*session), GFP_KERNEL);
	frame = kunit_kzalloc(test, sizeof(*frame), GFP_KERNEL);
	first_binding = kunit_kzalloc(test, sizeof(*first_binding), GFP_KERNEL);
	second_binding = kunit_kzalloc(test, sizeof(*second_binding), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, plan);
	KUNIT_ASSERT_NOT_NULL(test, steps);
	KUNIT_ASSERT_NOT_NULL(test, session);
	KUNIT_ASSERT_NOT_NULL(test, frame);
	KUNIT_ASSERT_NOT_NULL(test, first_binding);
	KUNIT_ASSERT_NOT_NULL(test, second_binding);
	plan[0].disposition = EBPFOS_CONTINUATION_DISPOSITION_CONTINUE;
	plan[0].scalar0 = 7;
	plan[0].frame_status = 0x100;
	plan[0].respond = true;
	plan[1].disposition = EBPFOS_CONTINUATION_DISPOSITION_COMPLETE;
	plan[1].frame_status = 0x200;
	plan[1].respond = true;

	first = ebpfos_continuation_test_prog(test);
	second = ebpfos_continuation_test_prog(test);
	/*
	 * Step one is served by `first` and step two by `second`, so the two
	 * bindings are distinct and the second can be refused on its own.
	 */
	ebpfos_continuation_chain_setup(test, session, steps, first_binding,
					first);
	steps[1].binding = second_binding;
	second_binding->prog = second;
	refcount_set(&second_binding->refs, 1);
	atomic64_set(&second_binding->invocation_state, 0);
	ebpfos_continuation_test_state = plan;
	/*
	 * Hold the *second* provider's recursion slot.  Step one runs normally,
	 * and step two is refused before it enters.
	 *
	 * The whole hold -> drive -> release sequence runs migration-pinned: the
	 * slot is per-CPU, so if the task migrated between the hold and the
	 * release the release would decrement a different CPU's counter and
	 * leave the held one permanently raised.  `guard(migrate)()` does not
	 * disable preemption, so the sleepable provider inside the drive can
	 * still run and sleep normally.
	 */
	{
		guard(migrate)();

		ebpfos_continuation_test_hold_recursion(second);
		/*
		 * Both counts are read inside this region, on the CPU that holds
		 * the slot.  Reading the count after leaving the guard would be
		 * meaningless: the task may then be inspecting a different CPU's
		 * per-CPU counter, which is exactly the migration hazard the
		 * region exists to remove.
		 */
		held = ebpfos_continuation_test_recursion_count(second);
		error = ebpfos_continuation_drive(NULL, session, frame, &status,
						  &prog_id);
		ebpfos_continuation_test_release_recursion(second);
		released = ebpfos_continuation_test_recursion_count(second);
	}
	ebpfos_continuation_test_state = NULL;
	KUNIT_EXPECT_EQ(test, held, 1);
	/*
	 * The held slot was given back on the CPU it was taken on: no leak
	 * (which would refuse every later entry of this program) and no
	 * underflow (which is what a release on another CPU produces).
	 */
	KUNIT_EXPECT_EQ(test, released, 0);
	KUNIT_EXPECT_EQ(test, error, -EBUSY);
	/* Step one ran, so the reports are step one's, not step two's. */
	KUNIT_EXPECT_EQ(test, status, 0x22U);
	KUNIT_EXPECT_EQ(test, prog_id, 11U);
	/* The first provider's frame status and output survived the refusal. */
	KUNIT_EXPECT_EQ(test, frame->status, 0x100);
	KUNIT_EXPECT_EQ(test, frame->output_size,
			EBPFOS_CONTINUATION_RESPONSE_SIZE);
	memcpy(&output_after_first, frame->output, sizeof(u64));
	KUNIT_EXPECT_EQ(test, output_after_first,
			(u64)EBPFOS_CONTINUATION_RESPONSE_MAGIC);
	/* And the session is unusable afterwards. */
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_state(session),
			EBPFOS_SESSION_POISONED);
}

/*
 * The runner itself refuses before entry with -EBUSY, and nothing is attributed.
 *
 * The refusal is produced by the real recursion-busy check the runner performs,
 * not by a mock: the provider's own recursion slot is held on this CPU, so
 * `__bpf_prog_enter_sleepable_recur()` returns zero and the runner reports
 * -EBUSY before any provider code executes.
 */
static void ebpfos_continuation_busy_entry_test(struct kunit *test)
{
	struct ebpfos_continuation_test_plan plan[2] = {
		{ .disposition = EBPFOS_CONTINUATION_DISPOSITION_CONTINUE,
		  .scalar0 = 7, .respond = true },
		{ .disposition = EBPFOS_CONTINUATION_DISPOSITION_COMPLETE,
		  .respond = true },
	};
	struct ebpfos_continuation_step steps[2] = {};
	struct ebpfos_continuation_session session = {};
	struct ebpfos_component_call_frame frame = {};
	struct ebpfos_binding binding = {};
	struct bpf_prog *provider;
	u32 status = 0, prog_id = 0;
	int error, held = 0, released = -1;

	provider = ebpfos_continuation_test_prog(test);
	ebpfos_continuation_chain_setup(test, &session, steps, &binding,
					provider);
	ebpfos_continuation_test_state = plan;
	ebpfos_continuation_test_observed_count = 0;
	/*
	 * Hold -> drive -> release as one migration-pinned region.  The recursion
	 * slot is per-CPU, so the hold and the release must happen on the CPU the
	 * drive refused on, or the release would land on another CPU's counter.
	 */
	{
		guard(migrate)();

		ebpfos_continuation_test_hold_recursion(provider);
		/*
		 * Both counts are read inside this region, on the CPU that holds
		 * the slot: `held` proves the -EBUSY below comes from a genuinely
		 * raised counter, and `released` proves it was given back there.
		 * Reading either after leaving the guard would be meaningless,
		 * because the task may then be inspecting another CPU's counter.
		 */
		held = ebpfos_continuation_test_recursion_count(provider);
		error = ebpfos_continuation_drive(NULL, &session, &frame,
						  &status, &prog_id);
		ebpfos_continuation_test_release_recursion(provider);
		released = ebpfos_continuation_test_recursion_count(provider);
	}
	ebpfos_continuation_test_state = NULL;
	KUNIT_EXPECT_EQ(test, held, 1);
	KUNIT_EXPECT_EQ(test, released, 0);
	KUNIT_EXPECT_EQ(test, error, -EBUSY);
	/* The provider never ran, so nothing observed and nothing attributed. */
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_test_observed_count, 0U);
	KUNIT_EXPECT_EQ(test, prog_id, 0U);
	KUNIT_EXPECT_EQ(test, status, 0U);
	KUNIT_EXPECT_EQ(test, frame.status, 0);
	KUNIT_EXPECT_EQ(test, frame.output_size, 0U);
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_state(&session),
			EBPFOS_SESSION_POISONED);
	/* And the session cannot be resumed after the refusal. */
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_drive(
		NULL, &session, &frame, &status, &prog_id), -EALREADY);
}

/* A per-step discriminator mismatch is refused before the provider enters. */
static void ebpfos_continuation_step_refusal_test(struct kunit *test)
{
	struct ebpfos_continuation_test_plan plan[2] = {
		{ .disposition = EBPFOS_CONTINUATION_DISPOSITION_CONTINUE,
		  .respond = true },
		{ .disposition = EBPFOS_CONTINUATION_DISPOSITION_COMPLETE,
		  .respond = true },
	};
	struct ebpfos_continuation_step steps[2] = {};
	struct ebpfos_continuation_session session = {};
	struct ebpfos_component_call_frame frame = {};
	struct ebpfos_binding binding = {};
	struct bpf_prog *provider;
	u32 status = 0, prog_id = 0;

	provider = ebpfos_continuation_test_prog(test);
	ebpfos_continuation_chain_setup(test, &session, steps, &binding,
					provider);
	steps[0].edge.destination_method_id = 6;
	ebpfos_continuation_test_state = plan;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_drive(
		NULL, &session, &frame, &status, &prog_id), -EPROTO);
	ebpfos_continuation_test_state = NULL;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_state(&session),
			EBPFOS_SESSION_POISONED);
	KUNIT_EXPECT_EQ(test, prog_id, 0U);
}
static void ebpfos_continuation_arena_binding_test(struct kunit *test)
{
	struct bpf_prog_aux *caller, *provider_aux;
	struct bpf_map *arena, *other;
	struct bpf_prog *provider;
	struct ebpfos_binding *binding;
	struct ebpfos_continuation_step *step;
	struct ebpfos_continuation_session *session;
	struct bpf_map *caller_maps[2], *provider_maps[2];

	caller = kunit_kzalloc(test, sizeof(*caller), GFP_KERNEL);
	provider_aux = kunit_kzalloc(test, sizeof(*provider_aux), GFP_KERNEL);
	arena = kunit_kzalloc(test, sizeof(*arena), GFP_KERNEL);
	other = kunit_kzalloc(test, sizeof(*other), GFP_KERNEL);
	provider = kunit_kzalloc(test, sizeof(*provider), GFP_KERNEL);
	binding = kunit_kzalloc(test, sizeof(*binding), GFP_KERNEL);
	step = kunit_kzalloc(test, sizeof(*step), GFP_KERNEL);
	session = kunit_kzalloc(test, sizeof(*session), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, caller);
	KUNIT_ASSERT_NOT_NULL(test, provider_aux);
	KUNIT_ASSERT_NOT_NULL(test, arena);
	KUNIT_ASSERT_NOT_NULL(test, other);
	KUNIT_ASSERT_NOT_NULL(test, provider);
	KUNIT_ASSERT_NOT_NULL(test, binding);
	KUNIT_ASSERT_NOT_NULL(test, step);
	KUNIT_ASSERT_NOT_NULL(test, session);
	mutex_init(&caller->used_maps_mutex);
	mutex_init(&provider_aux->used_maps_mutex);
	arena->map_type = BPF_MAP_TYPE_ARENA;
	arena->max_entries = 2;
	caller_maps[0] = arena;
	provider_maps[0] = arena;
	caller->used_maps = caller_maps;
	caller->used_map_cnt = 1;
	provider_aux->used_maps = provider_maps;
	provider_aux->used_map_cnt = 1;
	provider->aux = provider_aux;
	binding->prog = provider;
	step->binding = binding;
	step->edge.transport_kind =
		EBPFOS_CONTINUATION_TRANSPORT_ARENA_RANGE;
	step->edge.scalar_limit[0] = 2 * PAGE_SIZE;
	session->step_count = 1;
	session->steps = step;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_arenas_validate(caller,
							   session), 0);
	arena->max_entries = 1;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_arenas_validate(caller,
							   session), -EACCES);
	arena->max_entries = 2;
	other->map_type = arena->map_type;
	other->max_entries = arena->max_entries;
	provider_maps[0] = other;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_arenas_validate(caller,
							   session), -EACCES);
	provider_maps[0] = arena;
	caller_maps[1] = other;
	provider_maps[1] = other;
	caller->used_map_cnt = 2;
	provider_aux->used_map_cnt = 2;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_arenas_validate(caller,
							   session), -EACCES);
	caller->used_map_cnt = 1;
	provider_aux->used_map_cnt = 1;
	arena->map_type = BPF_MAP_TYPE_ARRAY;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_arenas_validate(caller,
							   session), -EACCES);
}

static void ebpfos_continuation_arena_range_test(struct kunit *test)
{
	struct ebpfos_continuation_edge edge = {};
	struct ebpfos_continuation_transition response = {};

	edge.transport_kind = EBPFOS_CONTINUATION_TRANSPORT_ARENA_RANGE;
	edge.scalar_limit[0] = 8192;
	edge.scalar_limit[1] = 4096;
	response.scalar[0] = 4096;
	response.scalar[1] = 4096;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_transport_validate(&edge,
							       &response), 0);
	response.scalar[0] = 8191;
	response.scalar[1] = 2;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_transport_validate(&edge,
							       &response), -ERANGE);
	response.scalar[0] = U64_MAX;
	response.scalar[1] = 1;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_transport_validate(&edge,
							       &response), -ERANGE);
	response.scalar[0] = 0;
	response.scalar[1] = 0;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_transport_validate(&edge,
							       &response), -ERANGE);
	response.scalar[1] = 4097;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_transport_validate(&edge,
							       &response), -ERANGE);
}


static struct kunit_case ebpfos_executor_root_cases[] = {
	KUNIT_CASE(ebpfos_executor_root_compare_test),
	KUNIT_CASE(ebpfos_executor_root_retained_binding_test),
	KUNIT_CASE(ebpfos_executor_root_request_test),
	KUNIT_CASE(ebpfos_executor_root_call_size_test),
	KUNIT_CASE(ebpfos_executor_method_test),
	KUNIT_CASE(ebpfos_executor_provider_run_test),
	KUNIT_CASE(ebpfos_continuation_generation_test),
	KUNIT_CASE(ebpfos_continuation_terminal_boundary_test),
	KUNIT_CASE(ebpfos_continuation_disposition_test),
	KUNIT_CASE(ebpfos_continuation_response_validity_test),
	KUNIT_CASE(ebpfos_continuation_release_test),
	KUNIT_CASE(ebpfos_continuation_retired_binding_test),
	KUNIT_CASE(ebpfos_continuation_lease_before_retirement_test),
	KUNIT_CASE(ebpfos_executor_continuation_call_size_test),
	KUNIT_CASE(ebpfos_executor_continuation_frame_test),
	KUNIT_CASE(ebpfos_executor_continuation_step_method_test),
	KUNIT_CASE(ebpfos_continuation_chain_test),
	KUNIT_CASE(ebpfos_continuation_silence_test),
	KUNIT_CASE(ebpfos_continuation_scalar_bound_test),
	KUNIT_CASE(ebpfos_continuation_disposition_mismatch_test),
	KUNIT_CASE(ebpfos_continuation_pre_entry_preservation_test),
	KUNIT_CASE(ebpfos_continuation_busy_entry_test),
	KUNIT_CASE(ebpfos_continuation_arena_binding_test),
	KUNIT_CASE(ebpfos_continuation_arena_range_test),
	KUNIT_CASE(ebpfos_continuation_step_refusal_test),
	KUNIT_CASE(ebpfos_executor_root_manifest_test),
	{}
};

static struct kunit_suite ebpfos_executor_root_suite = {
	.name = "ebpfos-executor-root",
	.test_cases = ebpfos_executor_root_cases,
};
kunit_test_suite(ebpfos_executor_root_suite);
#endif
