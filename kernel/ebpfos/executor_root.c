// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <crypto/sha2.h>
#include <linux/ebpfos.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
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
	    *expected_size != request_size)
		return -E2BIG;
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
	if (!descriptor ||
	    le32_to_cpu(descriptor->resource_count) != 1 ||
	    le32_to_cpu(descriptor->resource.kind) !=
		EBPFOS_RESOURCE_ARRAY_MAP ||
	    ebpfos_binding_kind(binding) != EBPFOS_ADMITTED_BINDING_BPF ||
	    !ebpfos_binding_prog(binding) || !ebpfos_binding_map(binding)) {
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
	error = ebpfos_admission_consume_bundle_locked(grants,
						       target->role_count);
	if (error)
		goto out_unlock;
	/* Unique linearization point: one immutable finite-role bundle pointer. */
	rcu_assign_pointer(slot->active, target);
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

__bpf_kfunc int bpf_ebpfos_executor_root_read(
	u64 object_id, void *snapshot_data, u32 snapshot_data__sz)
{
	struct ebpfos_executor_root_snapshot *snapshot = snapshot_data;
	struct ebpfos_executor_root_bundle *bundle;
	size_t expected_size, roles_size;
	u32 role;
	int error = 0;

	if (!object_id || !snapshot ||
	    snapshot_data__sz < sizeof(*snapshot))
		return -EINVAL;
	rcu_read_lock();
	bundle = rcu_dereference(ebpfos_executor_root.active);
	if (!bundle || bundle->object_id != object_id) {
		error = -ENOENT;
		goto out_unlock;
	}
	if (check_mul_overflow((size_t)bundle->role_count,
			       sizeof(snapshot->roles[0]), &roles_size) ||
	    check_add_overflow(sizeof(*snapshot), roles_size, &expected_size) ||
	    snapshot_data__sz != expected_size) {
		error = -ENOSPC;
		goto out_unlock;
	}
	memset(snapshot, 0, sizeof(*snapshot));
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

__bpf_kfunc_end_defs();

struct ebpfos_binding *ebpfos_executor_root_binding_get(
	u64 object_id, u64 role_type, u64 *epoch)
{
	struct ebpfos_executor_root_bundle *bundle;
	struct ebpfos_binding *binding = NULL;
	u32 role;

	if (!object_id || !role_type)
		return NULL;
	rcu_read_lock();
	bundle = rcu_dereference(ebpfos_executor_root.active);
	if (!bundle || bundle->object_id != object_id)
		goto out;
	for (role = 0; role < bundle->role_count; role++)
		if (bundle->roles[role].snapshot.role_type == role_type) {
			binding = ebpfos_binding_get(bundle->roles[role].binding);
			if (epoch)
				*epoch = bundle->epoch;
			break;
		}
out:
	rcu_read_unlock();
	return binding;
}

BTF_KFUNCS_START(ebpfos_executor_root_kfunc_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_executor_root_publish,
		     KF_IMPLICIT_ARGS | KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_executor_root_read)
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

static void ebpfos_executor_root_request_test(struct kunit *test)
{
	struct ebpfos_executor_root_publish_request *request;
	size_t request_size = sizeof(*request) + sizeof(request->roles[0]);
	size_t expected_size = 0;

	request = kunit_kzalloc(test, request_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, request);
	request->version = EBPFOS_EXECUTOR_ROOT_ABI_VERSION;
	request->object_id = 1;
	request->target_epoch = 1;
	request->role_count = 1;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_request_size(
		request, request_size, &expected_size), 0);
	KUNIT_EXPECT_EQ(test, expected_size, request_size);
	request->role_count = EBPFOS_EXECUTOR_ROOT_MAX_ROLES + 1;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_request_size(
		request, request_size, &expected_size), -EINVAL);
	request->role_count = 1;
	request->expected_epoch = U64_MAX;
	KUNIT_EXPECT_EQ(test, ebpfos_executor_root_request_size(
		request, request_size, &expected_size), -EINVAL);
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

static struct kunit_case ebpfos_executor_root_cases[] = {
	KUNIT_CASE(ebpfos_executor_root_compare_test),
	KUNIT_CASE(ebpfos_executor_root_request_test),
	KUNIT_CASE(ebpfos_executor_root_manifest_test),
	{}
};

static struct kunit_suite ebpfos_executor_root_suite = {
	.name = "ebpfos-executor-root",
	.test_cases = ebpfos_executor_root_cases,
};
kunit_test_suite(ebpfos_executor_root_suite);
#endif
