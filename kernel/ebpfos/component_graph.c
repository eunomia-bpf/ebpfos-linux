// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/overflow.h>
#include <linux/sched.h>
#include <linux/string.h>

#include "component_graph.h"

static void *ebpfos_component_slot_load(const void *slot)
{
	return READ_ONCE(*(void *const *)slot);
}

static void ebpfos_component_slot_store(void *slot, void *value)
{
	WRITE_ONCE(*(void **)slot, value);
}

static bool ebpfos_component_role_equal(
	const struct ebpfos_component_role_binding *left,
	const struct ebpfos_component_role_binding *right)
{
	/* Fill zeroes the complete representation, including alignment padding. */
	return !memcmp(left, right, sizeof(*left));
}

static bool ebpfos_component_snapshot_equal(
	const struct ebpfos_component_snapshot *left,
	const struct ebpfos_component_snapshot *right)
{
	return left && right &&
	       left->counter_count <= EBPFOS_COMPONENT_SNAPSHOT_COUNTERS &&
	       !memcmp(left, right, sizeof(*left));
}

static bool ebpfos_component_visibility_matches(
	const struct ebpfos_component_publish_transaction *transaction,
	u32 gate)
{
	const struct ebpfos_component_visibility *visibility =
		&transaction->visibility;
	u32 role;

	if (READ_ONCE(*visibility->route_state) != visibility->live_state ||
	    READ_ONCE(*visibility->gate) != gate ||
	    READ_ONCE(*visibility->epoch_slot) != transaction->source.epoch ||
	    ebpfos_component_slot_load(visibility->graph_slot) !=
		transaction->source.graph)
		return false;
	for (role = 0; role < transaction->source.role_count; role++)
		if (ebpfos_component_slot_load(visibility->role_slots[role]) !=
		    transaction->source.roles[role].binding)
			return false;
	return true;
}

static int ebpfos_component_views_validate(
	const struct ebpfos_component_graph_view *source,
	const struct ebpfos_component_graph_view *target)
{
	u64 target_epoch;
	u32 left, right;

	if (!source || !target || !source->object_id || !source->route_id ||
	    source->object_id != target->object_id ||
	    source->route_id != target->route_id || !source->epoch ||
	    check_add_overflow(source->epoch, 1ULL, &target_epoch) ||
	    target->epoch != target_epoch || !source->graph ||
	    !target->graph ||
	    !source->role_count ||
	    source->role_count > EBPFOS_COMPONENT_GRAPH_MAX_ROLES ||
	    source->role_count != target->role_count)
		return -EINVAL;
	for (left = 0; left < source->role_count; left++) {
		const struct ebpfos_component_role_binding *old =
			&source->roles[left];
		const struct ebpfos_component_role_binding *new =
			&target->roles[left];

		if (!old->role_type || old->role_type != new->role_type ||
		    !old->contract_id || old->contract_id != new->contract_id ||
		    !old->schema || !new->schema || !old->provider_id ||
		    !new->provider_id || old->provider_id == new->provider_id ||
		    !old->binding || !new->binding || !new->grant ||
		    !new->identity.grant_id || !new->identity.prog_id ||
		    !new->identity.map_id ||
		    new->identity.admission_state != EBPFOS_ADMISSION_STAGED ||
		    memcmp(old->identity.contract_sha256,
			   new->identity.contract_sha256,
			   SHA256_DIGEST_SIZE) ||
		    (new->authority & ~old->authority))
			return -EPROTOTYPE;
		for (right = 0; right < left; right++)
			if (old->role_type == source->roles[right].role_type ||
			    old->binding == source->roles[right].binding ||
			    new->binding == target->roles[right].binding ||
			    new->grant == target->roles[right].grant ||
			    new->identity.grant_id ==
				target->roles[right].identity.grant_id ||
			    new->identity.prog_id ==
				target->roles[right].identity.prog_id ||
			    new->identity.map_id ==
				target->roles[right].identity.map_id)
				return -EUCLEAN;
	}
	return 0;
}

static int ebpfos_component_role_binding_fill(
	struct ebpfos_component_role_binding *role, u64 role_type,
	u64 contract_id, u64 provider_id, struct ebpfos_binding *binding,
	struct ebpfos_admission *grant,
	const struct ebpfos_admission_identity_v1 *identity)
{
	const struct ebpfos_component_desc_v1 *descriptor;
	struct ebpfos_admission_identity_v1 actual = {};

	if (!role || !role_type || !contract_id || !provider_id || !binding)
		return -EINVAL;
	descriptor = ebpfos_binding_descriptor(binding);
	if (!descriptor)
		return -EUCLEAN;
	ebpfos_binding_fill_identity(binding, &actual);
	if (identity) {
		actual.admission_state = identity->admission_state;
		if (memcmp(identity, &actual, sizeof(actual)))
			return -ESTALE;
	}
	memset(role, 0, sizeof(*role));
	role->role_type = role_type;
	role->contract_id = contract_id;
	role->schema = le64_to_cpu(descriptor->runtime_schema_u64);
	role->provider_id = provider_id;
	role->provider_type_id = le64_to_cpu(descriptor->provider_type_id);
	role->authority = le64_to_cpu(descriptor->capability_mask);
	role->implementation_type = le32_to_cpu(descriptor->use);
	role->identity = actual;
	role->binding = binding;
	role->grant = grant;
	return 0;
}

static bool ebpfos_component_expected_identity_matches(
	const struct ebpfos_component_role_binding *role,
	const struct ebpfos_component_expected_identity *expected)
{
	return expected && expected->content_digest &&
	       (!expected->grant_id ||
		role->identity.grant_id == expected->grant_id) &&
	       role->identity.prog_id == expected->prog_id &&
	       role->identity.map_id == expected->map_id &&
	       !memcmp(role->identity.content_digest, expected->content_digest,
		       SHA256_DIGEST_SIZE);
}

int ebpfos_component_publish_transaction_init(
	struct ebpfos_component_publish_transaction *transaction,
	u64 object_id, u64 route_id, u64 source_epoch, const void *source_graph,
	const void *target_graph,
	const struct ebpfos_component_role_transition *roles, u32 role_count,
	const struct ebpfos_component_visibility *visibility)
{
	struct ebpfos_admission_identity_v1 identity;
	struct ebpfos_component_graph_view *source;
	struct ebpfos_component_graph_view *target;
	int error;
	u32 role;

	if (!transaction || !object_id || !route_id || !source_epoch ||
	    !source_graph || !target_graph || source_graph == target_graph ||
	    !roles || !role_count ||
	    role_count > EBPFOS_COMPONENT_GRAPH_MAX_ROLES || !visibility ||
	    !visibility->lock ||
	    !visibility->waitq || !visibility->acquired ||
	    !visibility->route_state || !visibility->gate ||
	    !visibility->graph_slot || !visibility->epoch_slot ||
	    !visibility->validate_target_graph ||
	    visibility->live_state == visibility->dead_state)
		return -EINVAL;
	memset(transaction, 0, sizeof(*transaction));
	source = &transaction->source;
	target = &transaction->target;
	source->object_id = target->object_id = object_id;
	source->route_id = target->route_id = route_id;
	source->epoch = source_epoch;
	if (check_add_overflow(source_epoch, 1ULL, &target->epoch)) {
		memset(transaction, 0, sizeof(*transaction));
		return -EOVERFLOW;
	}
	source->graph = source_graph;
	target->graph = target_graph;
	source->role_count = target->role_count = role_count;
	for (role = 0; role < role_count; role++) {
		const struct ebpfos_component_role_transition *transition =
			&roles[role];

		if (!transition->target_grant) {
			error = -EINVAL;
			goto out_clear;
		}
		error = ebpfos_component_role_binding_fill(
			&source->roles[role], transition->role_type,
			transition->contract_id, transition->source_provider_id,
			transition->source_binding, NULL, NULL);
		if (error)
			goto out_clear;
		memset(&identity, 0, sizeof(identity));
		ebpfos_admission_fill_identity_locked(transition->target_grant,
						      &identity);
		error = ebpfos_component_role_binding_fill(
			&target->roles[role], transition->role_type,
			transition->contract_id, transition->target_provider_id,
			transition->target_binding, transition->target_grant,
			&identity);
		if (error)
			goto out_clear;
		if (!ebpfos_component_expected_identity_matches(
			    &source->roles[role], &transition->expected_source) ||
		    !ebpfos_component_expected_identity_matches(
			    &target->roles[role], &transition->expected_target)) {
			error = -ESTALE;
			goto out_clear;
		}
	}
	error = ebpfos_component_views_validate(source, target);
	if (error)
		goto out_clear;
	for (role = 0; role < source->role_count; role++)
		if (!visibility->role_slots[role]) {
			error = -EINVAL;
			goto out_clear;
		}
	transaction->visibility = *visibility;
	transaction->state = EBPFOS_COMPONENT_PUBLISH_PREPARED;
	/*
	 * On success, adopt one caller-owned snapshot reference for every source
	 * and target binding and every target grant.  The active role slots keep
	 * separate references even when their pointer values equal source.roles.
	 */
	transaction->owns_snapshot_refs = true;
	return 0;

out_clear:
	memset(transaction, 0, sizeof(*transaction));
	return error;
}

static int ebpfos_component_publish_roles_recheck_locked(
	const struct ebpfos_component_publish_transaction *transaction)
{
	struct ebpfos_admission_identity_v1 identity;
	struct ebpfos_component_role_binding actual;
	const struct ebpfos_component_role_binding *role;
	u32 index;
	int error;

	if (!transaction || !transaction->owns_snapshot_refs)
		return -EINVAL;
	for (index = 0; index < transaction->source.role_count; index++) {
		role = &transaction->source.roles[index];
		error = ebpfos_component_role_binding_fill(
			&actual, role->role_type, role->contract_id,
			role->provider_id, role->binding, NULL, NULL);
		if (error || !ebpfos_component_role_equal(role, &actual))
			return error ?: -ESTALE;

		role = &transaction->target.roles[index];
		error = ebpfos_admission_publish_validate_locked(
			role->grant, transaction->source.roles[index].binding, false);
		if (error)
			return error;
		memset(&identity, 0, sizeof(identity));
		ebpfos_admission_fill_identity_locked(role->grant, &identity);
		error = ebpfos_component_role_binding_fill(
			&actual, role->role_type, role->contract_id,
			role->provider_id, role->binding, role->grant, &identity);
		if (error || !ebpfos_component_role_equal(role, &actual))
			return error ?: -ESTALE;
	}
	return 0;
}

int ebpfos_component_publish_engage_locked(
	struct ebpfos_component_publish_transaction *transaction)
{
	struct ebpfos_component_visibility *visibility;
	int error;

	if (!transaction ||
	    transaction->state != EBPFOS_COMPONENT_PUBLISH_PREPARED)
		return -EINVAL;
	error = ebpfos_component_publish_roles_recheck_locked(transaction);
	if (error)
		return error;
	visibility = &transaction->visibility;
	spin_lock(visibility->lock);
	if (!ebpfos_component_visibility_matches(
			transaction, visibility->open_gate)) {
		error = -ECANCELED;
	} else {
		WRITE_ONCE(*visibility->gate, visibility->draining_gate);
		transaction->drained_calls = atomic_read(visibility->acquired);
		transaction->state = EBPFOS_COMPONENT_PUBLISH_DRAINING;
		error = 0;
	}
	spin_unlock(visibility->lock);
	if (!error)
		wake_up_all(visibility->waitq);
	return error;
}

int ebpfos_component_publish_wait_drained(
	struct ebpfos_component_publish_transaction *transaction)
{
	struct ebpfos_component_visibility *visibility;

	if (!transaction ||
	    transaction->state != EBPFOS_COMPONENT_PUBLISH_DRAINING)
		return -EINVAL;
	visibility = &transaction->visibility;
	wait_event(*visibility->waitq,
		   !atomic_read(visibility->acquired) ||
		   READ_ONCE(*visibility->route_state) == visibility->dead_state);
	return READ_ONCE(*visibility->route_state) == visibility->dead_state ?
		-ESHUTDOWN : 0;
}

int ebpfos_component_publish_refresh_locked(
	struct ebpfos_component_publish_transaction *transaction,
	const struct ebpfos_component_snapshot *snapshot)
{
	int error;

	if (!transaction || !snapshot ||
	    transaction->state != EBPFOS_COMPONENT_PUBLISH_DRAINING ||
	    snapshot->counter_count > EBPFOS_COMPONENT_SNAPSHOT_COUNTERS ||
	    atomic_read(transaction->visibility.acquired))
		return -EINVAL;
	error = ebpfos_component_publish_roles_recheck_locked(transaction);
	if (error)
		return error;
	spin_lock(transaction->visibility.lock);
	error = ebpfos_component_visibility_matches(
		transaction, transaction->visibility.draining_gate) ? 0 : -ESTALE;
	spin_unlock(transaction->visibility.lock);
	if (error)
		return error;
	transaction->snapshot = *snapshot;
	transaction->state = EBPFOS_COMPONENT_PUBLISH_REFRESHED;
	return 0;
}

int ebpfos_component_publish_commit_locked(
	struct ebpfos_component_publish_transaction *transaction,
	const struct ebpfos_component_snapshot *snapshot, void **target_graph,
	ebpfos_component_publish_apply_fn apply, void *context)
{
	struct ebpfos_component_visibility *visibility;
	struct ebpfos_admission *grants[EBPFOS_COMPONENT_GRAPH_MAX_ROLES];
	u32 role;
	int error;

	if (!transaction || !snapshot || !target_graph || !*target_graph ||
	    !apply || transaction->state != EBPFOS_COMPONENT_PUBLISH_REFRESHED ||
	    atomic_read(transaction->visibility.acquired) ||
	    !ebpfos_component_snapshot_equal(&transaction->snapshot, snapshot))
		return -EINVAL;
	if (*target_graph != transaction->target.graph)
		return -ESTALE;
	error = transaction->visibility.validate_target_graph(
		transaction->target.graph, &transaction->target, snapshot);
	if (error)
		return error;
	error = ebpfos_component_publish_roles_recheck_locked(transaction);
	if (error)
		return error;
	visibility = &transaction->visibility;
	for (role = 0; role < transaction->target.role_count; role++)
		grants[role] = transaction->target.roles[role].grant;

	/*
	 * Caller lock order is publish gate -> object operation mutex -> this
	 * visibility lock -> grant state locks.  Admission code never acquires an
	 * object visibility lock while holding a grant state lock.  Keeping the
	 * visibility lock across the all-or-none consume removes a final stale
	 * window without waiting or allocating under a spinlock.
	 */
	spin_lock(visibility->lock);
	if (!ebpfos_component_visibility_matches(
		    transaction, visibility->draining_gate)) {
		error = -ESTALE;
		goto out_unlock;
	}
	error = ebpfos_admission_consume_set_locked(
		grants, transaction->target.role_count);
	if (error)
		goto out_unlock;

	/* No check, allocation, user copy, or other fallible step follows. */
	transaction->retired_graph =
		ebpfos_component_slot_load(visibility->graph_slot);
	for (role = 0; role < transaction->target.role_count; role++) {
		transaction->retired_bindings[role] =
			ebpfos_component_slot_load(visibility->role_slots[role]);
		ebpfos_component_slot_store(visibility->role_slots[role],
					    transaction->target.roles[role].binding);
		transaction->target.roles[role].binding = NULL;
	}
	ebpfos_component_slot_store(visibility->graph_slot, *target_graph);
	*target_graph = NULL;
	/*
	 * The epoch store is the unique abstract linearization point: it names the
	 * already-installed finite binding set.  This point is inside one locked,
	 * infallible transition, so observers only see its completed result after
	 * unlock; unlock and gate reopen are visibility boundaries, not additional
	 * linearization points.
	 */
	WRITE_ONCE(*visibility->epoch_slot, transaction->target.epoch);
	apply(transaction, snapshot, context);
	transaction->state = EBPFOS_COMPONENT_PUBLISH_COMMITTED;
	/*
	 * Acquisitions cannot observe the open gate until after unlock and thus
	 * never see a mixed role set.  This store is not a second linearizer.
	 */
	WRITE_ONCE(*visibility->gate, visibility->open_gate);
	error = 0;
out_unlock:
	spin_unlock(visibility->lock);
	if (!error)
		wake_up_all(visibility->waitq);
	return error;
}

int ebpfos_component_publish_abort_locked(
	struct ebpfos_component_publish_transaction *transaction)
{
	struct ebpfos_component_visibility *visibility;
	struct ebpfos_admission *grants[EBPFOS_COMPONENT_GRAPH_MAX_ROLES];
	int error;
	u32 role;

	if (!transaction || !transaction->owns_snapshot_refs ||
	    (transaction->state != EBPFOS_COMPONENT_PUBLISH_PREPARED &&
	     transaction->state != EBPFOS_COMPONENT_PUBLISH_DRAINING &&
	     transaction->state != EBPFOS_COMPONENT_PUBLISH_REFRESHED))
		return -EINVAL;
	for (role = 0; role < transaction->target.role_count; role++)
		grants[role] = transaction->target.roles[role].grant;
	visibility = &transaction->visibility;
	spin_lock(visibility->lock);
	/* Burn is terminal even for Begin failures before refresh or drain. */
	ebpfos_admission_burn_set_locked(grants,
					 transaction->target.role_count);
	if (ebpfos_component_visibility_matches(
		    transaction,
		    transaction->state == EBPFOS_COMPONENT_PUBLISH_PREPARED ?
			visibility->open_gate : visibility->draining_gate)) {
		/* PREPARED never closed the gate; later failures reopen it here. */
		if (transaction->state != EBPFOS_COMPONENT_PUBLISH_PREPARED)
			WRITE_ONCE(*visibility->gate, visibility->open_gate);
		error = 0;
	} else if (READ_ONCE(*visibility->route_state) ==
		   visibility->dead_state) {
		/* The object destruction path already owns the terminal state. */
		error = -ESHUTDOWN;
	} else {
		/* An unexplained source mutation cannot leave waiters on DRAINING. */
		WRITE_ONCE(*visibility->route_state, visibility->dead_state);
		WRITE_ONCE(*visibility->gate, visibility->failed_gate);
		error = -EUCLEAN;
	}
	transaction->state = EBPFOS_COMPONENT_PUBLISH_ABORTED;
	spin_unlock(visibility->lock);
	wake_up_all(visibility->waitq);
	return error;
}

void ebpfos_component_publish_transaction_release(
	struct ebpfos_component_publish_transaction *transaction)
{
	u32 role;

	if (!transaction || !transaction->owns_snapshot_refs)
		return;
	WARN_ON_ONCE(transaction->state == EBPFOS_COMPONENT_PUBLISH_PREPARED ||
		     transaction->state == EBPFOS_COMPONENT_PUBLISH_DRAINING ||
		     transaction->state == EBPFOS_COMPONENT_PUBLISH_REFRESHED);
	for (role = 0; role < transaction->source.role_count; role++) {
		ebpfos_binding_put(transaction->retired_bindings[role]);
		ebpfos_binding_put(transaction->source.roles[role].binding);
		ebpfos_binding_put(transaction->target.roles[role].binding);
		ebpfos_admission_put(transaction->target.roles[role].grant);
	}
	transaction->owns_snapshot_refs = false;
}
