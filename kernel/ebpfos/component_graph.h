/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _EBPFOS_COMPONENT_GRAPH_H
#define _EBPFOS_COMPONENT_GRAPH_H

#include <crypto/sha2.h>
#include <linux/atomic.h>
#include <linux/ebpfos.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>

#define EBPFOS_COMPONENT_GRAPH_MAX_ROLES 4U
#define EBPFOS_COMPONENT_SNAPSHOT_COUNTERS 8U

enum ebpfos_component_publish_state {
	EBPFOS_COMPONENT_PUBLISH_EMPTY,
	EBPFOS_COMPONENT_PUBLISH_PREPARED,
	EBPFOS_COMPONENT_PUBLISH_DRAINING,
	EBPFOS_COMPONENT_PUBLISH_REFRESHED,
	EBPFOS_COMPONENT_PUBLISH_COMMITTED,
	EBPFOS_COMPONENT_PUBLISH_ABORTED,
};

/* Exact executable identity behind one stable typed graph role. */
struct ebpfos_component_role_binding {
	u64 role_type;
	u64 contract_id;
	u64 schema;
	u64 provider_id;
	u64 provider_type_id;
	u64 authority;
	u32 implementation_type;
	struct ebpfos_admission_identity_v1 identity;
	struct ebpfos_binding *binding;
	struct ebpfos_admission *grant;
};

struct ebpfos_component_graph_view {
	u64 object_id;
	u64 route_id;
	u64 epoch;
	const void *graph;
	u32 role_count;
	struct ebpfos_component_role_binding
		roles[EBPFOS_COMPONENT_GRAPH_MAX_ROLES];
};

struct ebpfos_component_expected_identity {
	u64 grant_id;
	u32 prog_id;
	u32 map_id;
	const u8 *content_digest;
};

/* One typed old->new role transition supplied by an object adapter. */
struct ebpfos_component_role_transition {
	u64 role_type;
	u64 contract_id;
	u64 source_provider_id;
	u64 target_provider_id;
	struct ebpfos_binding *source_binding;
	struct ebpfos_binding *target_binding;
	struct ebpfos_admission *target_grant;
	struct ebpfos_component_expected_identity expected_source;
	struct ebpfos_component_expected_identity expected_target;
};

/* File Alpha and counters are opaque values whose equality core enforces. */
struct ebpfos_component_snapshot {
	u64 frontier;
	u64 visible_size;
	u32 counter_count;
	u64 counters[EBPFOS_COMPONENT_SNAPSHOT_COUNTERS];
	u8 alpha_digest[SHA256_DIGEST_SIZE];
};

/* Addresses of the object-visible cells changed at the linearization point. */
struct ebpfos_component_visibility {
	spinlock_t *lock;
	wait_queue_head_t *waitq;
	atomic_t *acquired;
	u32 *route_state;
	u32 live_state;
	u32 dead_state;
	u32 *gate;
	u32 open_gate;
	u32 draining_gate;
	u32 failed_gate;
	void *graph_slot;
	u64 *epoch_slot;
	void *role_slots[EBPFOS_COMPONENT_GRAPH_MAX_ROLES];
	int (*validate_target_graph)(
		const void *graph,
		const struct ebpfos_component_graph_view *target,
		const struct ebpfos_component_snapshot *snapshot);
};

struct ebpfos_component_publish_transaction {
	struct ebpfos_component_graph_view source;
	struct ebpfos_component_graph_view target;
	struct ebpfos_component_visibility visibility;
	struct ebpfos_component_snapshot snapshot;
	/* The old slot references, distinct from source snapshot references. */
	struct ebpfos_binding
		*retired_bindings[EBPFOS_COMPONENT_GRAPH_MAX_ROLES];
	void *retired_graph;
	u32 state;
	u32 drained_calls;
	bool owns_snapshot_refs;
};

typedef void (*ebpfos_component_publish_apply_fn)(
	struct ebpfos_component_publish_transaction *transaction,
	const struct ebpfos_component_snapshot *snapshot, void *context);

int ebpfos_component_publish_transaction_init(
	struct ebpfos_component_publish_transaction *transaction,
	u64 object_id, u64 route_id, u64 source_epoch, const void *source_graph,
	const void *target_graph,
	const struct ebpfos_component_role_transition *roles, u32 role_count,
	const struct ebpfos_component_visibility *visibility);
int ebpfos_component_publish_engage_locked(
	struct ebpfos_component_publish_transaction *transaction);
int ebpfos_component_publish_wait_drained(
	struct ebpfos_component_publish_transaction *transaction);
int ebpfos_component_publish_refresh_locked(
	struct ebpfos_component_publish_transaction *transaction,
	const struct ebpfos_component_snapshot *snapshot);
int ebpfos_component_publish_commit_locked(
	struct ebpfos_component_publish_transaction *transaction,
	const struct ebpfos_component_snapshot *snapshot, void **target_graph,
	ebpfos_component_publish_apply_fn apply, void *context);
int ebpfos_component_publish_abort_locked(
	struct ebpfos_component_publish_transaction *transaction);
void ebpfos_component_publish_transaction_release(
	struct ebpfos_component_publish_transaction *transaction);

/* Admission terminal transitions over a bounded, unique grant set. */
int ebpfos_admission_consume_set_locked(struct ebpfos_admission **grants,
					 unsigned int count);
void ebpfos_admission_burn_set_locked(struct ebpfos_admission **grants,
				      unsigned int count);

#endif /* _EBPFOS_COMPONENT_GRAPH_H */
