/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _EBPFOS_EXECUTOR_ROOT_H
#define _EBPFOS_EXECUTOR_ROOT_H

#include <linux/ebpfos.h>
#include <linux/errno.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include "component_graph.h"

/* Private L1 layout and shared non-sleepable acquisition. Published slots have
 * stable lifetime; RCU protects their active bundles through native commit.
 */
struct ebpfos_executor_root_role {
	struct ebpfos_executor_root_role_snapshot snapshot;
	struct ebpfos_binding *binding;
	struct ebpfos_admission *grant;
	/* Immutable stock JIT entry, selected before publication. */
	bpf_func_t entry;
	/* Native ABI subprogram from this same verified image, or NULL. */
	void *typed_entry;
	/* Nullable argument bits from this checked global export, never its root. */
	u64 null_args;
	/* Optional native marshaller around the verified context root. */
	void *context_image;
	/* Loaded calls select scope use; opaque native calls retain a scope. */
	bool needs_steps;
	bool wide_result;
	/* Native typed API uses vmlinux FUNC IDs. Zero means a different BTF
	 * namespace or no native export; explicit-BTF context entries are separate.
	 */
	u32 native_func_id;
	/* Stock-checked kptr channel for a native struct pointer. */
	struct bpf_map *pointer_result;
	/* Immutable per-CPU storage, kept alive by the role's admitted program. */
	void __percpu *pointer_value_percpu;
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

/* Publication sorts and rejects duplicate unsigned role keys. Keep the
 * single-role/first-role path short, then bound selection by log2(N) for a
 * component with many entries. RCU keeps this immutable array alive.
 */
static __always_inline struct ebpfos_executor_root_role *
ebpfos_executor_root_find_role(struct ebpfos_executor_root_bundle *bundle,
			       u64 role_type)
{
	u32 low = 1, high = bundle->role_count;

	if (high && bundle->roles[0].snapshot.role_type == role_type)
		return &bundle->roles[0];
	while (low < high) {
		u32 middle = low + (high - low) / 2;
		struct ebpfos_executor_root_role *role = &bundle->roles[middle];

		if (role->snapshot.role_type == role_type)
			return role;
		if (role->snapshot.role_type < role_type)
			low = middle + 1;
		else
			high = middle;
	}
	return NULL;
}

static __always_inline struct ebpfos_binding *ebpfos_executor_root_role_get_rcu(
	struct ebpfos_executor_root_slot *slot, u64 role_type, u64 *epoch,
	struct ebpfos_executor_root_role_snapshot *snapshot, bool pin)
{
	struct ebpfos_executor_root_bundle *bundle;
	struct ebpfos_binding *binding = NULL;
	struct ebpfos_executor_root_role *role;

	bundle = rcu_dereference(slot->active);
	if (!bundle)
		return NULL;
	role = ebpfos_executor_root_find_role(bundle, role_type);
	if (role) {
		binding = role->binding;
		if (pin)
			ebpfos_binding_get(binding);
		if (binding) {
			*epoch = bundle->epoch;
			*snapshot = role->snapshot;
		}
	}
	return binding;
}

static __always_inline int ebpfos_executor_root_lease_try_begin_slot_inner(
	struct ebpfos_executor_root_slot *slot, u64 role_type,
	struct ebpfos_executor_root_lease *lease,
	struct ebpfos_executor_root_role_snapshot *snapshot, bool borrowed)
{
	if (!lease || !snapshot)
		return -EINVAL;
	/* Only a successful acquisition makes lease_end own anything. */
	lease->slot = NULL;
	if (!slot)
		return -ENOENT;
	if (!borrowed)
		rcu_read_lock();
	/*
	 * This lease cannot sleep. Its own or its caller's RCU hold protects
	 * the bundle. Quiesce closes
	 * admission before a grace period, which drains these readers without
	 * modifying the shared gate count on every call.
	 */
	if (atomic_long_read_acquire(&slot->gate.state) & EBPFOS_GATE_DRAINING) {
		if (!borrowed)
			rcu_read_unlock();
		return -EAGAIN;
	}
	lease->binding = ebpfos_executor_root_role_get_rcu(
		slot, role_type, &lease->epoch, snapshot, false);
	if (!lease->binding) {
		if (!borrowed)
			rcu_read_unlock();
		return -ENOENT;
	}
	lease->slot = slot;
	lease->rcu_held = true;
	lease->rcu_borrowed = borrowed;
	return 0;
}

#endif
