// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/build_bug.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/ebpfos.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/wait.h>

#define EBPFOS_FILE_DIGEST_INITIAL 0xcbf29ce484222325ULL
#define EBPFOS_FILE_DIGEST_PRIME 0x100000001b3ULL

struct ebpfos_file_delta {
	u64 sequence;
	u64 file_cookie;
	u64 visible_before;
	u64 visible_after;
	u32 size;
	u8 data[EBPFOS_FILE_BPF_DATA_SIZE];
};

struct ebpfos_file_recovery_delta {
	u64 invocation_id;
	u64 acquire_id;
	u64 provider_id;
	u64 epoch;
	u64 sequence;
	u64 file_cookie;
	u64 visible_before;
	u64 visible_after;
	u32 size;
	u8 data[EBPFOS_FILE_BPF_DATA_SIZE];
};

struct ebpfos_file_map_lease {
	struct list_head node;
	struct bpf_map *map;
};

struct ebpfos_file_transaction;

struct ebpfos_file_provider_reply {
	u32 status;
	u32 payload;
};

enum ebpfos_file_fault_role {
	EBPFOS_FILE_FAULT_NONE,
	EBPFOS_FILE_FAULT_LEADER,
	EBPFOS_FILE_FAULT_FOLLOWER,
};

struct ebpfos_file_admission {
	struct bpf_prog *prog;
	u64 invocation_id;
	u64 acquire_id;
	u64 provider_id;
	u64 epoch;
	u64 schema_hash;
	u32 provider_kind;
	bool counted_e3;
	bool counted_e4;
};

struct ebpfos_file_call {
	struct ebpfos_file_admission admission;
	u64 invocation_id;
	u64 file_cookie;
	u32 count;
	u32 retry_count;
	bool data_valid;
	bool needs_retry;
	bool typed_fault;
	bool retry_started;
	bool retry_finished;
	u8 data[EBPFOS_FILE_BPF_DATA_SIZE];
};

struct ebpfos_file_recovery {
	struct bpf_prog *e4_prog;
	struct bpf_map *e4_map;
	struct ebpfos_file_map_lease *e4_map_lease;
	struct ebpfos_file_recovery_delta *log;
	void *canonical_base;
	u64 recovery_id;
	u64 e2_provider_id;
	u64 e2_epoch;
	u64 e2_schema_hash;
	u64 e3_provider_id;
	u64 e3_epoch;
	u64 e3_schema_hash;
	u64 e4_provider_id;
	u64 e4_epoch;
	u64 e4_schema_hash;
	u64 base_sequence;
	u64 base_size;
	u64 base_digest;
	u64 fence_acquire_id;
	u64 committed_delta_bytes;
	u64 backpressure_waits;
	u64 e3_write_attempts;
	u64 faults_observed;
	u64 coalesced_faults;
	u64 pending_retries;
	u64 retry_commits;
	u64 retry_failures;
	u64 unretried_invocations;
	u64 capacity_triggers;
	u64 trigger_invocation_id;
	u64 trigger_acquire_id;
	u64 trigger_sequence;
	u64 trigger_epoch;
	u64 fault_invocation_id;
	u64 fault_acquire_id;
	u64 fault_sequence;
	u64 fault_epoch;
	u64 retry_invocation_id;
	u64 retry_acquire_id;
	u64 retry_sequence;
	u64 retry_epoch;
	u32 log_capacity;
	u32 log_count;
	u32 frozen_count;
	u32 replay_index;
	u32 expected_fault_reason;
	u32 phase;
	u32 trigger;
	u32 retry_count;
	s32 retry_result;
	int fatal_error;
	bool base_validated;
	bool e3_ready;
	bool e4_base_ready;
	bool e4_ready;
};

struct ebpfos_file_stream_state {
	u64 captured_deltas;
	u64 captured_delta_bytes;
	u64 snapshotting_captured_deltas;
	u64 importing_captured_deltas;
	u64 catching_up_captured_deltas;
	u64 dequeued_deltas;
	u64 dequeued_delta_bytes;
	u64 replayed_deltas;
	u64 replayed_delta_bytes;
	u64 verified_deltas;
	u64 verified_delta_bytes;
	u64 pending_delta_bytes;
	u64 replay_batches;
	u64 ring_high_water;
	u64 ring_wraps;
	u64 backpressure_waits;
	u64 quiesce_waiters;
	u64 queue_tail_visible;
	u64 queue_last_write_sequence;
	u64 dequeue_visible;
	u64 dequeue_last_write_sequence;
	u64 candidate_visible;
	u64 candidate_last_write_sequence;
	u64 verified_visible;
	u64 verified_last_write_sequence;
	u64 quiesce_captured_deltas;
	u64 quiesce_pending_deltas;
	u64 freeze_route_sequence;
	u64 freeze_visible;
	u64 freeze_tail_deltas;
	u32 ring_head;
	u32 ring_count;
	u32 batch_count;
	u32 batch_applied;
	u32 phase;
	int fatal_error;
	bool candidate_busy;
	bool commit_requested;
};

/* Common tail copied into both public file-status layouts. */
struct ebpfos_file_stream_report {
	u64 dequeued_deltas;
	u64 dequeued_delta_bytes;
	u64 replayed_deltas;
	u64 replayed_delta_bytes;
	u64 verified_deltas;
	u64 verified_delta_bytes;
	u64 pending_deltas;
	u64 pending_delta_bytes;
	u64 queued_deltas;
	u64 queued_delta_bytes;
	u64 replay_batches;
	u64 ring_high_water;
	u64 ring_wraps;
	u64 backpressure_waits;
	u64 backpressure_waiters;
	u64 quiesce_waiters;
	u64 queue_tail_visible;
	u64 queue_last_write_sequence;
	u64 dequeue_visible;
	u64 dequeue_last_write_sequence;
	u64 candidate_visible;
	u64 candidate_last_write_sequence;
	u64 verified_visible;
	u64 verified_last_write_sequence;
	u64 quiesce_captured_deltas;
	u64 quiesce_pending_deltas;
	u64 freeze_route_sequence;
	u64 freeze_visible;
	u64 freeze_tail_deltas;
	u64 snapshotting_captured_deltas;
	u64 importing_captured_deltas;
	u64 catching_up_captured_deltas;
	u32 ring_head;
	u32 inflight_batch_count;
	u32 inflight_batch_applied;
	u32 candidate_busy;
	u32 commit_requested;
	s32 fatal_error;
};

struct ebpfos_inode_route {
	struct kref ref;
	struct mutex op_lock; /* Serializes route state and provider calls. */
	spinlock_t admission_lock;
	struct inode *inode;
	void *snapshot;
	struct bpf_prog *prog;
	struct bpf_map *map;
	struct ebpfos_file_map_lease *map_lease;
	struct ebpfos_file_transaction *migration;
	struct ebpfos_file_recovery *recovery;
	wait_queue_head_t migration_wait;
	atomic64_t migration_progress;
	atomic64_t migration_waiters;
	atomic64_t recovery_progress;
	atomic64_t next_invocation_id;
	atomic_t admitted_e3;
	atomic_t admitted_e4;
	u64 next_acquire_id;
	u64 route_id;
	u64 provider_id;
	u64 schema_hash;
	u64 epoch;
	u64 visible_size;
	u64 snapshot_size;
	u64 snapshot_digest;
	u64 last_sequence;
	u64 read_calls;
	u64 write_calls;
	u64 read_bytes;
	u64 write_bytes;
	u64 native_read_body_calls;
	u64 native_write_body_calls;
	u64 fault_count;
	u64 last_migration_txn_id;
	u64 last_migration_snapshot_sequence;
	u64 last_migration_snapshot_size;
	u64 last_migration_delta_count;
	u64 last_migration_delta_bytes;
	u64 last_migration_validated_bytes;
	struct ebpfos_file_stream_state last_migration_stream;
	atomic64_t rejected_calls;
	atomic64_t active_calls;
	/* Monotone after the first BPF cutover: tmpfs must never resurrect. */
	bool native_retired;
	bool last_migration_bytes_validated;
	u32 admission_gate;
	u32 provider_kind;
	u32 state;
};

struct ebpfos_file_transaction {
	struct ebpfos_inode_route *route;
	struct file *file;
	struct bpf_prog *prog;
	struct bpf_map *map;
	struct ebpfos_file_map_lease *map_lease;
	struct ebpfos_file_recovery *recovery;
	struct ebpfos_file_delta *deltas;
	struct ebpfos_file_delta *batch;
	void *snapshot;
	void **owner_slot;
	u64 txn_id;
	u64 provider_id;
	u64 source_provider_id;
	u64 source_epoch;
	u64 source_schema_hash;
	u64 target_epoch;
	u64 target_schema_hash;
	u64 snapshot_sequence;
	u64 snapshot_size;
	u64 snapshot_digest;
	u64 candidate_validated_bytes;
	struct ebpfos_file_stream_state stream;
	int capture_error;
	u32 source_provider_kind;
	bool candidate_ready;
	bool candidate_bytes_validated;
};

DEFINE_STATIC_SRCU(ebpfos_inode_srcu);
static DEFINE_MUTEX(ebpfos_file_enroll_lock);
static DEFINE_MUTEX(ebpfos_file_map_lease_lock);
static LIST_HEAD(ebpfos_file_map_leases);
static atomic64_t ebpfos_next_file_route_id = ATOMIC64_INIT(0);
static atomic64_t ebpfos_next_file_provider_id = ATOMIC64_INIT(0);
static atomic64_t ebpfos_next_file_cookie = ATOMIC64_INIT(0);
static atomic64_t ebpfos_next_file_transaction_id = ATOMIC64_INIT(0);
static atomic64_t ebpfos_next_file_recovery_id = ATOMIC64_INIT(0);

static_assert(sizeof(struct ebpfos_file_bpf_ctx) ==
	      EBPFOS_FILE_BPF_CTX_SIZE);
static_assert(EBPFOS_FILE_COMMIT_TAIL <= EBPFOS_FILE_CATCHUP_BATCH);
static_assert(EBPFOS_FILE_CATCHUP_BATCH <= EBPFOS_FILE_DELTA_CAPACITY);
static_assert(offsetof(struct ebpfos_ioc_file_status, fatal_error) +
	      sizeof_field(struct ebpfos_ioc_file_status, fatal_error) -
	      offsetof(struct ebpfos_ioc_file_status, dequeued_deltas) ==
	      sizeof(struct ebpfos_file_stream_report));
static_assert(offsetof(struct ebpfos_ioc_file_replace_status, fatal_error) +
	      sizeof_field(struct ebpfos_ioc_file_replace_status, fatal_error) -
	      offsetof(struct ebpfos_ioc_file_replace_status, dequeued_deltas) ==
	      sizeof(struct ebpfos_file_stream_report));

static u64 ebpfos_file_new_id(atomic64_t *counter)
{
	u64 id = atomic64_inc_return(counter);

	return id ? id : atomic64_inc_return(counter);
}

static void ebpfos_file_map_lease_release(
	struct ebpfos_file_map_lease *lease)
{
	if (!lease)
		return;
	mutex_lock(&ebpfos_file_map_lease_lock);
	list_del(&lease->node);
	mutex_unlock(&ebpfos_file_map_lease_lock);
	kfree(lease);
}

static int ebpfos_file_map_lease_reserve(
	struct bpf_map *map, struct ebpfos_file_map_lease **lease_out)
{
	struct ebpfos_file_map_lease *lease;
	struct ebpfos_file_map_lease *cursor;
	int error = 0;

	lease = kzalloc_obj(*lease, GFP_KERNEL);
	if (!lease)
		return -ENOMEM;
	lease->map = map;

	mutex_lock(&ebpfos_file_map_lease_lock);
	list_for_each_entry(cursor, &ebpfos_file_map_leases, node) {
		if (cursor->map == map) {
			error = -EBUSY;
			goto out_unlock;
		}
	}
	list_add_tail(&lease->node, &ebpfos_file_map_leases);
out_unlock:
	mutex_unlock(&ebpfos_file_map_lease_lock);
	if (error) {
		kfree(lease);
		return error;
	}
	*lease_out = lease;
	return 0;
}

static void ebpfos_file_recovery_free(struct ebpfos_file_recovery *recovery)
{
	if (!recovery)
		return;
	ebpfos_file_map_lease_release(recovery->e4_map_lease);
	if (recovery->e4_prog)
		bpf_prog_put(recovery->e4_prog);
	if (recovery->e4_map)
		bpf_map_put(recovery->e4_map);
	kvfree(recovery->canonical_base);
	kvfree(recovery->log);
	kfree(recovery);
}

static void ebpfos_inode_route_release(struct kref *ref)
{
	struct ebpfos_inode_route *route =
		container_of(ref, struct ebpfos_inode_route, ref);

	ebpfos_file_map_lease_release(route->map_lease);
	if (route->prog)
		bpf_prog_put(route->prog);
	if (route->map)
		bpf_map_put(route->map);
	ebpfos_file_recovery_free(route->recovery);
	kvfree(route->snapshot);
	kfree(route);
}

static void ebpfos_inode_route_put(struct ebpfos_inode_route *route)
{
	kref_put(&route->ref, ebpfos_inode_route_release);
}

static struct ebpfos_inode_route *
ebpfos_inode_route_get(struct inode *inode)
{
	struct ebpfos_inode_route *route;
	int index;

	index = srcu_read_lock(&ebpfos_inode_srcu);
	route = srcu_dereference(inode->i_ebpfos_route, &ebpfos_inode_srcu);
	if (route)
		kref_get(&route->ref);
	srcu_read_unlock(&ebpfos_inode_srcu, index);
	return route;
}

void ebpfos_inode_route_init(struct inode *inode)
{
	RCU_INIT_POINTER(inode->i_ebpfos_route, NULL);
}

void ebpfos_inode_route_destroy(struct inode *inode)
{
	struct ebpfos_inode_route *route;

	route = rcu_dereference_protected(inode->i_ebpfos_route, true);
	if (!route)
		return;

	rcu_assign_pointer(inode->i_ebpfos_route, NULL);
	synchronize_srcu(&ebpfos_inode_srcu);
	mutex_lock(&route->op_lock);
	spin_lock(&route->admission_lock);
	route->admission_gate = EBPFOS_FILE_ADMISSION_FAILED;
	WRITE_ONCE(route->state, EBPFOS_FILE_ROUTE_DEAD);
	spin_unlock(&route->admission_lock);
	atomic64_inc(&route->migration_progress);
	wake_up_all(&route->migration_wait);
	mutex_unlock(&route->op_lock);
	ebpfos_inode_route_put(route);
}

bool ebpfos_inode_reject_managed(struct inode *inode)
{
	struct ebpfos_inode_route *route;
	bool managed;
	int index;

	index = srcu_read_lock(&ebpfos_inode_srcu);
	route = srcu_dereference(inode->i_ebpfos_route, &ebpfos_inode_srcu);
	managed = !!route;
	if (route)
		atomic64_inc(&route->rejected_calls);
	srcu_read_unlock(&ebpfos_inode_srcu, index);
	return managed;
}

bool ebpfos_inode_visible_size(struct inode *inode, loff_t *size)
{
	struct ebpfos_inode_route *route;
	bool managed = false;
	u32 state;
	int index;

	index = srcu_read_lock(&ebpfos_inode_srcu);
	route = srcu_dereference(inode->i_ebpfos_route, &ebpfos_inode_srcu);
	state = route ? READ_ONCE(route->state) : EBPFOS_FILE_ROUTE_DEAD;
	if (state == EBPFOS_FILE_ROUTE_ACTIVE ||
	    state == EBPFOS_FILE_ROUTE_FENCED) {
		*size = READ_ONCE(route->visible_size);
		managed = true;
	}
	srcu_read_unlock(&ebpfos_inode_srcu, index);
	return managed;
}

static u64 ebpfos_file_cookie(struct file *file)
{
	u64 cookie = atomic64_read(&file->f_ebpfos_cookie);
	u64 new_cookie;

	if (cookie)
		return cookie;
	new_cookie = ebpfos_file_new_id(&ebpfos_next_file_cookie);
	cookie = atomic64_cmpxchg(&file->f_ebpfos_cookie, 0, new_cookie);
	return cookie ? cookie : new_cookie;
}

static bool ebpfos_file_scalar_io(struct kiocb *iocb,
				  struct iov_iter *iter, bool write)
{
	if (!is_sync_kiocb(iocb) || !iter_is_ubuf(iter))
		return false;
	if (iocb->ki_flags & IOCB_DIRECT)
		return false;
	if (write && !(iocb->ki_flags & IOCB_APPEND))
		return false;
	return true;
}

static int ebpfos_file_admission_acquire(
	struct ebpfos_inode_route *route,
	struct ebpfos_file_admission *admission)
{
	int error = 0;

	memset(admission, 0, sizeof(*admission));
	spin_lock(&route->admission_lock);
	switch (route->admission_gate) {
	case EBPFOS_FILE_ADMISSION_LEGACY:
		break;
	case EBPFOS_FILE_ADMISSION_E3_OPEN:
	case EBPFOS_FILE_ADMISSION_E4_OPEN:
		if (route->next_acquire_id == U64_MAX) {
			error = -EOVERFLOW;
			break;
		}
		admission->acquire_id = ++route->next_acquire_id;
		admission->prog = route->prog;
		admission->provider_id = route->provider_id;
		admission->epoch = route->epoch;
		admission->schema_hash = route->schema_hash;
		admission->provider_kind = route->provider_kind;
		if (route->admission_gate ==
		    EBPFOS_FILE_ADMISSION_E3_OPEN) {
			admission->counted_e3 = true;
			atomic_inc(&route->admitted_e3);
		} else {
			admission->counted_e4 = true;
			atomic_inc(&route->admitted_e4);
		}
		break;
	case EBPFOS_FILE_ADMISSION_RECOVERING:
		error = -EAGAIN;
		break;
	default:
		error = -EIO;
		break;
	}
	spin_unlock(&route->admission_lock);
	return error;
}

static void ebpfos_file_admission_release(
	struct ebpfos_inode_route *route,
	struct ebpfos_file_admission *admission)
{
	if (admission->counted_e3) {
		admission->counted_e3 = false;
		if (!atomic_dec_and_test(&route->admitted_e3))
			return;
	} else if (admission->counted_e4) {
		admission->counted_e4 = false;
		if (!atomic_dec_and_test(&route->admitted_e4))
			return;
	} else {
		return;
	}
	atomic64_inc(&route->recovery_progress);
	wake_up_all(&route->migration_wait);
}

static void ebpfos_file_recovery_progress_locked(
	struct ebpfos_inode_route *route)
{
	lockdep_assert_held(&route->op_lock);
	atomic64_inc(&route->recovery_progress);
	wake_up_all(&route->migration_wait);
}

static void ebpfos_file_fence_locked(struct ebpfos_inode_route *route)
{
	lockdep_assert_held(&route->op_lock);
	if (route->provider_kind == EBPFOS_PROVIDER_BPF &&
	    route->state == EBPFOS_FILE_ROUTE_ACTIVE) {
		route->fault_count++;
		WRITE_ONCE(route->state, EBPFOS_FILE_ROUTE_FENCED);
	}
}

static void
ebpfos_file_migration_progress_locked(struct ebpfos_inode_route *route)
{
	lockdep_assert_held(&route->op_lock);
	atomic64_inc(&route->migration_progress);
	wake_up_all(&route->migration_wait);
}

static bool ebpfos_file_migration_captures(u32 phase)
{
	return phase == EBPFOS_FILE_MIGRATION_SNAPSHOTTING ||
	       phase == EBPFOS_FILE_MIGRATION_IMPORTING ||
	       phase == EBPFOS_FILE_MIGRATION_CATCHING_UP;
}

static bool ebpfos_file_capture_phase_counts_valid(
	const struct ebpfos_file_stream_state *stream)
{
	u64 total;

	if (check_add_overflow(stream->snapshotting_captured_deltas,
			       stream->importing_captured_deltas, &total) ||
	    check_add_overflow(total, stream->catching_up_captured_deltas,
			       &total))
		return false;
	return total == stream->captured_deltas;
}

static void ebpfos_file_migration_doom_locked(
	struct ebpfos_file_transaction *txn, int error)
{
	lockdep_assert_held(&txn->route->op_lock);
	if (!txn->stream.fatal_error)
		txn->stream.fatal_error = error;
	txn->capture_error = txn->stream.fatal_error;
	txn->stream.phase = EBPFOS_FILE_MIGRATION_DOOMED;
	txn->stream.commit_requested = false;
	txn->stream.candidate_busy = false;
	ebpfos_file_migration_progress_locked(txn->route);
}

static void ebpfos_file_source_fault_locked(
	struct ebpfos_inode_route *route, int error)
{
	lockdep_assert_held(&route->op_lock);
	ebpfos_file_fence_locked(route);
	if (route->migration)
		ebpfos_file_migration_doom_locked(route->migration, error);
}

static void ebpfos_file_recovery_fail_locked(
	struct ebpfos_inode_route *route, int error)
{
	struct ebpfos_file_recovery *recovery = route->recovery;

	lockdep_assert_held(&route->op_lock);
	ebpfos_file_source_fault_locked(route, error);
	if (!recovery)
		return;
	if (!recovery->fatal_error)
		recovery->fatal_error = error;
	recovery->phase = EBPFOS_FILE_RECOVERY_FAILED;
	spin_lock(&route->admission_lock);
	route->admission_gate = EBPFOS_FILE_ADMISSION_FAILED;
	spin_unlock(&route->admission_lock);
	ebpfos_file_recovery_progress_locked(route);
}

static void ebpfos_file_recovery_attempt_fail_locked(
	struct ebpfos_inode_route *route, struct ebpfos_file_call *call,
	int error)
{
	struct ebpfos_file_recovery *recovery = route->recovery;

	lockdep_assert_held(&route->op_lock);
	if (recovery && !call->retry_finished && call->retry_started) {
		recovery->retry_failures++;
		recovery->retry_result = error;
		call->retry_finished = true;
	} else if (recovery && !call->retry_finished && call->needs_retry) {
		if (WARN_ON_ONCE(!recovery->pending_retries))
			error = -EREMOTEIO;
		else
			recovery->pending_retries--;
		recovery->unretried_invocations++;
		recovery->retry_result = error;
		call->retry_finished = true;
	}
	ebpfos_file_recovery_fail_locked(route, error);
}

static void ebpfos_file_recovery_trigger_locked(
	struct ebpfos_inode_route *route, struct ebpfos_file_call *call,
	u32 trigger, u64 sequence, u64 epoch)
{
	struct ebpfos_file_recovery *recovery = route->recovery;

	lockdep_assert_held(&route->op_lock);
	call->needs_retry = true;
	recovery->pending_retries++;
	recovery->trigger = trigger;
	recovery->trigger_invocation_id = call->invocation_id;
	recovery->trigger_acquire_id = call->admission.acquire_id;
	recovery->trigger_sequence = sequence;
	recovery->trigger_epoch = epoch;
	recovery->phase = EBPFOS_FILE_RECOVERY_FENCED;
	spin_lock(&route->admission_lock);
	recovery->fence_acquire_id = route->next_acquire_id;
	route->admission_gate = EBPFOS_FILE_ADMISSION_RECOVERING;
	WRITE_ONCE(route->state, EBPFOS_FILE_ROUTE_FENCED);
	spin_unlock(&route->admission_lock);
	ebpfos_file_recovery_progress_locked(route);
}

static bool ebpfos_file_recovery_capacity_locked(
	struct ebpfos_inode_route *route, struct ebpfos_file_call *call,
	u64 sequence)
{
	struct ebpfos_file_recovery *recovery = route->recovery;

	lockdep_assert_held(&route->op_lock);
	if (!recovery || recovery->phase != EBPFOS_FILE_RECOVERY_ARMED_E3 ||
	    !call->admission.counted_e3 || call->retry_count ||
	    call->admission.provider_id != recovery->e3_provider_id ||
	    call->admission.epoch != recovery->e3_epoch)
		return false;
	recovery->capacity_triggers++;
	ebpfos_file_recovery_trigger_locked(
		route, call, EBPFOS_FILE_RECOVERY_TRIGGER_LOG_CAPACITY,
		sequence, call->admission.epoch);
	return true;
}

static enum ebpfos_file_fault_role ebpfos_file_recovery_fault_locked(
	struct ebpfos_inode_route *route, struct ebpfos_file_call *call,
	const struct ebpfos_file_bpf_ctx *ctx, u32 reason)
{
	struct ebpfos_file_recovery *recovery = route->recovery;

	lockdep_assert_held(&route->op_lock);
	if (!recovery || !call->admission.counted_e3 || call->retry_count ||
	    reason != recovery->expected_fault_reason ||
	    call->admission.provider_id != recovery->e3_provider_id ||
	    call->admission.epoch != recovery->e3_epoch)
		return EBPFOS_FILE_FAULT_NONE;
	if (recovery->phase == EBPFOS_FILE_RECOVERY_FENCED) {
		if (READ_ONCE(route->admission_gate) !=
		    EBPFOS_FILE_ADMISSION_RECOVERING ||
		    call->admission.acquire_id > recovery->fence_acquire_id)
			return EBPFOS_FILE_FAULT_NONE;
		call->needs_retry = true;
		call->typed_fault = true;
		recovery->faults_observed++;
		recovery->coalesced_faults++;
		recovery->pending_retries++;
		return EBPFOS_FILE_FAULT_FOLLOWER;
	}
	if (recovery->phase != EBPFOS_FILE_RECOVERY_ARMED_E3)
		return EBPFOS_FILE_FAULT_NONE;

	call->typed_fault = true;
	recovery->faults_observed++;
	recovery->fault_invocation_id = call->admission.invocation_id;
	recovery->fault_acquire_id = call->admission.acquire_id;
	recovery->fault_sequence = ctx->sequence;
	recovery->fault_epoch = ctx->epoch;
	route->fault_count++;
	ebpfos_file_recovery_trigger_locked(
		route, call, EBPFOS_FILE_RECOVERY_TRIGGER_TYPED_FAULT,
		ctx->sequence, call->admission.epoch);
	return EBPFOS_FILE_FAULT_LEADER;
}

static int ebpfos_file_delta_slot_locked(
	struct ebpfos_inode_route *route, size_t count,
	struct ebpfos_file_delta **delta_out)
{
	struct ebpfos_file_transaction *txn = route->migration;
	u64 ring_index;

	lockdep_assert_held(&route->op_lock);
	*delta_out = NULL;
	if (!count || !txn ||
	    !ebpfos_file_migration_captures(txn->stream.phase))
		return 0;
	if (count > EBPFOS_FILE_BPF_DATA_SIZE)
		return -E2BIG;
	if (WARN_ON_ONCE(txn->stream.ring_count >=
			 EBPFOS_FILE_DELTA_CAPACITY))
		return -EIO;

	ring_index = txn->stream.captured_deltas %
		     EBPFOS_FILE_DELTA_CAPACITY;
	*delta_out = &txn->deltas[ring_index];
	return 0;
}

static int ebpfos_file_capture_delta_locked(
	struct ebpfos_inode_route *route, struct ebpfos_file_delta *delta,
	u64 file_cookie, u64 sequence, u64 visible_before, u64 visible_after,
	size_t requested, size_t committed)
{
	struct ebpfos_file_transaction *txn = route->migration;
	u64 expected_visible;
	u64 ring_index;

	lockdep_assert_held(&route->op_lock);
	if (!delta || !committed)
		return 0;
	if (!txn || !ebpfos_file_migration_captures(txn->stream.phase) ||
	    committed > requested ||
	    check_add_overflow(visible_before, (u64)committed,
			       &expected_visible) ||
	    visible_after != expected_visible) {
		if (txn)
			ebpfos_file_migration_doom_locked(txn, -EREMOTEIO);
		return -EREMOTEIO;
	}

	ring_index = txn->stream.captured_deltas %
		     EBPFOS_FILE_DELTA_CAPACITY;
	if (delta != &txn->deltas[ring_index]) {
		ebpfos_file_migration_doom_locked(txn, -EREMOTEIO);
		return -EREMOTEIO;
	}
	delta->sequence = sequence;
	delta->file_cookie = file_cookie;
	delta->visible_before = visible_before;
	delta->visible_after = visible_after;
	delta->size = committed;
	switch (txn->stream.phase) {
	case EBPFOS_FILE_MIGRATION_SNAPSHOTTING:
		txn->stream.snapshotting_captured_deltas++;
		break;
	case EBPFOS_FILE_MIGRATION_IMPORTING:
		txn->stream.importing_captured_deltas++;
		break;
	case EBPFOS_FILE_MIGRATION_CATCHING_UP:
		txn->stream.catching_up_captured_deltas++;
		break;
	default:
		WARN_ON_ONCE(1);
		ebpfos_file_migration_doom_locked(txn, -EREMOTEIO);
		return -EREMOTEIO;
	}
	if (!ring_index && txn->stream.captured_deltas)
		txn->stream.ring_wraps++;
	txn->stream.captured_deltas++;
	txn->stream.captured_delta_bytes += committed;
	txn->stream.ring_count++;
	txn->stream.pending_delta_bytes += committed;
	txn->stream.ring_high_water =
		max_t(u64, txn->stream.ring_high_water,
		      txn->stream.ring_count);
	txn->stream.queue_tail_visible = visible_after;
	txn->stream.queue_last_write_sequence = sequence;
	return 0;
}

static int ebpfos_file_run_provider_raw(
	struct bpf_prog *prog, struct ebpfos_file_bpf_ctx *ctx,
	struct ebpfos_file_provider_reply *reply)
{
#ifdef CONFIG_BPF_JIT
	struct bpf_tramp_run_ctx run_ctx = {
		.bpf_cookie = 0,
	};
	u64 start;
	u32 response;
	u32 payload;
	u32 status;

	reply->status = EBPFOS_CALL_RETURN_FAULT;
	reply->payload = 0;
	start = __bpf_prog_enter_sleepable_recur(prog, &run_ctx);
	if (!start) {
		__bpf_prog_exit_sleepable_recur(prog, 0, &run_ctx);
		return -EIO;
	}
	response = bpf_prog_run(prog, ctx);
	__bpf_prog_exit_sleepable_recur(prog, 0, &run_ctx);

	status = EBPFOS_CALL_RETURN_STATUS(response);
	payload = EBPFOS_CALL_RETURN_PAYLOAD(response);
	reply->status = status;
	reply->payload = payload;
	return 0;
#else
	reply->status = EBPFOS_CALL_RETURN_FAULT;
	reply->payload = 0;
	return -EIO;
#endif
}

static int ebpfos_file_run_provider(struct bpf_prog *prog,
				    struct ebpfos_file_bpf_ctx *ctx,
				    bool *must_fence)
{
	struct ebpfos_file_provider_reply reply;
	int error;

	*must_fence = false;
	error = ebpfos_file_run_provider_raw(prog, ctx, &reply);
	if (error) {
		*must_fence = true;
		return error;
	}
	if (reply.status == EBPFOS_CALL_RETURN_OK && !reply.payload)
		return 0;
	if (reply.status == EBPFOS_CALL_RETURN_DENY && reply.payload &&
	    reply.payload <= MAX_ERRNO)
		return -(int)reply.payload;
	*must_fence = true;
	return -EIO;
}

static void ebpfos_file_ctx_init(struct ebpfos_file_bpf_ctx *ctx,
				 u32 op, u32 flags,
				 struct ebpfos_inode_route *route,
				 u64 file_cookie, u64 epoch,
				 u64 sequence, u64 offset, u64 count,
				 u64 visible_size)
{
	memset(ctx, 0, sizeof(*ctx));
	ctx->op = op;
	ctx->flags = flags;
	ctx->route_id = route->route_id;
	ctx->file_cookie = file_cookie;
	ctx->epoch = epoch;
	ctx->sequence = sequence;
	ctx->offset = offset;
	ctx->count = count;
	ctx->visible_size = visible_size;
	ctx->result = -EINPROGRESS;
	ctx->result_offset = U64_MAX;
	ctx->result_visible_size = U64_MAX;
}

static ssize_t ebpfos_file_bpf_write_locked(
	struct ebpfos_inode_route *route, struct kiocb *iocb,
	struct iov_iter *from, struct ebpfos_file_call *call,
	bool *start_recovery, bool *wait_recovery)
{
	struct ebpfos_file_bpf_ctx *ctx;
	struct ebpfos_file_recovery_delta *recovery_delta = NULL;
	struct ebpfos_file_recovery *recovery = route->recovery;
	struct ebpfos_file_provider_reply reply;
	struct ebpfos_file_delta *delta = NULL;
	struct bpf_prog *prog = call->admission.prog ?: route->prog;
	enum ebpfos_file_fault_role fault_role;
	struct iov_iter source;
	u64 sequence = route->last_sequence + 1;
	u64 epoch = call->admission.prog ?
		call->admission.epoch : route->epoch;
	u64 before = route->visible_size;
	u64 file_cookie;
	u64 new_size;
	size_t count;
	bool logging_e3;
	int error;

	lockdep_assert_held(&route->op_lock);
	*start_recovery = false;
	*wait_recovery = false;
	logging_e3 = recovery && call->admission.counted_e3 &&
		call->admission.provider_id == recovery->e3_provider_id &&
		call->admission.epoch == recovery->e3_epoch;
	if (call->retry_count) {
		if (call->retry_count != 1 || !call->needs_retry ||
		    call->retry_started || call->retry_finished || !recovery ||
		    recovery->phase != EBPFOS_FILE_RECOVERY_PUBLISHED_E4 ||
		    !recovery->pending_retries ||
		    recovery->retry_count == U32_MAX ||
		    call->admission.provider_id != recovery->e4_provider_id ||
		    call->admission.epoch != recovery->e4_epoch) {
			ebpfos_file_recovery_attempt_fail_locked(
				route, call, -EREMOTEIO);
			return -EIO;
		}
		recovery->pending_retries--;
		recovery->retry_count++;
		call->retry_started = true;
		recovery->retry_invocation_id = call->invocation_id;
		recovery->retry_acquire_id = call->admission.acquire_id;
		recovery->retry_epoch = call->admission.epoch;
		recovery->retry_result = -EINPROGRESS;
	}
	if (call->data_valid) {
		count = call->count;
	} else {
		count = iov_iter_count(from);
		if (count > EBPFOS_FILE_BPF_DATA_SIZE)
			return -E2BIG;
		source = *from;
		if (copy_from_iter(call->data, count, &source) != count)
			return -EFAULT;
		call->count = count;
		call->data_valid = true;
	}
	if (!sequence) {
		ebpfos_file_recovery_attempt_fail_locked(route, call, -EOVERFLOW);
		return -EIO;
	}
	if (check_add_overflow(before, (u64)count, &new_size) ||
	    new_size > EBPFOS_FILE_SNAPSHOT_MAX) {
		if (call->retry_count)
			ebpfos_file_recovery_attempt_fail_locked(route, call, -EFBIG);
		return -EFBIG;
	}
	if (logging_e3) {
		if (recovery->log_count >= recovery->log_capacity) {
			/* No E3 call may run without a durable commit slot. */
			if (recovery->phase == EBPFOS_FILE_RECOVERY_ARMED_E3) {
				if (!ebpfos_file_recovery_capacity_locked(
					    route, call, sequence)) {
					ebpfos_file_recovery_attempt_fail_locked(
						route, call, -EREMOTEIO);
					return -EIO;
				}
				*start_recovery = true;
				return 0;
			}
			recovery->backpressure_waits++;
			*wait_recovery = true;
			return 0;
		}
		recovery_delta = &recovery->log[recovery->log_count];
		memcpy(recovery_delta->data, call->data, count);
	} else if (!call->admission.prog) {
		error = ebpfos_file_delta_slot_locked(route, count, &delta);
		if (error)
			return error;
		if (delta)
			memcpy(delta->data, call->data, count);
	}

	ctx = kzalloc_obj(*ctx, GFP_KERNEL);
	if (!ctx) {
		if (call->retry_count)
			ebpfos_file_recovery_attempt_fail_locked(route, call, -ENOMEM);
		return -ENOMEM;
	}
	file_cookie = ebpfos_file_cookie(iocb->ki_filp);
	call->file_cookie = file_cookie;
	ebpfos_file_ctx_init(ctx, EBPFOS_FILE_OP_WRITE,
			     EBPFOS_FILE_F_APPEND | EBPFOS_FILE_F_FOREGROUND,
			     route, file_cookie, epoch, sequence, before,
			     count, before);
	ctx->data_size = count;
	memcpy(ctx->data, call->data, count);
	if (logging_e3) {
		if (recovery->e3_write_attempts == U64_MAX) {
			ebpfos_file_recovery_attempt_fail_locked(
				route, call, -EOVERFLOW);
			error = -EOVERFLOW;
			goto out;
		}
		recovery->e3_write_attempts++;
	}

	error = ebpfos_file_run_provider_raw(prog, ctx, &reply);
	if (error) {
		ebpfos_file_recovery_attempt_fail_locked(route, call, -EIO);
		error = -EIO;
		goto out;
	}
	if (reply.status == EBPFOS_CALL_RETURN_DENY && reply.payload &&
	    reply.payload <= MAX_ERRNO) {
		error = -(int)reply.payload;
		if (call->retry_count)
			ebpfos_file_recovery_attempt_fail_locked(route, call, error);
		goto out;
	}
	if (reply.status == EBPFOS_CALL_RETURN_FAULT && reply.payload) {
		fault_role = ebpfos_file_recovery_fault_locked(
			route, call, ctx, reply.payload);
		if (fault_role == EBPFOS_FILE_FAULT_LEADER) {
			*start_recovery = true;
			error = 0;
			goto out;
		}
		if (fault_role == EBPFOS_FILE_FAULT_FOLLOWER) {
			*wait_recovery = true;
			error = 0;
			goto out;
		}
	}
	if (reply.status != EBPFOS_CALL_RETURN_OK || reply.payload) {
		ebpfos_file_recovery_attempt_fail_locked(route, call, -EIO);
		error = -EIO;
		goto out;
	}
	if (ctx->result != count || ctx->data_size ||
	    ctx->result_offset != new_size ||
	    ctx->result_visible_size != new_size) {
		ebpfos_file_recovery_attempt_fail_locked(route, call, -EREMOTEIO);
		error = -EIO;
		goto out;
	}

	route->visible_size = new_size;
	route->last_sequence = sequence;
	route->write_calls++;
	route->write_bytes += count;
	if (logging_e3) {
		recovery_delta->invocation_id = call->admission.invocation_id;
		recovery_delta->acquire_id = call->admission.acquire_id;
		recovery_delta->provider_id = call->admission.provider_id;
		recovery_delta->epoch = call->admission.epoch;
		recovery_delta->sequence = sequence;
		recovery_delta->file_cookie = file_cookie;
		recovery_delta->visible_before = before;
		recovery_delta->visible_after = new_size;
		recovery_delta->size = count;
		recovery->committed_delta_bytes += count;
		recovery->log_count++;
	} else if (!call->admission.prog) {
		ebpfos_file_capture_delta_locked(route, delta, file_cookie, sequence,
						 before, new_size, count, count);
	}
	if (recovery && call->retry_started &&
	    call->admission.provider_id == recovery->e4_provider_id) {
		recovery->retry_sequence = sequence;
		recovery->retry_epoch = call->admission.epoch;
		recovery->retry_result = count;
		recovery->retry_commits++;
		call->retry_finished = true;
	}
	iov_iter_advance(from, count);
	iocb->ki_pos = new_size;
	error = count;
out:
	kfree(ctx);
	return error;
}

static ssize_t ebpfos_file_bpf_read_locked(
	struct ebpfos_inode_route *route, struct kiocb *iocb,
	struct iov_iter *to, const struct ebpfos_file_admission *admission)
{
	struct ebpfos_file_bpf_ctx *ctx = NULL;
	struct ebpfos_file_provider_reply reply;
	struct bpf_prog *prog = admission->prog ?: route->prog;
	u64 epoch = admission->prog ? admission->epoch : route->epoch;
	u64 sequence = route->last_sequence + 1;
	u64 position;
	size_t requested = iov_iter_count(to);
	size_t target;
	size_t staged = 0;
	size_t copied;
	void *buffer = NULL;
	int error = 0;

	lockdep_assert_held(&route->op_lock);
	if (!sequence || iocb->ki_pos < 0) {
		if (!sequence)
			ebpfos_file_recovery_fail_locked(route, -EOVERFLOW);
		return !sequence ? -EIO : -EINVAL;
	}
	position = iocb->ki_pos;
	target = position < route->visible_size ?
		 min_t(u64, requested, route->visible_size - position) : 0;
	if (target) {
		buffer = kvmalloc(target, GFP_KERNEL | __GFP_NOWARN);
		if (!buffer)
			return -ENOMEM;
	}
	ctx = kzalloc_obj(*ctx, GFP_KERNEL);
	if (!ctx) {
		error = -ENOMEM;
		goto out;
	}

	do {
		size_t count = min_t(size_t, target - staged,
					 EBPFOS_FILE_BPF_DATA_SIZE);

		ebpfos_file_ctx_init(ctx, EBPFOS_FILE_OP_READ,
				     EBPFOS_FILE_F_FOREGROUND, route,
				     ebpfos_file_cookie(iocb->ki_filp),
				     epoch, sequence, position + staged,
				     count, route->visible_size);
		error = ebpfos_file_run_provider_raw(prog, ctx, &reply);
		if (error) {
			ebpfos_file_recovery_fail_locked(route, -EIO);
			error = -EIO;
			goto out;
		}
		if (reply.status == EBPFOS_CALL_RETURN_DENY && reply.payload &&
		    reply.payload <= MAX_ERRNO) {
			error = -(int)reply.payload;
			goto out;
		}
		if (reply.status != EBPFOS_CALL_RETURN_OK || reply.payload) {
			ebpfos_file_recovery_fail_locked(route, -EIO);
			error = -EIO;
			goto out;
		}
		if (ctx->result < 0 || ctx->result > count ||
		    ctx->data_size != ctx->result ||
		    ctx->result_offset != position + staged + ctx->result ||
		    ctx->result_visible_size != route->visible_size) {
			ebpfos_file_recovery_fail_locked(route, -EREMOTEIO);
			error = -EIO;
			goto out;
		}
		if (ctx->result)
			memcpy(buffer + staged, ctx->data, ctx->result);
		staged += ctx->result;
		if (ctx->result != count)
			break;
	} while (staged < target);

	copied = copy_to_iter(buffer, staged, to);
	if (copied != staged) {
		if (!copied && staged) {
			error = -EFAULT;
			goto out;
		}
		staged = copied;
	}
	iocb->ki_pos = position + staged;
	route->last_sequence = sequence;
	route->read_calls++;
	route->read_bytes += staged;
	error = staged;
out:
	kfree(ctx);
	kvfree(buffer);
	return error;
}

static ssize_t ebpfos_file_native_call_locked(
	struct ebpfos_inode_route *route, struct kiocb *iocb,
	struct iov_iter *iter, ebpfos_file_iter_fn native, bool write)
{
	struct ebpfos_file_delta *delta = NULL;
	struct iov_iter *original = iter;
	struct iov_iter native_iter;
	struct iov_iter source;
	struct kvec vector;
	u64 before = route->visible_size;
	u64 after;
	size_t count = iov_iter_count(iter);
	ssize_t result;
	int error;

	lockdep_assert_held(&route->op_lock);
	if (route->last_sequence == U64_MAX)
		return -EOVERFLOW;
	if (write && (before > EBPFOS_FILE_SNAPSHOT_MAX ||
		      count > EBPFOS_FILE_SNAPSHOT_MAX - before))
		return -EFBIG;

	if (write) {
		error = ebpfos_file_delta_slot_locked(route, count, &delta);
		if (error)
			return error;
	}
	if (delta) {
		source = *iter;
		if (copy_from_iter(delta->data, count, &source) != count)
			return -EFAULT;
		vector.iov_base = delta->data;
		vector.iov_len = count;
		iov_iter_kvec(&native_iter, ITER_SOURCE, &vector, 1, count);
		iter = &native_iter;
	}

	if (write)
		route->native_write_body_calls++;
	else
		route->native_read_body_calls++;
	result = native(iocb, iter);
	if (result < 0)
		return result;
	if (write && delta)
		iov_iter_advance(original, result);

	route->last_sequence++;
	if (write) {
		route->write_calls++;
		if (result > 0)
			route->write_bytes += result;
		after = i_size_read(route->inode);
		route->visible_size = after;
		ebpfos_file_capture_delta_locked(
			route, delta, ebpfos_file_cookie(iocb->ki_filp),
			route->last_sequence, before, after, count,
			result > 0 ? result : 0);
	} else {
		route->read_calls++;
		if (result > 0)
			route->read_bytes += result;
	}
	return result;
}

static bool ebpfos_file_write_must_wait_locked(
	struct ebpfos_inode_route *route)
{
	struct ebpfos_file_transaction *txn = route->migration;

	lockdep_assert_held(&route->op_lock);
	if (!txn)
		return false;
	if (txn->stream.phase == EBPFOS_FILE_MIGRATION_DRAINING ||
	    txn->stream.phase == EBPFOS_FILE_MIGRATION_FREEZING)
		return true;
	return ebpfos_file_migration_captures(txn->stream.phase) &&
	       txn->stream.ring_count >= EBPFOS_FILE_DELTA_CAPACITY;
}

static int ebpfos_file_complete_recovery(
	struct ebpfos_inode_route *route, struct ebpfos_file_call *call,
	struct file *file);

static bool ebpfos_file_admission_valid_locked(
	struct ebpfos_inode_route *route,
	const struct ebpfos_file_admission *admission)
{
	struct ebpfos_file_recovery *recovery = route->recovery;

	lockdep_assert_held(&route->op_lock);
	if (!admission->prog)
		return route->state == EBPFOS_FILE_ROUTE_ACTIVE &&
		       READ_ONCE(route->admission_gate) ==
			       EBPFOS_FILE_ADMISSION_LEGACY;
	if (route->state == EBPFOS_FILE_ROUTE_ACTIVE &&
	    route->prog == admission->prog &&
	    route->provider_id == admission->provider_id &&
	    route->epoch == admission->epoch)
		return true;
	return admission->counted_e3 && recovery &&
	       recovery->phase == EBPFOS_FILE_RECOVERY_FENCED &&
	       admission->provider_id == recovery->e3_provider_id &&
	       admission->epoch == recovery->e3_epoch &&
	       admission->acquire_id <= recovery->fence_acquire_id;
}

static ssize_t
ebpfos_file_locked_call(struct ebpfos_inode_route *route, struct kiocb *iocb,
			struct iov_iter *iter, ebpfos_file_iter_fn native,
			bool write, struct ebpfos_file_call *call)
{
	bool start_recovery;
	bool wait_recovery;
	ssize_t result;
	u64 progress;
	int error;

	if (!ebpfos_file_scalar_io(iocb, iter, write)) {
		atomic64_inc(&route->rejected_calls);
		return -EOPNOTSUPP;
	}

retry_admission:
	error = ebpfos_file_admission_acquire(route, &call->admission);
	if (error == -EAGAIN) {
		result = wait_event_killable(
			route->migration_wait,
			READ_ONCE(route->admission_gate) !=
				EBPFOS_FILE_ADMISSION_RECOVERING);
		if (result)
			return result;
		goto retry_admission;
	}
	if (error) {
		if (call->needs_retry && !call->retry_finished) {
			mutex_lock(&route->op_lock);
			ebpfos_file_recovery_attempt_fail_locked(route, call, error);
			mutex_unlock(&route->op_lock);
		}
		return error;
	}
	call->admission.invocation_id = call->invocation_id;

	mutex_lock(&route->op_lock);
retry_legacy:
	if (route->state == EBPFOS_FILE_ROUTE_DEAD) {
		bool retired = route->native_retired;

		if (call->needs_retry && !call->retry_finished)
			ebpfos_file_recovery_attempt_fail_locked(route, call, -EIO);
		mutex_unlock(&route->op_lock);
		ebpfos_file_admission_release(route, &call->admission);
		return retired ? -EIO : native(iocb, iter);
	}
	if (!ebpfos_file_admission_valid_locked(route, &call->admission)) {
		u32 gate = READ_ONCE(route->admission_gate);

		atomic64_inc(&route->rejected_calls);
		mutex_unlock(&route->op_lock);
		ebpfos_file_admission_release(route, &call->admission);
		if (gate == EBPFOS_FILE_ADMISSION_E3_OPEN ||
		    gate == EBPFOS_FILE_ADMISSION_E4_OPEN ||
		    gate == EBPFOS_FILE_ADMISSION_RECOVERING)
			goto retry_admission;
		mutex_lock(&route->op_lock);
		if (call->needs_retry && !call->retry_finished)
			ebpfos_file_recovery_attempt_fail_locked(route, call, -EIO);
		mutex_unlock(&route->op_lock);
		return -EIO;
	}
	if (!call->admission.prog && write &&
	    ebpfos_file_write_must_wait_locked(route)) {
		route->migration->stream.backpressure_waits++;
		atomic64_inc(&route->migration_waiters);
		progress = atomic64_read(&route->migration_progress);
		mutex_unlock(&route->op_lock);
		result = wait_event_killable(
			route->migration_wait,
			atomic64_read(&route->migration_progress) != progress);
		atomic64_dec(&route->migration_waiters);
		if (result)
			return result;
		mutex_lock(&route->op_lock);
		goto retry_legacy;
	}
	ebpfos_file_cookie(iocb->ki_filp);
	start_recovery = false;
	wait_recovery = false;
	atomic64_inc(&route->active_calls);
	if ((call->admission.prog &&
	     call->admission.provider_kind == EBPFOS_PROVIDER_BPF) ||
	    (!call->admission.prog &&
	     route->provider_kind == EBPFOS_PROVIDER_BPF))
		result = write ? ebpfos_file_bpf_write_locked(
			route, iocb, iter, call, &start_recovery,
			&wait_recovery) :
			ebpfos_file_bpf_read_locked(route, iocb, iter,
						    &call->admission);
	else
		result = ebpfos_file_native_call_locked(route, iocb, iter,
							native, write);
	atomic64_dec(&route->active_calls);
	mutex_unlock(&route->op_lock);
	ebpfos_file_admission_release(route, &call->admission);
	if (write && start_recovery) {
		error = ebpfos_file_complete_recovery(route, call,
						      iocb->ki_filp);
		if (error) {
			mutex_lock(&route->op_lock);
			if (!call->retry_finished)
				ebpfos_file_recovery_attempt_fail_locked(
					route, call, error);
			mutex_unlock(&route->op_lock);
			return error;
		}
		call->retry_count = 1;
		goto retry_admission;
	}
	if (write && wait_recovery) {
		if (call->needs_retry) {
			wait_event(route->migration_wait,
				   READ_ONCE(route->admission_gate) !=
					   EBPFOS_FILE_ADMISSION_RECOVERING);
			if (READ_ONCE(route->admission_gate) !=
			    EBPFOS_FILE_ADMISSION_E4_OPEN) {
				mutex_lock(&route->op_lock);
				error = route->recovery &&
					route->recovery->fatal_error ?
					route->recovery->fatal_error : -EIO;
				ebpfos_file_recovery_attempt_fail_locked(
					route, call, error);
				mutex_unlock(&route->op_lock);
				return error;
			}
			call->retry_count = 1;
			goto retry_admission;
		}
		result = wait_event_killable(
			route->migration_wait,
			READ_ONCE(route->admission_gate) !=
				EBPFOS_FILE_ADMISSION_E3_OPEN);
		if (result)
			return result;
		goto retry_admission;
	}
	return result;
}

static ssize_t ebpfos_file_iter(struct kiocb *iocb, struct iov_iter *iter,
				ebpfos_file_iter_fn native, bool write)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	struct ebpfos_file_call *call;
	struct ebpfos_inode_route *route;
	ssize_t result;
	int index;

	index = srcu_read_lock(&ebpfos_inode_srcu);
	route = srcu_dereference(inode->i_ebpfos_route, &ebpfos_inode_srcu);
	if (!route) {
		result = native(iocb, iter);
		srcu_read_unlock(&ebpfos_inode_srcu, index);
		return result;
	}
	kref_get(&route->ref);
	srcu_read_unlock(&ebpfos_inode_srcu, index);

	call = kzalloc_obj(*call, GFP_KERNEL);
	if (!call) {
		result = -ENOMEM;
		goto out_route;
	}
	call->invocation_id =
		ebpfos_file_new_id(&route->next_invocation_id);
	result = ebpfos_file_locked_call(route, iocb, iter, native, write,
					 call);
	kfree(call);
out_route:
	ebpfos_inode_route_put(route);
	return result;
}

ssize_t ebpfos_file_read_iter(struct kiocb *iocb, struct iov_iter *to,
			      ebpfos_file_iter_fn native_read)
{
	return ebpfos_file_iter(iocb, to, native_read, false);
}

ssize_t ebpfos_file_write_iter(struct kiocb *iocb, struct iov_iter *from,
			       ebpfos_file_iter_fn native_write)
{
	return ebpfos_file_iter(iocb, from, native_write, true);
}

static bool ebpfos_file_supported(struct file *file)
{
#ifdef CONFIG_TMPFS
	return ebpfos_shmem_file_supported(file);
#else
	return false;
#endif
}

static ssize_t ebpfos_file_snapshot(struct file *file, void *buffer,
				    size_t size)
{
#ifdef CONFIG_TMPFS
	return ebpfos_shmem_native_snapshot(file, buffer, size);
#else
	return -EOPNOTSUPP;
#endif
}

static ssize_t ebpfos_file_native_read(struct file *file, void *buffer,
				       size_t size, loff_t offset)
{
#ifdef CONFIG_TMPFS
	return ebpfos_shmem_native_read(file, buffer, size, offset);
#else
	return -EOPNOTSUPP;
#endif
}

static u64 ebpfos_file_digest(const void *buffer, size_t size)
{
	const u8 *bytes = buffer;
	u64 digest = EBPFOS_FILE_DIGEST_INITIAL;
	size_t i;

	for (i = 0; i < size; i++)
		digest = (digest ^ bytes[i]) * EBPFOS_FILE_DIGEST_PRIME;
	return digest;
}

static struct ebpfos_inode_route *
ebpfos_inode_route_alloc(struct inode *inode)
{
	struct ebpfos_inode_route *route;

	route = kzalloc_obj(*route, GFP_KERNEL);
	if (!route)
		return NULL;
	kref_init(&route->ref);
	mutex_init(&route->op_lock);
	spin_lock_init(&route->admission_lock);
	init_waitqueue_head(&route->migration_wait);
	atomic64_set(&route->migration_progress, 0);
	atomic64_set(&route->migration_waiters, 0);
	atomic64_set(&route->recovery_progress, 0);
	atomic64_set(&route->next_invocation_id, 0);
	atomic_set(&route->admitted_e3, 0);
	atomic_set(&route->admitted_e4, 0);
	route->inode = inode;
	route->route_id = ebpfos_file_new_id(&ebpfos_next_file_route_id);
	route->provider_id =
		ebpfos_file_new_id(&ebpfos_next_file_provider_id);
	route->schema_hash = EBPFOS_FILE_SCHEMA_NATIVE;
	route->visible_size = i_size_read(inode);
	route->provider_kind = EBPFOS_PROVIDER_NATIVE;
	route->admission_gate = EBPFOS_FILE_ADMISSION_LEGACY;
	route->state = EBPFOS_FILE_ROUTE_ACTIVATING;
	atomic64_set(&route->rejected_calls, 0);
	atomic64_set(&route->active_calls, 0);
	return route;
}

static void ebpfos_file_enroll_fail(struct inode *inode,
				    struct ebpfos_inode_route *route)
{
	rcu_assign_pointer(inode->i_ebpfos_route, NULL);
	synchronize_srcu(&ebpfos_inode_srcu);
	WRITE_ONCE(route->state, EBPFOS_FILE_ROUTE_DEAD);
	mutex_unlock(&route->op_lock);
	ebpfos_inode_route_put(route);
}

long ebpfos_file_enroll_ioctl(void __user *argp)
{
	struct ebpfos_ioc_file_enroll request;
	struct ebpfos_inode_route *route = NULL;
	struct inode *inode;
	struct file *file;
	ssize_t copied;
	loff_t size;
	long error = 0;
	u64 cookie;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags || request.file_fd < 0)
		return -EINVAL;

	file = fget(request.file_fd);
	if (!file)
		return -EBADF;
	if (!ebpfos_file_supported(file) || !S_ISREG(file_inode(file)->i_mode)) {
		error = -EOPNOTSUPP;
		goto out_file;
	}
	inode = file_inode(file);

	mutex_lock(&ebpfos_file_enroll_lock);
	if (rcu_access_pointer(inode->i_ebpfos_route)) {
		error = -EALREADY;
		goto out_enroll;
	}

	route = ebpfos_inode_route_alloc(inode);
	if (!route) {
		error = -ENOMEM;
		goto out_enroll;
	}
	mutex_lock(&route->op_lock);

	i_mmap_lock_write(inode->i_mapping);
	if (mapping_mapped(inode->i_mapping)) {
		i_mmap_unlock_write(inode->i_mapping);
		error = -EBUSY;
		mutex_unlock(&route->op_lock);
		ebpfos_inode_route_put(route);
		goto out_enroll;
	}
	rcu_assign_pointer(inode->i_ebpfos_route, route);
	i_mmap_unlock_write(inode->i_mapping);

	/* Drain every read/write call that observed the native NULL route. */
	synchronize_srcu(&ebpfos_inode_srcu);

	/* Lock order: route operation mutex before inode i_rwsem. */
	inode_lock(inode);
	size = i_size_read(inode);
	route->visible_size = size;
	inode_unlock(inode);
	if (size < 0 || size > EBPFOS_FILE_SNAPSHOT_MAX) {
		error = size < 0 ? -EIO : -EFBIG;
		goto fail_published;
	}
	if (size) {
		route->snapshot = kvmalloc(size, GFP_KERNEL | __GFP_NOWARN);
		if (!route->snapshot) {
			error = -ENOMEM;
			goto fail_published;
		}
	}

	inode_lock(inode);
	if (size != i_size_read(inode)) {
		error = -EAGAIN;
		goto out_inode_fail;
	}
	copied = ebpfos_file_snapshot(file, route->snapshot, size);
	if (copied != size) {
		error = copied < 0 ? copied : -EIO;
		goto out_inode_fail;
	}
	route->snapshot_size = size;
	route->visible_size = size;
	route->snapshot_digest = ebpfos_file_digest(route->snapshot, size);
	cookie = ebpfos_file_cookie(file);
	WRITE_ONCE(route->state, EBPFOS_FILE_ROUTE_ACTIVE);
	inode_unlock(inode);

	request.route_id = route->route_id;
	request.provider_id = route->provider_id;
	request.epoch = route->epoch;
	request.file_cookie = cookie;
	request.inode_number = inode->i_ino;
	request.device = new_encode_dev(inode->i_sb->s_dev);
	request.snapshot_size = route->snapshot_size;
	request.snapshot_digest = route->snapshot_digest;
	if (copy_to_user(argp, &request, sizeof(request))) {
		error = -EFAULT;
		ebpfos_file_enroll_fail(inode, route);
	} else {
		mutex_unlock(&route->op_lock);
	}
	goto out_enroll;

out_inode_fail:
	inode_unlock(inode);
fail_published:
	ebpfos_file_enroll_fail(inode, route);
out_enroll:
	mutex_unlock(&ebpfos_file_enroll_lock);
out_file:
	fput(file);
	return error;
}

static int ebpfos_file_schema_tuple(u64 schema_hash, u32 *key_size,
				    u32 *value_size, u32 *max_entries)
{
	switch (schema_hash) {
	case EBPFOS_FILE_SCHEMA_V1:
		*key_size = EBPFOS_FILE_V1_KEY_SIZE;
		*value_size = EBPFOS_FILE_V1_VALUE_SIZE;
		*max_entries = EBPFOS_FILE_V1_MAX_ENTRIES;
		return 0;
	case EBPFOS_FILE_SCHEMA_V2:
		*key_size = EBPFOS_FILE_V2_KEY_SIZE;
		*value_size = EBPFOS_FILE_V2_VALUE_SIZE;
		*max_entries = EBPFOS_FILE_V2_MAX_ENTRIES;
		return 0;
	default:
		return -EPROTONOSUPPORT;
	}
}

static int ebpfos_file_validate_candidate(struct bpf_prog *prog,
					  struct bpf_map *map,
					  u64 target_schema_hash)
{
	u32 max_entries;
	u32 value_size;
	u32 key_size;
	bool valid;
	int error;

	error = ebpfos_file_schema_tuple(target_schema_hash, &key_size,
					 &value_size, &max_entries);
	if (error)
		return error;

	if (prog->type != BPF_PROG_TYPE_SYSCALL || !prog->sleepable ||
	    !prog->aux->ebpfos_provider ||
	    prog->aux->max_ctx_offset > EBPFOS_FILE_BPF_CTX_SIZE)
		return -EPROTO;
	mutex_lock(&prog->aux->used_maps_mutex);
	valid = prog->aux->used_map_cnt == 1 &&
		prog->aux->used_maps[0] == map;
	mutex_unlock(&prog->aux->used_maps_mutex);
	if (!valid)
		return -EXDEV;

	if (map->map_type != BPF_MAP_TYPE_ARRAY ||
	    map->key_size != key_size || map->value_size != value_size ||
	    map->max_entries != max_entries || map->map_flags ||
	    map->map_extra || map->inner_map_meta || map->record || map->btf ||
	    map->btf_key_type_id || map->btf_value_type_id ||
	    map->btf_vmlinux_value_type_id)
		return -EPROTO;
	mutex_lock(&map->freeze_mutex);
	valid = READ_ONCE(map->frozen);
	mutex_unlock(&map->freeze_mutex);
	return valid ? 0 : -EPERM;
}

static void ebpfos_file_transaction_free(
	struct ebpfos_file_transaction *txn)
{
	if (!txn)
		return;
	ebpfos_file_map_lease_release(txn->map_lease);
	if (txn->prog)
		bpf_prog_put(txn->prog);
	if (txn->map)
		bpf_map_put(txn->map);
	ebpfos_file_recovery_free(txn->recovery);
	kvfree(txn->snapshot);
	kvfree(txn->deltas);
	kvfree(txn->batch);
	if (txn->file)
		fput(txn->file);
	if (txn->route)
		ebpfos_inode_route_put(txn->route);
	kfree(txn);
}

static int ebpfos_file_candidate_control(
	struct ebpfos_file_transaction *txn, struct ebpfos_file_bpf_ctx *ctx,
	u32 op, u64 offset, size_t count, const void *data)
{
	bool fence;
	int error;

	ebpfos_file_ctx_init(ctx, op, EBPFOS_FILE_F_SHADOW, txn->route,
			     ebpfos_file_cookie(txn->file), txn->target_epoch,
			     txn->snapshot_sequence, offset, count,
			     txn->snapshot_size);
	if (data) {
		memcpy(ctx->data, data, count);
		ctx->data_size = count;
	}
	error = ebpfos_file_run_provider(txn->prog, ctx, &fence);
	if (error)
		return fence ? -EIO : error;

	switch (op) {
	case EBPFOS_FILE_OP_IMPORT_BEGIN:
	case EBPFOS_FILE_OP_IMPORT_END:
		if (ctx->result || ctx->result_offset || ctx->data_size ||
		    ctx->result_visible_size != txn->snapshot_size)
			return -EREMOTEIO;
		break;
	case EBPFOS_FILE_OP_IMPORT_CHUNK:
		if (ctx->result != count || ctx->result_offset != offset + count ||
		    ctx->result_visible_size != txn->snapshot_size ||
		    ctx->data_size)
			return -EREMOTEIO;
		break;
	case EBPFOS_FILE_OP_DESCRIBE:
		if (ctx->result || ctx->result_offset || ctx->data_size)
			return -EREMOTEIO;
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int ebpfos_file_candidate_describe_at(
	struct ebpfos_file_transaction *txn, struct ebpfos_file_bpf_ctx *ctx,
	u64 sequence, u64 total_size)
{
	bool fence;
	int error;

	ebpfos_file_ctx_init(ctx, EBPFOS_FILE_OP_DESCRIBE,
			     EBPFOS_FILE_F_SHADOW, txn->route,
			     ebpfos_file_cookie(txn->file), txn->target_epoch,
			     sequence, 0, 0, total_size);
	error = ebpfos_file_run_provider(txn->prog, ctx, &fence);
	if (error)
		return fence ? -EIO : error;
	if (ctx->result || ctx->result_offset || ctx->data_size ||
	    ctx->result_visible_size != total_size)
		return -EREMOTEIO;
	return 0;
}

static int ebpfos_file_candidate_export_at(
	struct ebpfos_file_transaction *txn, struct ebpfos_file_bpf_ctx *ctx,
	u64 sequence, u64 offset, size_t count, u64 total_size)
{
	u64 expected = offset < total_size ?
		min_t(u64, count, total_size - offset) : 0;
	bool fence;
	int error;

	ebpfos_file_ctx_init(ctx, EBPFOS_FILE_OP_EXPORT_CHUNK,
			     EBPFOS_FILE_F_SHADOW, txn->route,
			     ebpfos_file_cookie(txn->file), txn->target_epoch,
			     sequence, offset, count, total_size);
	error = ebpfos_file_run_provider(txn->prog, ctx, &fence);
	if (error)
		return fence ? -EIO : error;
	if (ctx->result != expected || ctx->data_size != expected ||
	    ctx->result_offset != offset + expected ||
	    ctx->result_visible_size != total_size)
		return -EREMOTEIO;
	return 0;
}

static bool ebpfos_file_source_matches_locked(
	const struct ebpfos_file_transaction *txn)
{
	const struct ebpfos_inode_route *route = txn->route;

	lockdep_assert_held(&route->op_lock);
	return route->migration == txn &&
	       route->state == EBPFOS_FILE_ROUTE_ACTIVE &&
	       route->provider_id == txn->source_provider_id &&
	       route->epoch == txn->source_epoch &&
	       route->schema_hash == txn->source_schema_hash &&
	       route->provider_kind == txn->source_provider_kind;
}

static int ebpfos_file_source_export_locked(
	struct ebpfos_file_transaction *txn, struct ebpfos_file_bpf_ctx *ctx,
	u64 sequence, u64 offset, size_t count, u64 total_size, void *output)
{
	struct ebpfos_inode_route *route = txn->route;
	u64 expected = offset < total_size ?
		min_t(u64, count, total_size - offset) : 0;
	bool fence;
	int error;

	lockdep_assert_held(&route->op_lock);
	if (!ebpfos_file_source_matches_locked(txn) ||
	    txn->source_provider_kind != EBPFOS_PROVIDER_BPF || !route->prog) {
		error = -ECANCELED;
		goto fail;
	}
	ebpfos_file_ctx_init(ctx, EBPFOS_FILE_OP_EXPORT_CHUNK,
			     EBPFOS_FILE_F_SHADOW |
			     EBPFOS_FILE_F_SOURCE_SNAPSHOT,
			     route, ebpfos_file_cookie(txn->file),
			     txn->source_epoch, sequence, offset, count,
			     total_size);
	error = ebpfos_file_run_provider(route->prog, ctx, &fence);
	if (error)
		goto fail;
	if (ctx->result != expected || ctx->data_size != expected ||
	    ctx->result_offset != offset + expected ||
	    ctx->result_visible_size != total_size) {
		error = -EREMOTEIO;
		goto fail;
	}
	if (expected)
		memcpy(output, ctx->data, expected);
	return 0;

fail:
	ebpfos_file_source_fault_locked(route, error);
	return error;
}

static int ebpfos_file_capture_source_snapshot(
	struct ebpfos_file_transaction *txn)
{
	struct ebpfos_file_bpf_ctx *ctx;
	u64 offset;
	int error = 0;

	if (txn->source_provider_kind == EBPFOS_PROVIDER_NATIVE) {
		ssize_t copied = ebpfos_file_snapshot(txn->file, txn->snapshot,
						      txn->snapshot_size);

		if (copied != txn->snapshot_size)
			return copied < 0 ? copied : -EIO;
		return 0;
	}

	ctx = kzalloc_obj(*ctx, GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	for (offset = 0; offset < txn->snapshot_size;) {
		size_t count = min_t(u64, EBPFOS_FILE_BPF_DATA_SIZE,
					 txn->snapshot_size - offset);

		mutex_lock(&txn->route->op_lock);
		if (txn->stream.phase != EBPFOS_FILE_MIGRATION_SNAPSHOTTING ||
		    txn->capture_error) {
			error = txn->capture_error ? txn->capture_error : -ECANCELED;
			mutex_unlock(&txn->route->op_lock);
			goto out;
		}
		error = ebpfos_file_source_export_locked(
			txn, ctx, txn->snapshot_sequence, offset, count,
			txn->snapshot_size, txn->snapshot + offset);
		mutex_unlock(&txn->route->op_lock);
		if (error)
			goto out;
		offset += count;
		cond_resched();
	}

	/* Validate the frozen frontier even for an empty snapshot. */
	mutex_lock(&txn->route->op_lock);
	if (txn->stream.phase != EBPFOS_FILE_MIGRATION_SNAPSHOTTING ||
	    txn->capture_error) {
		error = txn->capture_error ? txn->capture_error : -ECANCELED;
	} else {
		error = ebpfos_file_source_export_locked(
			txn, ctx, txn->snapshot_sequence, txn->snapshot_size, 1,
			txn->snapshot_size, NULL);
	}
	mutex_unlock(&txn->route->op_lock);
out:
	kfree(ctx);
	return error;
}

/*
 * Compare the complete candidate image with the still-authoritative source
 * using constant scratch space.  FREEZING excludes writes.  Native bytes are
 * read directly; each BPF-source chunk is exported under op_lock and copied
 * before the lock is released.
 */
static int ebpfos_file_validate_candidate_source(
	struct ebpfos_file_transaction *txn, struct ebpfos_file_bpf_ctx *ctx,
	u64 sequence, u64 total_size)
{
	u8 *source;
	u64 offset;
	int error;

	source = kmalloc(EBPFOS_FILE_BPF_DATA_SIZE, GFP_KERNEL);
	if (!source)
		return -ENOMEM;
	error = ebpfos_file_candidate_describe_at(txn, ctx, sequence,
						  total_size);
	if (error)
		goto out;
	for (offset = 0; offset < total_size;) {
		size_t count = min_t(u64, EBPFOS_FILE_BPF_DATA_SIZE,
					 total_size - offset);

		if (txn->source_provider_kind == EBPFOS_PROVIDER_NATIVE) {
			ssize_t copied = ebpfos_file_native_read(
				txn->file, source, count, (loff_t)offset);

			if (copied != count) {
				error = copied < 0 ? copied : -EREMOTEIO;
				goto out;
			}
		} else {
			mutex_lock(&txn->route->op_lock);
			if (txn->stream.phase != EBPFOS_FILE_MIGRATION_FREEZING ||
			    txn->capture_error) {
				error = txn->capture_error ? txn->capture_error :
					-ECANCELED;
			} else {
				error = ebpfos_file_source_export_locked(
					txn, ctx, sequence, offset, count,
					total_size, source);
			}
			mutex_unlock(&txn->route->op_lock);
			if (error)
				goto out;
		}
		error = ebpfos_file_candidate_export_at(
			txn, ctx, sequence, offset, count, total_size);
		if (error)
			goto out;
		if (memcmp(ctx->data, source, count)) {
			error = -EREMOTEIO;
			goto out;
		}
		offset += count;
	}
	if (txn->source_provider_kind == EBPFOS_PROVIDER_BPF) {
		mutex_lock(&txn->route->op_lock);
		if (txn->stream.phase != EBPFOS_FILE_MIGRATION_FREEZING ||
		    txn->capture_error) {
			error = txn->capture_error ? txn->capture_error : -ECANCELED;
		} else {
			error = ebpfos_file_source_export_locked(
				txn, ctx, sequence, total_size, 1, total_size,
				NULL);
		}
		mutex_unlock(&txn->route->op_lock);
		if (error)
			goto out;
	}
	error = ebpfos_file_candidate_export_at(txn, ctx, sequence,
						total_size, 1, total_size);
out:
	kfree(source);
	return error;
}

static int ebpfos_file_candidate_import(
	struct ebpfos_file_transaction *txn);

static int ebpfos_file_validate_candidate_buffer(
	struct ebpfos_file_transaction *txn, struct ebpfos_file_bpf_ctx *ctx,
	const void *source, u64 sequence, u64 total_size)
{
	u64 offset;
	int error;

	error = ebpfos_file_candidate_describe_at(txn, ctx, sequence,
						  total_size);
	if (error)
		return error;
	for (offset = 0; offset < total_size;) {
		size_t count = min_t(u64, EBPFOS_FILE_BPF_DATA_SIZE,
					 total_size - offset);

		error = ebpfos_file_candidate_export_at(
			txn, ctx, sequence, offset, count, total_size);
		if (error)
			return error;
		if (memcmp(ctx->data, source + offset, count))
			return -EREMOTEIO;
		offset += count;
	}
	return ebpfos_file_candidate_export_at(txn, ctx, sequence,
					       total_size, 1, total_size);
}

static int ebpfos_file_capture_recovery_base(
	struct ebpfos_file_transaction *txn, struct ebpfos_file_bpf_ctx *ctx,
	u64 sequence, u64 total_size)
{
	struct ebpfos_file_recovery *recovery = txn->recovery;
	u64 offset;
	int error = 0;

	if (!recovery)
		return -EINVAL;
	if (total_size) {
		recovery->canonical_base =
			kvmalloc(total_size, GFP_KERNEL | __GFP_NOWARN);
		if (!recovery->canonical_base)
			return -ENOMEM;
	}
	for (offset = 0; offset < total_size;) {
		size_t count = min_t(u64, EBPFOS_FILE_BPF_DATA_SIZE,
					 total_size - offset);

		if (txn->source_provider_kind == EBPFOS_PROVIDER_NATIVE) {
			ssize_t copied = ebpfos_file_native_read(
				txn->file, recovery->canonical_base + offset,
				count, (loff_t)offset);

			if (copied != count)
				return copied < 0 ? copied : -EREMOTEIO;
		} else {
			mutex_lock(&txn->route->op_lock);
			if (txn->stream.phase !=
			    EBPFOS_FILE_MIGRATION_FREEZING ||
			    txn->capture_error) {
				error = txn->capture_error ?
					txn->capture_error : -ECANCELED;
			} else {
				error = ebpfos_file_source_export_locked(
					txn, ctx, sequence, offset, count,
					total_size,
					recovery->canonical_base + offset);
			}
			mutex_unlock(&txn->route->op_lock);
			if (error)
				return error;
		}
		offset += count;
	}
	if (txn->source_provider_kind == EBPFOS_PROVIDER_BPF) {
		mutex_lock(&txn->route->op_lock);
		if (txn->stream.phase != EBPFOS_FILE_MIGRATION_FREEZING ||
		    txn->capture_error) {
			error = txn->capture_error ?
				txn->capture_error : -ECANCELED;
		} else {
			error = ebpfos_file_source_export_locked(
				txn, ctx, sequence, total_size, 1, total_size,
				NULL);
		}
		mutex_unlock(&txn->route->op_lock);
		if (error)
			return error;
	}
	recovery->base_sequence = sequence;
	recovery->base_size = total_size;
	recovery->base_digest = ebpfos_file_digest(
		recovery->canonical_base, total_size);
	recovery->base_validated = true;
	return 0;
}

static int ebpfos_file_prepare_e4(
	struct ebpfos_file_transaction *txn, struct ebpfos_file_bpf_ctx *ctx)
{
	struct ebpfos_file_recovery *recovery = txn->recovery;
	struct ebpfos_file_transaction e4 = {
		.route = txn->route,
		.file = txn->file,
		.prog = recovery->e4_prog,
		.snapshot = recovery->canonical_base,
		.target_epoch = recovery->e4_epoch,
		.snapshot_sequence = recovery->base_sequence,
		.snapshot_size = recovery->base_size,
	};
	int error;

	error = ebpfos_file_candidate_import(&e4);
	if (error)
		return error;
	error = ebpfos_file_validate_candidate_buffer(
		&e4, ctx, recovery->canonical_base, recovery->base_sequence,
		recovery->base_size);
	if (error)
		return error;
	recovery->e4_base_ready = true;
	return 0;
}

static int ebpfos_file_candidate_import(
	struct ebpfos_file_transaction *txn)
{
	struct ebpfos_file_bpf_ctx *ctx;
	u64 offset;
	int error;

	ctx = kzalloc_obj(*ctx, GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	error = ebpfos_file_candidate_control(
		txn, ctx, EBPFOS_FILE_OP_IMPORT_BEGIN, 0, 0, NULL);
	if (error)
		goto out;
	for (offset = 0; offset < txn->snapshot_size;) {
		size_t count = min_t(u64, EBPFOS_FILE_BPF_DATA_SIZE,
					 txn->snapshot_size - offset);

		error = ebpfos_file_candidate_control(
			txn, ctx, EBPFOS_FILE_OP_IMPORT_CHUNK, offset, count,
			txn->snapshot + offset);
		if (error)
			goto out;
		offset += count;
	}
	error = ebpfos_file_candidate_control(
		txn, ctx, EBPFOS_FILE_OP_IMPORT_END, 0, 0, NULL);
	if (error)
		goto out;
	error = ebpfos_file_candidate_control(
		txn, ctx, EBPFOS_FILE_OP_DESCRIBE, 0, 0, NULL);
	if (!error && ctx->result_visible_size != txn->snapshot_size)
		error = -EREMOTEIO;
out:
	kfree(ctx);
	return error;
}

static void ebpfos_file_transaction_detach_locked(
	struct ebpfos_file_transaction *txn)
{
	lockdep_assert_held(&txn->route->op_lock);
	if (txn->route->migration == txn)
		txn->route->migration = NULL;
	if (txn->owner_slot && *txn->owner_slot == txn)
		*txn->owner_slot = NULL;
	ebpfos_file_migration_progress_locked(txn->route);
}

static long ebpfos_file_replace_begin(
	struct ebpfos_ioc_file_replace_begin *request, void **txn_slot)
{
	struct ebpfos_file_transaction *txn = NULL;
	struct ebpfos_inode_route *route = NULL;
	struct bpf_prog *prog = NULL;
	struct bpf_map *map = NULL;
	struct inode *inode;
	struct file *file = NULL;
	u32 ignored_entries;
	u32 ignored_value;
	u32 ignored_key;
	long error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (request->flags || request->file_fd < 0 || request->prog_fd < 0 ||
	    request->map_fd < 0)
		return -EINVAL;
	error = ebpfos_file_schema_tuple(request->target_schema_hash,
					 &ignored_key, &ignored_value,
					 &ignored_entries);
	if (error)
		return error;
	if (*txn_slot)
		return -EBUSY;

	file = fget(request->file_fd);
	if (!file)
		return -EBADF;
	if (!ebpfos_file_supported(file) || !S_ISREG(file_inode(file)->i_mode)) {
		error = -EOPNOTSUPP;
		goto out;
	}
	inode = file_inode(file);
	route = ebpfos_inode_route_get(inode);
	if (!route) {
		error = -ENOENT;
		goto out;
	}

	prog = bpf_prog_get_type_dev(request->prog_fd, BPF_PROG_TYPE_SYSCALL,
				     false);
	if (IS_ERR(prog)) {
		error = PTR_ERR(prog);
		prog = NULL;
		goto out;
	}
	map = bpf_map_get(request->map_fd);
	if (IS_ERR(map)) {
		error = PTR_ERR(map);
		map = NULL;
		goto out;
	}
	error = ebpfos_file_validate_candidate(prog, map,
					       request->target_schema_hash);
	if (error)
		goto out;

	txn = kzalloc_obj(*txn, GFP_KERNEL);
	if (!txn) {
		error = -ENOMEM;
		goto out;
	}
	txn->deltas = kvcalloc(EBPFOS_FILE_DELTA_CAPACITY,
			       sizeof(*txn->deltas), GFP_KERNEL | __GFP_NOWARN);
	if (!txn->deltas) {
		error = -ENOMEM;
		goto out;
	}
	txn->batch = kvcalloc(EBPFOS_FILE_CATCHUP_BATCH,
			      sizeof(*txn->batch), GFP_KERNEL | __GFP_NOWARN);
	if (!txn->batch) {
		error = -ENOMEM;
		goto out;
	}
	error = ebpfos_file_map_lease_reserve(map, &txn->map_lease);
	if (error)
		goto out;
	txn->route = route;
	route = NULL;
	txn->file = file;
	file = NULL;
	txn->prog = prog;
	prog = NULL;
	txn->map = map;
	map = NULL;
	txn->owner_slot = txn_slot;
	txn->txn_id =
		ebpfos_file_new_id(&ebpfos_next_file_transaction_id);
	txn->provider_id =
		ebpfos_file_new_id(&ebpfos_next_file_provider_id);
	txn->target_schema_hash = request->target_schema_hash;

	mutex_lock(&txn->route->op_lock);
	if (txn->route->state != EBPFOS_FILE_ROUTE_ACTIVE) {
		error = -EOPNOTSUPP;
		goto out_unlock;
	}
	if (txn->route->provider_kind == EBPFOS_PROVIDER_NATIVE) {
		if (txn->route->schema_hash != EBPFOS_FILE_SCHEMA_NATIVE ||
		    txn->route->native_retired) {
			error = -EOPNOTSUPP;
			goto out_unlock;
		}
	} else if (txn->route->provider_kind == EBPFOS_PROVIDER_BPF) {
		if (!txn->route->native_retired || !txn->route->prog ||
		    !txn->route->map || !txn->route->map_lease ||
		    ebpfos_file_schema_tuple(txn->route->schema_hash,
					     &ignored_key, &ignored_value,
					     &ignored_entries)) {
			error = -EOPNOTSUPP;
			goto out_unlock;
		}
	} else {
		error = -EOPNOTSUPP;
		goto out_unlock;
	}
	if (txn->route->migration || txn->route->recovery) {
		error = -EBUSY;
		goto out_unlock;
	}
	if (request->expected_route_id != txn->route->route_id ||
	    request->expected_epoch != txn->route->epoch) {
		error = -ESTALE;
		goto out_unlock;
	}
	if (request->expected_schema_hash != txn->route->schema_hash) {
		error = -EXDEV;
		goto out_unlock;
	}
	if (txn->route->epoch == U64_MAX ||
	    txn->route->last_sequence == U64_MAX) {
		error = -EOVERFLOW;
		goto out_unlock;
	}
	txn->source_provider_id = txn->route->provider_id;
	txn->source_epoch = txn->route->epoch;
	txn->source_schema_hash = txn->route->schema_hash;
	txn->source_provider_kind = txn->route->provider_kind;
	txn->target_epoch = txn->route->epoch + 1;
	txn->snapshot_sequence = txn->route->last_sequence;
	txn->snapshot_size = txn->route->visible_size;
	if (txn->snapshot_size > EBPFOS_FILE_SNAPSHOT_MAX) {
		error = -EFBIG;
		goto out_unlock;
	}
	if (txn->source_provider_kind == EBPFOS_PROVIDER_NATIVE &&
	    i_size_read(inode) != txn->snapshot_size) {
		error = -EREMOTEIO;
		goto out_unlock;
	}
	txn->stream.phase = EBPFOS_FILE_MIGRATION_SNAPSHOTTING;
	txn->stream.queue_tail_visible = txn->snapshot_size;
	txn->stream.queue_last_write_sequence = txn->snapshot_sequence;
	txn->stream.dequeue_visible = txn->snapshot_size;
	txn->stream.dequeue_last_write_sequence = txn->snapshot_sequence;
	txn->stream.candidate_visible = txn->snapshot_size;
	txn->stream.candidate_last_write_sequence = txn->snapshot_sequence;
	txn->stream.verified_visible = txn->snapshot_size;
	txn->stream.verified_last_write_sequence = txn->snapshot_sequence;
	txn->route->migration = txn;
	*txn_slot = txn;
	ebpfos_file_migration_progress_locked(txn->route);
	mutex_unlock(&txn->route->op_lock);

	/*
	 * Capture is installed before this allocation and immutable-prefix read.
	 * The managed tmpfs route admits only serialized append writes, so bytes
	 * below snapshot_size cannot change while the prefix is copied.
	 */
	if (txn->snapshot_size) {
		txn->snapshot = kvmalloc(txn->snapshot_size,
					 GFP_KERNEL | __GFP_NOWARN);
		if (!txn->snapshot) {
			error = -ENOMEM;
			goto fail_installed;
		}
	}
	error = ebpfos_file_capture_source_snapshot(txn);
	if (error)
		goto fail_installed;
	txn->snapshot_digest =
		ebpfos_file_digest(txn->snapshot, txn->snapshot_size);

	mutex_lock(&txn->route->op_lock);
	if (txn->route->migration != txn || txn->capture_error ||
	    txn->route->state != EBPFOS_FILE_ROUTE_ACTIVE ||
	    txn->stream.phase != EBPFOS_FILE_MIGRATION_SNAPSHOTTING) {
		error = txn->capture_error ? txn->capture_error : -ECANCELED;
		goto fail_installed_locked;
	}
	txn->stream.phase = EBPFOS_FILE_MIGRATION_IMPORTING;
	ebpfos_file_migration_progress_locked(txn->route);
	mutex_unlock(&txn->route->op_lock);

	/* Bulk import is outside op_lock; active-source appends continue. */
	error = ebpfos_file_candidate_import(txn);
	kvfree(txn->snapshot);
	txn->snapshot = NULL;
	mutex_lock(&txn->route->op_lock);
	if (!error && txn->route->migration == txn &&
	    !txn->capture_error &&
	    txn->route->state == EBPFOS_FILE_ROUTE_ACTIVE &&
	    txn->stream.phase == EBPFOS_FILE_MIGRATION_IMPORTING) {
		txn->candidate_ready = true;
		txn->stream.phase = EBPFOS_FILE_MIGRATION_CATCHING_UP;
		ebpfos_file_migration_progress_locked(txn->route);
	} else if (!error) {
		error = txn->capture_error ? txn->capture_error : -ECANCELED;
	}
	if (error)
		goto fail_installed_locked;
	mutex_unlock(&txn->route->op_lock);

	request->txn_id = txn->txn_id;
	request->candidate_provider_id = txn->provider_id;
	request->snapshot_sequence = txn->snapshot_sequence;
	request->snapshot_size = txn->snapshot_size;
	request->snapshot_digest = txn->snapshot_digest;
	request->delta_capacity = EBPFOS_FILE_DELTA_CAPACITY;
	request->candidate_prog_id = txn->prog->aux->id;
	request->candidate_map_id = txn->map->id;
	return 0;

fail_installed:
	mutex_lock(&txn->route->op_lock);
fail_installed_locked:
	if (txn->route->migration == txn)
		ebpfos_file_transaction_detach_locked(txn);
	mutex_unlock(&txn->route->op_lock);
	ebpfos_file_transaction_free(txn);
	return error;

out_unlock:
	mutex_unlock(&txn->route->op_lock);
out:
	if (txn)
		ebpfos_file_transaction_free(txn);
	if (prog)
		bpf_prog_put(prog);
	if (map)
		bpf_map_put(map);
	if (route)
		ebpfos_inode_route_put(route);
	if (file)
		fput(file);
	return error;
}

long ebpfos_file_replace_begin_ioctl(void __user *argp, void **txn_slot)
{
	struct ebpfos_ioc_file_replace_begin request;
	long error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	error = ebpfos_file_replace_begin(&request, txn_slot);
	if (error)
		return error;
	if (!copy_to_user(argp, &request, sizeof(request)))
		return 0;
	ebpfos_file_replace_release(txn_slot);
	return -EFAULT;
}

long ebpfos_file_recovery_begin_ioctl(void __user *argp, void **txn_slot)
{
	struct ebpfos_ioc_file_recovery_begin request;
	struct ebpfos_ioc_file_replace_begin e3_request = {};
	struct ebpfos_file_recovery *recovery = NULL;
	struct ebpfos_file_transaction *txn;
	struct bpf_prog *e4_prog = NULL;
	struct bpf_map *e4_map = NULL;
	long error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags || request.file_fd < 0 ||
	    request.e3_prog_fd < 0 || request.e3_map_fd < 0 ||
	    request.e4_prog_fd < 0 || request.e4_map_fd < 0 ||
	    request.log_capacity < 2 ||
	    request.log_capacity > EBPFOS_FILE_DELTA_CAPACITY ||
	    !request.expected_fault_reason ||
	    request.expected_fault_reason >
		    EBPFOS_CALL_RETURN_PAYLOAD_MASK ||
	    request.e3_schema_hash != EBPFOS_FILE_SCHEMA_V2 ||
	    request.e4_schema_hash != EBPFOS_FILE_SCHEMA_V2)
		return -EINVAL;
	if (request.expected_epoch > U64_MAX - 2)
		return -EOVERFLOW;
	if (*txn_slot)
		return -EBUSY;

	recovery = kzalloc_obj(*recovery, GFP_KERNEL);
	if (!recovery)
		return -ENOMEM;
	recovery->log = kvcalloc(request.log_capacity,
				 sizeof(*recovery->log),
				 GFP_KERNEL | __GFP_NOWARN);
	if (!recovery->log) {
		error = -ENOMEM;
		goto out;
	}
	e4_prog = bpf_prog_get_type_dev(request.e4_prog_fd,
					BPF_PROG_TYPE_SYSCALL, false);
	if (IS_ERR(e4_prog)) {
		error = PTR_ERR(e4_prog);
		e4_prog = NULL;
		goto out;
	}
	e4_map = bpf_map_get(request.e4_map_fd);
	if (IS_ERR(e4_map)) {
		error = PTR_ERR(e4_map);
		e4_map = NULL;
		goto out;
	}
	error = ebpfos_file_validate_candidate(e4_prog, e4_map,
					       request.e4_schema_hash);
	if (error)
		goto out;
	error = ebpfos_file_map_lease_reserve(
		e4_map, &recovery->e4_map_lease);
	if (error)
		goto out;
	recovery->e4_prog = e4_prog;
	e4_prog = NULL;
	recovery->e4_map = e4_map;
	e4_map = NULL;

	e3_request.file_fd = request.file_fd;
	e3_request.prog_fd = request.e3_prog_fd;
	e3_request.map_fd = request.e3_map_fd;
	e3_request.expected_route_id = request.expected_route_id;
	e3_request.expected_epoch = request.expected_epoch;
	e3_request.expected_schema_hash = request.expected_schema_hash;
	e3_request.target_schema_hash = request.e3_schema_hash;
	error = ebpfos_file_replace_begin(&e3_request, txn_slot);
	if (error)
		goto out;
	txn = *txn_slot;
	if (txn->source_provider_id != request.expected_provider_id ||
	    txn->target_epoch == U64_MAX || txn->map == recovery->e4_map ||
	    txn->prog == recovery->e4_prog) {
		error = txn->source_provider_id != request.expected_provider_id ?
			-ESTALE : -EINVAL;
		goto out_txn;
	}

	recovery->recovery_id =
		ebpfos_file_new_id(&ebpfos_next_file_recovery_id);
	recovery->e2_provider_id = txn->source_provider_id;
	recovery->e2_epoch = txn->source_epoch;
	recovery->e2_schema_hash = txn->source_schema_hash;
	recovery->e3_provider_id = txn->provider_id;
	recovery->e3_epoch = txn->target_epoch;
	recovery->e3_schema_hash = txn->target_schema_hash;
	recovery->e4_provider_id =
		ebpfos_file_new_id(&ebpfos_next_file_provider_id);
	recovery->e4_epoch = txn->target_epoch + 1;
	recovery->e4_schema_hash = request.e4_schema_hash;
	recovery->log_capacity = request.log_capacity;
	recovery->expected_fault_reason = request.expected_fault_reason;
	recovery->phase = EBPFOS_FILE_RECOVERY_PREPARING;
	recovery->retry_result = -EINPROGRESS;
	txn->recovery = recovery;
	recovery = NULL;

	request.txn_id = txn->txn_id;
	request.recovery_id = txn->recovery->recovery_id;
	request.e3_provider_id = txn->provider_id;
	request.e3_epoch = txn->target_epoch;
	request.e4_provider_id = txn->recovery->e4_provider_id;
	request.e4_epoch = txn->recovery->e4_epoch;
	request.snapshot_sequence = e3_request.snapshot_sequence;
	request.snapshot_size = e3_request.snapshot_size;
	request.snapshot_digest = e3_request.snapshot_digest;
	request.e3_prog_id = txn->prog->aux->id;
	request.e3_map_id = txn->map->id;
	request.e4_prog_id = txn->recovery->e4_prog->aux->id;
	request.e4_map_id = txn->recovery->e4_map->id;
	if (copy_to_user(argp, &request, sizeof(request))) {
		error = -EFAULT;
		goto out_txn;
	}
	return 0;

out_txn:
	ebpfos_file_replace_release(txn_slot);
out:
	if (e4_prog)
		bpf_prog_put(e4_prog);
	if (e4_map)
		bpf_map_put(e4_map);
	ebpfos_file_recovery_free(recovery);
	return error;
}

static int ebpfos_file_replay_delta(
	struct ebpfos_file_transaction *txn, struct ebpfos_file_bpf_ctx *ctx,
	const struct ebpfos_file_delta *delta)
{
	bool fence;
	int error;

	ebpfos_file_ctx_init(ctx, EBPFOS_FILE_OP_WRITE,
			     EBPFOS_FILE_F_APPEND | EBPFOS_FILE_F_SHADOW,
			     txn->route, delta->file_cookie, txn->target_epoch,
			     delta->sequence, delta->visible_before, delta->size,
			     delta->visible_before);
	memcpy(ctx->data, delta->data, delta->size);
	ctx->data_size = delta->size;
	error = ebpfos_file_run_provider(txn->prog, ctx, &fence);
	if (error)
		return fence ? -EIO : error;
	if (ctx->result != delta->size || ctx->data_size ||
	    ctx->result_offset != delta->visible_after ||
	    ctx->result_visible_size != delta->visible_after)
		return -EREMOTEIO;
	return 0;
}

static int ebpfos_file_take_batch_locked(
	struct ebpfos_file_transaction *txn, u32 limit)
{
	struct ebpfos_file_stream_state *stream = &txn->stream;
	u64 visible = stream->dequeue_visible;
	u64 sequence = stream->dequeue_last_write_sequence;
	u64 bytes = 0;
	u32 count;
	u32 i;

	lockdep_assert_held(&txn->route->op_lock);
	if (stream->candidate_busy || stream->batch_count || !limit)
		return -EBUSY;
	if (!stream->ring_count)
		return 0;
	if (stream->captured_deltas !=
	    stream->dequeued_deltas + stream->ring_count ||
	    stream->captured_delta_bytes !=
	    stream->dequeued_delta_bytes + stream->pending_delta_bytes ||
	    !ebpfos_file_capture_phase_counts_valid(stream))
		return -EREMOTEIO;

	count = min3(stream->ring_count, limit,
		     (u32)EBPFOS_FILE_CATCHUP_BATCH);
	for (i = 0; i < count; i++) {
		const struct ebpfos_file_delta *delta =
			&txn->deltas[(stream->ring_head + i) %
				     EBPFOS_FILE_DELTA_CAPACITY];
		u64 visible_after;

		if (!delta->size || delta->size > EBPFOS_FILE_BPF_DATA_SIZE ||
		    delta->visible_before != visible ||
		    check_add_overflow(visible, (u64)delta->size,
				       &visible_after) ||
		    delta->visible_after != visible_after ||
		    delta->sequence <= sequence ||
		    delta->sequence > txn->route->last_sequence ||
		    check_add_overflow(bytes, (u64)delta->size, &bytes))
			return -EREMOTEIO;
		txn->batch[i] = *delta;
		visible = visible_after;
		sequence = delta->sequence;
	}

	stream->ring_head = (stream->ring_head + count) %
			    EBPFOS_FILE_DELTA_CAPACITY;
	stream->ring_count -= count;
	stream->pending_delta_bytes -= bytes;
	stream->dequeued_deltas += count;
	stream->dequeued_delta_bytes += bytes;
	stream->dequeue_visible = visible;
	stream->dequeue_last_write_sequence = sequence;
	stream->batch_count = count;
	stream->batch_applied = 0;
	stream->candidate_busy = true;
	ebpfos_file_migration_progress_locked(txn->route);
	return count;
}

static int ebpfos_file_apply_batch(
	struct ebpfos_file_transaction *txn, struct ebpfos_file_bpf_ctx *ctx,
	u32 *applied_out, u64 *applied_bytes_out)
{
	u64 final_visible;
	u64 final_sequence;
	u64 applied_bytes = 0;
	u32 count = txn->stream.batch_count;
	u32 applied = 0;
	u32 i;
	int error;

	*applied_out = 0;
	*applied_bytes_out = 0;
	if (!count || count > EBPFOS_FILE_CATCHUP_BATCH)
		return -EREMOTEIO;
	if (txn->batch[0].visible_before != txn->stream.candidate_visible)
		return -EREMOTEIO;

	for (i = 0; i < count; i++) {
		error = ebpfos_file_replay_delta(txn, ctx, &txn->batch[i]);
		if (error)
			goto out;
		applied++;
		applied_bytes += txn->batch[i].size;
	}
	final_visible = txn->batch[count - 1].visible_after;
	final_sequence = txn->batch[count - 1].sequence;
	error = ebpfos_file_candidate_describe_at(txn, ctx, final_sequence,
						  final_visible);
	if (error)
		goto out;

	/* Reclaim ring slots only after retaining this exact batch copy. */
	for (i = 0; i < count; i++) {
		const struct ebpfos_file_delta *delta = &txn->batch[i];

		error = ebpfos_file_candidate_export_at(
			txn, ctx, final_sequence, delta->visible_before,
			delta->size, final_visible);
		if (error)
			goto out;
		if (memcmp(ctx->data, delta->data, delta->size)) {
			error = -EREMOTEIO;
			goto out;
		}
	}
out:
	*applied_out = applied;
	*applied_bytes_out = applied_bytes;
	return error;
}

static int ebpfos_file_finish_batch_locked(
	struct ebpfos_file_transaction *txn, u32 applied, u64 applied_bytes,
	int error)
{
	struct ebpfos_file_stream_state *stream = &txn->stream;
	u32 count = stream->batch_count;

	lockdep_assert_held(&txn->route->op_lock);
	if (!stream->candidate_busy || !count || applied > count)
		error = -EREMOTEIO;
	stream->batch_applied = applied;
	stream->replayed_deltas += applied;
	stream->replayed_delta_bytes += applied_bytes;
	if (applied) {
		stream->candidate_visible =
			txn->batch[applied - 1].visible_after;
		stream->candidate_last_write_sequence =
			txn->batch[applied - 1].sequence;
	}
	if (!error && applied != count)
		error = -EREMOTEIO;
	if (error) {
		ebpfos_file_migration_doom_locked(txn, error);
		return error;
	}

	stream->verified_deltas += count;
	stream->verified_delta_bytes += applied_bytes;
	stream->verified_visible = stream->candidate_visible;
	stream->verified_last_write_sequence =
		stream->candidate_last_write_sequence;
	stream->replay_batches++;
	stream->batch_count = 0;
	stream->batch_applied = 0;
	stream->candidate_busy = false;
	return 0;
}

static int ebpfos_file_catchup_one(
	struct ebpfos_file_transaction *txn, struct ebpfos_file_bpf_ctx *ctx)
{
	u64 applied_bytes = 0;
	u32 applied = 0;
	int error;
	int count;

	mutex_lock(&txn->route->op_lock);
	if (txn->route->migration != txn || !txn->candidate_ready ||
	    txn->capture_error ||
	    (txn->stream.phase != EBPFOS_FILE_MIGRATION_CATCHING_UP &&
	     txn->stream.phase != EBPFOS_FILE_MIGRATION_DRAINING)) {
		error = txn->capture_error ? txn->capture_error : -ECANCELED;
		goto out_unlock;
	}
	count = ebpfos_file_take_batch_locked(txn,
					      EBPFOS_FILE_CATCHUP_BATCH);
	if (count <= 0) {
		error = count;
		if (error)
			ebpfos_file_migration_doom_locked(txn, error);
		goto out_unlock;
	}
	mutex_unlock(&txn->route->op_lock);

	error = ebpfos_file_apply_batch(txn, ctx, &applied, &applied_bytes);
	mutex_lock(&txn->route->op_lock);
	if (txn->route->migration != txn && !error)
		error = -ECANCELED;
	error = ebpfos_file_finish_batch_locked(txn, applied, applied_bytes,
						 error);
out_unlock:
	mutex_unlock(&txn->route->op_lock);
	return error ? error : count;
}

long ebpfos_file_replace_catchup_ioctl(void __user *argp, void **txn_slot)
{
	struct ebpfos_ioc_file_replace_catchup request;
	struct ebpfos_file_transaction *txn = *txn_slot;
	struct ebpfos_file_bpf_ctx *ctx;
	struct file *file;
	u32 max_batches;
	u32 batch;
	u32 completed = 0;
	long error = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (!request.max_batches || request.file_fd < 0)
		return -EINVAL;
	if (!txn)
		return -ENOENT;
	if (request.txn_id != txn->txn_id ||
	    request.expected_route_id != txn->route->route_id ||
	    request.expected_epoch + 1 != txn->target_epoch ||
	    request.expected_schema_hash != txn->source_schema_hash)
		return -ESTALE;
	file = fget(request.file_fd);
	if (!file)
		return -EBADF;
	if (file != txn->file) {
		fput(file);
		return -EXDEV;
	}
	fput(file);

	ctx = kzalloc_obj(*ctx, GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	max_batches = min_t(u32, request.max_batches,
			    EBPFOS_FILE_CATCHUP_MAX_BATCHES);
	for (batch = 0; batch < max_batches; batch++) {
		error = ebpfos_file_catchup_one(txn, ctx);
		if (!error) {
			error = completed ? 0 : -EAGAIN;
			break;
		}
		if (error < 0)
			break;
		completed++;
		cond_resched();
		if (signal_pending(current)) {
			/* A completed batch is durable progress for this ioctl. */
			error = 0;
			break;
		}
	}
	if (error > 0)
		error = 0;
	kfree(ctx);
	return error;
}

static int ebpfos_file_replay_recovery_delta_locked(
	struct ebpfos_inode_route *route,
	struct ebpfos_file_recovery *recovery,
	struct ebpfos_file_bpf_ctx *ctx,
	const struct ebpfos_file_recovery_delta *delta)
{
	struct ebpfos_file_provider_reply reply;
	int error;

	lockdep_assert_held(&route->op_lock);
	ebpfos_file_ctx_init(ctx, EBPFOS_FILE_OP_WRITE,
			     EBPFOS_FILE_F_APPEND | EBPFOS_FILE_F_SHADOW,
			     route, delta->file_cookie, recovery->e4_epoch,
			     delta->sequence, delta->visible_before, delta->size,
			     delta->visible_before);
	memcpy(ctx->data, delta->data, delta->size);
	ctx->data_size = delta->size;
	error = ebpfos_file_run_provider_raw(recovery->e4_prog, ctx, &reply);
	if (error)
		return error;
	if (reply.status != EBPFOS_CALL_RETURN_OK || reply.payload)
		return -EIO;
	if (ctx->result != delta->size || ctx->data_size ||
	    ctx->result_offset != delta->visible_after ||
	    ctx->result_visible_size != delta->visible_after)
		return -EREMOTEIO;
	return 0;
}

static int ebpfos_file_complete_recovery(
	struct ebpfos_inode_route *route, struct ebpfos_file_call *call,
	struct file *file)
{
	struct ebpfos_file_map_lease *old_map_lease = NULL;
	struct ebpfos_file_recovery *recovery;
	struct ebpfos_file_transaction e4 = {};
	struct ebpfos_file_bpf_ctx *ctx;
	struct bpf_prog *old_prog = NULL;
	struct bpf_map *old_map = NULL;
	void *expected = NULL;
	u64 expected_size;
	u64 cursor;
	u32 i;
	int error = 0;

	wait_event(route->migration_wait,
		   !atomic_read(&route->admitted_e3) ||
		   READ_ONCE(route->state) == EBPFOS_FILE_ROUTE_DEAD);
	ctx = kzalloc_obj(*ctx, GFP_KERNEL);
	if (!ctx) {
		mutex_lock(&route->op_lock);
		if (route->recovery)
			ebpfos_file_recovery_fail_locked(route, -ENOMEM);
		mutex_unlock(&route->op_lock);
		return -ENOMEM;
	}

	mutex_lock(&route->op_lock);
	recovery = route->recovery;
	if (!recovery ||
	    recovery->phase != EBPFOS_FILE_RECOVERY_FENCED ||
	    recovery->trigger_invocation_id != call->invocation_id ||
	    (recovery->trigger != EBPFOS_FILE_RECOVERY_TRIGGER_TYPED_FAULT &&
	     recovery->trigger != EBPFOS_FILE_RECOVERY_TRIGGER_LOG_CAPACITY) ||
	    atomic_read(&route->admitted_e3) ||
	    route->state == EBPFOS_FILE_ROUTE_DEAD) {
		error = -ECANCELED;
		goto out_fail;
	}
	recovery->frozen_count = recovery->log_count;
	recovery->phase = EBPFOS_FILE_RECOVERY_DRAINED;
	recovery->replay_index = 0;
	ebpfos_file_recovery_progress_locked(route);

	expected_size = recovery->base_size;
	for (i = 0; i < recovery->frozen_count; i++) {
		if (check_add_overflow(expected_size,
				       (u64)recovery->log[i].size,
				       &expected_size) ||
		    expected_size > EBPFOS_FILE_SNAPSHOT_MAX) {
			error = -EOVERFLOW;
			goto out_fail;
		}
	}
	if (expected_size) {
		expected = kvmalloc(expected_size,
				    GFP_KERNEL | __GFP_NOWARN);
		if (!expected) {
			error = -ENOMEM;
			goto out_fail;
		}
	}
	if (recovery->base_size)
		memcpy(expected, recovery->canonical_base,
		       recovery->base_size);
	cursor = recovery->base_size;
	recovery->phase = EBPFOS_FILE_RECOVERY_REPLAYING;
	for (i = 0; i < recovery->frozen_count; i++) {
		const struct ebpfos_file_recovery_delta *delta =
			&recovery->log[i];

		if (delta->provider_id != recovery->e3_provider_id ||
		    delta->epoch != recovery->e3_epoch ||
		    delta->visible_before != cursor ||
		    delta->visible_after != cursor + delta->size) {
			error = -EREMOTEIO;
			goto out_fail;
		}
		error = ebpfos_file_replay_recovery_delta_locked(
			route, recovery, ctx, delta);
		if (error)
			goto out_fail;
		memcpy(expected + cursor, delta->data, delta->size);
		cursor = delta->visible_after;
		recovery->replay_index++;
	}
	if (cursor != expected_size || cursor != route->visible_size) {
		error = -EREMOTEIO;
		goto out_fail;
	}
	e4.route = route;
	e4.file = file;
	e4.prog = recovery->e4_prog;
	e4.target_epoch = recovery->e4_epoch;
	error = ebpfos_file_validate_candidate_buffer(
		&e4, ctx, expected, route->last_sequence, expected_size);
	if (error)
		goto out_fail;
	recovery->e4_ready = true;
	recovery->phase = EBPFOS_FILE_RECOVERY_READY_E4;

	if (route->epoch == U64_MAX ||
	    recovery->e4_epoch != route->epoch + 1 ||
	    !recovery->e4_prog || !recovery->e4_map ||
	    !recovery->e4_map_lease) {
		error = -EREMOTEIO;
		goto out_fail;
	}
	spin_lock(&route->admission_lock);
	old_prog = route->prog;
	old_map = route->map;
	old_map_lease = route->map_lease;
	route->prog = recovery->e4_prog;
	recovery->e4_prog = NULL;
	route->map = recovery->e4_map;
	recovery->e4_map = NULL;
	route->map_lease = recovery->e4_map_lease;
	recovery->e4_map_lease = NULL;
	route->provider_id = recovery->e4_provider_id;
	route->epoch = recovery->e4_epoch;
	route->schema_hash = recovery->e4_schema_hash;
	route->provider_kind = EBPFOS_PROVIDER_BPF;
	recovery->phase = EBPFOS_FILE_RECOVERY_PUBLISHED_E4;
	WRITE_ONCE(route->state, EBPFOS_FILE_ROUTE_ACTIVE);
	route->admission_gate = EBPFOS_FILE_ADMISSION_E4_OPEN;
	spin_unlock(&route->admission_lock);
	ebpfos_file_recovery_progress_locked(route);
	mutex_unlock(&route->op_lock);

	ebpfos_file_map_lease_release(old_map_lease);
	if (old_prog)
		bpf_prog_put(old_prog);
	if (old_map)
		bpf_map_put(old_map);
	kvfree(expected);
	kfree(ctx);
	return 0;

out_fail:
	if (recovery)
		ebpfos_file_recovery_fail_locked(route, error);
	mutex_unlock(&route->op_lock);
	kvfree(expected);
	kfree(ctx);
	return error;
}

static long ebpfos_file_replace_commit(
	struct ebpfos_ioc_file_replace_end *request, void **txn_slot,
	bool recovery_arm, struct ebpfos_ioc_file_recovery_end *recovery_result)
{
	struct ebpfos_file_transaction *txn = *txn_slot;
	struct ebpfos_file_map_lease *old_map_lease = NULL;
	struct ebpfos_file_bpf_ctx *ctx;
	struct bpf_prog *old_prog = NULL;
	struct bpf_map *old_map = NULL;
	struct file *file;
	u64 total_size;
	u64 applied_bytes = 0;
	u32 applied = 0;
	int count;
	long error = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (request->flags || request->file_fd < 0)
		return -EINVAL;
	if (!txn)
		return -ENOENT;
	if (!!txn->recovery != recovery_arm)
		return -EINVAL;
	if (request->txn_id != txn->txn_id ||
	    request->expected_route_id != txn->route->route_id ||
	    request->expected_epoch + 1 != txn->target_epoch ||
	    request->expected_schema_hash != txn->source_schema_hash)
		return -ESTALE;
	file = fget(request->file_fd);
	if (!file)
		return -EBADF;
	if (file != txn->file) {
		fput(file);
		return -EXDEV;
	}
	fput(file);

	ctx = kzalloc_obj(*ctx, GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	mutex_lock(&txn->route->op_lock);
	if (txn->route->migration != txn || !txn->candidate_ready ||
	    txn->capture_error || !ebpfos_file_source_matches_locked(txn) ||
	    txn->route->epoch + 1 != txn->target_epoch ||
	    txn->route->last_sequence == U64_MAX ||
	    txn->stream.phase != EBPFOS_FILE_MIGRATION_CATCHING_UP ||
	    txn->stream.candidate_busy) {
		error = txn->capture_error ? txn->capture_error :
			(txn->route->last_sequence == U64_MAX ? -EOVERFLOW :
			 -ECANCELED);
		goto out_unlock;
	}

	/*
	 * This is the write-admission fence.  A writer that has not yet called the
	 * active source sleeps and later reselects whichever provider is published.
	 * Consequently the lock-free drain below is finite even under a producer
	 * that would otherwise refill every reclaimed ring slot.
	 */
	txn->stream.commit_requested = true;
	txn->stream.phase = EBPFOS_FILE_MIGRATION_DRAINING;
	txn->stream.quiesce_captured_deltas = txn->stream.captured_deltas;
	txn->stream.quiesce_pending_deltas = txn->stream.ring_count;
	txn->stream.quiesce_waiters =
		atomic64_read(&txn->route->migration_waiters);
	ebpfos_file_migration_progress_locked(txn->route);
	mutex_unlock(&txn->route->op_lock);

	for (;;) {
		mutex_lock(&txn->route->op_lock);
		if (txn->route->migration != txn || txn->capture_error ||
		    txn->stream.phase != EBPFOS_FILE_MIGRATION_DRAINING) {
			error = txn->capture_error ? txn->capture_error :
				-ECANCELED;
			goto out_unlock;
		}
		if (txn->stream.ring_count <= EBPFOS_FILE_COMMIT_TAIL) {
			mutex_unlock(&txn->route->op_lock);
			break;
		}
		mutex_unlock(&txn->route->op_lock);
		error = ebpfos_file_catchup_one(txn, ctx);
		if (error < 0)
			goto fail_unlocked;
	}

	mutex_lock(&txn->route->op_lock);
	if (txn->route->migration != txn || txn->capture_error ||
	    txn->stream.phase != EBPFOS_FILE_MIGRATION_DRAINING ||
	    txn->stream.ring_count > EBPFOS_FILE_COMMIT_TAIL ||
	    txn->route->last_sequence == U64_MAX) {
		error = txn->capture_error ? txn->capture_error : -ECANCELED;
		if (txn->route->last_sequence == U64_MAX)
			error = -EOVERFLOW;
		goto out_unlock;
	}

	/* The op_lock-held tail is bounded and no new source write is admitted. */
	txn->stream.phase = EBPFOS_FILE_MIGRATION_FREEZING;
	txn->stream.freeze_route_sequence = txn->route->last_sequence;
	txn->stream.freeze_visible = txn->route->visible_size;
	txn->stream.freeze_tail_deltas = txn->stream.ring_count;
	count = ebpfos_file_take_batch_locked(txn,
					      EBPFOS_FILE_COMMIT_TAIL);
	if (count < 0) {
		error = count;
		goto out_unlock;
	}
	if (count) {
		error = ebpfos_file_apply_batch(txn, ctx, &applied,
						&applied_bytes);
		error = ebpfos_file_finish_batch_locked(txn, applied,
							 applied_bytes, error);
		if (error)
			goto out_unlock;
	}

	if (txn->stream.ring_count || txn->stream.pending_delta_bytes ||
	    txn->stream.candidate_busy ||
	    !ebpfos_file_capture_phase_counts_valid(&txn->stream) ||
	    txn->stream.captured_deltas != txn->stream.dequeued_deltas ||
	    txn->stream.captured_deltas != txn->stream.replayed_deltas ||
	    txn->stream.captured_deltas != txn->stream.verified_deltas ||
	    txn->stream.captured_delta_bytes !=
		    txn->stream.dequeued_delta_bytes ||
	    txn->stream.captured_delta_bytes !=
		    txn->stream.replayed_delta_bytes ||
	    txn->stream.captured_delta_bytes !=
		    txn->stream.verified_delta_bytes ||
	    txn->stream.queue_tail_visible != txn->route->visible_size ||
	    txn->stream.dequeue_visible != txn->route->visible_size ||
	    txn->stream.candidate_visible != txn->route->visible_size ||
	    txn->stream.verified_visible != txn->route->visible_size ||
	    txn->stream.queue_last_write_sequence !=
		    txn->stream.dequeue_last_write_sequence ||
	    txn->stream.queue_last_write_sequence !=
		    txn->stream.candidate_last_write_sequence ||
	    txn->stream.queue_last_write_sequence !=
		    txn->stream.verified_last_write_sequence ||
	    (txn->source_provider_kind == EBPFOS_PROVIDER_NATIVE &&
	     i_size_read(txn->route->inode) != txn->route->visible_size)) {
		error = -EREMOTEIO;
		goto out_unlock;
	}
	total_size = txn->route->visible_size;
	mutex_unlock(&txn->route->op_lock);

	/* Writes remain fenced while complete byte refinement is established. */
	if (recovery_arm) {
		error = ebpfos_file_capture_recovery_base(
			txn, ctx, txn->stream.candidate_last_write_sequence,
			total_size);
		if (!error)
			error = ebpfos_file_validate_candidate_buffer(
				txn, ctx, txn->recovery->canonical_base,
				txn->stream.candidate_last_write_sequence,
				total_size);
		if (!error) {
			txn->recovery->e3_ready = true;
			error = ebpfos_file_prepare_e4(txn, ctx);
		}
	} else {
		error = ebpfos_file_validate_candidate_source(
			txn, ctx, txn->stream.candidate_last_write_sequence,
			total_size);
	}
	if (error)
		goto fail_unlocked;
	mutex_lock(&txn->route->op_lock);
	if (txn->route->migration != txn || txn->capture_error ||
	    txn->stream.phase != EBPFOS_FILE_MIGRATION_FREEZING ||
	    !ebpfos_file_source_matches_locked(txn) ||
	    txn->route->epoch + 1 != txn->target_epoch ||
	    txn->route->last_sequence == U64_MAX ||
	    txn->stream.ring_count || txn->stream.candidate_busy ||
	    !ebpfos_file_capture_phase_counts_valid(&txn->stream) ||
	    txn->stream.captured_deltas != txn->stream.verified_deltas ||
	    txn->stream.candidate_visible != total_size ||
	    txn->stream.verified_visible != total_size ||
	    txn->route->visible_size != total_size ||
	    (recovery_arm &&
	     (!txn->recovery->base_validated || !txn->recovery->e3_ready ||
	      !txn->recovery->e4_base_ready || !txn->recovery->log)) ||
	    (txn->source_provider_kind == EBPFOS_PROVIDER_NATIVE &&
	     i_size_read(txn->route->inode) != total_size)) {
		error = txn->capture_error ? txn->capture_error : -EREMOTEIO;
		if (txn->route->last_sequence == U64_MAX)
			error = -EOVERFLOW;
		goto out_unlock;
	}
	error = ebpfos_file_candidate_describe_at(
		txn, ctx, txn->route->last_sequence, total_size);
	if (error)
		goto out_unlock;
	error = ebpfos_file_candidate_export_at(
		txn, ctx, txn->route->last_sequence, total_size, 1, total_size);
	if (error)
		goto out_unlock;
	txn->candidate_validated_bytes = total_size;
	txn->candidate_bytes_validated = true;

	if (recovery_arm)
		spin_lock(&txn->route->admission_lock);
	old_prog = txn->route->prog;
	old_map = txn->route->map;
	old_map_lease = txn->route->map_lease;
	txn->route->prog = txn->prog;
	txn->prog = NULL;
	txn->route->map = txn->map;
	txn->map = NULL;
	txn->route->map_lease = txn->map_lease;
	txn->map_lease = NULL;
	txn->route->provider_id = txn->provider_id;
	txn->route->schema_hash = txn->target_schema_hash;
	txn->route->epoch = txn->target_epoch;
	txn->route->provider_kind = EBPFOS_PROVIDER_BPF;
	txn->route->native_retired = txn->route->native_retired ||
				    txn->source_provider_kind ==
					    EBPFOS_PROVIDER_NATIVE;
	txn->route->last_migration_txn_id = txn->txn_id;
	txn->route->last_migration_snapshot_sequence =
		txn->snapshot_sequence;
	txn->route->last_migration_snapshot_size = txn->snapshot_size;
	txn->route->last_migration_delta_count =
		txn->stream.captured_deltas;
	txn->route->last_migration_delta_bytes =
		txn->stream.captured_delta_bytes;
	txn->route->last_migration_validated_bytes =
		txn->candidate_validated_bytes;
	txn->route->last_migration_bytes_validated =
		txn->candidate_bytes_validated;
	txn->stream.commit_requested = false;
	txn->stream.phase = EBPFOS_FILE_MIGRATION_IDLE;
	txn->route->last_migration_stream = txn->stream;
	if (recovery_arm) {
		txn->recovery->phase = EBPFOS_FILE_RECOVERY_ARMED_E3;
		txn->route->recovery = txn->recovery;
		txn->recovery = NULL;
		txn->route->admission_gate =
			EBPFOS_FILE_ADMISSION_E3_OPEN;
		spin_unlock(&txn->route->admission_lock);
		ebpfos_file_recovery_progress_locked(txn->route);
		if (recovery_result) {
			recovery_result->base_sequence =
				txn->route->recovery->base_sequence;
			recovery_result->base_size =
				txn->route->recovery->base_size;
			recovery_result->base_digest =
				txn->route->recovery->base_digest;
			recovery_result->e3_provider_id =
				txn->route->recovery->e3_provider_id;
			recovery_result->e3_epoch =
				txn->route->recovery->e3_epoch;
			recovery_result->e4_provider_id =
				txn->route->recovery->e4_provider_id;
			recovery_result->e4_epoch =
				txn->route->recovery->e4_epoch;
		}
	}
	ebpfos_file_transaction_detach_locked(txn);
out_unlock:
	if (error && txn->route->migration == txn)
		ebpfos_file_transaction_detach_locked(txn);
	mutex_unlock(&txn->route->op_lock);
	ebpfos_file_map_lease_release(old_map_lease);
	if (old_prog)
		bpf_prog_put(old_prog);
	if (old_map)
		bpf_map_put(old_map);
	kfree(ctx);
	ebpfos_file_transaction_free(txn);
	return error;

fail_unlocked:
	mutex_lock(&txn->route->op_lock);
	goto out_unlock;
}

long ebpfos_file_replace_commit_ioctl(void __user *argp, void **txn_slot)
{
	struct ebpfos_ioc_file_replace_end request;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	return ebpfos_file_replace_commit(&request, txn_slot, false, NULL);
}

long ebpfos_file_recovery_arm_ioctl(void __user *argp, void **txn_slot)
{
	struct ebpfos_ioc_file_recovery_end request;
	struct ebpfos_ioc_file_replace_end replace = {};
	struct ebpfos_file_transaction *txn = *txn_slot;
	long error;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags || request.file_fd < 0)
		return -EINVAL;
	if (!txn || !txn->recovery)
		return -ENOENT;
	if (request.recovery_id != txn->recovery->recovery_id ||
	    request.expected_provider_id != txn->source_provider_id)
		return -ESTALE;
	replace.file_fd = request.file_fd;
	replace.txn_id = request.txn_id;
	replace.expected_route_id = request.expected_route_id;
	replace.expected_epoch = request.expected_epoch;
	replace.expected_schema_hash = request.expected_schema_hash;
	error = ebpfos_file_replace_commit(&replace, txn_slot, true,
					   &request);
	if (error)
		return error;
	return copy_to_user(argp, &request, sizeof(request)) ? -EFAULT : 0;
}

long ebpfos_file_replace_abort_ioctl(void __user *argp, void **txn_slot)
{
	struct ebpfos_ioc_file_replace_end request;
	struct ebpfos_file_transaction *txn = *txn_slot;
	struct file *file;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags || request.file_fd < 0)
		return -EINVAL;
	if (!txn)
		return -ENOENT;
	if (txn->recovery)
		return -EINVAL;
	if (request.txn_id != txn->txn_id ||
	    request.expected_route_id != txn->route->route_id ||
	    request.expected_epoch + 1 != txn->target_epoch ||
	    request.expected_schema_hash != txn->source_schema_hash)
		return -ESTALE;
	file = fget(request.file_fd);
	if (!file)
		return -EBADF;
	if (file != txn->file) {
		fput(file);
		return -EXDEV;
	}
	fput(file);

	mutex_lock(&txn->route->op_lock);
	if (txn->route->migration != txn) {
		mutex_unlock(&txn->route->op_lock);
		return -ECANCELED;
	}
	ebpfos_file_transaction_detach_locked(txn);
	mutex_unlock(&txn->route->op_lock);
	ebpfos_file_transaction_free(txn);
	return 0;
}

long ebpfos_file_recovery_abort_ioctl(void __user *argp, void **txn_slot)
{
	struct ebpfos_ioc_file_recovery_end request;
	struct ebpfos_file_transaction *txn = *txn_slot;
	struct file *file;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags || request.file_fd < 0)
		return -EINVAL;
	if (!txn || !txn->recovery)
		return -ENOENT;
	if (request.txn_id != txn->txn_id ||
	    request.recovery_id != txn->recovery->recovery_id ||
	    request.expected_route_id != txn->route->route_id ||
	    request.expected_provider_id != txn->source_provider_id ||
	    request.expected_epoch + 1 != txn->target_epoch ||
	    request.expected_schema_hash != txn->source_schema_hash)
		return -ESTALE;
	file = fget(request.file_fd);
	if (!file)
		return -EBADF;
	if (file != txn->file) {
		fput(file);
		return -EXDEV;
	}
	fput(file);

	mutex_lock(&txn->route->op_lock);
	if (txn->route->migration != txn ||
	    txn->recovery->phase != EBPFOS_FILE_RECOVERY_PREPARING) {
		mutex_unlock(&txn->route->op_lock);
		return -ECANCELED;
	}
	ebpfos_file_transaction_detach_locked(txn);
	mutex_unlock(&txn->route->op_lock);
	ebpfos_file_transaction_free(txn);
	return 0;
}

long ebpfos_file_recovery_retire_ioctl(void __user *argp)
{
	struct ebpfos_ioc_file_recovery_retire request;
	struct ebpfos_file_recovery *recovery;
	struct ebpfos_inode_route *route;
	struct file *file;
	long error = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags || request.file_fd < 0)
		return -EINVAL;
	file = fget(request.file_fd);
	if (!file)
		return -EBADF;
	route = ebpfos_inode_route_get(file_inode(file));
	if (!route) {
		error = -ENOENT;
		goto out_file;
	}

	mutex_lock(&route->op_lock);
	recovery = route->recovery;
	if (!recovery) {
		error = -ENOENT;
		goto out_unlock;
	}
	if (request.recovery_id != recovery->recovery_id ||
	    request.expected_route_id != route->route_id ||
	    request.expected_provider_id != route->provider_id ||
	    request.expected_epoch != route->epoch ||
	    request.expected_schema_hash != route->schema_hash) {
		error = -ESTALE;
		goto out_unlock;
	}
	if (recovery->phase != EBPFOS_FILE_RECOVERY_PUBLISHED_E4 ||
	    recovery->pending_retries ||
	    recovery->retry_count !=
		    recovery->retry_commits + recovery->retry_failures) {
		error = -EBUSY;
		goto out_unlock;
	}
	if (!recovery->trigger_invocation_id ||
	    recovery->retry_count !=
		    recovery->faults_observed + recovery->capacity_triggers ||
	    recovery->retry_commits != recovery->retry_count ||
	    recovery->retry_failures || recovery->unretried_invocations ||
	    (recovery->trigger == EBPFOS_FILE_RECOVERY_TRIGGER_TYPED_FAULT &&
	     (!recovery->faults_observed || recovery->capacity_triggers ||
	      recovery->coalesced_faults + 1 != recovery->faults_observed)) ||
	    (recovery->trigger == EBPFOS_FILE_RECOVERY_TRIGGER_LOG_CAPACITY &&
	     (recovery->capacity_triggers != 1 || recovery->faults_observed ||
	      recovery->coalesced_faults)) ||
	    (recovery->trigger != EBPFOS_FILE_RECOVERY_TRIGGER_TYPED_FAULT &&
	     recovery->trigger != EBPFOS_FILE_RECOVERY_TRIGGER_LOG_CAPACITY)) {
		error = -EREMOTEIO;
		goto out_unlock;
	}
	if (route->state != EBPFOS_FILE_ROUTE_ACTIVE || !recovery->e4_ready ||
	    route->provider_id != recovery->e4_provider_id ||
	    route->epoch != recovery->e4_epoch ||
	    route->schema_hash != recovery->e4_schema_hash ||
	    atomic_read(&route->admitted_e3)) {
		error = -EREMOTEIO;
		goto out_unlock;
	}
	spin_lock(&route->admission_lock);
	if (route->admission_gate != EBPFOS_FILE_ADMISSION_E4_OPEN) {
		spin_unlock(&route->admission_lock);
		error = -EBUSY;
		goto out_unlock;
	}
	route->admission_gate = EBPFOS_FILE_ADMISSION_RECOVERING;
	recovery->phase = EBPFOS_FILE_RECOVERY_RETIRING;
	spin_unlock(&route->admission_lock);
	ebpfos_file_recovery_progress_locked(route);
	mutex_unlock(&route->op_lock);

	wait_event(route->migration_wait,
		   !atomic_read(&route->admitted_e4) ||
		   READ_ONCE(route->state) == EBPFOS_FILE_ROUTE_DEAD);
	mutex_lock(&route->op_lock);
	if (route->recovery != recovery ||
	    recovery->phase != EBPFOS_FILE_RECOVERY_RETIRING ||
	    atomic_read(&route->admitted_e4) ||
	    route->state != EBPFOS_FILE_ROUTE_ACTIVE ||
	    route->provider_id != recovery->e4_provider_id ||
	    route->epoch != recovery->e4_epoch) {
		error = -ECANCELED;
		goto out_reopen;
	}
	spin_lock(&route->admission_lock);
	if (route->admission_gate != EBPFOS_FILE_ADMISSION_RECOVERING) {
		spin_unlock(&route->admission_lock);
		error = -ECANCELED;
		goto out_reopen;
	}
	route->recovery = NULL;
	route->admission_gate = EBPFOS_FILE_ADMISSION_LEGACY;
	spin_unlock(&route->admission_lock);
	ebpfos_file_recovery_progress_locked(route);
	mutex_unlock(&route->op_lock);
	ebpfos_file_recovery_free(recovery);
	ebpfos_inode_route_put(route);
	fput(file);
	return 0;

out_reopen:
	if (route->recovery == recovery &&
	    recovery->phase == EBPFOS_FILE_RECOVERY_RETIRING &&
	    route->state == EBPFOS_FILE_ROUTE_ACTIVE) {
		spin_lock(&route->admission_lock);
		if (route->admission_gate == EBPFOS_FILE_ADMISSION_RECOVERING) {
			recovery->phase = EBPFOS_FILE_RECOVERY_PUBLISHED_E4;
			route->admission_gate = EBPFOS_FILE_ADMISSION_E4_OPEN;
		}
		spin_unlock(&route->admission_lock);
		ebpfos_file_recovery_progress_locked(route);
	}
out_unlock:
	mutex_unlock(&route->op_lock);
	ebpfos_inode_route_put(route);
out_file:
	fput(file);
	return error;
}

void ebpfos_file_replace_release(void **txn_slot)
{
	struct ebpfos_file_transaction *txn = *txn_slot;

	if (!txn)
		return;
	mutex_lock(&txn->route->op_lock);
	ebpfos_file_transaction_detach_locked(txn);
	mutex_unlock(&txn->route->op_lock);
	ebpfos_file_transaction_free(txn);
}

static void ebpfos_file_assign_stream_status(
	void *destination, const struct ebpfos_file_stream_state *stream,
	u64 backpressure_waiters)
{
	struct ebpfos_file_stream_report report = {
		.dequeued_deltas = stream->dequeued_deltas,
		.dequeued_delta_bytes = stream->dequeued_delta_bytes,
		.replayed_deltas = stream->replayed_deltas,
		.replayed_delta_bytes = stream->replayed_delta_bytes,
		.verified_deltas = stream->verified_deltas,
		.verified_delta_bytes = stream->verified_delta_bytes,
		.pending_deltas = stream->captured_deltas -
				  stream->verified_deltas,
		.pending_delta_bytes = stream->captured_delta_bytes -
				      stream->verified_delta_bytes,
		.queued_deltas = stream->ring_count,
		.queued_delta_bytes = stream->pending_delta_bytes,
		.replay_batches = stream->replay_batches,
		.ring_high_water = stream->ring_high_water,
		.ring_wraps = stream->ring_wraps,
		.backpressure_waits = stream->backpressure_waits,
		.backpressure_waiters = backpressure_waiters,
		.quiesce_waiters = stream->quiesce_waiters,
		.queue_tail_visible = stream->queue_tail_visible,
		.queue_last_write_sequence = stream->queue_last_write_sequence,
		.dequeue_visible = stream->dequeue_visible,
		.dequeue_last_write_sequence =
			stream->dequeue_last_write_sequence,
		.candidate_visible = stream->candidate_visible,
		.candidate_last_write_sequence =
			stream->candidate_last_write_sequence,
		.verified_visible = stream->verified_visible,
		.verified_last_write_sequence =
			stream->verified_last_write_sequence,
		.quiesce_captured_deltas = stream->quiesce_captured_deltas,
		.quiesce_pending_deltas = stream->quiesce_pending_deltas,
		.freeze_route_sequence = stream->freeze_route_sequence,
		.freeze_visible = stream->freeze_visible,
		.freeze_tail_deltas = stream->freeze_tail_deltas,
		.snapshotting_captured_deltas =
			stream->snapshotting_captured_deltas,
		.importing_captured_deltas =
			stream->importing_captured_deltas,
		.catching_up_captured_deltas =
			stream->catching_up_captured_deltas,
		.ring_head = stream->ring_head,
		.inflight_batch_count = stream->batch_count,
		.inflight_batch_applied = stream->batch_applied,
		.candidate_busy = stream->candidate_busy,
		.commit_requested = stream->commit_requested,
		.fatal_error = stream->fatal_error,
	};

	memcpy(destination, &report, sizeof(report));
}

long ebpfos_file_replace_status_ioctl(void __user *argp, void **txn_slot)
{
	struct ebpfos_ioc_file_replace_status request;
	struct ebpfos_file_transaction *migration;
	struct ebpfos_inode_route *route;
	struct file *file;
	s32 file_fd;
	u64 expected_route_id;
	long error = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags || request.file_fd < 0)
		return -EINVAL;
	file_fd = request.file_fd;
	expected_route_id = request.expected_route_id;
	memset(&request, 0, sizeof(request));
	request.file_fd = file_fd;
	request.expected_route_id = expected_route_id;
	file = fget(file_fd);
	if (!file)
		return -EBADF;
	route = ebpfos_inode_route_get(file_inode(file));
	if (!route) {
		error = -ENOENT;
		goto out_file;
	}

	mutex_lock(&route->op_lock);
	if (request.expected_route_id != route->route_id) {
		error = -ESTALE;
		goto out_unlock;
	}
	migration = route->migration;
	request.route_id = route->route_id;
	request.active_provider_id = route->provider_id;
	request.active_epoch = route->epoch;
	request.active_schema_hash = route->schema_hash;
	request.active_prog_id = route->prog ? route->prog->aux->id : 0;
	request.active_map_id = route->map ? route->map->id : 0;
	request.native_retired = route->native_retired;
	if (migration) {
		request.txn_id = migration->txn_id;
		request.candidate_provider_id = migration->provider_id;
		request.target_epoch = migration->target_epoch;
		request.target_schema_hash = migration->target_schema_hash;
		request.snapshot_sequence = migration->snapshot_sequence;
		request.snapshot_size = migration->snapshot_size;
		request.captured_deltas = migration->stream.captured_deltas;
		request.captured_delta_bytes =
			migration->stream.captured_delta_bytes;
		request.candidate_validated_bytes =
			migration->candidate_validated_bytes;
		request.delta_capacity = EBPFOS_FILE_DELTA_CAPACITY;
		request.candidate_prog_id = migration->prog->aux->id;
		request.candidate_map_id = migration->map->id;
		request.migration_phase = migration->stream.phase;
		request.candidate_ready = migration->candidate_ready;
		request.candidate_bytes_validated =
			migration->candidate_bytes_validated;
		request.caller_owns_transaction = *txn_slot == migration;
		ebpfos_file_assign_stream_status(&request.dequeued_deltas,
						 &migration->stream,
						 atomic64_read(
							 &route->migration_waiters));
	} else if (route->last_migration_txn_id) {
		request.txn_id = route->last_migration_txn_id;
		request.candidate_provider_id = route->provider_id;
		request.target_epoch = route->epoch;
		request.target_schema_hash = route->schema_hash;
		request.snapshot_sequence =
			route->last_migration_snapshot_sequence;
		request.snapshot_size = route->last_migration_snapshot_size;
		request.captured_deltas = route->last_migration_delta_count;
		request.captured_delta_bytes =
			route->last_migration_delta_bytes;
		request.candidate_validated_bytes =
			route->last_migration_validated_bytes;
		request.delta_capacity = EBPFOS_FILE_DELTA_CAPACITY;
		request.candidate_prog_id = request.active_prog_id;
		request.candidate_map_id = request.active_map_id;
		request.candidate_ready = true;
		request.candidate_bytes_validated =
			route->last_migration_bytes_validated;
		ebpfos_file_assign_stream_status(
			&request.dequeued_deltas, &route->last_migration_stream,
			atomic64_read(&route->migration_waiters));
	}
out_unlock:
	mutex_unlock(&route->op_lock);
	ebpfos_inode_route_put(route);
	if (!error && copy_to_user(argp, &request, sizeof(request)))
		error = -EFAULT;
out_file:
	fput(file);
	return error;
}

long ebpfos_file_recovery_status_ioctl(void __user *argp)
{
	struct ebpfos_ioc_file_recovery_status request;
	struct ebpfos_file_recovery *recovery;
	struct ebpfos_inode_route *route;
	struct file *file;
	u64 expected_route_id;
	s32 file_fd;
	long error = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags || request.file_fd < 0)
		return -EINVAL;
	file_fd = request.file_fd;
	expected_route_id = request.expected_route_id;
	memset(&request, 0, sizeof(request));
	request.file_fd = file_fd;
	request.expected_route_id = expected_route_id;
	file = fget(file_fd);
	if (!file)
		return -EBADF;
	route = ebpfos_inode_route_get(file_inode(file));
	if (!route) {
		error = -ENOENT;
		goto out_file;
	}

	mutex_lock(&route->op_lock);
	recovery = route->recovery;
	if (!recovery) {
		error = -ENOENT;
		goto out_unlock;
	}
	if (expected_route_id && expected_route_id != route->route_id) {
		error = -ESTALE;
		goto out_unlock;
	}
	request.route_id = route->route_id;
	request.recovery_id = recovery->recovery_id;
	request.active_provider_id = route->provider_id;
	request.active_epoch = route->epoch;
	request.active_schema_hash = route->schema_hash;
	request.e2_provider_id = recovery->e2_provider_id;
	request.e2_epoch = recovery->e2_epoch;
	request.e3_provider_id = recovery->e3_provider_id;
	request.e3_epoch = recovery->e3_epoch;
	request.e4_provider_id = recovery->e4_provider_id;
	request.e4_epoch = recovery->e4_epoch;
	request.base_sequence = recovery->base_sequence;
	request.base_size = recovery->base_size;
	request.base_digest = recovery->base_digest;
	spin_lock(&route->admission_lock);
	request.next_acquire_id = route->next_acquire_id;
	request.admission_gate = route->admission_gate;
	spin_unlock(&route->admission_lock);
	request.fence_acquire_id = recovery->fence_acquire_id;
	request.admitted_e3 = atomic_read(&route->admitted_e3);
	request.admitted_e4 = atomic_read(&route->admitted_e4);
	request.committed_deltas = recovery->log_count;
	request.committed_delta_bytes = recovery->committed_delta_bytes;
	request.frozen_deltas = recovery->frozen_count;
	request.replayed_deltas = recovery->replay_index;
	request.backpressure_waits = recovery->backpressure_waits;
	request.e3_write_attempts = recovery->e3_write_attempts;
	request.faults_observed = recovery->faults_observed;
	request.coalesced_faults = recovery->coalesced_faults;
	request.pending_retries = recovery->pending_retries;
	request.retry_commits = recovery->retry_commits;
	request.retry_failures = recovery->retry_failures;
	request.unretried_invocations = recovery->unretried_invocations;
	request.capacity_triggers = recovery->capacity_triggers;
	request.trigger_invocation_id = recovery->trigger_invocation_id;
	request.trigger_acquire_id = recovery->trigger_acquire_id;
	request.trigger_sequence = recovery->trigger_sequence;
	request.trigger_epoch = recovery->trigger_epoch;
	request.fault_invocation_id = recovery->fault_invocation_id;
	request.fault_acquire_id = recovery->fault_acquire_id;
	request.fault_sequence = recovery->fault_sequence;
	request.fault_epoch = recovery->fault_epoch;
	request.retry_invocation_id = recovery->retry_invocation_id;
	request.retry_acquire_id = recovery->retry_acquire_id;
	request.retry_sequence = recovery->retry_sequence;
	request.retry_epoch = recovery->retry_epoch;
	request.log_capacity = recovery->log_capacity;
	request.fault_reason = recovery->expected_fault_reason;
	request.retry_count = recovery->retry_count;
	request.retry_result = recovery->retry_result;
	request.recovery_phase = recovery->phase;
	request.recovery_trigger = recovery->trigger;
	request.fatal_error = recovery->fatal_error;
	request.e4_ready = recovery->e4_ready;
out_unlock:
	mutex_unlock(&route->op_lock);
	ebpfos_inode_route_put(route);
	if (!error && copy_to_user(argp, &request, sizeof(request)))
		error = -EFAULT;
out_file:
	fput(file);
	return error;
}

long ebpfos_file_status_ioctl(void __user *argp)
{
	struct ebpfos_ioc_file_status request;
	struct ebpfos_file_transaction *migration;
	struct ebpfos_inode_route *route;
	struct inode *inode;
	struct file *file;
	s32 file_fd;
	long error = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags || request.file_fd < 0)
		return -EINVAL;
	file_fd = request.file_fd;
	memset(&request, 0, sizeof(request));
	request.file_fd = file_fd;
	file = fget(file_fd);
	if (!file)
		return -EBADF;
	inode = file_inode(file);
	route = ebpfos_inode_route_get(inode);
	if (!route) {
		error = -ENOENT;
		goto out_file;
	}

	mutex_lock(&route->op_lock);
	migration = route->migration;
	request.route_id = route->route_id;
	request.provider_id = route->provider_id;
	request.epoch = route->epoch;
	request.file_cookie = ebpfos_file_cookie(file);
	request.inode_number = inode->i_ino;
	request.device = new_encode_dev(inode->i_sb->s_dev);
	request.visible_size = route->visible_size;
	request.native_backing_size = i_size_read(inode);
	request.snapshot_size = route->snapshot_size;
	request.snapshot_digest = route->snapshot_digest;
	request.last_sequence = route->last_sequence;
	request.read_calls = route->read_calls;
	request.write_calls = route->write_calls;
	request.read_bytes = route->read_bytes;
	request.write_bytes = route->write_bytes;
	request.native_read_body_calls = route->native_read_body_calls;
	request.native_write_body_calls = route->native_write_body_calls;
	request.rejected_calls = atomic64_read(&route->rejected_calls);
	request.active_calls = atomic64_read(&route->active_calls);
	request.route_state = route->state;
	request.provider_kind = route->provider_kind;
	request.inode_mode = inode->i_mode;
	request.inode_uid = i_uid_read(inode);
	request.inode_gid = i_gid_read(inode);
	request.file_flags = file->f_flags;
	request.file_mode = file->f_mode;
	request.file_cred_uid = __kuid_val(file->f_cred->fsuid);
	request.file_cred_gid = __kgid_val(file->f_cred->fsgid);
	request.active_schema_hash = route->schema_hash;
	request.fault_count = route->fault_count;
	request.active_prog_id = route->prog ? route->prog->aux->id : 0;
	request.active_map_id = route->map ? route->map->id : 0;
	request.native_retired = route->native_retired;
	if (migration) {
		request.migration_txn_id = migration->txn_id;
		request.candidate_provider_id = migration->provider_id;
		request.migration_snapshot_sequence =
			migration->snapshot_sequence;
		request.migration_snapshot_size = migration->snapshot_size;
		request.captured_deltas = migration->stream.captured_deltas;
		request.captured_delta_bytes =
			migration->stream.captured_delta_bytes;
		request.candidate_validated_bytes =
			migration->candidate_validated_bytes;
		request.migration_phase = migration->stream.phase;
		request.candidate_ready = migration->candidate_ready;
		request.candidate_bytes_validated =
			migration->candidate_bytes_validated;
		ebpfos_file_assign_stream_status(&request.dequeued_deltas,
						 &migration->stream,
						 atomic64_read(
							 &route->migration_waiters));
	} else if (route->last_migration_txn_id) {
		request.migration_txn_id = route->last_migration_txn_id;
		request.candidate_provider_id = route->provider_id;
		request.migration_snapshot_sequence =
			route->last_migration_snapshot_sequence;
		request.migration_snapshot_size =
			route->last_migration_snapshot_size;
		request.captured_deltas = route->last_migration_delta_count;
		request.captured_delta_bytes =
			route->last_migration_delta_bytes;
		request.candidate_validated_bytes =
			route->last_migration_validated_bytes;
		request.candidate_ready = true;
		request.candidate_bytes_validated =
			route->last_migration_bytes_validated;
		ebpfos_file_assign_stream_status(
			&request.dequeued_deltas, &route->last_migration_stream,
			atomic64_read(&route->migration_waiters));
	}
	mutex_unlock(&route->op_lock);

	if (copy_to_user(argp, &request, sizeof(request)))
		error = -EFAULT;
	ebpfos_inode_route_put(route);
out_file:
	fput(file);
	return error;
}
