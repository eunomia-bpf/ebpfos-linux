/* SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note */
#ifndef _UAPI_EBPFOS_H
#define _UAPI_EBPFOS_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define EBPFOS_UAPI_VERSION 8
#define EBPFOS_IOC_MAGIC 0xe7
#define EBPFOS_MAX_ARGS 6
#define EBPFOS_MAX_STATE_SLOTS 16

/* Legacy global hook graph. */
enum ebpfos_hook_id {
	EBPFOS_HOOK_SYSCALL_ENTER = 0,
	EBPFOS_HOOK_SYSCALL_EXIT,
	EBPFOS_HOOK_VFS_LOOKUP,
	EBPFOS_HOOK_VFS_READDIR,
	EBPFOS_HOOK_SCHED_SELECT,
	EBPFOS_HOOK_SCHED_ENQUEUE,
	EBPFOS_HOOK_MM_RECLAIM,
	EBPFOS_HOOK_BLOCK_SUBMIT,
	EBPFOS_HOOK_NET_RX,
	EBPFOS_HOOK_NET_TX,
	EBPFOS_HOOK_SECURITY,
	EBPFOS_HOOK_DRIVER_PROBE,
	EBPFOS_HOOK_DRIVER_LIFECYCLE,
	EBPFOS_HOOK_MAX,
};

enum ebpfos_verdict {
	EBPFOS_VERDICT_CONTINUE = 0,
	EBPFOS_VERDICT_DENY = 1,
	EBPFOS_VERDICT_REDIRECT = 2,
	EBPFOS_VERDICT_OVERRIDE = 3,
	EBPFOS_VERDICT_FALLBACK = 4,
};

#define EBPFOS_ABI_SYSCALL_ENTER 0x6d23c2ef91efa8b9ULL
#define EBPFOS_ABI_SYSCALL_EXIT 0xccaea0a5c69ba3b3ULL
#define EBPFOS_ABI_VFS_LOOKUP 0x15ad64cb3a2fddd5ULL
#define EBPFOS_ABI_VFS_READDIR 0x76a4934657508e52ULL
#define EBPFOS_ABI_SCHED_SELECT 0xe9bf4388fce4d2d3ULL
#define EBPFOS_ABI_SCHED_ENQUEUE 0x27b841226676ba43ULL
#define EBPFOS_ABI_MM_RECLAIM 0xe1137d1be95f0529ULL
#define EBPFOS_ABI_BLOCK_SUBMIT 0xbdcaa660e509145bULL
#define EBPFOS_ABI_NET_RX 0x702a869a2a96a073ULL
#define EBPFOS_ABI_NET_TX 0xf9d9b7dfcf0fb589ULL
#define EBPFOS_ABI_SECURITY 0x8fa27536eeabab62ULL
#define EBPFOS_ABI_DRIVER_PROBE 0x087fa77d3aa0d222ULL
#define EBPFOS_ABI_DRIVER_LIFECYCLE 0x8a7fbda2b451c51cULL

#define EBPFOS_ACTION_SHIFT 28U
#define EBPFOS_ACTION_PAYLOAD_MASK 0x0fffffffU
#define EBPFOS_ACTION(_verdict, _payload) \
	(((__u32)(_verdict) << EBPFOS_ACTION_SHIFT) | \
	 ((__u32)(_payload) & EBPFOS_ACTION_PAYLOAD_MASK))
#define EBPFOS_ACTION_VERDICT(_action) \
	((__u32)(_action) >> EBPFOS_ACTION_SHIFT)
#define EBPFOS_ACTION_PAYLOAD(_action) \
	((__u32)(_action) & EBPFOS_ACTION_PAYLOAD_MASK)

struct ebpfos_ioc_version {
	__u32 uapi_version;
	__u32 hook_count;
};

struct ebpfos_ioc_set_hook {
	__u32 hook_id;
	__s32 prog_fd;
	__u64 abi_hash;
	__u64 flags;
};

#define EBPFOS_STATE_F_MIGRATED (1ULL << 0)

struct ebpfos_ioc_set_state {
	__u32 slot;
	__s32 map_fd;
	__u64 schema_hash;
	__u64 previous_schema_hash;
	__u64 flags;
};

struct ebpfos_ioc_commit {
	__u64 expected_generation;
	__u64 new_generation;
};

struct ebpfos_ioc_status {
	__u64 generation;
	__u64 hook_mask;
	__u64 state_mask;
};

struct ebpfos_ioc_run {
	__u32 hook_id;
	__u32 nr_args;
	__u64 args[EBPFOS_MAX_ARGS];
	__u32 result;
	__u32 reserved;
};

#define EBPFOS_IOC_VERSION \
	_IOR(EBPFOS_IOC_MAGIC, 0x00, struct ebpfos_ioc_version)
#define EBPFOS_IOC_BEGIN _IO(EBPFOS_IOC_MAGIC, 0x01)
#define EBPFOS_IOC_SET_HOOK \
	_IOW(EBPFOS_IOC_MAGIC, 0x02, struct ebpfos_ioc_set_hook)
#define EBPFOS_IOC_COMMIT \
	_IOWR(EBPFOS_IOC_MAGIC, 0x03, struct ebpfos_ioc_commit)
#define EBPFOS_IOC_ABORT _IO(EBPFOS_IOC_MAGIC, 0x04)
#define EBPFOS_IOC_STATUS \
	_IOR(EBPFOS_IOC_MAGIC, 0x05, struct ebpfos_ioc_status)
#define EBPFOS_IOC_RUN \
	_IOWR(EBPFOS_IOC_MAGIC, 0x06, struct ebpfos_ioc_run)
#define EBPFOS_IOC_SET_STATE \
	_IOW(EBPFOS_IOC_MAGIC, 0x07, struct ebpfos_ioc_set_state)

/* Stable object/capability component model. */
#define EBPFOS_OBJECT_MAX_ARGS 2
#define EBPFOS_OBJECT_MAX_RESULTS 2
#define EBPFOS_OBJECT_AUDIT_CAPACITY 16384U
#define EBPFOS_OBJECT_DELTA_CAPACITY 1024U
#define EBPFOS_PROVIDER_HISTORY_CAPACITY 64U

/*
 * Initialize with EBPFOS_DIGEST_INITIAL.  For each committed logical call,
 * apply word-wise FNV-1a over seq, epoch, method, arg0, then result0.  Failed
 * attempts are omitted; a successful rollback retry appears once at its new
 * epoch.
 */
#define EBPFOS_DIGEST_INITIAL 0xcbf29ce484222325ULL
#define EBPFOS_DIGEST_PRIME 0x100000001b3ULL
#define EBPFOS_DIGEST_MIX(_digest, _word) \
	(((__u64)(_digest) ^ (__u64)(_word)) * EBPFOS_DIGEST_PRIME)

#define EBPFOS_RIGHT_READ (1ULL << 0)
#define EBPFOS_RIGHT_WRITE (1ULL << 1)
#define EBPFOS_RIGHT_INSPECT (1ULL << 2)
#define EBPFOS_RIGHT_REPLACE (1ULL << 3)
#define EBPFOS_RIGHT_ALL \
	(EBPFOS_RIGHT_READ | EBPFOS_RIGHT_WRITE | EBPFOS_RIGHT_INSPECT | \
	 EBPFOS_RIGHT_REPLACE)

#define EBPFOS_CONTRACT_CELL_V1 0x43454c4c00000001ULL
#define EBPFOS_ABI_CELL_V1 0x6b968e2f53e467c1ULL
#define EBPFOS_SCHEMA_CELL_NATIVE 0x43454c4c4e415401ULL
#define EBPFOS_SCHEMA_CELL_V1 0x43454c4c42504631ULL
#define EBPFOS_SCHEMA_CELL_V2 0x43454c4c42504632ULL
#define EBPFOS_CELL_VALUE_MASK 0x0fffffffULL
#define EBPFOS_CELL_V2_LOW_MASK 0x0000ffffULL
#define EBPFOS_CELL_V2_HIGH_MASK 0x00000fffULL
#define EBPFOS_CELL_V2_TAG 0x5632000000000000ULL

enum ebpfos_cell_method {
	EBPFOS_CELL_GET = 0,
	EBPFOS_CELL_ADD = 1,
};

enum ebpfos_provider_kind {
	EBPFOS_PROVIDER_NATIVE = 0,
	EBPFOS_PROVIDER_BPF = 1,
};

enum ebpfos_migration_phase {
	EBPFOS_MIGRATION_IDLE = 0,
	EBPFOS_MIGRATION_CAPTURING = 1,
};

enum ebpfos_call_return_status {
	EBPFOS_CALL_RETURN_OK = 0,
	EBPFOS_CALL_RETURN_DENY = 1,
	EBPFOS_CALL_RETURN_FAULT = 2,
};

#define EBPFOS_CALL_RETURN_SHIFT 28U
#define EBPFOS_CALL_RETURN_PAYLOAD_MASK 0x0fffffffU
#define EBPFOS_CALL_RETURN(_status, _payload) \
	(((__u32)(_status) << EBPFOS_CALL_RETURN_SHIFT) | \
	 ((__u32)(_payload) & EBPFOS_CALL_RETURN_PAYLOAD_MASK))
#define EBPFOS_CALL_RETURN_STATUS(_result) \
	((__u32)(_result) >> EBPFOS_CALL_RETURN_SHIFT)
#define EBPFOS_CALL_RETURN_PAYLOAD(_result) \
	((__u32)(_result) & EBPFOS_CALL_RETURN_PAYLOAD_MASK)

#define EBPFOS_BPF_CALL_F_FOREGROUND (1ULL << 0)
#define EBPFOS_BPF_CALL_F_SHADOW (1ULL << 1)

/* Exactly twelve u64 words: the RAW_TRACEPOINT verifier's context limit. */
struct ebpfos_bpf_call_ctx {
	__u64 object_id;
	__u64 contract_id;
	__u64 epoch;
	__u64 sequence;
	__u64 method_id;
	__u64 effective_rights;
	__u64 state[2];
	__u64 args[2];
	__u64 flags;
	__u64 reserved;
};

struct ebpfos_ioc_object_create {
	__u64 contract_id;
	__u64 rights_ceiling;
	__u64 initial_state[2];
	__u64 object_id;
	__s32 object_fd;
	__u32 flags;
};

struct ebpfos_ioc_cap_derive {
	__u64 rights;
	__u64 capability_id;
	__s32 new_fd;
	__u32 flags;
};

struct ebpfos_ioc_cap_info {
	__u64 object_id;
	__u64 capability_id;
	__u64 contract_id;
	__u64 rights;
};

struct ebpfos_ioc_call {
	__u64 method_id;
	__u64 args[EBPFOS_OBJECT_MAX_ARGS];
	__u64 results[EBPFOS_OBJECT_MAX_RESULTS];
	__u64 sequence;
	__u64 epoch;
	__u64 provider_id;
	__s32 status;
	__u32 flags;
};

struct ebpfos_ioc_replace_begin {
	__u64 expected_epoch;
	__u64 expected_schema_hash;
	__u64 target_schema_hash;
	__u64 contract_abi_hash;
	__u64 required_rights;
	__s32 prog_fd;
	__u32 flags;
	__u64 txn_id;
	__u64 snapshot_sequence;
	__u64 target_provider_id;
};

struct ebpfos_ioc_replace_end {
	__u64 txn_id;
};

struct ebpfos_ioc_object_status {
	__u64 object_id;
	__u64 contract_id;
	__u64 rights_ceiling;
	__u64 epoch;
	__u64 active_provider_id;
	__u64 active_schema_hash;
	__u64 last_sequence;
	__u64 committed_calls;
	__u64 committed_writes;
	__u64 abstract_value;
	__u64 abstract_digest;
	__u64 migration_txn_id;
	__u64 migration_owner_capability_id;
	__u64 snapshot_sequence;
	__u64 captured_deltas;
	__u64 rollback_count;
	__u64 fault_count;
	__u64 retired_call_violations;
	__u64 rollback_log_count;
	__u64 audit_first_sequence;
	__u64 audit_capacity;
	__u64 delta_capacity;
	__u64 provider_history_capacity;
	__u64 rollback_valid;
	__u32 migration_phase;
	__u32 reserved;
};

struct ebpfos_ioc_provider_stats {
	__u64 provider_id;
	__u64 schema_hash;
	__u64 attempts;
	__u64 foreground_commits;
	__u64 shadow_replays;
	__u64 faults;
	__u64 activated_epoch;
	__u64 deactivated_epoch;
	__u32 kind;
	__u32 active;
};

#define EBPFOS_AUDIT_F_MUTATING (1U << 0)
#define EBPFOS_AUDIT_F_ROLLBACK (1U << 1)

struct ebpfos_audit_record {
	__u64 sequence;
	__u64 epoch;
	__u64 provider_id;
	__u64 method_id;
	__u64 argument;
	__u64 result;
	__u64 abstract_digest;
	__s32 status;
	__u32 flags;
};

struct ebpfos_ioc_audit_get {
	__u64 sequence;
	struct ebpfos_audit_record record;
};

/* Already-open regular-file replacement nucleus. */
#define EBPFOS_FILE_SNAPSHOT_MAX (32U * 1024U * 1024U)
#define EBPFOS_FILE_DELTA_CAPACITY 1024U
#define EBPFOS_FILE_CATCHUP_BATCH 64U
#define EBPFOS_FILE_COMMIT_TAIL 32U
#define EBPFOS_FILE_CATCHUP_MAX_BATCHES 1024U

#define EBPFOS_FILE_SCHEMA_NATIVE 0x46494c454e415401ULL
#define EBPFOS_FILE_SCHEMA_V1 0xc63b53e891db458eULL
#define EBPFOS_FILE_SCHEMA_V2 0xeee4a07cb179aee4ULL
#define EBPFOS_FILE_V1_KEY_SIZE 4U
#define EBPFOS_FILE_V1_VALUE_SIZE 256U
#define EBPFOS_FILE_V1_MAX_ENTRIES 131073U
#define EBPFOS_FILE_V2_KEY_SIZE 4U
#define EBPFOS_FILE_V2_VALUE_SIZE 1056U
#define EBPFOS_FILE_V2_MAX_ENTRIES 32770U

enum ebpfos_file_route_state {
	EBPFOS_FILE_ROUTE_ACTIVATING = 0,
	EBPFOS_FILE_ROUTE_ACTIVE = 1,
	EBPFOS_FILE_ROUTE_FENCED = 2,
	EBPFOS_FILE_ROUTE_DEAD = 3,
};

enum ebpfos_file_migration_phase {
	EBPFOS_FILE_MIGRATION_IDLE = 0,
	EBPFOS_FILE_MIGRATION_SNAPSHOTTING = 1,
	EBPFOS_FILE_MIGRATION_IMPORTING = 2,
	EBPFOS_FILE_MIGRATION_CATCHING_UP = 3,
	EBPFOS_FILE_MIGRATION_DRAINING = 4,
	EBPFOS_FILE_MIGRATION_FREEZING = 5,
	EBPFOS_FILE_MIGRATION_DOOMED = 6,
};

enum ebpfos_file_recovery_phase {
	EBPFOS_FILE_RECOVERY_NONE = 0,
	EBPFOS_FILE_RECOVERY_PREPARING = 1,
	EBPFOS_FILE_RECOVERY_ARMED_E3 = 2,
	EBPFOS_FILE_RECOVERY_FENCED = 3,
	EBPFOS_FILE_RECOVERY_DRAINED = 4,
	EBPFOS_FILE_RECOVERY_REPLAYING = 5,
	EBPFOS_FILE_RECOVERY_READY_E4 = 6,
	EBPFOS_FILE_RECOVERY_PUBLISHED_E4 = 7,
	EBPFOS_FILE_RECOVERY_RETIRING = 8,
	EBPFOS_FILE_RECOVERY_FAILED = 9,
};

enum ebpfos_file_admission_gate {
	EBPFOS_FILE_ADMISSION_LEGACY = 0,
	EBPFOS_FILE_ADMISSION_E3_OPEN = 1,
	EBPFOS_FILE_ADMISSION_RECOVERING = 2,
	EBPFOS_FILE_ADMISSION_E4_OPEN = 3,
	EBPFOS_FILE_ADMISSION_FAILED = 4,
};

enum ebpfos_file_recovery_trigger {
	EBPFOS_FILE_RECOVERY_TRIGGER_NONE = 0,
	EBPFOS_FILE_RECOVERY_TRIGGER_TYPED_FAULT = 1,
	EBPFOS_FILE_RECOVERY_TRIGGER_LOG_CAPACITY = 2,
};

/* Source compatibility for the original single-phase migration ABI. */
#define EBPFOS_FILE_MIGRATION_CAPTURING \
	EBPFOS_FILE_MIGRATION_CATCHING_UP

enum ebpfos_file_op {
	EBPFOS_FILE_OP_READ = 1,
	EBPFOS_FILE_OP_WRITE = 2,
	EBPFOS_FILE_OP_DESCRIBE = 3,
	EBPFOS_FILE_OP_EXPORT_CHUNK = 4,
	EBPFOS_FILE_OP_IMPORT_BEGIN = 5,
	EBPFOS_FILE_OP_IMPORT_CHUNK = 6,
	EBPFOS_FILE_OP_IMPORT_END = 7,
};

#define EBPFOS_FILE_F_APPEND (1U << 0)
#define EBPFOS_FILE_F_FOREGROUND (1U << 1)
#define EBPFOS_FILE_F_SHADOW (1U << 2)
/* EXPORT_CHUNK is bounded by ctx->visible_size, not the live source size. */
#define EBPFOS_FILE_F_SOURCE_SNAPSHOT (1U << 3)

/*
 * Fixed verifier-visible provider context.  The header is exactly 128 bytes
 * and the opaque payload is exactly 1024 bytes.  Providers own the payload
 * schema; the nucleus interprets only the header and transfer length.
 */
#define EBPFOS_FILE_BPF_DATA_SIZE 1024U
#define EBPFOS_FILE_BPF_CTX_SIZE 1152U

struct ebpfos_file_bpf_ctx {
	__u32 op;
	__u32 flags;
	__u64 route_id;
	__u64 file_cookie;
	__u64 epoch;
	__u64 sequence;
	__u64 offset;
	__u64 count;
	__u64 visible_size;
	__s64 result;
	__u64 result_offset;
	__u64 result_visible_size;
	__u64 data_size;
	__u64 reserved[4];
	__u8 data[EBPFOS_FILE_BPF_DATA_SIZE];
};

struct ebpfos_ioc_file_enroll {
	__s32 file_fd;
	__u32 flags;
	__u64 route_id;
	__u64 provider_id;
	__u64 epoch;
	__u64 file_cookie;
	__u64 inode_number;
	__u64 device;
	__u64 snapshot_size;
	__u64 snapshot_digest;
};

struct ebpfos_ioc_file_status {
	__s32 file_fd;
	__u32 flags;
	__u64 route_id;
	__u64 provider_id;
	__u64 epoch;
	__u64 file_cookie;
	__u64 inode_number;
	__u64 device;
	__u64 visible_size;
	__u64 native_backing_size;
	__u64 snapshot_size;
	__u64 snapshot_digest;
	__u64 last_sequence;
	__u64 read_calls;
	__u64 write_calls;
	__u64 read_bytes;
	__u64 write_bytes;
	__u64 native_read_body_calls;
	__u64 native_write_body_calls;
	__u64 rejected_calls;
	__u64 active_calls;
	__u32 route_state;
	__u32 provider_kind;
	__u32 inode_mode;
	__u32 inode_uid;
	__u32 inode_gid;
	__u32 file_flags;
	__u32 file_mode;
	__u32 file_cred_uid;
	__u32 file_cred_gid;
	__u64 active_schema_hash;
	__u64 migration_txn_id;
	__u64 candidate_provider_id;
	__u64 migration_snapshot_sequence;
	__u64 migration_snapshot_size;
	__u64 captured_deltas;
	__u64 captured_delta_bytes;
	__u64 candidate_validated_bytes;
	__u64 fault_count;
	__u32 active_prog_id;
	__u32 active_map_id;
	__u32 migration_phase;
	__u32 candidate_ready;
	__u32 native_retired;
	__u32 candidate_bytes_validated;
	__u64 dequeued_deltas;
	__u64 dequeued_delta_bytes;
	__u64 replayed_deltas;
	__u64 replayed_delta_bytes;
	__u64 verified_deltas;
	__u64 verified_delta_bytes;
	/* Logical outstanding work, including an ownership-transferred batch. */
	__u64 pending_deltas;
	__u64 pending_delta_bytes;
	/* Physical producer ring occupancy; inflight_batch_* is disjoint. */
	__u64 queued_deltas;
	__u64 queued_delta_bytes;
	__u64 replay_batches;
	__u64 ring_high_water;
	__u64 ring_wraps;
	__u64 backpressure_waits;
	__u64 backpressure_waiters;
	__u64 quiesce_waiters;
	__u64 queue_tail_visible;
	__u64 queue_last_write_sequence;
	__u64 dequeue_visible;
	__u64 dequeue_last_write_sequence;
	__u64 candidate_visible;
	__u64 candidate_last_write_sequence;
	__u64 verified_visible;
	__u64 verified_last_write_sequence;
	__u64 quiesce_captured_deltas;
	__u64 quiesce_pending_deltas;
	__u64 freeze_route_sequence;
	__u64 freeze_visible;
	__u64 freeze_tail_deltas;
	/* Successful nonzero deltas classified by their enqueue phase. */
	__u64 snapshotting_captured_deltas;
	__u64 importing_captured_deltas;
	__u64 catching_up_captured_deltas;
	__u32 ring_head;
	__u32 inflight_batch_count;
	__u32 inflight_batch_applied;
	__u32 candidate_busy;
	__u32 commit_requested;
	__s32 fatal_error;
};

/* Active native or BPF provider -> verifier-isolated BPF transaction. */
struct ebpfos_ioc_file_replace_begin {
	__s32 file_fd;
	__s32 prog_fd;
	__s32 map_fd;
	__u32 flags;
	__u64 expected_route_id;
	__u64 expected_epoch;
	__u64 expected_schema_hash;
	__u64 target_schema_hash;
	__u64 txn_id;
	__u64 candidate_provider_id;
	__u64 snapshot_sequence;
	__u64 snapshot_size;
	__u64 snapshot_digest;
	__u64 delta_capacity;
	__u32 candidate_prog_id;
	__u32 candidate_map_id;
};

struct ebpfos_ioc_file_replace_end {
	__s32 file_fd;
	__u32 flags;
	__u64 txn_id;
	__u64 expected_route_id;
	__u64 expected_epoch;
	__u64 expected_schema_hash;
};

struct ebpfos_ioc_file_replace_status {
	__s32 file_fd;
	__u32 flags;
	__u64 expected_route_id;
	__u64 route_id;
	__u64 active_provider_id;
	__u64 active_epoch;
	__u64 active_schema_hash;
	__u64 txn_id;
	__u64 candidate_provider_id;
	__u64 target_epoch;
	__u64 target_schema_hash;
	__u64 snapshot_sequence;
	__u64 snapshot_size;
	__u64 captured_deltas;
	__u64 captured_delta_bytes;
	__u64 candidate_validated_bytes;
	__u64 delta_capacity;
	__u32 active_prog_id;
	__u32 active_map_id;
	__u32 candidate_prog_id;
	__u32 candidate_map_id;
	__u32 migration_phase;
	__u32 candidate_ready;
	__u32 caller_owns_transaction;
	__u32 native_retired;
	__u32 candidate_bytes_validated;
	__u64 dequeued_deltas;
	__u64 dequeued_delta_bytes;
	__u64 replayed_deltas;
	__u64 replayed_delta_bytes;
	__u64 verified_deltas;
	__u64 verified_delta_bytes;
	/* Logical outstanding work, including an ownership-transferred batch. */
	__u64 pending_deltas;
	__u64 pending_delta_bytes;
	/* Physical producer ring occupancy; inflight_batch_* is disjoint. */
	__u64 queued_deltas;
	__u64 queued_delta_bytes;
	__u64 replay_batches;
	__u64 ring_high_water;
	__u64 ring_wraps;
	__u64 backpressure_waits;
	__u64 backpressure_waiters;
	__u64 quiesce_waiters;
	__u64 queue_tail_visible;
	__u64 queue_last_write_sequence;
	__u64 dequeue_visible;
	__u64 dequeue_last_write_sequence;
	__u64 candidate_visible;
	__u64 candidate_last_write_sequence;
	__u64 verified_visible;
	__u64 verified_last_write_sequence;
	__u64 quiesce_captured_deltas;
	__u64 quiesce_pending_deltas;
	__u64 freeze_route_sequence;
	__u64 freeze_visible;
	__u64 freeze_tail_deltas;
	/* Successful nonzero deltas classified by their enqueue phase. */
	__u64 snapshotting_captured_deltas;
	__u64 importing_captured_deltas;
	__u64 catching_up_captured_deltas;
	__u32 ring_head;
	__u32 inflight_batch_count;
	__u32 inflight_batch_applied;
	__u32 candidate_busy;
	__u32 commit_requested;
	__s32 fatal_error;
};

struct ebpfos_ioc_file_replace_catchup {
	__s32 file_fd;
	/* EAGAIN means this ioctl completed no batch; partial work returns 0. */
	__u32 max_batches;
	__u64 txn_id;
	__u64 expected_route_id;
	__u64 expected_epoch;
	__u64 expected_schema_hash;
};

/* One E2 transaction prepares both recoverable E3 and private fresh E4. */
struct ebpfos_ioc_file_recovery_begin {
	__s32 file_fd;
	__s32 e3_prog_fd;
	__s32 e3_map_fd;
	__s32 e4_prog_fd;
	__s32 e4_map_fd;
	__u32 flags;
	/* Exhaustion fences E3 before provider execution and recovers through E4. */
	__u32 log_capacity;
	__u32 expected_fault_reason;
	__u64 expected_route_id;
	__u64 expected_provider_id;
	__u64 expected_epoch;
	__u64 expected_schema_hash;
	__u64 e3_schema_hash;
	__u64 e4_schema_hash;
	__u64 txn_id;
	__u64 recovery_id;
	__u64 e3_provider_id;
	__u64 e3_epoch;
	__u64 e4_provider_id;
	__u64 e4_epoch;
	__u64 snapshot_sequence;
	__u64 snapshot_size;
	__u64 snapshot_digest;
	__u32 e3_prog_id;
	__u32 e3_map_id;
	__u32 e4_prog_id;
	__u32 e4_map_id;
};

struct ebpfos_ioc_file_recovery_end {
	__s32 file_fd;
	__u32 flags;
	__u64 txn_id;
	__u64 recovery_id;
	__u64 expected_route_id;
	__u64 expected_provider_id;
	__u64 expected_epoch;
	__u64 expected_schema_hash;
	__u64 base_sequence;
	__u64 base_size;
	__u64 base_digest;
	__u64 e3_provider_id;
	__u64 e3_epoch;
	__u64 e4_provider_id;
	__u64 e4_epoch;
};

/* Explicitly discard published recovery evidence and reopen ordinary replace. */
struct ebpfos_ioc_file_recovery_retire {
	__s32 file_fd;
	__u32 flags;
	__u64 recovery_id;
	__u64 expected_route_id;
	__u64 expected_provider_id;
	__u64 expected_epoch;
	__u64 expected_schema_hash;
};

struct ebpfos_ioc_file_recovery_status {
	__s32 file_fd;
	__u32 flags;
	__u64 expected_route_id;
	__u64 route_id;
	__u64 recovery_id;
	__u64 active_provider_id;
	__u64 active_epoch;
	__u64 active_schema_hash;
	__u64 e2_provider_id;
	__u64 e2_epoch;
	__u64 e3_provider_id;
	__u64 e3_epoch;
	__u64 e4_provider_id;
	__u64 e4_epoch;
	__u64 base_sequence;
	__u64 base_size;
	__u64 base_digest;
	__u64 next_acquire_id;
	__u64 fence_acquire_id;
	__u64 admitted_e3;
	__u64 admitted_e4;
	__u64 committed_deltas;
	__u64 committed_delta_bytes;
	__u64 frozen_deltas;
	__u64 replayed_deltas;
	__u64 backpressure_waits;
	__u64 e3_write_attempts;
	__u64 faults_observed;
	__u64 coalesced_faults;
	__u64 pending_retries;
	__u64 retry_commits;
	__u64 retry_failures;
	__u64 unretried_invocations;
	__u64 capacity_triggers;
	__u64 trigger_invocation_id;
	__u64 trigger_acquire_id;
	__u64 trigger_sequence;
	__u64 trigger_epoch;
	__u64 fault_invocation_id;
	__u64 fault_acquire_id;
	__u64 fault_sequence;
	__u64 fault_epoch;
	__u64 retry_invocation_id;
	__u64 retry_acquire_id;
	__u64 retry_sequence;
	__u64 retry_epoch;
	__u32 log_capacity;
	__u32 fault_reason;
	__u32 retry_count;
	__s32 retry_result;
	__u32 recovery_phase;
	__u32 admission_gate;
	__u32 recovery_trigger;
	__s32 fatal_error;
	__u32 e4_ready;
	__u32 reserved;
};

#define EBPFOS_IOC_OBJECT_CREATE \
	_IOWR(EBPFOS_IOC_MAGIC, 0x10, struct ebpfos_ioc_object_create)
#define EBPFOS_IOC_CAP_DERIVE \
	_IOWR(EBPFOS_IOC_MAGIC, 0x11, struct ebpfos_ioc_cap_derive)
#define EBPFOS_IOC_CAP_INFO \
	_IOR(EBPFOS_IOC_MAGIC, 0x12, struct ebpfos_ioc_cap_info)
#define EBPFOS_IOC_CALL \
	_IOWR(EBPFOS_IOC_MAGIC, 0x13, struct ebpfos_ioc_call)
#define EBPFOS_IOC_REPLACE_BEGIN \
	_IOWR(EBPFOS_IOC_MAGIC, 0x14, struct ebpfos_ioc_replace_begin)
#define EBPFOS_IOC_REPLACE_COMMIT \
	_IOW(EBPFOS_IOC_MAGIC, 0x15, struct ebpfos_ioc_replace_end)
#define EBPFOS_IOC_REPLACE_ABORT \
	_IOW(EBPFOS_IOC_MAGIC, 0x16, struct ebpfos_ioc_replace_end)
#define EBPFOS_IOC_OBJECT_STATUS \
	_IOR(EBPFOS_IOC_MAGIC, 0x17, struct ebpfos_ioc_object_status)
#define EBPFOS_IOC_PROVIDER_STATS \
	_IOWR(EBPFOS_IOC_MAGIC, 0x18, struct ebpfos_ioc_provider_stats)
#define EBPFOS_IOC_AUDIT_GET \
	_IOWR(EBPFOS_IOC_MAGIC, 0x19, struct ebpfos_ioc_audit_get)
#define EBPFOS_IOC_FILE_ENROLL \
	_IOWR(EBPFOS_IOC_MAGIC, 0x20, struct ebpfos_ioc_file_enroll)
#define EBPFOS_IOC_FILE_STATUS \
	_IOWR(EBPFOS_IOC_MAGIC, 0x21, struct ebpfos_ioc_file_status)
#define EBPFOS_IOC_FILE_REPLACE_BEGIN \
	_IOWR(EBPFOS_IOC_MAGIC, 0x22, struct ebpfos_ioc_file_replace_begin)
#define EBPFOS_IOC_FILE_REPLACE_COMMIT \
	_IOW(EBPFOS_IOC_MAGIC, 0x23, struct ebpfos_ioc_file_replace_end)
#define EBPFOS_IOC_FILE_REPLACE_ABORT \
	_IOW(EBPFOS_IOC_MAGIC, 0x24, struct ebpfos_ioc_file_replace_end)
#define EBPFOS_IOC_FILE_REPLACE_STATUS \
	_IOWR(EBPFOS_IOC_MAGIC, 0x25, struct ebpfos_ioc_file_replace_status)
#define EBPFOS_IOC_FILE_REPLACE_CATCHUP \
	_IOW(EBPFOS_IOC_MAGIC, 0x26, struct ebpfos_ioc_file_replace_catchup)
#define EBPFOS_IOC_FILE_RECOVERY_BEGIN \
	_IOWR(EBPFOS_IOC_MAGIC, 0x27, struct ebpfos_ioc_file_recovery_begin)
#define EBPFOS_IOC_FILE_RECOVERY_ARM \
	_IOWR(EBPFOS_IOC_MAGIC, 0x28, struct ebpfos_ioc_file_recovery_end)
#define EBPFOS_IOC_FILE_RECOVERY_ABORT \
	_IOW(EBPFOS_IOC_MAGIC, 0x29, struct ebpfos_ioc_file_recovery_end)
#define EBPFOS_IOC_FILE_RECOVERY_STATUS \
	_IOWR(EBPFOS_IOC_MAGIC, 0x2a, struct ebpfos_ioc_file_recovery_status)
#define EBPFOS_IOC_FILE_RECOVERY_RETIRE \
	_IOW(EBPFOS_IOC_MAGIC, 0x2b, struct ebpfos_ioc_file_recovery_retire)

#endif /* _UAPI_EBPFOS_H */
