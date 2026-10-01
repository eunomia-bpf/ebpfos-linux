/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_H
#define _LINUX_EBPFOS_H

#include <linux/atomic.h>
#include <linux/bits.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/refcount.h>
#include <linux/types.h>
#include <uapi/linux/ebpfos.h>

struct bpf_map;
struct bpf_prog;
struct bpf_prog_aux;
struct ebpfos_admission;
struct ebpfos_prog_identity;
struct ebpfos_executor_root_slot;

struct ebpfos_executor_root_lease {
	struct ebpfos_binding *binding;
	struct ebpfos_executor_root_slot *slot;
	u64 epoch;
};

struct ebpfos_binding {
	refcount_t refs;
	/* Bit 63: retired; bits 16..62: entries; bits 0..15: active. */
	atomic64_t invocation_state;
	atomic64_t map_rehashes;
	u64 retired_epoch;
	u64 retirement_snapshot;
	struct bpf_prog *prog;
	struct bpf_map *map;
	struct bpf_map **maps;
	u32 map_count;
	struct ebpfos_prog_identity *prog_identity;
	u64 grant_id;
	u64 policy_generation;
	u64 runtime_schema;
	u32 kind;
	u32 use;
	u32 prog_id;
	u32 map_id;
	u8 realm_id[16];
	u8 policy_digest[32];
	u8 content_digest[32];
	u8 program_digest[32];
	u8 map_digest[32];
	u8 contract_sha256[32];
	u8 abstract_schema_sha256[32];
	u8 concrete_schema_sha256[32];
	u8 authority_sha256[32];
};

/* Policy-free generic executor-root substrate. */
#define EBPFOS_EXECUTOR_ROOT_ABI_VERSION 1U
#define EBPFOS_EXECUTOR_ROOT_MAX_ROLES 64U
#define EBPFOS_EXECUTOR_ROOT_MAX_CONTEXT_SIZE EBPFOS_COMPONENT_CALL_CONTEXT_SIZE
#define EBPFOS_COMPONENT_USE_CALL_PROVIDER 12U
#define EBPFOS_EXECUTOR_ROOT_F_TEST_FAIL_AFTER_STAGE BIT(0)

#define EBPFOS_COMPONENT_CALL_ABI_ID 0x454243414c4c0001ULL
#define EBPFOS_COMPONENT_CALL_ABI_VERSION 1U
#define EBPFOS_COMPONENT_CALL_INPUT_SIZE 128U
#define EBPFOS_COMPONENT_CALL_OUTPUT_SIZE 128U
#define EBPFOS_CAP_KPROG_TERMINAL_ROOT BIT_ULL(4)
#define EBPFOS_EFFECT_KPROG_TERMINAL_WAIT BIT_ULL(7)

struct ebpfos_component_call_frame {
	u32 version;
	u32 flags;
	u64 method_id;
	u64 object_id;
	u64 epoch;
	u32 input_size;
	u32 output_capacity;
	u8 input[EBPFOS_COMPONENT_CALL_INPUT_SIZE];
	s32 status;
	u32 output_size;
	u8 output[EBPFOS_COMPONENT_CALL_OUTPUT_SIZE];
};

#define EBPFOS_COMPONENT_CALL_CONTEXT_SIZE \
	((u32)sizeof(struct ebpfos_component_call_frame))

#define EBPFOS_EXECUTOR_CALL_F_EXPECT_EPOCH BIT(0)

struct ebpfos_executor_call {
	u32 version;
	u32 flags;
	u64 object_id;
	u64 role_type;
	u64 expected_epoch;
	u64 observed_epoch;
	u32 provider_prog_id;
	u32 provider_status;
	u32 context_size;
	u32 method_id;
	u8 context[];
};

struct ebpfos_executor_root_role_request {
	s32 admission_fd;
	u32 reserved;
	u64 role_type;
};

struct ebpfos_executor_root_publish_request {
	u32 version;
	u32 flags;
	u64 object_id;
	u64 expected_epoch;
	u64 target_epoch;
	u32 role_count;
	u32 reserved;
	struct ebpfos_executor_root_role_request roles[];
};

struct ebpfos_executor_root_role_snapshot {
	u64 role_type;
	u64 authority;
	u64 provider_type_id;
	u64 schema;
	u32 prog_id;
	u32 map_id;
	u8 content_digest[32];
	u8 contract_digest[32];
};

#ifdef CONFIG_EBPFOS
long ebpfos_admission_seal_ioctl(void __user *argp);
long ebpfos_admission_info_ioctl(void __user *argp);
long ebpfos_admission_runtime_info_ioctl(void __user *argp);
void ebpfos_admission_gate_lock(void);
void ebpfos_admission_gate_unlock(void);
struct ebpfos_admission *ebpfos_admission_get_from_fd(int fd);
void ebpfos_admission_put(struct ebpfos_admission *admission);
int ebpfos_admission_stage_bundle_locked(
	struct ebpfos_admission **grants,
	struct ebpfos_binding *const *predecessors, unsigned int count);
int ebpfos_admission_consume_bundle_locked(
	struct ebpfos_admission **grants, unsigned int count);
int ebpfos_admission_publish_validate_locked(
	struct ebpfos_admission *admission,
	const struct ebpfos_binding *predecessor, bool recovery);
int ebpfos_admission_consume_set_locked(struct ebpfos_admission **grants,
					 unsigned int count);
void ebpfos_admission_burn_set_locked(struct ebpfos_admission **grants,
				      unsigned int count);
void ebpfos_admission_burn_locked(struct ebpfos_admission *admission);
u32 ebpfos_admission_state_locked(struct ebpfos_admission *admission);
void ebpfos_admission_fill_identity_locked(
	struct ebpfos_admission *admission,
	struct ebpfos_admission_identity_v1 *identity);
struct ebpfos_binding *ebpfos_admission_binding_get(
	struct ebpfos_admission *admission);
struct ebpfos_binding *ebpfos_binding_get(struct ebpfos_binding *binding);
void ebpfos_binding_put(struct ebpfos_binding *binding);
int ebpfos_binding_invocation_enter(struct ebpfos_binding *binding);
void ebpfos_binding_invocation_exit(struct ebpfos_binding *binding);
u32 ebpfos_binding_active_invocations(const struct ebpfos_binding *binding);
u64 ebpfos_binding_invocation_entries(const struct ebpfos_binding *binding);
bool ebpfos_binding_is_retired(const struct ebpfos_binding *binding);
void ebpfos_binding_retire(struct ebpfos_binding *binding, u64 epoch);
bool ebpfos_binding_content_matches(const struct ebpfos_binding *binding,
				    const u8 digest[32]);
u64 ebpfos_binding_policy_generation(const struct ebpfos_binding *binding);
u64 ebpfos_binding_runtime_schema(const struct ebpfos_binding *binding);
u32 ebpfos_binding_use(const struct ebpfos_binding *binding);
u32 ebpfos_binding_kind(const struct ebpfos_binding *binding);
const u8 *ebpfos_binding_content_digest(const struct ebpfos_binding *binding);
const struct ebpfos_component_desc_v1 *
ebpfos_binding_descriptor(const struct ebpfos_binding *binding);
struct bpf_prog *ebpfos_binding_prog(const struct ebpfos_binding *binding);
struct bpf_map *ebpfos_binding_map(const struct ebpfos_binding *binding);
void ebpfos_binding_fill_identity(const struct ebpfos_binding *binding,
				  struct ebpfos_admission_identity_v1 *identity);
int ebpfos_executor_root_lease_begin(u64 object_id, u64 role_type,
	struct ebpfos_executor_root_lease *lease,
	struct ebpfos_executor_root_role_snapshot *snapshot);
void ebpfos_executor_root_lease_end(struct ebpfos_executor_root_lease *lease);
int ebpfos_executor_root_quiesce(u64 object_id, u64 expected_epoch);
void ebpfos_executor_root_resume(u64 object_id);
long ebpfos_executor_root_publish_ioctl(void __user *argp);
void ebpfos_prog_identity_put(struct ebpfos_prog_identity *identity);
#endif

#endif /* _LINUX_EBPFOS_H */
