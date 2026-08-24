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

/* Kernel-private generated KOperation transaction ABI. */
#define EBPFOS_KOPERATION_ABI_VERSION 1U
#define EBPFOS_KOPERATION_PAGE_TABLE_READ_CR3_ROOT 1U
#define EBPFOS_KOPERATION_PAGE_TABLE_RELOAD_CR3_ROOT 2U
#define EBPFOS_KOPERATION_STATUS_STAGED 1U
#define EBPFOS_KOPERATION_STATUS_COMPLETE 2U
#define EBPFOS_KOPERATION_STATUS_BURNED 3U
#define EBPFOS_KOPERATION_ARCH_CR4_PCIDE BIT_ULL(0)
#define EBPFOS_KOPERATION_ARCH_CR4_PGE BIT_ULL(1)
#define EBPFOS_KOPERATION_ARCH_CR3_NOFLUSH BIT_ULL(2)

struct ebpfos_koperation_prepare {
	__u32 version;
	__u32 operation_id;
	__u32 flags;
	__u32 reserved0;
	__u64 transaction_id;
	__u64 staged_shadow;
	__u8 semantic_sha256[32];
	__u8 proof_template_sha256[32];
	__u8 native_sha256[32];
	__u8 equivalence_sha256[32];
	__u64 attempts;
	__u64 commits;
	__u64 rejects;
};

struct ebpfos_koperation_execute {
	__u32 version;
	__u32 operation_id;
	__s32 proof_prog_fd;
	__u32 flags;
	__u64 transaction_id;
	__u64 expected_shadow;
	__u8 expected_semantic_sha256[32];
	__u8 expected_proof_template_sha256[32];
	__u8 expected_native_sha256[32];
	__u8 expected_equivalence_sha256[32];
};

struct ebpfos_koperation_result {
	__u32 version;
	__u32 operation_id;
	__u32 status;
	__s32 error;
	__u64 transaction_id;
	__u64 staged_shadow;
	__u64 native_result;
	__u64 native_operand_before;
	__u64 architecture_flags;
	__u32 cpu_before;
	__u32 cpu_after;
	__u8 semantic_sha256[32];
	__u8 proof_program_sha256[32];
	__u8 native_sha256[32];
	__u8 equivalence_sha256[32];
	__u64 attempts;
	__u64 commits;
	__u64 rejects;
};

#define EBPFOS_IOC_KOPERATION_PREPARE_EXPERIMENTAL \
	_IOWR(EBPFOS_IOC_MAGIC, 0x40, struct ebpfos_koperation_prepare)
#define EBPFOS_IOC_KOPERATION_EXECUTE_EXPERIMENTAL \
	_IOW(EBPFOS_IOC_MAGIC, 0x41, struct ebpfos_koperation_execute)
#define EBPFOS_IOC_KOPERATION_RESULT_EXPERIMENTAL \
	_IOR(EBPFOS_IOC_MAGIC, 0x42, struct ebpfos_koperation_result)

struct bpf_map;
struct bpf_prog;
struct bpf_prog_aux;
struct ebpfos_admission;
struct ebpfos_prog_identity;

struct ebpfos_binding {
	refcount_t refs;
	/* Bit 63: retired; bits 16..62: entries; bits 0..15: active. */
	atomic64_t invocation_state;
	atomic64_t map_rehashes;
	u64 retired_epoch;
	u64 retirement_snapshot;
	struct bpf_prog *prog;
	struct bpf_map *map;
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
#define EBPFOS_EXECUTOR_ROOT_ABI_ID 0x4558524f4f540001ULL
#define EBPFOS_EXECUTOR_ROOT_ABI_VERSION 1U
#define EBPFOS_EXECUTOR_ROOT_PUBLISH_CAPABILITY BIT_ULL(63)
#define EBPFOS_EXECUTOR_ROOT_PUBLISH_EFFECT BIT_ULL(63)
#define EBPFOS_EXECUTOR_ROOT_MAX_ROLES 64U
#define EBPFOS_EXECUTOR_ROOT_MAX_CONTEXT_SIZE 7800U
#define EBPFOS_EXECUTOR_ROOT_MANIFEST_SCHEMA 0x4558524d414e0001ULL
#define EBPFOS_COMPONENT_DOMAIN_EXECUTOR_ROOT 2U
#define EBPFOS_COMPONENT_DOMAIN_EXECUTOR_ROOT_MASK \
	BIT(EBPFOS_COMPONENT_DOMAIN_EXECUTOR_ROOT)
#define EBPFOS_COMPONENT_USE_EXECUTOR_ROOT_PUBLISHER 10U
#define EBPFOS_COMPONENT_USE_EXECUTOR_ROOT_CALLER 11U
#define EBPFOS_COMPONENT_USE_CALL_PROVIDER 12U
#define EBPFOS_VERIFIER_PROFILE_EXECUTOR_ROOT 2U
#define EBPFOS_VERIFIER_PROFILE_EXECUTOR_ROOT_MASK \
	BIT_ULL(EBPFOS_VERIFIER_PROFILE_EXECUTOR_ROOT)
#define EBPFOS_EXECUTOR_ROOT_PUBLISHER_TYPE 0x4558525055420001ULL
#define EBPFOS_EXECUTOR_ROOT_F_TEST_FAIL_AFTER_STAGE BIT(0)

#define EBPFOS_COMPONENT_CALL_ABI_ID 0x454243414c4c0001ULL
#define EBPFOS_COMPONENT_CALL_ABI_VERSION 1U
#define EBPFOS_COMPONENT_CALL_INPUT_SIZE 128U
#define EBPFOS_COMPONENT_CALL_OUTPUT_SIZE 128U
#define EBPFOS_CAP_KPROG_MACHINE_ROOT BIT_ULL(3)
#define EBPFOS_EFFECT_KPROG_MACHINE_STATE BIT_ULL(6)

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

#define EBPFOS_EXECUTOR_IMPORT_ABI_ID 0x4558494d504f0001ULL
#define EBPFOS_EXECUTOR_IMPORT_MANIFEST_VERSION 1U
#define EBPFOS_EXECUTOR_IMPORT_MANIFEST_SCHEMA 0x4558494d414e0001ULL
#define EBPFOS_EXECUTOR_IMPORT_MAX_ENTRIES 64U
#define EBPFOS_EXECUTOR_CALL_F_EXPECT_EPOCH BIT(0)

struct ebpfos_executor_import {
	u64 object_id;
	u64 role_type;
	u64 provider_type_id;
	u64 runtime_schema;
	u64 authority_ceiling;
	u64 effect_ceiling;
	u64 call_abi_id;
	u32 context_size;
	u32 flags;
	u32 method_id;
	u32 discriminator_offset;
	u32 discriminator_size;
	u32 reserved;
	u64 discriminator_value;
	u64 discriminator_mask;
	u8 contract_digest[32];
	u8 prototype_digest[32];
};

struct ebpfos_executor_import_manifest {
	u32 version;
	u32 import_count;
	u32 flags;
	u32 reserved;
	u64 authority_ceiling;
	u64 effect_ceiling;
	u8 provenance_digest[32];
	struct ebpfos_executor_import imports[EBPFOS_EXECUTOR_IMPORT_MAX_ENTRIES];
};

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

struct ebpfos_executor_root_manifest_role {
	u64 role_type;
	u64 provider_type_id;
	u64 schema;
	u64 authority;
	u8 content_digest[32];
	u8 contract_digest[32];
};

struct ebpfos_executor_root_manifest {
	u32 version;
	u32 role_count;
	u64 object_id;
	u64 authority_ceiling;
	struct ebpfos_executor_root_manifest_role
		roles[EBPFOS_EXECUTOR_ROOT_MAX_ROLES];
	u8 platform_digest[32];
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

struct ebpfos_executor_root_snapshot {
	u32 version;
	u32 flags;
	u64 object_id;
	u64 epoch;
	u64 authority;
	u32 publisher_prog_id;
	u32 role_count;
	u8 publisher_digest[32];
	struct ebpfos_executor_root_role_snapshot roles[];
};

#ifdef CONFIG_EBPFOS
long ebpfos_policy_activate_ioctl(void __user *argp);
long ebpfos_policy_status_ioctl(void __user *argp);
long ebpfos_admission_seal_ioctl(void __user *argp);
long ebpfos_admission_info_ioctl(void __user *argp);
long ebpfos_admission_runtime_info_ioctl(void __user *argp);
void ebpfos_admission_gate_lock(void);
void ebpfos_admission_gate_unlock(void);
bool ebpfos_policy_enforcing(void);
bool ebpfos_policy_enforcing_locked(void);
int ebpfos_policy_identity_validate_locked(
	u64 generation, const u8 realm_id[16], const u8 policy_digest[32],
	const u8 host_policy_digest[32], u32 required_flags);
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
int ebpfos_admission_root_publisher_validate_locked(
	struct bpf_prog_aux *aux, u32 *prog_id, u8 content_digest[32],
	struct ebpfos_executor_root_manifest *manifest);
bool ebpfos_admission_root_publisher_program(const struct bpf_prog *prog);
bool ebpfos_admission_meta_program(const struct bpf_prog *prog);
int ebpfos_admission_import_validate(
	struct bpf_prog_aux *aux, u64 object_id, u64 role_type, u32 method_id,
	const struct ebpfos_component_desc_v1 *provider,
	const struct ebpfos_executor_root_role_snapshot *role,
	struct ebpfos_executor_import *matched);

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
struct ebpfos_binding *ebpfos_executor_root_binding_get(
	u64 object_id, u64 role_type, u64 *epoch);
void ebpfos_prog_identity_put(struct ebpfos_prog_identity *identity);
bool ebpfos_executor_root_kfunc_allowed(u32 btf_id);
#else
static inline bool ebpfos_admission_root_publisher_program(
	const struct bpf_prog *prog)
{
	return false;
}
static inline bool ebpfos_admission_meta_program(const struct bpf_prog *prog)
{
	return false;
}
static inline bool ebpfos_executor_root_kfunc_allowed(u32 btf_id)
{
	return false;
}
#endif

#ifdef CONFIG_EBPFOS_KOPERATION
int ebpfos_kprog_domain_filter(const struct bpf_prog *prog,
			       bool own_koperation_id);
long ebpfos_koperation_prepare_ioctl(void __user *argp, void **txn_slot);
long ebpfos_koperation_execute_ioctl(void __user *argp, void **txn_slot);
long ebpfos_koperation_result_ioctl(void __user *argp, void **txn_slot);
void ebpfos_koperation_release(void **txn_slot);
#else
static inline int ebpfos_kprog_domain_filter(const struct bpf_prog *prog,
					      bool own_koperation_id)
{
	return -EACCES;
}
static inline long ebpfos_koperation_prepare_ioctl(void __user *argp,
						    void **txn_slot)
{
	return -EOPNOTSUPP;
}
static inline long ebpfos_koperation_execute_ioctl(void __user *argp,
						    void **txn_slot)
{
	return -EOPNOTSUPP;
}
static inline long ebpfos_koperation_result_ioctl(void __user *argp,
						   void **txn_slot)
{
	return -EOPNOTSUPP;
}
static inline void ebpfos_koperation_release(void **txn_slot) { }
#endif

#endif /* _LINUX_EBPFOS_H */
