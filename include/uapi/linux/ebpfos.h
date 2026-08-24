/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_EBPFOS_H
#define _UAPI_EBPFOS_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define EBPFOS_UAPI_VERSION 11
#define EBPFOS_IOC_MAGIC 0xe7

struct ebpfos_ioc_version {
	__u32 uapi_version;
	__u32 feature_flags;
};

#define EBPFOS_IOC_VERSION \
	_IOR(EBPFOS_IOC_MAGIC, 0x00, struct ebpfos_ioc_version)

#define EBPFOS_POLICY_RECORD_V1_SIZE 256U
#define EBPFOS_RESOURCE_DESC_V1_SIZE 96U
#define EBPFOS_COMPONENT_DESC_V1_SIZE 1024U
#define EBPFOS_ADMISSION_MAX_RESOURCES 1U
#define EBPFOS_ADMISSION_MAX_SIGNATURE 16384U

#define EBPFOS_POLICY_RECORD_V1_MAGIC "EBPFPOL1"
#define EBPFOS_COMPONENT_DESC_V1_MAGIC "EBPFDES1"
#define EBPFOS_ADMISSION_FORMAT_VERSION 1U

#define EBPFOS_POLICY_F_TEST_ONLY (1U << 1)
#define EBPFOS_POLICY_F_ALL EBPFOS_POLICY_F_TEST_ONLY

#define EBPFOS_COMPONENT_F_TEST_ONLY (1U << 0)
#define EBPFOS_COMPONENT_F_ALL EBPFOS_COMPONENT_F_TEST_ONLY

#define EBPFOS_RESOURCE_F_FROZEN_BEFORE_LOAD (1U << 0)
#define EBPFOS_RESOURCE_F_EXCLUSIVE_PROGRAM_OWNER (1U << 1)
#define EBPFOS_RESOURCE_F_INITIAL_HASH_REQUIRED (1U << 2)
#define EBPFOS_RESOURCE_F_ALL \
	(EBPFOS_RESOURCE_F_FROZEN_BEFORE_LOAD | \
	 EBPFOS_RESOURCE_F_EXCLUSIVE_PROGRAM_OWNER | \
	 EBPFOS_RESOURCE_F_INITIAL_HASH_REQUIRED)

#define EBPFOS_EFFECT_MAP_LOOKUP (1ULL << 0)
#define EBPFOS_EFFECT_MAP_UPDATE (1ULL << 1)
#define EBPFOS_EFFECT_OBJECT_READ (1ULL << 2)
#define EBPFOS_EFFECT_OBJECT_WRITE (1ULL << 3)
#define EBPFOS_EFFECT_STATE_READ (1ULL << 4)
#define EBPFOS_EFFECT_STATE_WRITE (1ULL << 5)

enum ebpfos_policy_state {
	EBPFOS_POLICY_INACTIVE = 0,
	EBPFOS_POLICY_ACTIVE = 1,
};

enum ebpfos_component_domain {
	EBPFOS_COMPONENT_DOMAIN_COMPONENT = 3,
};

#define EBPFOS_COMPONENT_DOMAIN_COMPONENT_MASK \
	(1U << EBPFOS_COMPONENT_DOMAIN_COMPONENT)

enum ebpfos_component_code_format {
	EBPFOS_COMPONENT_CODE_BPF_ELF = 1,
};

enum ebpfos_verifier_profile {
	EBPFOS_VERIFIER_PROFILE_COMPONENT_CALL = 3,
};

#define EBPFOS_VERIFIER_PROFILE_COMPONENT_CALL_MASK \
	(1ULL << EBPFOS_VERIFIER_PROFILE_COMPONENT_CALL)

enum ebpfos_resource_kind {
	EBPFOS_RESOURCE_ARRAY_MAP = 1,
};

enum ebpfos_admission_state {
	EBPFOS_ADMISSION_NONE = 0,
	EBPFOS_ADMISSION_FRESH = 1,
	EBPFOS_ADMISSION_STAGED = 2,
	EBPFOS_ADMISSION_STAGED_RECOVERY = 3,
	EBPFOS_ADMISSION_CONSUMED = 4,
	EBPFOS_ADMISSION_BURNED = 5,
	EBPFOS_ADMISSION_STALE = 6,
};

enum ebpfos_admitted_binding_kind {
	EBPFOS_ADMITTED_BINDING_BPF = 2,
};

struct ebpfos_policy_record_v1 {
	__u8 magic[8];
	__le16 format_version;
	__le16 header_size;
	__le32 total_size;
	__le32 flags;
	__le32 domain_mask;
	__u8 realm_id[16];
	__le64 generation;
	__u8 previous_record_digest[32];
	__u8 host_policy_sha256[32];
	__le64 verifier_profile_mask;
	__le64 capability_ceiling;
	__le64 effect_ceiling;
	__le32 max_static_insns;
	__le32 max_verified_insns;
	__le32 max_stack_depth;
	__le32 max_context_size;
	__le32 max_resources;
	__le32 reserved0;
	__le64 max_map_bytes;
	__le64 max_call_bytes;
	__u8 kernel_abi_sha256[32];
	__u8 native_bootstrap_sha256[32];
	__u8 reserved[16];
};

struct ebpfos_resource_desc_v1 {
	__le32 kind;
	__le32 flags;
	__le32 map_type;
	__le32 key_size;
	__le32 value_size;
	__le32 max_entries;
	__le32 map_flags;
	__le32 reserved0;
	__le64 map_extra;
	__le64 logical_bytes;
	__le64 canonical_bytes;
	__u8 reserved[40];
};

struct ebpfos_component_desc_v1 {
	__u8 magic[8];
	__le16 format_version;
	__le16 header_size;
	__le32 total_size;
	__le32 flags;
	__le32 domain;
	__le32 use;
	__le32 code_format;
	__le32 verifier_profile;
	__le32 reserved0;
	__u8 realm_id[16];
	__le64 policy_generation;
	__u8 policy_record_digest[32];
	__u8 host_policy_sha256[32];
	__u8 component_id[16];
	__le64 component_version;
	__le64 provider_type_id;
	__le64 transition_id;
	__le64 predecessor_policy_generation;
	__u8 predecessor_policy_digest[32];
	__u8 predecessor_content_digest[32];
	__u8 contract_sha256[32];
	__u8 interface_sha256[32];
	__u8 authority_sha256[32];
	__u8 abstract_schema_sha256[32];
	__u8 concrete_schema_sha256[32];
	__u8 attested_elf_sha256[32];
	__u8 load_image_sha256[32];
	__u8 initial_map_sha256[32];
	__le64 abi_id;
	__le32 abi_version;
	__le32 context_size;
	__le64 runtime_schema_u64;
	__le64 capability_mask;
	__le64 effect_mask;
	__le32 prog_type;
	__le32 semantic_prog_flags;
	__le32 exact_insn_count;
	__le32 max_verified_insns;
	__le32 max_stack_depth;
	__le32 max_ctx_offset;
	__le32 max_tail_calls;
	__le32 resource_count;
	__le64 max_call_bytes;
	struct ebpfos_resource_desc_v1 resource;
	__u8 reserved[352];
};

struct ebpfos_ioc_policy_activate {
	struct ebpfos_policy_record_v1 record;
	__aligned_u64 signature;
	__u32 signature_size;
	__u32 flags;
};

struct ebpfos_ioc_policy_status {
	__u32 state;
	__u32 policy_flags;
	__u8 realm_id[16];
	__u64 generation;
	__u8 policy_record_digest[32];
	__u8 root_fingerprint[32];
	__u64 staged_grants;
	__u64 reserved0;
	__u8 reserved[16];
};

struct ebpfos_ioc_admission_seal {
	__s32 prog_fd;
	__s32 map_fd;
	__u32 flags;
	__u32 signature_size;
	__aligned_u64 signature;
	struct ebpfos_component_desc_v1 descriptor;
	__s32 admission_fd;
	__u32 admission_state;
	__u64 grant_id;
	__u32 prog_id;
	__u32 map_id;
	__u8 content_digest[32];
	__u8 program_digest[32];
	__u8 map_digest[32];
};

struct ebpfos_ioc_admission_info {
	__s32 admission_fd;
	__u32 flags;
	__u64 grant_id;
	__u32 admission_state;
	__u32 prog_id;
	__u32 map_id;
	__u32 reserved0;
	__u8 content_digest[32];
	__u8 program_digest[32];
	__u8 map_digest[32];
	struct ebpfos_component_desc_v1 descriptor;
};

#define EBPFOS_ADMISSION_RUNTIME_INFO_VERSION 1U

struct ebpfos_ioc_admission_runtime_info {
	__s32 admission_fd;
	__u32 version;
	__u32 flags;
	__u32 prog_id;
	__u32 map_id;
	__u32 active_invocations;
	__u64 map_rehashes;
	__u64 invocation_entries;
	__u8 content_digest[32];
	__u64 retired_epoch;
	__u64 entries_at_publication;
	__u32 active_at_publication;
	__u32 reserved2;
};

struct ebpfos_admission_identity_v1 {
	__u64 grant_id;
	__u64 policy_generation;
	__u32 binding_kind;
	__u32 admission_state;
	__u32 prog_id;
	__u32 map_id;
	__u8 policy_record_digest[32];
	__u8 content_digest[32];
	__u8 program_digest[32];
	__u8 map_digest[32];
	__u8 contract_sha256[32];
	__u8 abstract_schema_sha256[32];
	__u8 concrete_schema_sha256[32];
	__u8 authority_sha256[32];
};

#define EBPFOS_IOC_POLICY_ACTIVATE \
	_IOW(EBPFOS_IOC_MAGIC, 0x30, struct ebpfos_ioc_policy_activate)
#define EBPFOS_IOC_POLICY_STATUS \
	_IOR(EBPFOS_IOC_MAGIC, 0x31, struct ebpfos_ioc_policy_status)
#define EBPFOS_IOC_ADMISSION_SEAL \
	_IOWR(EBPFOS_IOC_MAGIC, 0x32, struct ebpfos_ioc_admission_seal)
#define EBPFOS_IOC_ADMISSION_INFO \
	_IOWR(EBPFOS_IOC_MAGIC, 0x33, struct ebpfos_ioc_admission_info)
#define EBPFOS_IOC_ADMISSION_RUNTIME_INFO \
	_IOWR(EBPFOS_IOC_MAGIC, 0x38, struct ebpfos_ioc_admission_runtime_info)

#endif /* _UAPI_EBPFOS_H */
