// SPDX-License-Identifier: GPL-2.0-only
#include <crypto/sha2.h>
#include <linux/anon_inodes.h>
#include <linux/bpf.h>
#include <linux/build_bug.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/ebpfos.h>
#include <linux/file.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/key.h>
#include <linux/kref.h>
#include <linux/lockdep.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/verification.h>

#include "admission_certificates.h"

#define EBPFOS_FILE_PROVIDER_PROG_FLAGS 0x110U
#define EBPFOS_FILE_PROVIDER_CONTEXT_SIZE 1152U
#define EBPFOS_FILE_PROVIDER_CALL_BYTES 1024U
#define EBPFOS_FILE_PROVIDER_ABI_ID 0x46494c4541424901ULL
#define EBPFOS_FILE_PROVIDER_ABI_VERSION 1U

#define EBPFOS_ASSERT_OFFSET(_type, _field, _offset) \
	static_assert(offsetof(struct _type, _field) == (_offset))

static_assert(sizeof(struct ebpfos_policy_record_v1) ==
	      EBPFOS_POLICY_RECORD_V1_SIZE);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, magic, 0);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, format_version, 8);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, header_size, 10);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, total_size, 12);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, flags, 16);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, domain_mask, 20);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, realm_id, 24);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, generation, 40);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, previous_record_digest, 48);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, host_policy_sha256, 80);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, verifier_profile_mask, 112);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, capability_ceiling, 120);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, effect_ceiling, 128);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, max_static_insns, 136);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, max_verified_insns, 140);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, max_stack_depth, 144);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, max_context_size, 148);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, max_resources, 152);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, reserved0, 156);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, max_map_bytes, 160);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, max_call_bytes, 168);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, kernel_abi_sha256, 176);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, native_bootstrap_sha256, 208);
EBPFOS_ASSERT_OFFSET(ebpfos_policy_record_v1, reserved, 240);

static_assert(sizeof(struct ebpfos_resource_desc_v1) ==
	      EBPFOS_RESOURCE_DESC_V1_SIZE);
EBPFOS_ASSERT_OFFSET(ebpfos_resource_desc_v1, kind, 0);
EBPFOS_ASSERT_OFFSET(ebpfos_resource_desc_v1, flags, 4);
EBPFOS_ASSERT_OFFSET(ebpfos_resource_desc_v1, map_type, 8);
EBPFOS_ASSERT_OFFSET(ebpfos_resource_desc_v1, key_size, 12);
EBPFOS_ASSERT_OFFSET(ebpfos_resource_desc_v1, value_size, 16);
EBPFOS_ASSERT_OFFSET(ebpfos_resource_desc_v1, max_entries, 20);
EBPFOS_ASSERT_OFFSET(ebpfos_resource_desc_v1, map_flags, 24);
EBPFOS_ASSERT_OFFSET(ebpfos_resource_desc_v1, reserved0, 28);
EBPFOS_ASSERT_OFFSET(ebpfos_resource_desc_v1, map_extra, 32);
EBPFOS_ASSERT_OFFSET(ebpfos_resource_desc_v1, logical_bytes, 40);
EBPFOS_ASSERT_OFFSET(ebpfos_resource_desc_v1, canonical_bytes, 48);
EBPFOS_ASSERT_OFFSET(ebpfos_resource_desc_v1, reserved, 56);

static_assert(sizeof(struct ebpfos_component_desc_v1) ==
	      EBPFOS_COMPONENT_DESC_V1_SIZE);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, magic, 0);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, format_version, 8);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, header_size, 10);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, total_size, 12);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, flags, 16);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, domain, 20);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, use, 24);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, code_format, 28);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, verifier_profile, 32);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, reserved0, 36);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, realm_id, 40);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, policy_generation, 56);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, policy_record_digest, 64);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, host_policy_sha256, 96);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, component_id, 128);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, component_version, 144);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, provider_type_id, 152);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, transition_id, 160);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1,
		     predecessor_policy_generation, 168);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1,
		     predecessor_policy_digest, 176);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1,
		     predecessor_content_digest, 208);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, contract_sha256, 240);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, interface_sha256, 272);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, authority_sha256, 304);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1,
		     abstract_schema_sha256, 336);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1,
		     concrete_schema_sha256, 368);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, attested_elf_sha256, 400);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, load_image_sha256, 432);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, initial_map_sha256, 464);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, abi_id, 496);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, abi_version, 504);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, context_size, 508);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, runtime_schema_u64, 512);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, capability_mask, 520);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, effect_mask, 528);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, prog_type, 536);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, semantic_prog_flags, 540);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, exact_insn_count, 544);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, max_verified_insns, 548);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, max_stack_depth, 552);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, max_ctx_offset, 556);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, max_tail_calls, 560);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, resource_count, 564);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, max_call_bytes, 568);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, resource, 576);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, reserved, 672);

static_assert(sizeof(struct ebpfos_ioc_policy_activate) == 272);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_policy_activate, signature, 256);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_policy_activate, signature_size, 264);
static_assert(sizeof(struct ebpfos_ioc_policy_status) == 128);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_policy_status, generation, 24);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_policy_status, policy_record_digest, 32);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_policy_status, root_fingerprint, 64);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_policy_status, staged_grants, 96);
static_assert(sizeof(struct ebpfos_ioc_admission_seal) == 1168);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_seal, signature, 16);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_seal, descriptor, 24);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_seal, admission_fd, 1048);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_seal, grant_id, 1056);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_seal, content_digest, 1072);
static_assert(sizeof(struct ebpfos_ioc_admission_info) == 1152);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_info, descriptor, 128);
static_assert(sizeof(struct ebpfos_ioc_file_replace_begin_v2) == 160);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_file_replace_begin_v2,
		     expected_active_content_digest, 32);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_file_replace_begin_v2, txn_id, 64);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_file_replace_begin_v2,
		     candidate_content_digest, 120);
static_assert(sizeof(struct ebpfos_ioc_file_recovery_begin_v2) == 224);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_file_recovery_begin_v2,
		     expected_active_content_digest, 56);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_file_recovery_begin_v2, txn_id, 88);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_file_recovery_begin_v2,
		     e3_content_digest, 160);
static_assert(sizeof(struct ebpfos_ioc_file_recovery_arm_v2) == 160);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_file_recovery_arm_v2,
		     expected_active_content_digest, 48);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_file_recovery_arm_v2,
		     expected_e3_content_digest, 80);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_file_recovery_arm_v2,
		     expected_e4_content_digest, 112);
static_assert(sizeof(struct ebpfos_admission_identity_v1) == 288);
EBPFOS_ASSERT_OFFSET(ebpfos_admission_identity_v1,
		     policy_record_digest, 32);
EBPFOS_ASSERT_OFFSET(ebpfos_admission_identity_v1, authority_sha256, 256);
static_assert(sizeof(struct ebpfos_ioc_file_admission_status) == 640);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_file_admission_status, admission_gate, 52);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_file_admission_status, active, 56);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_file_admission_status, candidate, 344);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_file_admission_status, admitted_calls, 632);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_file_admission_status,
		     admission_waiters, 636);
static_assert(BPF_PROG_TYPE_SYSCALL == 31);
static_assert((BPF_F_EBPFOS_PROVIDER | BPF_F_SLEEPABLE) ==
	      EBPFOS_FILE_PROVIDER_PROG_FLAGS);
static_assert(EBPFOS_FILE_ADMISSION_LEGACY == 0);
static_assert(EBPFOS_FILE_ADMISSION_FAILED == 4);
static_assert(EBPFOS_FILE_ADMISSION_NATIVE_OPEN == 5);
static_assert(EBPFOS_FILE_ADMISSION_BPF_OPEN == 6);
static_assert(EBPFOS_FILE_ADMISSION_DRAINING == 7);
static_assert((u64)(EBPFOS_FILE_V1_KEY_SIZE +
			    EBPFOS_FILE_V1_VALUE_SIZE) *
	      EBPFOS_FILE_V1_MAX_ENTRIES == 34078980ULL);
static_assert((u64)ALIGN(EBPFOS_FILE_V1_VALUE_SIZE, 8) *
	      EBPFOS_FILE_V1_MAX_ENTRIES == 33554688ULL);
static_assert((u64)(EBPFOS_FILE_V2_KEY_SIZE +
			    EBPFOS_FILE_V2_VALUE_SIZE) *
	      EBPFOS_FILE_V2_MAX_ENTRIES == 34736200ULL);
static_assert((u64)ALIGN(EBPFOS_FILE_V2_VALUE_SIZE, 8) *
	      EBPFOS_FILE_V2_MAX_ENTRIES == 34605120ULL);

static const u8 ebpfos_policy_domain[] = "eBPFOS-policy-v1";
static const u8 ebpfos_admission_domain[] = "eBPFOS-admission-v1";
static const u8 ebpfos_content_domain[] = "eBPFOS-content-v1";
static const u8 ebpfos_native_domain[] = "eBPFOS-native-file-v1";
static const u8 ebpfos_state_adapter_domain[] =
	"eBPFOS-state-adapter-v1";

static const u8 ebpfos_kernel_abi_sha256[SHA256_DIGEST_SIZE] = {
	0x30, 0xfc, 0x01, 0x36, 0xde, 0x41, 0x9c, 0x62,
	0xcf, 0x4a, 0x21, 0x25, 0x7c, 0x21, 0x88, 0xd3,
	0x82, 0xaf, 0x4b, 0x02, 0xa1, 0x50, 0x68, 0x65,
	0x88, 0x9a, 0x80, 0x89, 0x80, 0x3d, 0xf8, 0x3b,
};

static const u8 ebpfos_native_contract_sha256[SHA256_DIGEST_SIZE] = {
	0x61, 0x52, 0xbc, 0x81, 0x29, 0x79, 0xb8, 0x30,
	0x5a, 0xc3, 0x28, 0x22, 0xb2, 0x5c, 0x95, 0xae,
	0x47, 0x76, 0x37, 0x02, 0x5e, 0xc7, 0x4c, 0x29,
	0xf8, 0xc2, 0xee, 0x17, 0x5b, 0x2a, 0xb1, 0x19,
};

static const u8 ebpfos_native_interface_sha256[SHA256_DIGEST_SIZE] = {
	0x3d, 0x0b, 0xab, 0xb8, 0xfb, 0x73, 0x51, 0xd8,
	0xce, 0xb4, 0x33, 0xfa, 0xc2, 0x3f, 0xdc, 0x91,
	0x0f, 0xb8, 0x66, 0xcb, 0xe3, 0x8c, 0xb6, 0xe2,
	0x40, 0x65, 0xe3, 0xda, 0x4b, 0xf7, 0xb6, 0x9a,
};

static const u8 ebpfos_native_schema_sha256[SHA256_DIGEST_SIZE] = {
	0x45, 0xb3, 0xb8, 0x2f, 0x7b, 0x33, 0x47, 0x73,
	0xa1, 0x0e, 0x06, 0x5f, 0x82, 0xaa, 0x4b, 0x88,
	0xe0, 0x3c, 0xaf, 0x4c, 0x02, 0x07, 0xde, 0x65,
	0x96, 0x3d, 0x6c, 0xe9, 0xe1, 0xe9, 0x89, 0x99,
};

static const u8 ebpfos_native_authority_sha256[SHA256_DIGEST_SIZE] = {
	0x15, 0x6f, 0x5f, 0xea, 0x1b, 0x3e, 0xe5, 0xdb,
	0xa1, 0xfa, 0x08, 0x18, 0x5b, 0x30, 0x9a, 0x7f,
	0x5e, 0x83, 0x07, 0xd8, 0x4c, 0x1f, 0xae, 0x45,
	0x06, 0x8c, 0xc8, 0xdf, 0x8d, 0x12, 0x73, 0x93,
};

static const u8 ebpfos_file_component_id[16] = {
	0x01, 0x00, 0x00, 0x00, 0x45, 0x4c, 0x49, 0x46,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const u8 ebpfos_file_v1_concrete_schema_sha256[SHA256_DIGEST_SIZE] = {
	0xe2, 0x08, 0x17, 0xb4, 0x9e, 0xd1, 0x42, 0x37,
	0x32, 0x57, 0xef, 0x9b, 0x90, 0xe4, 0x14, 0x1c,
	0x29, 0x23, 0x54, 0x23, 0x72, 0x43, 0xa4, 0xa3,
	0x73, 0x7d, 0x41, 0xbb, 0xb5, 0x15, 0x14, 0x74,
};

static const u8 ebpfos_file_v2_concrete_schema_sha256[SHA256_DIGEST_SIZE] = {
	0x4d, 0xe6, 0x61, 0x79, 0xde, 0x96, 0x8d, 0xf8,
	0x2e, 0x67, 0x82, 0x82, 0x30, 0x13, 0x52, 0x38,
	0xeb, 0x0c, 0x0b, 0x72, 0xc3, 0xa8, 0x0e, 0xa7,
	0xfe, 0x72, 0x66, 0x59, 0xa0, 0x3c, 0xf4, 0x1c,
};

enum ebpfos_prog_seal_state {
	EBPFOS_PROG_SEALING = 1,
	EBPFOS_PROG_SEALED = 2,
};

struct ebpfos_prog_identity {
	refcount_t refs;
	u32 seal_state;
	struct ebpfos_component_desc_v1 descriptor;
	u8 content_digest[SHA256_DIGEST_SIZE];
	u8 program_digest[SHA256_DIGEST_SIZE];
	u8 map_digest[SHA256_DIGEST_SIZE];
};

struct ebpfos_binding {
	refcount_t refs;
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
	u8 policy_digest[SHA256_DIGEST_SIZE];
	u8 content_digest[SHA256_DIGEST_SIZE];
	u8 program_digest[SHA256_DIGEST_SIZE];
	u8 map_digest[SHA256_DIGEST_SIZE];
	u8 contract_sha256[SHA256_DIGEST_SIZE];
	u8 abstract_schema_sha256[SHA256_DIGEST_SIZE];
	u8 concrete_schema_sha256[SHA256_DIGEST_SIZE];
	u8 authority_sha256[SHA256_DIGEST_SIZE];
};

struct ebpfos_admission {
	struct kref ref;
	/* Serializes one-shot transitions shared by duplicated grant FDs. */
	spinlock_t state_lock;
	struct ebpfos_binding *binding;
	u64 grant_id;
	u32 state;
};

struct ebpfos_policy {
	struct ebpfos_policy_record_v1 record;
	u8 digest[SHA256_DIGEST_SIZE];
	u32 state;
};

static DEFINE_MUTEX(ebpfos_publish_gate);
static DEFINE_MUTEX(ebpfos_seal_lock);
static struct ebpfos_policy ebpfos_policy;
static struct key *ebpfos_trusted_keyring;
static u8 ebpfos_root_fingerprint[SHA256_DIGEST_SIZE];
static bool ebpfos_trust_ready;
static u64 ebpfos_staged_grants;
static u64 ebpfos_legacy_bindings;
static DEFINE_SPINLOCK(ebpfos_grant_id_lock);
static u64 ebpfos_next_grant_id;

static const struct file_operations ebpfos_admission_fops;

static bool ebpfos_all_zero(const void *data, size_t size)
{
	return !memchr_inv(data, 0, size);
}

static bool ebpfos_nonzero(const void *data, size_t size)
{
	return !!memchr_inv(data, 0, size);
}

static void ebpfos_hash_parts(const u8 *domain, size_t domain_size,
			      const void *first, size_t first_size,
			      const void *second, size_t second_size,
			      u8 digest[SHA256_DIGEST_SIZE])
{
	struct sha256_ctx context;

	sha256_init(&context);
	sha256_update(&context, domain, domain_size);
	sha256_update(&context, first, first_size);
	if (second_size)
		sha256_update(&context, second, second_size);
	sha256_final(&context, digest);
}

static void ebpfos_policy_digest(
	const struct ebpfos_policy_record_v1 *record,
	u8 digest[SHA256_DIGEST_SIZE])
{
	ebpfos_hash_parts(ebpfos_policy_domain, sizeof(ebpfos_policy_domain),
			  record, sizeof(*record), NULL, 0, digest);
}

static void ebpfos_descriptor_content_digest(
	const struct ebpfos_component_desc_v1 *descriptor,
	u8 digest[SHA256_DIGEST_SIZE])
{
	ebpfos_hash_parts(ebpfos_content_domain,
			  sizeof(ebpfos_content_domain), descriptor,
			  sizeof(*descriptor), NULL, 0, digest);
}

static void ebpfos_native_bootstrap_digest(
	const struct ebpfos_policy_record_v1 *record,
	u8 digest[SHA256_DIGEST_SIZE])
{
	struct sha256_ctx context;

	sha256_init(&context);
	sha256_update(&context, ebpfos_native_domain,
		      sizeof(ebpfos_native_domain));
	sha256_update(&context, record->realm_id, sizeof(record->realm_id));
	sha256_update(&context, record->host_policy_sha256,
		      sizeof(record->host_policy_sha256));
	sha256_update(&context, record->kernel_abi_sha256,
		      sizeof(record->kernel_abi_sha256));
	sha256_update(&context, ebpfos_native_contract_sha256,
		      sizeof(ebpfos_native_contract_sha256));
	sha256_update(&context, ebpfos_native_interface_sha256,
		      sizeof(ebpfos_native_interface_sha256));
	sha256_update(&context, ebpfos_native_schema_sha256,
		      sizeof(ebpfos_native_schema_sha256));
	sha256_update(&context, ebpfos_native_authority_sha256,
		      sizeof(ebpfos_native_authority_sha256));
	sha256_final(&context, digest);
}

static int ebpfos_verify_signature(const u8 *domain, size_t domain_size,
				   const void *record, size_t record_size,
				   const void *signature,
				   size_t signature_size)
{
	size_t payload_size;
	u8 *payload;
	int error;

	if (!READ_ONCE(ebpfos_trust_ready) || !ebpfos_trusted_keyring)
		return -ENOKEY;
	if (check_add_overflow(domain_size, record_size, &payload_size))
		return -EOVERFLOW;
	payload = kmalloc(payload_size, GFP_KERNEL);
	if (!payload)
		return -ENOMEM;
	memcpy(payload, domain, domain_size);
	memcpy(payload + domain_size, record, record_size);
	error = verify_pkcs7_signature(payload, payload_size, signature,
				       signature_size, ebpfos_trusted_keyring,
				       VERIFYING_UNSPECIFIED_SIGNATURE, NULL,
				       NULL);
	kfree_sensitive(payload);
	return error;
}

int ebpfos_state_adapter_verify_signature(
	const struct ebpfos_state_adapter_record_v1 *record,
	const void *signature, size_t signature_size)
{
	if (!record || !signature || !signature_size ||
	    signature_size > EBPFOS_ADMISSION_MAX_SIGNATURE)
		return -EINVAL;
	return ebpfos_verify_signature(ebpfos_state_adapter_domain,
				       sizeof(ebpfos_state_adapter_domain),
				       record, sizeof(*record), signature,
				       signature_size);
}

static int ebpfos_validate_policy_record(
	const struct ebpfos_policy_record_v1 *record)
{
	u8 native_digest[SHA256_DIGEST_SIZE];
	u32 flags = le32_to_cpu(record->flags);

	if (memcmp(record->magic, EBPFOS_POLICY_RECORD_V1_MAGIC,
		   sizeof(record->magic)) ||
	    le16_to_cpu(record->format_version) !=
		EBPFOS_ADMISSION_FORMAT_VERSION ||
	    le16_to_cpu(record->header_size) != sizeof(*record) ||
	    le32_to_cpu(record->total_size) != sizeof(*record))
		return -EPROTO;
	if (flags & ~EBPFOS_POLICY_F_ALL ||
	    le32_to_cpu(record->domain_mask) !=
		EBPFOS_COMPONENT_DOMAIN_FILE_MASK ||
	    le64_to_cpu(record->verifier_profile_mask) !=
		EBPFOS_VERIFIER_PROFILE_FILE_PROVIDER_MASK ||
	    le64_to_cpu(record->capability_ceiling) != EBPFOS_CAP_FILE_ALL ||
	    le64_to_cpu(record->effect_ceiling) !=
		EBPFOS_EFFECT_FILE_PROVIDER_ALL)
		return -EACCES;
	if (!le64_to_cpu(record->generation) ||
	    !ebpfos_nonzero(record->realm_id, sizeof(record->realm_id)) ||
	    !ebpfos_nonzero(record->host_policy_sha256,
			    sizeof(record->host_policy_sha256)))
		return -EINVAL;
	if (!le32_to_cpu(record->max_static_insns) ||
	    !le32_to_cpu(record->max_verified_insns) ||
	    !le32_to_cpu(record->max_stack_depth) ||
	    le32_to_cpu(record->max_stack_depth) > MAX_BPF_STACK ||
	    le32_to_cpu(record->max_context_size) <
		EBPFOS_FILE_PROVIDER_CONTEXT_SIZE ||
	    le32_to_cpu(record->max_resources) !=
		EBPFOS_ADMISSION_MAX_RESOURCES ||
	    !le64_to_cpu(record->max_map_bytes) ||
	    le64_to_cpu(record->max_call_bytes) <
		EBPFOS_FILE_PROVIDER_CALL_BYTES)
		return -ERANGE;
	if (le32_to_cpu(record->reserved0) ||
	    !ebpfos_all_zero(record->reserved, sizeof(record->reserved)))
		return -EINVAL;
	if (memcmp(record->kernel_abi_sha256, ebpfos_kernel_abi_sha256,
		   SHA256_DIGEST_SIZE))
		return -EPROTO;
	ebpfos_native_bootstrap_digest(record, native_digest);
	if (memcmp(record->native_bootstrap_sha256, native_digest,
		   sizeof(native_digest)))
		return -EKEYREJECTED;
	return 0;
}

static int ebpfos_expected_map_tuple(u32 use, u32 *value_size,
				     u32 *max_entries, u64 *schema)
{
	switch (use) {
	case EBPFOS_COMPONENT_USE_PROD_V1:
		*value_size = EBPFOS_FILE_V1_VALUE_SIZE;
		*max_entries = EBPFOS_FILE_V1_MAX_ENTRIES;
		*schema = EBPFOS_FILE_SCHEMA_V1;
		return 0;
	case EBPFOS_COMPONENT_USE_PROD_V2:
	case EBPFOS_COMPONENT_USE_RECOVERY_E2:
	case EBPFOS_COMPONENT_USE_RECOVERY_E3_FAULT:
	case EBPFOS_COMPONENT_USE_RECOVERY_E4:
	case EBPFOS_COMPONENT_USE_SPLIT_READER:
	case EBPFOS_COMPONENT_USE_SPLIT_WRITER:
		*value_size = EBPFOS_FILE_V2_VALUE_SIZE;
		*max_entries = EBPFOS_FILE_V2_MAX_ENTRIES;
		*schema = EBPFOS_FILE_SCHEMA_V2;
		return 0;
	default:
		return -EPROTOTYPE;
	}
}

static int ebpfos_validate_resource(
	const struct ebpfos_resource_desc_v1 *resource, u32 use,
	const struct ebpfos_policy_record_v1 *policy)
{
	u64 logical_bytes, canonical_bytes;
	u32 expected_value_size, expected_max_entries;
	u64 expected_schema;
	int error;

	error = ebpfos_expected_map_tuple(use, &expected_value_size,
					  &expected_max_entries,
					  &expected_schema);
	if (error)
		return error;
	if (!expected_schema)
		return -EPROTO;
	if (le32_to_cpu(resource->kind) != EBPFOS_RESOURCE_ARRAY_MAP ||
	    le32_to_cpu(resource->flags) != EBPFOS_RESOURCE_F_ALL ||
	    le32_to_cpu(resource->map_type) != BPF_MAP_TYPE_ARRAY ||
	    le32_to_cpu(resource->key_size) != sizeof(u32) ||
	    le32_to_cpu(resource->value_size) != expected_value_size ||
	    le32_to_cpu(resource->max_entries) != expected_max_entries ||
	    le32_to_cpu(resource->map_flags) ||
	    le32_to_cpu(resource->reserved0) ||
	    le64_to_cpu(resource->map_extra) ||
	    !ebpfos_all_zero(resource->reserved, sizeof(resource->reserved)))
		return -EINVAL;
	if (check_add_overflow((u64)sizeof(u32),
			       (u64)expected_value_size, &logical_bytes) ||
	    check_mul_overflow(logical_bytes,
			       (u64)expected_max_entries, &logical_bytes) ||
	    check_mul_overflow((u64)round_up(expected_value_size, 8U),
			       (u64)expected_max_entries, &canonical_bytes))
		return -EOVERFLOW;
	if (le64_to_cpu(resource->logical_bytes) != logical_bytes ||
	    le64_to_cpu(resource->canonical_bytes) != canonical_bytes ||
	    canonical_bytes > le64_to_cpu(policy->max_map_bytes))
		return -E2BIG;
	return 0;
}

static int ebpfos_validate_descriptor(
	const struct ebpfos_component_desc_v1 *descriptor,
	const struct ebpfos_policy_record_v1 *policy,
	const u8 policy_digest[SHA256_DIGEST_SIZE])
{
	u32 flags = le32_to_cpu(descriptor->flags);
	u32 policy_flags = le32_to_cpu(policy->flags);
	u32 use = le32_to_cpu(descriptor->use);
	u32 value_size, max_entries;
	u64 expected_provider_type;
	u64 expected_transition;
	u64 expected_capabilities = EBPFOS_CAP_FILE_ALL;
	const u8 *expected_concrete_schema;
	u64 expected_schema;
	bool test_use;
	int error;

	if (memcmp(descriptor->magic, EBPFOS_COMPONENT_DESC_V1_MAGIC,
		   sizeof(descriptor->magic)) ||
	    le16_to_cpu(descriptor->format_version) !=
		EBPFOS_ADMISSION_FORMAT_VERSION ||
	    le16_to_cpu(descriptor->header_size) != sizeof(*descriptor) ||
	    le32_to_cpu(descriptor->total_size) != sizeof(*descriptor))
		return -EPROTO;
	if (flags & ~EBPFOS_COMPONENT_F_ALL ||
	    !!(flags & EBPFOS_COMPONENT_F_TEST_ONLY) !=
		!!(policy_flags & EBPFOS_POLICY_F_TEST_ONLY) ||
	    le32_to_cpu(descriptor->domain) != EBPFOS_COMPONENT_DOMAIN_FILE ||
	    le32_to_cpu(descriptor->code_format) !=
		EBPFOS_COMPONENT_CODE_BPF_ELF ||
	    le32_to_cpu(descriptor->verifier_profile) !=
		EBPFOS_VERIFIER_PROFILE_FILE_PROVIDER ||
	    le32_to_cpu(descriptor->reserved0))
		return -EACCES;
	error = ebpfos_expected_map_tuple(use, &value_size, &max_entries,
					  &expected_schema);
	if (error)
		return error;
	switch (use) {
	case EBPFOS_COMPONENT_USE_PROD_V1:
		expected_provider_type = 1;
		expected_transition = 1;
		expected_concrete_schema =
			ebpfos_file_v1_concrete_schema_sha256;
		break;
	case EBPFOS_COMPONENT_USE_PROD_V2:
		expected_provider_type = 2;
		expected_transition = 2;
		expected_concrete_schema =
			ebpfos_file_v2_concrete_schema_sha256;
		break;
	case EBPFOS_COMPONENT_USE_RECOVERY_E2:
		expected_provider_type = 2;
		expected_transition = 0x101;
		expected_concrete_schema =
			ebpfos_file_v2_concrete_schema_sha256;
		break;
	case EBPFOS_COMPONENT_USE_RECOVERY_E3_FAULT:
		expected_provider_type = 3;
		expected_transition = 0x102;
		expected_concrete_schema =
			ebpfos_file_v2_concrete_schema_sha256;
		break;
	case EBPFOS_COMPONENT_USE_RECOVERY_E4:
		expected_provider_type = 2;
		expected_transition = 0x103;
		expected_concrete_schema =
			ebpfos_file_v2_concrete_schema_sha256;
		break;
	case EBPFOS_COMPONENT_USE_SPLIT_READER:
		expected_provider_type = 4;
		expected_transition = EBPFOS_COMPONENT_SPLIT_TRANSITION_ID;
		expected_capabilities = EBPFOS_CAP_FILE_READ |
					EBPFOS_CAP_FILE_MIGRATE;
		expected_concrete_schema =
			ebpfos_file_v2_concrete_schema_sha256;
		break;
	case EBPFOS_COMPONENT_USE_SPLIT_WRITER:
		expected_provider_type = 5;
		expected_transition = EBPFOS_COMPONENT_SPLIT_TRANSITION_ID;
		expected_capabilities = EBPFOS_CAP_FILE_APPEND |
					EBPFOS_CAP_FILE_MIGRATE;
		expected_concrete_schema =
			ebpfos_file_v2_concrete_schema_sha256;
		break;
	default:
		return -EPROTOTYPE;
	}
	test_use = use >= EBPFOS_COMPONENT_USE_RECOVERY_E2;
	if (!!(policy_flags & EBPFOS_POLICY_F_TEST_ONLY) != test_use)
		return -EACCES;
	if (memcmp(descriptor->realm_id, policy->realm_id,
		   sizeof(descriptor->realm_id)) ||
	    le64_to_cpu(descriptor->policy_generation) !=
		le64_to_cpu(policy->generation) ||
	    memcmp(descriptor->policy_record_digest, policy_digest,
		   SHA256_DIGEST_SIZE) ||
	    memcmp(descriptor->host_policy_sha256, policy->host_policy_sha256,
		   SHA256_DIGEST_SIZE))
		return -ESTALE;
	if (memcmp(descriptor->component_id, ebpfos_file_component_id,
		   sizeof(descriptor->component_id)) ||
	    le64_to_cpu(descriptor->component_version) != 1 ||
	    le64_to_cpu(descriptor->provider_type_id) !=
		expected_provider_type ||
	    le64_to_cpu(descriptor->transition_id) != expected_transition ||
	    !le64_to_cpu(descriptor->predecessor_policy_generation) ||
	    !ebpfos_nonzero(descriptor->predecessor_policy_digest,
			    SHA256_DIGEST_SIZE) ||
	    !ebpfos_nonzero(descriptor->predecessor_content_digest,
			    SHA256_DIGEST_SIZE))
		return -EINVAL;
	if (memcmp(descriptor->contract_sha256,
		   ebpfos_native_contract_sha256, SHA256_DIGEST_SIZE) ||
	    memcmp(descriptor->interface_sha256,
		   ebpfos_native_interface_sha256, SHA256_DIGEST_SIZE) ||
	    memcmp(descriptor->authority_sha256,
		   ebpfos_native_authority_sha256, SHA256_DIGEST_SIZE) ||
	    memcmp(descriptor->abstract_schema_sha256,
		   ebpfos_native_schema_sha256, SHA256_DIGEST_SIZE) ||
	    memcmp(descriptor->concrete_schema_sha256,
		   expected_concrete_schema, SHA256_DIGEST_SIZE) ||
	    !ebpfos_nonzero(descriptor->attested_elf_sha256,
			    SHA256_DIGEST_SIZE) ||
	    !ebpfos_nonzero(descriptor->load_image_sha256,
			    SHA256_DIGEST_SIZE) ||
	    !ebpfos_nonzero(descriptor->initial_map_sha256,
			    SHA256_DIGEST_SIZE))
		return -EINVAL;
	if (le64_to_cpu(descriptor->abi_id) != EBPFOS_FILE_PROVIDER_ABI_ID ||
	    le32_to_cpu(descriptor->abi_version) !=
		EBPFOS_FILE_PROVIDER_ABI_VERSION ||
	    le32_to_cpu(descriptor->context_size) !=
		EBPFOS_FILE_PROVIDER_CONTEXT_SIZE ||
	    le64_to_cpu(descriptor->runtime_schema_u64) != expected_schema ||
	    le64_to_cpu(descriptor->capability_mask) != expected_capabilities ||
	    le64_to_cpu(descriptor->effect_mask) !=
		EBPFOS_EFFECT_FILE_PROVIDER_ALL ||
	    le32_to_cpu(descriptor->prog_type) != BPF_PROG_TYPE_SYSCALL ||
	    le32_to_cpu(descriptor->semantic_prog_flags) !=
		EBPFOS_FILE_PROVIDER_PROG_FLAGS)
		return -EPROTO;
	if (!le32_to_cpu(descriptor->exact_insn_count) ||
	    le32_to_cpu(descriptor->exact_insn_count) >
		le32_to_cpu(policy->max_static_insns) ||
	    !le32_to_cpu(descriptor->max_verified_insns) ||
	    le32_to_cpu(descriptor->max_verified_insns) >
		le32_to_cpu(policy->max_verified_insns) ||
	    !le32_to_cpu(descriptor->max_stack_depth) ||
	    le32_to_cpu(descriptor->max_stack_depth) >
		le32_to_cpu(policy->max_stack_depth) ||
	    le32_to_cpu(descriptor->max_ctx_offset) !=
		EBPFOS_FILE_PROVIDER_CONTEXT_SIZE ||
	    le32_to_cpu(descriptor->max_tail_calls) ||
	    le32_to_cpu(descriptor->resource_count) !=
		EBPFOS_ADMISSION_MAX_RESOURCES ||
	    le64_to_cpu(descriptor->max_call_bytes) !=
		EBPFOS_FILE_PROVIDER_CALL_BYTES ||
	    le64_to_cpu(descriptor->max_call_bytes) >
		le64_to_cpu(policy->max_call_bytes))
		return -ERANGE;
	if (!ebpfos_all_zero(descriptor->reserved,
			     sizeof(descriptor->reserved)))
		return -EINVAL;
	return ebpfos_validate_resource(&descriptor->resource, use, policy);
}

void ebpfos_admission_gate_lock(void)
{
	mutex_lock(&ebpfos_publish_gate);
}

void ebpfos_admission_gate_unlock(void)
{
	mutex_unlock(&ebpfos_publish_gate);
}

bool ebpfos_policy_enforcing(void)
{
	return READ_ONCE(ebpfos_policy.state) == EBPFOS_POLICY_ACTIVE;
}

bool ebpfos_policy_enforcing_locked(void)
{
	lockdep_assert_held(&ebpfos_publish_gate);
	return ebpfos_policy.state == EBPFOS_POLICY_ACTIVE;
}

int ebpfos_legacy_mutation_check_locked(void)
{
	lockdep_assert_held(&ebpfos_publish_gate);
	if (!ebpfos_trust_ready)
		return -ENOKEY;
	return ebpfos_policy.state == EBPFOS_POLICY_ACTIVE ? -EPERM : 0;
}

int ebpfos_legacy_binding_add_locked(void)
{
	int error;

	lockdep_assert_held(&ebpfos_publish_gate);
	error = ebpfos_legacy_mutation_check_locked();
	if (error)
		return error;
	if (ebpfos_legacy_bindings == U64_MAX)
		return -EOVERFLOW;
	ebpfos_legacy_bindings++;
	return 0;
}

void ebpfos_legacy_binding_del_locked(void)
{
	lockdep_assert_held(&ebpfos_publish_gate);
	if (WARN_ON_ONCE(!ebpfos_legacy_bindings))
		return;
	ebpfos_legacy_bindings--;
}

int __weak ebpfos_file_policy_rotate_locked(void)
{
	lockdep_assert_held(&ebpfos_publish_gate);
	return -EOPNOTSUPP;
}

static bool ebpfos_policy_matches_locked(
	u64 generation, const u8 realm_id[16],
	const u8 digest[SHA256_DIGEST_SIZE])
{
	lockdep_assert_held(&ebpfos_publish_gate);
	return ebpfos_policy.state == EBPFOS_POLICY_ACTIVE &&
	       le64_to_cpu(ebpfos_policy.record.generation) == generation &&
	       !memcmp(ebpfos_policy.record.realm_id, realm_id,
		       sizeof(ebpfos_policy.record.realm_id)) &&
	       !memcmp(ebpfos_policy.digest, digest, SHA256_DIGEST_SIZE);
}

int ebpfos_policy_identity_validate_locked(
	u64 generation, const u8 realm_id[16],
	const u8 policy_digest[SHA256_DIGEST_SIZE],
	const u8 host_policy_digest[SHA256_DIGEST_SIZE], u32 required_flags)
{
	u32 flags;

	lockdep_assert_held(&ebpfos_publish_gate);
	if (!ebpfos_trust_ready)
		return -ENOKEY;
	if (ebpfos_policy.state != EBPFOS_POLICY_ACTIVE)
		return -EACCES;
	if (!ebpfos_policy_matches_locked(generation, realm_id, policy_digest) ||
	    memcmp(ebpfos_policy.record.host_policy_sha256,
		   host_policy_digest, SHA256_DIGEST_SIZE))
		return -ESTALE;
	flags = le32_to_cpu(ebpfos_policy.record.flags);
	if (required_flags & ~EBPFOS_POLICY_F_ALL ||
	    (flags & required_flags) != required_flags)
		return -EACCES;
	return 0;
}

static struct ebpfos_prog_identity *
ebpfos_prog_identity_get(struct ebpfos_prog_identity *identity)
{
	if (identity)
		refcount_inc(&identity->refs);
	return identity;
}

void ebpfos_prog_identity_put(struct ebpfos_prog_identity *identity)
{
	if (identity && refcount_dec_and_test(&identity->refs))
		kfree(identity);
}

struct ebpfos_binding *ebpfos_binding_get(struct ebpfos_binding *binding)
{
	if (binding)
		refcount_inc(&binding->refs);
	return binding;
}

void ebpfos_binding_put(struct ebpfos_binding *binding)
{
	if (!binding || !refcount_dec_and_test(&binding->refs))
		return;
	if (binding->prog)
		bpf_prog_put(binding->prog);
	if (binding->map)
		bpf_map_put(binding->map);
	ebpfos_prog_identity_put(binding->prog_identity);
	kfree(binding);
}

static void ebpfos_admission_release_kref(struct kref *ref)
{
	struct ebpfos_admission *admission =
		container_of(ref, struct ebpfos_admission, ref);

	mutex_lock(&ebpfos_publish_gate);
	ebpfos_admission_burn_locked(admission);
	mutex_unlock(&ebpfos_publish_gate);
	ebpfos_binding_put(admission->binding);
	kfree(admission);
}

void ebpfos_admission_put(struct ebpfos_admission *admission)
{
	if (admission) {
		lockdep_assert_not_held(&ebpfos_publish_gate);
		kref_put(&admission->ref, ebpfos_admission_release_kref);
	}
}

static int ebpfos_admission_release(struct inode *inode, struct file *file)
{
	ebpfos_admission_put(file->private_data);
	return 0;
}

static const struct file_operations ebpfos_admission_fops = {
	.owner = THIS_MODULE,
	.release = ebpfos_admission_release,
	.llseek = noop_llseek,
};

struct ebpfos_admission *ebpfos_admission_get_from_fd(int fd)
{
	struct ebpfos_admission *admission;
	struct file *file;

	file = fget(fd);
	if (!file)
		return ERR_PTR(-EBADF);
	if (file->f_op != &ebpfos_admission_fops) {
		fput(file);
		return ERR_PTR(-EINVAL);
	}
	admission = file->private_data;
	kref_get(&admission->ref);
	fput(file);
	return admission;
}

static struct ebpfos_binding *
ebpfos_binding_alloc_bpf(struct bpf_prog *prog, struct bpf_map *map,
			 struct ebpfos_prog_identity *identity, u64 grant_id)
{
	const struct ebpfos_component_desc_v1 *descriptor =
		&identity->descriptor;
	struct ebpfos_binding *binding;

	binding = kzalloc_obj(*binding, GFP_KERNEL);
	if (!binding)
		return NULL;
	refcount_set(&binding->refs, 1);
	binding->prog = prog;
	binding->map = map;
	binding->prog_identity = ebpfos_prog_identity_get(identity);
	binding->grant_id = grant_id;
	binding->policy_generation =
		le64_to_cpu(descriptor->policy_generation);
	binding->runtime_schema = le64_to_cpu(descriptor->runtime_schema_u64);
	binding->kind = EBPFOS_ADMITTED_BINDING_BPF;
	binding->use = le32_to_cpu(descriptor->use);
	binding->prog_id = prog->aux->id;
	binding->map_id = map->id;
	memcpy(binding->realm_id, descriptor->realm_id,
	       sizeof(binding->realm_id));
	memcpy(binding->policy_digest, descriptor->policy_record_digest,
	       sizeof(binding->policy_digest));
	memcpy(binding->content_digest, identity->content_digest,
	       sizeof(binding->content_digest));
	memcpy(binding->program_digest, identity->program_digest,
	       sizeof(binding->program_digest));
	memcpy(binding->map_digest, identity->map_digest,
	       sizeof(binding->map_digest));
	memcpy(binding->contract_sha256, descriptor->contract_sha256,
	       sizeof(binding->contract_sha256));
	memcpy(binding->abstract_schema_sha256,
	       descriptor->abstract_schema_sha256,
	       sizeof(binding->abstract_schema_sha256));
	memcpy(binding->concrete_schema_sha256,
	       descriptor->concrete_schema_sha256,
	       sizeof(binding->concrete_schema_sha256));
	memcpy(binding->authority_sha256, descriptor->authority_sha256,
	       sizeof(binding->authority_sha256));
	return binding;
}

int ebpfos_native_binding_create_locked(struct ebpfos_binding **result)
{
	struct ebpfos_binding *binding;

	lockdep_assert_held(&ebpfos_publish_gate);
	if (!result)
		return -EINVAL;
	if (ebpfos_policy.state != EBPFOS_POLICY_ACTIVE ||
	    !(le32_to_cpu(ebpfos_policy.record.flags) &
	      EBPFOS_POLICY_F_ALLOW_NATIVE_BOOTSTRAP))
		return -EACCES;
	binding = kzalloc_obj(*binding, GFP_KERNEL);
	if (!binding)
		return -ENOMEM;
	refcount_set(&binding->refs, 1);
	binding->policy_generation =
		le64_to_cpu(ebpfos_policy.record.generation);
	binding->runtime_schema = EBPFOS_FILE_SCHEMA_NATIVE;
	binding->kind = EBPFOS_ADMITTED_BINDING_NATIVE;
	memcpy(binding->realm_id, ebpfos_policy.record.realm_id,
	       sizeof(binding->realm_id));
	memcpy(binding->policy_digest, ebpfos_policy.digest,
	       sizeof(binding->policy_digest));
	memcpy(binding->content_digest,
	       ebpfos_policy.record.native_bootstrap_sha256,
	       sizeof(binding->content_digest));
	memcpy(binding->contract_sha256, ebpfos_native_contract_sha256,
	       sizeof(binding->contract_sha256));
	memcpy(binding->abstract_schema_sha256, ebpfos_native_schema_sha256,
	       sizeof(binding->abstract_schema_sha256));
	memcpy(binding->concrete_schema_sha256, ebpfos_native_schema_sha256,
	       sizeof(binding->concrete_schema_sha256));
	memcpy(binding->authority_sha256, ebpfos_native_authority_sha256,
	       sizeof(binding->authority_sha256));
	*result = binding;
	return 0;
}

int ebpfos_binding_acquire_current_locked(struct ebpfos_binding *binding)
{
	lockdep_assert_held(&ebpfos_publish_gate);
	if (!binding)
		return -EINVAL;
	if (!ebpfos_policy_matches_locked(binding->policy_generation,
					  binding->realm_id,
					  binding->policy_digest))
		return -EAGAIN;
	ebpfos_binding_get(binding);
	return 0;
}

bool ebpfos_binding_content_matches(const struct ebpfos_binding *binding,
				    const u8 digest[SHA256_DIGEST_SIZE])
{
	return binding && digest &&
	       !memcmp(binding->content_digest, digest, SHA256_DIGEST_SIZE);
}

u64 ebpfos_binding_policy_generation(const struct ebpfos_binding *binding)
{
	return binding ? binding->policy_generation : 0;
}

u64 ebpfos_binding_runtime_schema(const struct ebpfos_binding *binding)
{
	return binding ? binding->runtime_schema : 0;
}

u32 ebpfos_binding_use(const struct ebpfos_binding *binding)
{
	return binding ? binding->use : 0;
}

u32 ebpfos_binding_kind(const struct ebpfos_binding *binding)
{
	return binding ? binding->kind : 0;
}

const u8 *ebpfos_binding_content_digest(const struct ebpfos_binding *binding)
{
	return binding ? binding->content_digest : NULL;
}

const struct ebpfos_component_desc_v1 *
ebpfos_binding_descriptor(const struct ebpfos_binding *binding)
{
	return binding && binding->prog_identity ?
	       &binding->prog_identity->descriptor : NULL;
}

struct bpf_prog *ebpfos_binding_prog(const struct ebpfos_binding *binding)
{
	return binding ? binding->prog : NULL;
}

struct bpf_map *ebpfos_binding_map(const struct ebpfos_binding *binding)
{
	return binding ? binding->map : NULL;
}

void ebpfos_binding_fill_identity(
	const struct ebpfos_binding *binding,
	struct ebpfos_admission_identity_v1 *identity)
{
	if (!identity)
		return;
	memset(identity, 0, sizeof(*identity));
	if (!binding)
		return;
	identity->grant_id = binding->grant_id;
	identity->policy_generation = binding->policy_generation;
	identity->binding_kind = binding->kind;
	identity->admission_state =
		binding->kind == EBPFOS_ADMITTED_BINDING_BPF ?
		EBPFOS_ADMISSION_CONSUMED : EBPFOS_ADMISSION_NONE;
	identity->prog_id = binding->prog_id;
	identity->map_id = binding->map_id;
	memcpy(identity->policy_record_digest, binding->policy_digest,
	       sizeof(identity->policy_record_digest));
	memcpy(identity->content_digest, binding->content_digest,
	       sizeof(identity->content_digest));
	memcpy(identity->program_digest, binding->program_digest,
	       sizeof(identity->program_digest));
	memcpy(identity->map_digest, binding->map_digest,
	       sizeof(identity->map_digest));
	memcpy(identity->contract_sha256, binding->contract_sha256,
	       sizeof(identity->contract_sha256));
	memcpy(identity->abstract_schema_sha256,
	       binding->abstract_schema_sha256,
	       sizeof(identity->abstract_schema_sha256));
	memcpy(identity->concrete_schema_sha256,
	       binding->concrete_schema_sha256,
	       sizeof(identity->concrete_schema_sha256));
	memcpy(identity->authority_sha256, binding->authority_sha256,
	       sizeof(identity->authority_sha256));
}

static bool ebpfos_map_owner_matches(struct bpf_prog *prog,
				     struct bpf_map *map)
{
	bool matches;

	spin_lock(&map->owner_lock);
	matches = map->ebpfos_provider_owner == prog->aux &&
		  map->ebpfos_prog_users == 1 &&
		  !map->ebpfos_external_writers &&
		  !map->ebpfos_external_gp_refs &&
		  !map->ebpfos_external_next_refs &&
		  !map->ebpfos_external_gp_queued;
	spin_unlock(&map->owner_lock);
	return matches;
}

static bool ebpfos_map_tuple_matches(
	const struct ebpfos_component_desc_v1 *descriptor,
	const struct bpf_map *map)
{
	const struct ebpfos_resource_desc_v1 *resource = &descriptor->resource;

	return map->map_type == le32_to_cpu(resource->map_type) &&
	       map->key_size == le32_to_cpu(resource->key_size) &&
	       map->value_size == le32_to_cpu(resource->value_size) &&
	       map->max_entries == le32_to_cpu(resource->max_entries) &&
	       map->map_flags == le32_to_cpu(resource->map_flags) &&
	       map->map_extra == le64_to_cpu(resource->map_extra) &&
	       !map->inner_map_meta && !map->btf && !map->btf_key_type_id &&
	       !map->btf_value_type_id && !map->btf_vmlinux_value_type_id &&
	       !map->record && !map->excl && !map->excl_prog_sha &&
	       READ_ONCE(map->frozen);
}

static int ebpfos_measure_map(struct bpf_prog *prog, struct bpf_map *map,
			      const struct ebpfos_component_desc_v1 *descriptor,
			      struct ebpfos_prog_identity *expected_identity,
			      bool calculate_hash,
			      u8 digest[SHA256_DIGEST_SIZE])
{
	bool externally_reachable;
	int error = 0;

	mutex_lock(&prog->aux->used_maps_mutex);
	if (prog->aux->used_map_cnt != 1 ||
	    prog->aux->used_maps[0] != map ||
	    !ebpfos_map_tuple_matches(descriptor, map) ||
	    !ebpfos_map_owner_matches(prog, map)) {
		error = -EXDEV;
		goto out_unlock_maps;
	}
	if (expected_identity &&
	    READ_ONCE(prog->aux->ebpfos_identity) != expected_identity) {
		error = -EKEYREJECTED;
		goto out_unlock_maps;
	}
	mutex_lock(&prog->aux->ext_mutex);
	externally_reachable = prog->aux->is_extended ||
			       prog->aux->prog_array_member_cnt;
	mutex_unlock(&prog->aux->ext_mutex);
	if (externally_reachable) {
		error = -EBUSY;
		goto out_unlock_maps;
	}
	if (calculate_hash) {
		if (!map->ops->map_get_hash) {
			error = -EOPNOTSUPP;
			goto out_unlock_maps;
		}
		error = map->ops->map_get_hash(map, SHA256_DIGEST_SIZE,
					      digest);
		if (error)
			goto out_unlock_maps;
		if (!ebpfos_map_tuple_matches(descriptor, map) ||
		    !ebpfos_map_owner_matches(prog, map))
			error = -EAGAIN;
	}
out_unlock_maps:
	mutex_unlock(&prog->aux->used_maps_mutex);
	return error;
}

static int ebpfos_measure_program(
	struct bpf_prog *prog, struct bpf_map *map,
	const struct ebpfos_component_desc_v1 *descriptor,
	struct ebpfos_prog_identity *expected_identity,
	u8 map_digest[SHA256_DIGEST_SIZE])
{
	if (!prog->aux->ebpfos_provider ||
	    prog->type != BPF_PROG_TYPE_SYSCALL || !prog->sleepable ||
	    prog->aux->ebpfos_load_insn_cnt !=
		le32_to_cpu(descriptor->exact_insn_count) ||
	    prog->aux->verified_insns >
		le32_to_cpu(descriptor->max_verified_insns) ||
	    prog->aux->stack_depth > le32_to_cpu(descriptor->max_stack_depth) ||
	    prog->aux->max_ctx_offset >
		le32_to_cpu(descriptor->max_ctx_offset) ||
	    memcmp(prog->digest, descriptor->load_image_sha256,
		   SHA256_DIGEST_SIZE))
		return -EKEYREJECTED;
	return ebpfos_measure_map(prog, map, descriptor, expected_identity,
				  true, map_digest);
}

long ebpfos_policy_activate_ioctl(void __user *argp)
{
	struct ebpfos_ioc_policy_activate request;
	u8 digest[SHA256_DIGEST_SIZE];
	void *signature;
	u64 generation;
	int error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags || !request.signature || !request.signature_size ||
	    request.signature_size > EBPFOS_ADMISSION_MAX_SIGNATURE)
		return -EINVAL;
	error = ebpfos_validate_policy_record(&request.record);
	if (error)
		return error;
	signature = memdup_user(u64_to_user_ptr(request.signature),
				request.signature_size);
	if (IS_ERR(signature))
		return PTR_ERR(signature);
	error = ebpfos_verify_signature(ebpfos_policy_domain,
					sizeof(ebpfos_policy_domain),
					&request.record,
					sizeof(request.record), signature,
					request.signature_size);
	kfree_sensitive(signature);
	if (error)
		return error;
	ebpfos_policy_digest(&request.record, digest);
	generation = le64_to_cpu(request.record.generation);

	mutex_lock(&ebpfos_publish_gate);
	if (!ebpfos_trust_ready) {
		error = -ENOKEY;
		goto out_unlock;
	}
	if (ebpfos_staged_grants) {
		error = -EBUSY;
		goto out_unlock;
	}
	if (ebpfos_policy.state == EBPFOS_POLICY_INACTIVE) {
		if (ebpfos_legacy_bindings) {
			error = -EBUSY;
			goto out_unlock;
		}
		if (generation != 1 ||
		    !ebpfos_all_zero(request.record.previous_record_digest,
				     SHA256_DIGEST_SIZE)) {
			error = -ESTALE;
			goto out_unlock;
		}
	} else {
		if (memcmp(request.record.realm_id,
			   ebpfos_policy.record.realm_id,
			   sizeof(request.record.realm_id))) {
			error = -EXDEV;
			goto out_unlock;
		}
		if (generation <=
		    le64_to_cpu(ebpfos_policy.record.generation) ||
		    memcmp(request.record.previous_record_digest,
			   ebpfos_policy.digest, SHA256_DIGEST_SIZE)) {
			error = -ESTALE;
			goto out_unlock;
		}
		error = ebpfos_file_policy_rotate_locked();
		if (error)
			goto out_unlock;
	}
	ebpfos_policy.record = request.record;
	memcpy(ebpfos_policy.digest, digest, sizeof(ebpfos_policy.digest));
	WRITE_ONCE(ebpfos_policy.state, EBPFOS_POLICY_ACTIVE);
	error = 0;
out_unlock:
	mutex_unlock(&ebpfos_publish_gate);
	return error;
}

long ebpfos_policy_status_ioctl(void __user *argp)
{
	struct ebpfos_ioc_policy_status status = { 0 };

	mutex_lock(&ebpfos_publish_gate);
	status.state = ebpfos_policy.state;
	if (ebpfos_policy.state == EBPFOS_POLICY_ACTIVE) {
		status.policy_flags = le32_to_cpu(ebpfos_policy.record.flags);
		memcpy(status.realm_id, ebpfos_policy.record.realm_id,
		       sizeof(status.realm_id));
		status.generation =
			le64_to_cpu(ebpfos_policy.record.generation);
		memcpy(status.policy_record_digest, ebpfos_policy.digest,
		       sizeof(status.policy_record_digest));
	}
	memcpy(status.root_fingerprint, ebpfos_root_fingerprint,
	       sizeof(status.root_fingerprint));
	status.staged_grants = ebpfos_staged_grants;
	status.legacy_bindings = ebpfos_legacy_bindings;
	mutex_unlock(&ebpfos_publish_gate);
	return copy_to_user(argp, &status, sizeof(status)) ? -EFAULT : 0;
}

static struct ebpfos_prog_identity *
ebpfos_prog_identity_alloc(
	const struct ebpfos_component_desc_v1 *descriptor,
	const u8 content_digest[SHA256_DIGEST_SIZE],
	const u8 program_digest[SHA256_DIGEST_SIZE],
	const u8 map_digest[SHA256_DIGEST_SIZE])
{
	struct ebpfos_prog_identity *identity;

	identity = kzalloc_obj(*identity, GFP_KERNEL);
	if (!identity)
		return NULL;
	refcount_set(&identity->refs, 1);
	identity->seal_state = EBPFOS_PROG_SEALING;
	identity->descriptor = *descriptor;
	memcpy(identity->content_digest, content_digest,
	       sizeof(identity->content_digest));
	memcpy(identity->program_digest, program_digest,
	       sizeof(identity->program_digest));
	memcpy(identity->map_digest, map_digest,
	       sizeof(identity->map_digest));
	return identity;
}

static struct ebpfos_admission *
ebpfos_admission_alloc(struct ebpfos_binding *binding, u64 grant_id)
{
	struct ebpfos_admission *admission;

	admission = kzalloc_obj(*admission, GFP_KERNEL);
	if (!admission)
		return NULL;
	kref_init(&admission->ref);
	spin_lock_init(&admission->state_lock);
	admission->binding = binding;
	admission->grant_id = grant_id;
	admission->state = EBPFOS_ADMISSION_FRESH;
	return admission;
}

static int ebpfos_grant_id_alloc(u64 *grant_id)
{
	int error = 0;

	spin_lock(&ebpfos_grant_id_lock);
	if (ebpfos_next_grant_id == U64_MAX)
		error = -EOVERFLOW;
	else
		*grant_id = ++ebpfos_next_grant_id;
	spin_unlock(&ebpfos_grant_id_lock);
	return error;
}

static int ebpfos_descriptor_policy_snapshot(
	const struct ebpfos_component_desc_v1 *descriptor,
	struct ebpfos_policy_record_v1 *policy,
	u8 policy_digest[SHA256_DIGEST_SIZE])
{
	int error;

	mutex_lock(&ebpfos_publish_gate);
	if (!ebpfos_trust_ready) {
		error = -ENOKEY;
	} else if (ebpfos_policy.state != EBPFOS_POLICY_ACTIVE) {
		error = -EACCES;
	} else {
		*policy = ebpfos_policy.record;
		memcpy(policy_digest, ebpfos_policy.digest,
		       SHA256_DIGEST_SIZE);
		error = ebpfos_validate_descriptor(descriptor, policy,
						   policy_digest);
	}
	mutex_unlock(&ebpfos_publish_gate);
	return error;
}

long ebpfos_admission_seal_ioctl(void __user *argp)
{
	struct ebpfos_policy_record_v1 policy;
	u8 policy_digest[SHA256_DIGEST_SIZE];
	struct ebpfos_ioc_admission_seal request;
	struct ebpfos_prog_identity *identity = NULL;
	struct ebpfos_admission *admission = NULL;
	struct ebpfos_binding *binding = NULL;
	struct bpf_prog *prog = NULL;
	struct bpf_map *map = NULL;
	struct file *admission_file = NULL;
	u8 content_digest[SHA256_DIGEST_SIZE];
	u8 map_digest[SHA256_DIGEST_SIZE];
	void *signature = NULL;
	u64 grant_id;
	int fd = -1;
	int error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags || !request.signature || !request.signature_size ||
	    request.signature_size > EBPFOS_ADMISSION_MAX_SIGNATURE)
		return -EINVAL;
	error = ebpfos_descriptor_policy_snapshot(&request.descriptor, &policy,
						  policy_digest);
	if (error)
		return error;
	signature = memdup_user(u64_to_user_ptr(request.signature),
				request.signature_size);
	if (IS_ERR(signature))
		return PTR_ERR(signature);
	error = ebpfos_verify_signature(ebpfos_admission_domain,
					sizeof(ebpfos_admission_domain),
					&request.descriptor,
					sizeof(request.descriptor), signature,
					request.signature_size);
	kfree_sensitive(signature);
	if (error)
		return error;

	prog = bpf_prog_get_type_dev(request.prog_fd, BPF_PROG_TYPE_SYSCALL,
				     false);
	if (IS_ERR(prog))
		return PTR_ERR(prog);
	map = bpf_map_get(request.map_fd);
	if (IS_ERR(map)) {
		error = PTR_ERR(map);
		map = NULL;
		goto out_put_prog;
	}
	error = ebpfos_measure_program(prog, map, &request.descriptor, NULL,
				       map_digest);
	if (error)
		goto out_put_map;
	if (memcmp(map_digest, request.descriptor.initial_map_sha256,
		   sizeof(map_digest))) {
		error = -EKEYREJECTED;
		goto out_put_map;
	}
	ebpfos_descriptor_content_digest(&request.descriptor, content_digest);
	error = ebpfos_grant_id_alloc(&grant_id);
	if (error)
		goto out_put_map;
	identity = ebpfos_prog_identity_alloc(&request.descriptor,
					      content_digest, prog->digest,
					      map_digest);
	if (!identity) {
		error = -ENOMEM;
		goto out_put_map;
	}
	binding = ebpfos_binding_alloc_bpf(prog, map, identity, grant_id);
	if (!binding) {
		error = -ENOMEM;
		goto out_put_identity;
	}
	/* Binding ownership now covers the references obtained from both FDs. */
	prog = NULL;
	map = NULL;
	admission = ebpfos_admission_alloc(binding, grant_id);
	if (!admission) {
		error = -ENOMEM;
		goto out_put_binding;
	}
	binding = NULL;
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		error = fd;
		goto out_put_admission;
	}
	admission_file = anon_inode_getfile("[ebpfos-admission]",
					    &ebpfos_admission_fops,
					    admission, O_RDWR);
	if (IS_ERR(admission_file)) {
		error = PTR_ERR(admission_file);
		admission_file = NULL;
		goto out_put_fd;
	}
	request.admission_fd = fd;
	request.admission_state = EBPFOS_ADMISSION_FRESH;
	request.grant_id = grant_id;
	request.prog_id = admission->binding->prog_id;
	request.map_id = admission->binding->map_id;
	memcpy(request.content_digest, content_digest,
	       sizeof(request.content_digest));
	memcpy(request.program_digest, identity->program_digest,
	       sizeof(request.program_digest));
	memcpy(request.map_digest, identity->map_digest,
	       sizeof(request.map_digest));

	mutex_lock(&ebpfos_publish_gate);
	if (!ebpfos_policy_matches_locked(
			admission->binding->policy_generation,
			admission->binding->realm_id,
			admission->binding->policy_digest)) {
		error = -ESTALE;
		goto out_unlock_gate;
	}
	mutex_lock(&ebpfos_seal_lock);
	prog = admission->binding->prog;
	map = admission->binding->map;
	if (READ_ONCE(prog->aux->ebpfos_identity)) {
		error = -EALREADY;
		goto out_unlock_seal;
	}
	error = ebpfos_measure_map(prog, map, &identity->descriptor, NULL,
				   false, NULL);
	if (error)
		goto out_unlock_seal;
	WRITE_ONCE(prog->aux->ebpfos_identity, identity);
	mutex_unlock(&ebpfos_seal_lock);
	mutex_unlock(&ebpfos_publish_gate);

	if (copy_to_user(argp, &request, sizeof(request))) {
		mutex_lock(&ebpfos_seal_lock);
		if (WARN_ON_ONCE(READ_ONCE(prog->aux->ebpfos_identity) !=
				 identity)) {
			mutex_unlock(&ebpfos_seal_lock);
			error = -EUCLEAN;
			goto out_release_file;
		}
		WRITE_ONCE(prog->aux->ebpfos_identity, NULL);
		mutex_unlock(&ebpfos_seal_lock);
		error = -EFAULT;
		goto out_release_file;
	}
	mutex_lock(&ebpfos_seal_lock);
	if (WARN_ON_ONCE(READ_ONCE(prog->aux->ebpfos_identity) != identity)) {
		mutex_unlock(&ebpfos_seal_lock);
		error = -EUCLEAN;
		goto out_release_file;
	}
	WRITE_ONCE(identity->seal_state, EBPFOS_PROG_SEALED);
	mutex_unlock(&ebpfos_seal_lock);
	fd_install(fd, admission_file);
	return 0;

out_unlock_seal:
	mutex_unlock(&ebpfos_seal_lock);
out_unlock_gate:
	mutex_unlock(&ebpfos_publish_gate);
out_release_file:
	prog = NULL;
	map = NULL;
	fput(admission_file);
	admission_file = NULL;
	admission = NULL;
out_put_fd:
	put_unused_fd(fd);
out_put_admission:
	if (admission)
		ebpfos_admission_put(admission);
out_put_binding:
	ebpfos_binding_put(binding);
out_put_identity:
	ebpfos_prog_identity_put(identity);
out_put_map:
	if (map)
		bpf_map_put(map);
out_put_prog:
	if (prog)
		bpf_prog_put(prog);
	return error;
}

static u32 ebpfos_admission_effective_state_locked(
	struct ebpfos_admission *admission)
{
	u32 state;

	lockdep_assert_held(&ebpfos_publish_gate);
	spin_lock(&admission->state_lock);
	state = admission->state;
	spin_unlock(&admission->state_lock);
	if (state == EBPFOS_ADMISSION_FRESH &&
	    !ebpfos_policy_matches_locked(admission->binding->policy_generation,
					  admission->binding->realm_id,
					  admission->binding->policy_digest))
		return EBPFOS_ADMISSION_STALE;
	return state;
}

u32 ebpfos_admission_state_locked(struct ebpfos_admission *admission)
{
	lockdep_assert_held(&ebpfos_publish_gate);
	return admission ? ebpfos_admission_effective_state_locked(admission) :
	       EBPFOS_ADMISSION_NONE;
}

void ebpfos_admission_fill_identity_locked(
	struct ebpfos_admission *admission,
	struct ebpfos_admission_identity_v1 *identity)
{
	lockdep_assert_held(&ebpfos_publish_gate);
	if (!identity)
		return;
	ebpfos_binding_fill_identity(admission ? admission->binding : NULL,
				     identity);
	if (admission)
		identity->admission_state =
			ebpfos_admission_effective_state_locked(admission);
}

struct ebpfos_binding *
ebpfos_admission_binding_get(struct ebpfos_admission *admission)
{
	return admission ? ebpfos_binding_get(admission->binding) : NULL;
}

long ebpfos_admission_info_ioctl(void __user *argp)
{
	struct ebpfos_ioc_admission_info request;
	struct ebpfos_admission *admission;
	struct ebpfos_binding *binding;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags || request.reserved0)
		return -EINVAL;
	admission = ebpfos_admission_get_from_fd(request.admission_fd);
	if (IS_ERR(admission))
		return PTR_ERR(admission);
	binding = admission->binding;
	mutex_lock(&ebpfos_publish_gate);
	request.grant_id = admission->grant_id;
	request.admission_state =
		ebpfos_admission_effective_state_locked(admission);
	request.prog_id = binding->prog_id;
	request.map_id = binding->map_id;
	request.reserved0 = 0;
	memcpy(request.content_digest, binding->content_digest,
	       sizeof(request.content_digest));
	memcpy(request.program_digest, binding->program_digest,
	       sizeof(request.program_digest));
	memcpy(request.map_digest, binding->map_digest,
	       sizeof(request.map_digest));
	request.descriptor = binding->prog_identity->descriptor;
	mutex_unlock(&ebpfos_publish_gate);
	ebpfos_admission_put(admission);
	return copy_to_user(argp, &request, sizeof(request)) ? -EFAULT : 0;
}

static bool ebpfos_admission_current_locked(
	const struct ebpfos_admission *admission)
{
	return ebpfos_policy_matches_locked(admission->binding->policy_generation,
					    admission->binding->realm_id,
					    admission->binding->policy_digest);
}

static bool ebpfos_predecessor_matches(
	const struct ebpfos_admission *admission,
	const struct ebpfos_binding *predecessor)
{
	const struct ebpfos_component_desc_v1 *descriptor;

	if (!predecessor || !admission->binding->prog_identity)
		return false;
	descriptor = &admission->binding->prog_identity->descriptor;
	return le64_to_cpu(descriptor->predecessor_policy_generation) ==
		       predecessor->policy_generation &&
	       !memcmp(descriptor->predecessor_policy_digest,
		       predecessor->policy_digest, SHA256_DIGEST_SIZE) &&
	       !memcmp(descriptor->predecessor_content_digest,
		       predecessor->content_digest, SHA256_DIGEST_SIZE);
}

static int ebpfos_admission_owner_recheck(
	struct ebpfos_admission *admission, bool calculate_hash)
{
	struct ebpfos_binding *binding = admission->binding;
	u8 map_digest[SHA256_DIGEST_SIZE];
	int error;

	if (READ_ONCE(binding->prog_identity->seal_state) !=
	    EBPFOS_PROG_SEALED)
		return -EKEYREJECTED;
	error = ebpfos_measure_map(binding->prog, binding->map,
				   &binding->prog_identity->descriptor,
				   binding->prog_identity, calculate_hash,
				   map_digest);
	if (!error && calculate_hash &&
	    memcmp(map_digest, binding->map_digest, sizeof(map_digest)))
		error = -EKEYREJECTED;
	return error;
}

static void ebpfos_admission_lock_pair(struct ebpfos_admission *first,
				       struct ebpfos_admission *second,
				       struct ebpfos_admission **low,
				       struct ebpfos_admission **high)
{
	if (first->grant_id < second->grant_id) {
		*low = first;
		*high = second;
	} else {
		*low = second;
		*high = first;
	}
	spin_lock(&(*low)->state_lock);
	spin_lock_nested(&(*high)->state_lock, SINGLE_DEPTH_NESTING);
}

static void ebpfos_admission_unlock_pair(struct ebpfos_admission *low,
					 struct ebpfos_admission *high)
{
	spin_unlock(&high->state_lock);
	spin_unlock(&low->state_lock);
}

int ebpfos_admission_claim_locked(struct ebpfos_admission *admission,
				  const struct ebpfos_binding *predecessor,
				  u32 expected_use)
{
	u32 state;
	int error;

	lockdep_assert_held(&ebpfos_publish_gate);
	if (!admission || !predecessor ||
	    admission->binding->use != expected_use)
		return -EPROTOTYPE;
	if (!ebpfos_admission_current_locked(admission))
		return -ESTALE;
	if (!ebpfos_predecessor_matches(admission, predecessor))
		return -EXDEV;
	error = ebpfos_admission_owner_recheck(admission, false);
	if (error)
		return error;
	if (ebpfos_staged_grants == U64_MAX)
		return -EOVERFLOW;
	spin_lock(&admission->state_lock);
	state = admission->state;
	if (state == EBPFOS_ADMISSION_FRESH) {
		admission->state = EBPFOS_ADMISSION_STAGED;
		ebpfos_staged_grants++;
		error = 0;
	} else {
		error = state == EBPFOS_ADMISSION_STAGED ||
			state == EBPFOS_ADMISSION_STAGED_RECOVERY ?
			-EBUSY : -EALREADY;
	}
	spin_unlock(&admission->state_lock);
	return error;
}

static bool ebpfos_sibling_digest_matches(const u8 *reader, const u8 *writer,
					  const u8 *predecessor)
{
	return !memcmp(reader, writer, SHA256_DIGEST_SIZE) &&
	       !memcmp(reader, predecessor, SHA256_DIGEST_SIZE);
}

static bool
ebpfos_sibling_implementation_matches(const struct ebpfos_admission *reader,
				      const struct ebpfos_admission *writer,
				      const struct ebpfos_binding *predecessor)
{
	const struct ebpfos_component_desc_v1 *reader_desc;
	const struct ebpfos_component_desc_v1 *writer_desc;
	const struct ebpfos_component_desc_v1 *predecessor_desc;

	reader_desc = ebpfos_binding_descriptor(reader->binding);
	writer_desc = ebpfos_binding_descriptor(writer->binding);
	predecessor_desc = ebpfos_binding_descriptor(predecessor);
	if (!reader_desc || !writer_desc || !predecessor_desc ||
	    predecessor->kind != EBPFOS_ADMITTED_BINDING_BPF ||
	    predecessor->use != EBPFOS_COMPONENT_USE_RECOVERY_E4 ||
	    le64_to_cpu(reader_desc->transition_id) !=
		    EBPFOS_COMPONENT_SPLIT_TRANSITION_ID ||
	    le64_to_cpu(writer_desc->transition_id) !=
		    EBPFOS_COMPONENT_SPLIT_TRANSITION_ID)
		return false;
	return ebpfos_sibling_digest_matches(reader_desc->contract_sha256,
					     writer_desc->contract_sha256,
					     predecessor_desc->contract_sha256) &&
	       ebpfos_sibling_digest_matches(reader_desc->interface_sha256,
					     writer_desc->interface_sha256,
					     predecessor_desc->interface_sha256) &&
	       ebpfos_sibling_digest_matches(reader_desc->authority_sha256,
					     writer_desc->authority_sha256,
					     predecessor_desc->authority_sha256) &&
	       ebpfos_sibling_digest_matches(reader_desc->abstract_schema_sha256,
					     writer_desc->abstract_schema_sha256,
					     predecessor_desc->abstract_schema_sha256) &&
	       ebpfos_sibling_digest_matches(reader_desc->concrete_schema_sha256,
					     writer_desc->concrete_schema_sha256,
					     predecessor_desc->concrete_schema_sha256) &&
	       ebpfos_sibling_digest_matches(reader_desc->attested_elf_sha256,
					     writer_desc->attested_elf_sha256,
					     predecessor_desc->attested_elf_sha256) &&
	       ebpfos_sibling_digest_matches(reader_desc->load_image_sha256,
					     writer_desc->load_image_sha256,
					     predecessor_desc->load_image_sha256) &&
	       ebpfos_sibling_digest_matches(reader_desc->initial_map_sha256,
					     writer_desc->initial_map_sha256,
					     predecessor_desc->initial_map_sha256) &&
	       !memcmp(&reader_desc->resource, &writer_desc->resource,
		       sizeof(reader_desc->resource)) &&
	       !memcmp(&reader_desc->resource, &predecessor_desc->resource,
		       sizeof(reader_desc->resource));
}

static int
ebpfos_admission_claim_pair_common_locked(struct ebpfos_admission *first,
					  struct ebpfos_admission *second,
					  const struct ebpfos_binding *predecessor,
					  u32 first_use, u32 second_use,
					  bool siblings)
{
	struct ebpfos_admission *low, *high;
	int error;

	lockdep_assert_held(&ebpfos_publish_gate);
	if (!first || !second || first == second ||
	    first->grant_id == second->grant_id ||
	    !predecessor)
		return -EINVAL;
	if (first->binding->use != first_use ||
	    second->binding->use != second_use)
		return -EPROTOTYPE;
	if (!ebpfos_admission_current_locked(first) ||
	    !ebpfos_admission_current_locked(second))
		return -ESTALE;
	if (!ebpfos_predecessor_matches(first, predecessor) ||
	    !ebpfos_predecessor_matches(second,
					 siblings ? predecessor : first->binding))
		return -EXDEV;
	if (siblings &&
	    !ebpfos_sibling_implementation_matches(first, second, predecessor))
		return -EXDEV;
	error = ebpfos_admission_owner_recheck(first, false);
	if (error)
		return error;
	error = ebpfos_admission_owner_recheck(second, false);
	if (error)
		return error;
	if (ebpfos_staged_grants > U64_MAX - 2)
		return -EOVERFLOW;
	ebpfos_admission_lock_pair(first, second, &low, &high);
	if (first->state != EBPFOS_ADMISSION_FRESH ||
	    second->state != EBPFOS_ADMISSION_FRESH) {
		error = first->state == EBPFOS_ADMISSION_STAGED ||
			first->state == EBPFOS_ADMISSION_STAGED_RECOVERY ||
			second->state == EBPFOS_ADMISSION_STAGED ||
			second->state == EBPFOS_ADMISSION_STAGED_RECOVERY ? -EBUSY :
			-EALREADY;
	} else {
		first->state = EBPFOS_ADMISSION_STAGED;
		second->state = EBPFOS_ADMISSION_STAGED;
		ebpfos_staged_grants += 2;
		error = 0;
	}
	ebpfos_admission_unlock_pair(low, high);
	return error;
}

int ebpfos_admission_claim_pair_locked(struct ebpfos_admission *e3,
				       struct ebpfos_admission *e4,
				       const struct ebpfos_binding *predecessor)
{
	return ebpfos_admission_claim_pair_common_locked(e3, e4, predecessor,
		EBPFOS_COMPONENT_USE_RECOVERY_E3_FAULT,
		EBPFOS_COMPONENT_USE_RECOVERY_E4, false);
}

int
ebpfos_admission_claim_sibling_pair_locked(struct ebpfos_admission *reader,
					   struct ebpfos_admission *writer,
					   const struct ebpfos_binding *predecessor)
{
	return ebpfos_admission_claim_pair_common_locked(reader, writer, predecessor,
		EBPFOS_COMPONENT_USE_SPLIT_READER,
		EBPFOS_COMPONENT_USE_SPLIT_WRITER, true);
}

static bool
ebpfos_restore_admission_matches(const struct ebpfos_admission *admission,
				 const struct ebpfos_admission_restore_pair *pair,
				 const u8 expected_content_digest[32])
{
	const struct ebpfos_component_desc_v1 *descriptor;

	if (!admission || !admission->binding ||
	    admission->binding->kind != EBPFOS_ADMITTED_BINDING_BPF ||
	    memcmp(admission->binding->content_digest, expected_content_digest,
		   SHA256_DIGEST_SIZE))
		return false;
	descriptor = ebpfos_binding_descriptor(admission->binding);
	return descriptor &&
	       le64_to_cpu(descriptor->transition_id) ==
		       EBPFOS_COMPONENT_SPLIT_TRANSITION_ID &&
	       le64_to_cpu(descriptor->predecessor_policy_generation) ==
		       pair->predecessor_policy_generation &&
	       !memcmp(descriptor->predecessor_policy_digest,
		       pair->predecessor_policy_digest, SHA256_DIGEST_SIZE) &&
	       !memcmp(descriptor->predecessor_content_digest,
		       pair->predecessor_content_digest, SHA256_DIGEST_SIZE);
}

static int
ebpfos_admission_restore_identity_locked(struct ebpfos_admission_restore_pair *pair)
{
	struct ebpfos_admission *reader;
	struct ebpfos_admission *writer;
	int error;

	lockdep_assert_held(&ebpfos_publish_gate);
	if (!pair || !pair->predecessor_policy_digest ||
	    !pair->predecessor_content_digest || !pair->reader_content_digest ||
	    !pair->writer_content_digest)
		return -EINVAL;
	reader = pair->reader;
	writer = pair->writer;
	if (!reader || !writer || reader == writer ||
	    reader->grant_id == writer->grant_id)
		return -EINVAL;
	if (!reader->binding || !writer->binding)
		return -EUCLEAN;
	if (reader->binding->use != EBPFOS_COMPONENT_USE_SPLIT_READER ||
	    writer->binding->use != EBPFOS_COMPONENT_USE_SPLIT_WRITER)
		return -EPROTOTYPE;
	if (!ebpfos_restore_admission_matches(reader, pair,
					      pair->reader_content_digest) ||
	    !ebpfos_restore_admission_matches(writer, pair,
					      pair->writer_content_digest))
		return -EXDEV;
	if (!ebpfos_admission_current_locked(reader) ||
	    !ebpfos_admission_current_locked(writer))
		return -ESTALE;
	error = ebpfos_admission_owner_recheck(reader, false);
	if (error)
		return error;
	return ebpfos_admission_owner_recheck(writer, false);
}

int
ebpfos_admission_restore_claim_locked(struct ebpfos_admission_restore_pair *pair)
{
	struct ebpfos_admission *reader = pair ? pair->reader : NULL;
	struct ebpfos_admission *writer = pair ? pair->writer : NULL;
	struct ebpfos_admission *low, *high;
	int error;

	error = ebpfos_admission_restore_identity_locked(pair);
	if (error)
		return error;
	if (ebpfos_staged_grants > U64_MAX - 2)
		return -EOVERFLOW;
	ebpfos_admission_lock_pair(reader, writer, &low, &high);
	if (reader->state != EBPFOS_ADMISSION_FRESH ||
	    writer->state != EBPFOS_ADMISSION_FRESH) {
		error = reader->state == EBPFOS_ADMISSION_STAGED ||
			reader->state == EBPFOS_ADMISSION_STAGED_RECOVERY ||
			writer->state == EBPFOS_ADMISSION_STAGED ||
			writer->state == EBPFOS_ADMISSION_STAGED_RECOVERY ?
			-EBUSY : -EALREADY;
	} else {
		reader->state = EBPFOS_ADMISSION_STAGED;
		writer->state = EBPFOS_ADMISSION_STAGED;
		ebpfos_staged_grants += 2;
		error = 0;
	}
	ebpfos_admission_unlock_pair(low, high);
	return error;
}

int
ebpfos_admission_restore_validate_locked(struct ebpfos_admission_restore_pair *pair)
{
	struct ebpfos_admission *reader = pair ? pair->reader : NULL;
	struct ebpfos_admission *writer = pair ? pair->writer : NULL;
	struct ebpfos_admission *low, *high;
	int error;

	error = ebpfos_admission_restore_identity_locked(pair);
	if (error)
		return error;
	ebpfos_admission_lock_pair(reader, writer, &low, &high);
	error = reader->state == EBPFOS_ADMISSION_STAGED &&
		writer->state == EBPFOS_ADMISSION_STAGED ? 0 : -ESTALE;
	ebpfos_admission_unlock_pair(low, high);
	return error;
}

int ebpfos_admission_publish_validate_locked(
	struct ebpfos_admission *admission,
	const struct ebpfos_binding *predecessor, bool recovery)
{
	u32 expected_state = recovery ? EBPFOS_ADMISSION_STAGED_RECOVERY :
					EBPFOS_ADMISSION_STAGED;
	u32 state;

	lockdep_assert_held(&ebpfos_publish_gate);
	if (!admission || !predecessor)
		return -EINVAL;
	spin_lock(&admission->state_lock);
	state = admission->state;
	spin_unlock(&admission->state_lock);
	if (state != expected_state)
		return state == EBPFOS_ADMISSION_CONSUMED ||
		       state == EBPFOS_ADMISSION_BURNED ? -EALREADY : -ESTALE;
	if (!ebpfos_admission_current_locked(admission))
		return -ESTALE;
	if (!ebpfos_predecessor_matches(admission, predecessor))
		return -EXDEV;
	return ebpfos_admission_owner_recheck(admission, false);
}

int ebpfos_admission_consume_locked(struct ebpfos_admission *admission,
				    bool recovery)
{
	u32 expected_state = recovery ? EBPFOS_ADMISSION_STAGED_RECOVERY :
					EBPFOS_ADMISSION_STAGED;
	int error = 0;

	lockdep_assert_held(&ebpfos_publish_gate);
	if (!admission)
		return -EINVAL;
	spin_lock(&admission->state_lock);
	if (admission->state != expected_state) {
		error = -ESTALE;
	} else if (!ebpfos_staged_grants) {
		error = -EUCLEAN;
	} else {
		admission->state = EBPFOS_ADMISSION_CONSUMED;
		ebpfos_staged_grants--;
	}
	spin_unlock(&admission->state_lock);
	return error;
}

int ebpfos_admission_consume_pair_locked(struct ebpfos_admission *first,
					 struct ebpfos_admission *second)
{
	struct ebpfos_admission *low, *high;
	int error = 0;

	lockdep_assert_held(&ebpfos_publish_gate);
	if (!first || !second || first == second ||
	    first->grant_id == second->grant_id)
		return -EINVAL;
	ebpfos_admission_lock_pair(first, second, &low, &high);
	if (first->state != EBPFOS_ADMISSION_STAGED ||
	    second->state != EBPFOS_ADMISSION_STAGED) {
		error = -ESTALE;
	} else if (ebpfos_staged_grants < 2) {
		error = -EUCLEAN;
	} else {
		first->state = EBPFOS_ADMISSION_CONSUMED;
		second->state = EBPFOS_ADMISSION_CONSUMED;
		ebpfos_staged_grants -= 2;
	}
	ebpfos_admission_unlock_pair(low, high);
	return error;
}

int ebpfos_admission_recovery_e3_consume_locked(
	struct ebpfos_admission *e3, struct ebpfos_admission *e4)
{
	struct ebpfos_admission *low, *high;
	int error = 0;

	lockdep_assert_held(&ebpfos_publish_gate);
	if (!e3 || !e4 || e3 == e4)
		return -EINVAL;
	ebpfos_admission_lock_pair(e3, e4, &low, &high);
	if (e3->state != EBPFOS_ADMISSION_STAGED ||
	    e4->state != EBPFOS_ADMISSION_STAGED) {
		error = -ESTALE;
	} else if (ebpfos_staged_grants < 2) {
		error = -EUCLEAN;
	} else {
		e3->state = EBPFOS_ADMISSION_CONSUMED;
		e4->state = EBPFOS_ADMISSION_STAGED_RECOVERY;
		ebpfos_staged_grants--;
	}
	ebpfos_admission_unlock_pair(low, high);
	return error;
}

void ebpfos_admission_burn_locked(struct ebpfos_admission *admission)
{
	lockdep_assert_held(&ebpfos_publish_gate);
	if (!admission)
		return;
	spin_lock(&admission->state_lock);
	if (admission->state == EBPFOS_ADMISSION_STAGED ||
	    admission->state == EBPFOS_ADMISSION_STAGED_RECOVERY) {
		if (!WARN_ON_ONCE(!ebpfos_staged_grants)) {
			admission->state = EBPFOS_ADMISSION_BURNED;
			ebpfos_staged_grants--;
		}
	}
	spin_unlock(&admission->state_lock);
}

void ebpfos_admission_burn_pair_locked(struct ebpfos_admission *first,
				       struct ebpfos_admission *second)
{
	struct ebpfos_admission *low, *high;
	struct ebpfos_admission *items[2];
	unsigned int i;
	u64 staged = 0;

	lockdep_assert_held(&ebpfos_publish_gate);
	if (!first || !second || first == second) {
		ebpfos_admission_burn_locked(first);
		return;
	}
	ebpfos_admission_lock_pair(first, second, &low, &high);
	items[0] = first;
	items[1] = second;
	for (i = 0; i < ARRAY_SIZE(items); i++) {
		if (items[i]->state == EBPFOS_ADMISSION_STAGED ||
		    items[i]->state == EBPFOS_ADMISSION_STAGED_RECOVERY)
			staged++;
	}
	if (WARN_ON_ONCE(ebpfos_staged_grants < staged)) {
		ebpfos_admission_unlock_pair(low, high);
		return;
	}
	for (i = 0; i < ARRAY_SIZE(items); i++) {
		if (items[i]->state != EBPFOS_ADMISSION_STAGED &&
		    items[i]->state != EBPFOS_ADMISSION_STAGED_RECOVERY)
			continue;
		items[i]->state = EBPFOS_ADMISSION_BURNED;
	}
	ebpfos_staged_grants -= staged;
	ebpfos_admission_unlock_pair(low, high);
}

static int ebpfos_der_object_size(const u8 *der, size_t der_size,
				  size_t *object_size)
{
	size_t content_size;
	size_t header_size = 2;
	size_t length_octets;
	size_t i;

	if (der_size < header_size || der[0] != 0x30)
		return -EKEYREJECTED;
	if (!(der[1] & 0x80)) {
		content_size = der[1];
	} else {
		length_octets = der[1] & 0x7f;
		if (!length_octets || length_octets > sizeof(content_size) ||
		    der_size < header_size + length_octets || !der[2])
			return -EKEYREJECTED;
		header_size += length_octets;
		content_size = 0;
		for (i = 0; i < length_octets; i++) {
			if (content_size > (SIZE_MAX >> 8))
				return -EOVERFLOW;
			content_size = (content_size << 8) | der[2 + i];
		}
		if (content_size < 0x80)
			return -EKEYREJECTED;
	}
	if (content_size > der_size - header_size)
		return -EKEYREJECTED;
	if (check_add_overflow(header_size, content_size, object_size))
		return -EOVERFLOW;
	return 0;
}

static int __init ebpfos_admission_init(void)
{
	const u8 *certificate = ebpfos_certificate_list;
	size_t certificate_size =
		ebpfos_certificate_list_end - ebpfos_certificate_list;
	key_perm_t permissions = (KEY_POS_ALL & ~KEY_POS_SETATTR) |
				 KEY_USR_VIEW | KEY_USR_READ | KEY_USR_SEARCH;
	key_ref_t key_ref;
	size_t object_size;
	int error;

	error = ebpfos_der_object_size(certificate, certificate_size,
				       &object_size);
	if (error)
		return error;
	if (object_size != certificate_size)
		return -EKEYREJECTED;

	ebpfos_trusted_keyring =
		keyring_alloc(".ebpfos_trusted_keys", GLOBAL_ROOT_UID,
			      GLOBAL_ROOT_GID, current_cred(), permissions,
			      KEY_ALLOC_NOT_IN_QUOTA, NULL, NULL);
	if (IS_ERR(ebpfos_trusted_keyring)) {
		error = PTR_ERR(ebpfos_trusted_keyring);

		ebpfos_trusted_keyring = NULL;
		return error;
	}
	key_ref = key_create_or_update(make_key_ref(ebpfos_trusted_keyring, true),
				       "asymmetric", NULL, certificate,
				       certificate_size,
				       (KEY_POS_ALL & ~KEY_POS_SETATTR) |
				       KEY_USR_VIEW | KEY_USR_READ,
				       KEY_ALLOC_NOT_IN_QUOTA |
				       KEY_ALLOC_BUILT_IN |
				       KEY_ALLOC_BYPASS_RESTRICTION);
	if (IS_ERR(key_ref)) {
		error = PTR_ERR(key_ref);

		key_put(ebpfos_trusted_keyring);
		ebpfos_trusted_keyring = NULL;
		return error;
	}
	key_ref_put(key_ref);
	sha256(certificate, certificate_size, ebpfos_root_fingerprint);
	WRITE_ONCE(ebpfos_trust_ready, true);
	pr_info("ebpfos: admission trust root ready (one certificate)\n");
	return 0;
}
late_initcall(ebpfos_admission_init);
