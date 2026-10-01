// SPDX-License-Identifier: GPL-2.0-only
#include <crypto/sha2.h>
#include <linux/anon_inodes.h>
#include <linux/bpf.h>
#include <linux/build_bug.h>
#include <linux/capability.h>
#include <linux/ebpfos.h>
#include <linux/file.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/kref.h>
#include <linux/lockdep.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/seqlock.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include "component_graph.h"

#define EBPFOS_COMPONENT_CALL_PROG_FLAGS 0x410U

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
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_policy_activate, reserved, 256);
static_assert(sizeof(struct ebpfos_ioc_policy_status) == 128);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_policy_status, generation, 24);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_policy_status, policy_record_digest, 32);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_policy_status, reserved_root, 64);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_policy_status, staged_grants, 96);
static_assert(sizeof(struct ebpfos_ioc_admission_seal) == 1168);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_seal, reserved1, 16);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_seal, descriptor, 24);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_seal, admission_fd, 1048);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_seal, grant_id, 1056);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_seal, content_digest, 1072);
static_assert(sizeof(struct ebpfos_ioc_admission_info) == 1152);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_info, descriptor, 128);
static_assert(sizeof(struct ebpfos_ioc_admission_runtime_info) == 96);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_runtime_info, map_rehashes, 24);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_runtime_info,
			     invocation_entries, 32);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_runtime_info, content_digest, 40);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_runtime_info, retired_epoch, 72);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_runtime_info,
		     entries_at_publication, 80);
static_assert(sizeof(struct ebpfos_admission_identity_v1) == 288);
EBPFOS_ASSERT_OFFSET(ebpfos_admission_identity_v1,
		     policy_record_digest, 32);
EBPFOS_ASSERT_OFFSET(ebpfos_admission_identity_v1, authority_sha256, 256);
static_assert(BPF_PROG_TYPE_SYSCALL == 31);
static_assert((BPF_F_EBPFOS_COMPONENT | BPF_F_SLEEPABLE) ==
	      EBPFOS_COMPONENT_CALL_PROG_FLAGS);
static_assert(sizeof(struct ebpfos_component_call_frame) ==
	      EBPFOS_COMPONENT_CALL_CONTEXT_SIZE);
static const u8 ebpfos_policy_domain[] = "eBPFOS-policy-v1";
static const u8 ebpfos_content_domain[] = "eBPFOS-content-v1";

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
static u64 ebpfos_staged_grants;
static DEFINE_SPINLOCK(ebpfos_grant_id_lock);
static u64 ebpfos_next_grant_id;
static u64 ebpfos_active_policy_generation;
static seqcount_mutex_t ebpfos_policy_epoch_seq =
	SEQCNT_MUTEX_ZERO(ebpfos_policy_epoch_seq, &ebpfos_publish_gate);

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

static int ebpfos_validate_policy_record(
	const struct ebpfos_policy_record_v1 *record)
{
	u32 flags = le32_to_cpu(record->flags);

	if (memcmp(record->magic, EBPFOS_POLICY_RECORD_V1_MAGIC,
		   sizeof(record->magic)) ||
	    le16_to_cpu(record->format_version) !=
		EBPFOS_ADMISSION_FORMAT_VERSION ||
	    le16_to_cpu(record->header_size) != sizeof(*record) ||
	    le32_to_cpu(record->total_size) != sizeof(*record))
		return -EPROTO;
	if (flags & ~EBPFOS_POLICY_F_ALL)
		return -EACCES;
	if (!le64_to_cpu(record->generation) ||
	    !ebpfos_nonzero(record->realm_id, sizeof(record->realm_id)) ||
	    !ebpfos_nonzero(record->host_policy_sha256,
			    sizeof(record->host_policy_sha256)))
		return -EINVAL;
	if (le32_to_cpu(record->reserved0) ||
	    !ebpfos_all_zero(record->reserved, sizeof(record->reserved)))
		return -EINVAL;
	if (!ebpfos_all_zero(record->native_bootstrap_sha256,
			     sizeof(record->native_bootstrap_sha256)))
		return -EINVAL;
	return 0;
}

static int ebpfos_validate_component_call_descriptor(
	const struct ebpfos_component_desc_v1 *descriptor)
{
	u32 flags = le32_to_cpu(descriptor->flags);
	const struct ebpfos_resource_desc_v1 *resource = &descriptor->resource;
	u32 resource_count = le32_to_cpu(descriptor->resource_count);

	if (flags & ~EBPFOS_COMPONENT_F_ALL ||
	    le32_to_cpu(descriptor->domain) !=
		EBPFOS_COMPONENT_DOMAIN_COMPONENT ||
	    le32_to_cpu(descriptor->use) != EBPFOS_COMPONENT_USE_CALL_PROVIDER ||
	    le32_to_cpu(descriptor->code_format) !=
		EBPFOS_COMPONENT_CODE_BPF_ELF ||
	    le32_to_cpu(descriptor->verifier_profile) !=
		EBPFOS_VERIFIER_PROFILE_COMPONENT_CALL ||
	    le32_to_cpu(descriptor->reserved0))
		return -EACCES;
	if (le64_to_cpu(descriptor->abi_id) != EBPFOS_COMPONENT_CALL_ABI_ID ||
	    le32_to_cpu(descriptor->abi_version) !=
		EBPFOS_COMPONENT_CALL_ABI_VERSION ||
	    le32_to_cpu(descriptor->context_size) !=
		EBPFOS_COMPONENT_CALL_CONTEXT_SIZE ||
	    le32_to_cpu(descriptor->prog_type) != BPF_PROG_TYPE_SYSCALL)
		return -EPROTO;
	if (resource_count > 1)
		return -ERANGE;
	if (!ebpfos_all_zero(descriptor->reserved,
			    sizeof(descriptor->reserved)))
		return -EINVAL;
	if (!resource_count)
		return ebpfos_all_zero(resource, sizeof(*resource)) ? 0 : -EINVAL;

	if ((le32_to_cpu(resource->kind) != EBPFOS_RESOURCE_ARRAY_MAP &&
	     le32_to_cpu(resource->kind) != EBPFOS_RESOURCE_MAP) ||
	    le32_to_cpu(resource->flags) & ~EBPFOS_RESOURCE_F_ALL ||
	    !le32_to_cpu(resource->map_type) ||
	    !le32_to_cpu(resource->max_entries) ||
	    le32_to_cpu(resource->reserved0) ||
	    !ebpfos_all_zero(resource->reserved, sizeof(resource->reserved)))
		return -EINVAL;
	return 0;
}

static int ebpfos_validate_descriptor(
	const struct ebpfos_component_desc_v1 *descriptor)
{
	if (memcmp(descriptor->magic, EBPFOS_COMPONENT_DESC_V1_MAGIC,
		   sizeof(descriptor->magic)) ||
	    le16_to_cpu(descriptor->format_version) !=
		EBPFOS_ADMISSION_FORMAT_VERSION ||
	    le16_to_cpu(descriptor->header_size) != sizeof(*descriptor) ||
	    le32_to_cpu(descriptor->total_size) != sizeof(*descriptor))
		return -EPROTO;

	switch (le32_to_cpu(descriptor->domain)) {
	case EBPFOS_COMPONENT_DOMAIN_COMPONENT:
		return ebpfos_validate_component_call_descriptor(descriptor);
	default:
		return -EACCES;
	}
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
	if (identity && refcount_dec_and_test(&identity->refs)) {
		kfree(identity);
	}
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

#define EBPFOS_BINDING_ACTIVE_BITS 16
#define EBPFOS_BINDING_ACTIVE_MASK ((1ULL << EBPFOS_BINDING_ACTIVE_BITS) - 1)
#define EBPFOS_BINDING_ENTRY_ONE (1ULL << EBPFOS_BINDING_ACTIVE_BITS)
#define EBPFOS_BINDING_ENTRY_BITS 47
#define EBPFOS_BINDING_ENTRY_MASK \
	(((1ULL << EBPFOS_BINDING_ENTRY_BITS) - 1) << \
	 EBPFOS_BINDING_ACTIVE_BITS)
#define EBPFOS_BINDING_RETIRED BIT_ULL(63)

static void ebpfos_binding_decode_invocation_state(u64 state, u32 *active,
						   u64 *entries)
{
	*active = (u32)(state & EBPFOS_BINDING_ACTIVE_MASK);
	*entries = (state & EBPFOS_BINDING_ENTRY_MASK) >>
		EBPFOS_BINDING_ACTIVE_BITS;
}

int ebpfos_binding_invocation_enter(struct ebpfos_binding *binding)
{
	u64 old, new;

	if (!binding)
		return -EINVAL;
	do {
		old = atomic64_read(&binding->invocation_state);
		if (old & EBPFOS_BINDING_RETIRED)
			return -ESHUTDOWN;
		if ((old & EBPFOS_BINDING_ACTIVE_MASK) ==
		    EBPFOS_BINDING_ACTIVE_MASK ||
		    (old & EBPFOS_BINDING_ENTRY_MASK) ==
		    EBPFOS_BINDING_ENTRY_MASK)
			return -EOVERFLOW;
		new = old + EBPFOS_BINDING_ENTRY_ONE + 1;
	} while (atomic64_cmpxchg(&binding->invocation_state, old, new) != old);
	return 0;
}

void ebpfos_binding_invocation_exit(struct ebpfos_binding *binding)
{
	u64 old, new;

	if (!binding)
		return;
	do {
		old = atomic64_read(&binding->invocation_state);
		if (WARN_ON_ONCE(!(old & EBPFOS_BINDING_ACTIVE_MASK)))
			return;
		new = old - 1;
	} while (atomic64_cmpxchg(&binding->invocation_state, old, new) != old);
}

u32 ebpfos_binding_active_invocations(const struct ebpfos_binding *binding)
{
	return binding ? (u32)(atomic64_read(&binding->invocation_state) &
			       EBPFOS_BINDING_ACTIVE_MASK) : 0;
}

u64 ebpfos_binding_invocation_entries(const struct ebpfos_binding *binding)
{
	return binding ? (atomic64_read(&binding->invocation_state) &
		EBPFOS_BINDING_ENTRY_MASK) >> EBPFOS_BINDING_ACTIVE_BITS : 0;
}

bool ebpfos_binding_is_retired(const struct ebpfos_binding *binding)
{
	return binding && (atomic64_read(&binding->invocation_state) &
			   EBPFOS_BINDING_RETIRED);
}

void ebpfos_binding_retire(struct ebpfos_binding *binding, u64 epoch)
{
	u64 old, new;

	if (!binding || !epoch)
		return;
	do {
		old = atomic64_read(&binding->invocation_state);
		if (WARN_ON_ONCE(old & EBPFOS_BINDING_RETIRED))
			return;
		new = old | EBPFOS_BINDING_RETIRED;
	} while (atomic64_cmpxchg(&binding->invocation_state, old, new) != old);
	/* One immutable pre-retirement word backs both decoded UAPI fields. */
	WRITE_ONCE(binding->retirement_snapshot, old);
	smp_store_release(&binding->retired_epoch, epoch);
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
	atomic64_set(&binding->invocation_state, 0);
	atomic64_set(&binding->map_rehashes, 0);
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
	binding->map_id = map ? map->id : 0;
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

	spin_lock_bh(&map->owner_lock);
	matches = map->ebpfos_component_owner == prog->aux &&
		  map->ebpfos_prog_users == 1 &&
		  !map->ebpfos_external_writers &&
		  !map->ebpfos_user_mmaps &&
		  !atomic64_read(&map->writecnt) &&
		  !map->ebpfos_external_gp_refs &&
		  !map->ebpfos_external_next_refs &&
		  !map->ebpfos_external_gp_queued;
	spin_unlock_bh(&map->owner_lock);
	return matches;
}

static bool ebpfos_map_tuple_matches(
	const struct ebpfos_component_desc_v1 *descriptor,
	const struct bpf_map *map)
{
	const struct ebpfos_resource_desc_v1 *resource = &descriptor->resource;

	return map->map_type == le32_to_cpu(resource->map_type) &&
	       /* Nested maps and program arrays need package-wide leases. */
	       !map->inner_map_meta && map->map_type != BPF_MAP_TYPE_PROG_ARRAY &&
	       map->key_size == le32_to_cpu(resource->key_size) &&
	       map->value_size == le32_to_cpu(resource->value_size) &&
	       map->max_entries == le32_to_cpu(resource->max_entries) &&
	       map->map_flags == le32_to_cpu(resource->map_flags) &&
	       map->map_extra == le64_to_cpu(resource->map_extra);
}

static int ebpfos_check_map_lease(struct bpf_prog *prog, struct bpf_map *map,
			      const struct ebpfos_component_desc_v1 *descriptor,
			      struct ebpfos_prog_identity *expected_identity)
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
out_unlock_maps:
	mutex_unlock(&prog->aux->used_maps_mutex);
	return error;
}

static int ebpfos_check_program(
	struct bpf_prog *prog, struct bpf_map *map,
	const struct ebpfos_component_desc_v1 *descriptor,
	struct ebpfos_prog_identity *expected_identity)
{
	bool component = le32_to_cpu(descriptor->domain) ==
			 EBPFOS_COMPONENT_DOMAIN_COMPONENT;
	bool externally_reachable;
	int error = 0;

	if (!component || !prog->aux->ebpfos_component ||
	    prog->type != BPF_PROG_TYPE_SYSCALL || !prog->sleepable)
		return -EKEYREJECTED;
	if (le32_to_cpu(descriptor->resource_count))
		return ebpfos_check_map_lease(prog, map, descriptor,
					      expected_identity);
	if (map)
		return -EXDEV;
	mutex_lock(&prog->aux->used_maps_mutex);
	if (prog->aux->used_map_cnt ||
	    (expected_identity &&
	     READ_ONCE(prog->aux->ebpfos_identity) != expected_identity)) {
		error = expected_identity ? -EKEYREJECTED : -EXDEV;
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
out_unlock_maps:
	mutex_unlock(&prog->aux->used_maps_mutex);
	return error;
}

long ebpfos_policy_activate_ioctl(void __user *argp)
{
	struct ebpfos_ioc_policy_activate request;
	u8 digest[SHA256_DIGEST_SIZE];
	u64 generation;
	int error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags || !ebpfos_all_zero(request.reserved,
					     sizeof(request.reserved)))
		return -EINVAL;
	error = ebpfos_validate_policy_record(&request.record);
	if (error)
		return error;
	ebpfos_policy_digest(&request.record, digest);
	generation = le64_to_cpu(request.record.generation);

	mutex_lock(&ebpfos_publish_gate);
	if (ebpfos_staged_grants) {
		error = -EBUSY;
		goto out_unlock;
	}
	if (ebpfos_policy.state == EBPFOS_POLICY_INACTIVE) {
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
	}
	write_seqcount_begin(&ebpfos_policy_epoch_seq);
	ebpfos_policy.record = request.record;
	memcpy(ebpfos_policy.digest, digest, sizeof(ebpfos_policy.digest));
	WRITE_ONCE(ebpfos_active_policy_generation, generation);
	WRITE_ONCE(ebpfos_policy.state, EBPFOS_POLICY_ACTIVE);
	write_seqcount_end(&ebpfos_policy_epoch_seq);
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
	status.staged_grants = ebpfos_staged_grants;
	status.reserved0 = 0;
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

long ebpfos_admission_seal_ioctl(void __user *argp)
{
	struct ebpfos_ioc_admission_seal request;
	struct ebpfos_prog_identity *identity = NULL;
	struct ebpfos_admission *admission = NULL;
	struct ebpfos_binding *binding = NULL;
	struct bpf_prog *prog = NULL;
	struct bpf_map *map = NULL;
	struct file *admission_file = NULL;
	u8 content_digest[SHA256_DIGEST_SIZE];
	u8 map_digest[SHA256_DIGEST_SIZE] = {};
	u64 grant_id;
	bool mapless;
	int fd = -1;
	int error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags || request.reserved0 || request.reserved1)
		return -EINVAL;
	error = ebpfos_validate_descriptor(&request.descriptor);
	if (error)
		return error;
	prog = bpf_prog_get_type_dev(request.prog_fd, BPF_PROG_TYPE_SYSCALL,
				     false);
	if (IS_ERR(prog))
		return PTR_ERR(prog);
	mapless = !le32_to_cpu(request.descriptor.resource_count);
	if (mapless) {
		if (request.map_fd != -1) {
			error = -EINVAL;
			goto out_put_prog;
		}
	} else {
		map = bpf_map_get(request.map_fd);
		if (IS_ERR(map)) {
			error = PTR_ERR(map);
			map = NULL;
			goto out_put_prog;
		}
	}
	error = ebpfos_check_program(prog, map, &request.descriptor, NULL);
	if (error)
		goto out_put_map;
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
	mutex_lock(&ebpfos_seal_lock);
	prog = admission->binding->prog;
	map = admission->binding->map;
	if (READ_ONCE(prog->aux->ebpfos_identity)) {
		error = -EALREADY;
		goto out_unlock_seal;
	}
	error = ebpfos_check_program(prog, map, &identity->descriptor, NULL);
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

long ebpfos_admission_runtime_info_ioctl(void __user *argp)
{
	struct ebpfos_ioc_admission_runtime_info request;
	struct ebpfos_admission *admission;
	struct ebpfos_binding *binding;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.version != EBPFOS_ADMISSION_RUNTIME_INFO_VERSION ||
	    request.flags || request.prog_id || request.map_id ||
	    request.active_invocations || request.map_rehashes ||
	    request.invocation_entries ||
	    memchr_inv(request.content_digest, 0, sizeof(request.content_digest)) ||
	    request.retired_epoch || request.entries_at_publication ||
	    request.active_at_publication ||
	    request.reserved2)
		return -EINVAL;
	admission = ebpfos_admission_get_from_fd(request.admission_fd);
	if (IS_ERR(admission))
		return PTR_ERR(admission);
	binding = admission->binding;
	request.prog_id = binding->prog_id;
	request.map_id = binding->map_id;
	request.map_rehashes = atomic64_read(&binding->map_rehashes);
	/* Both values are decoded from one atomic snapshot. */
	{
		u64 state = atomic64_read(&binding->invocation_state);

		ebpfos_binding_decode_invocation_state(
			state, &request.active_invocations,
			&request.invocation_entries);
	}
	memcpy(request.content_digest, binding->content_digest,
	       sizeof(request.content_digest));
	request.retired_epoch = smp_load_acquire(&binding->retired_epoch);
	if (request.retired_epoch) {
		u64 snapshot = READ_ONCE(binding->retirement_snapshot);

		request.active_at_publication =
			(u32)(snapshot & EBPFOS_BINDING_ACTIVE_MASK);
		request.entries_at_publication =
			(snapshot & EBPFOS_BINDING_ENTRY_MASK) >>
			EBPFOS_BINDING_ACTIVE_BITS;
	}
	ebpfos_admission_put(admission);
	return copy_to_user(argp, &request, sizeof(request)) ? -EFAULT : 0;
}

static int ebpfos_admission_owner_recheck(struct ebpfos_admission *admission)
{
	struct ebpfos_binding *binding = admission->binding;

	if (READ_ONCE(binding->prog_identity->seal_state) !=
	    EBPFOS_PROG_SEALED)
		return -EKEYREJECTED;
	return ebpfos_check_program(binding->prog, binding->map,
				       &binding->prog_identity->descriptor,
				       binding->prog_identity);
}

int ebpfos_admission_stage_bundle_locked(
	struct ebpfos_admission **grants,
	struct ebpfos_binding *const *predecessors, unsigned int count)
{
	unsigned int index, prior;
	u64 staged_grants;
	int error;

	lockdep_assert_held(&ebpfos_publish_gate);
	if (!grants || !predecessors || !count ||
	    count > EBPFOS_EXECUTOR_ROOT_MAX_ROLES)
		return -EINVAL;
	for (index = 0; index < count; index++) {
		struct ebpfos_admission *grant = grants[index];
		const struct ebpfos_component_desc_v1 *descriptor;
		bool mapless;
		u32 state;

		if (!grant || !grant->grant_id || !grant->binding ||
		    !grant->binding->prog_id)
			return -EINVAL;
		descriptor = ebpfos_binding_descriptor(grant->binding);
		if (!descriptor)
			return -EUCLEAN;
		mapless = !le32_to_cpu(descriptor->resource_count);
		if (mapless != (!grant->binding->map && !grant->binding->map_id))
			return -EUCLEAN;
		for (prior = 0; prior < index; prior++)
			if (grant == grants[prior] ||
			    grant->grant_id == grants[prior]->grant_id ||
			    grant->binding == grants[prior]->binding ||
			    grant->binding->prog_id == grants[prior]->binding->prog_id ||
			    (grant->binding->map_id &&
			     grant->binding->map_id ==
				grants[prior]->binding->map_id))
				return -EUCLEAN;
		spin_lock(&grant->state_lock);
		state = grant->state;
		spin_unlock(&grant->state_lock);
		if (state != EBPFOS_ADMISSION_FRESH)
			return state == EBPFOS_ADMISSION_STAGED ? -EBUSY : -EALREADY;
		/* Recheck the state lease immediately before publication. */
		error = ebpfos_admission_owner_recheck(grant);
		if (error)
			return error;
	}
	if (check_add_overflow(ebpfos_staged_grants, (u64)count,
			       &staged_grants))
		return -EOVERFLOW;
	ebpfos_staged_grants = staged_grants;
	/*
	 * The admission gate excludes every state transition, so after the full
	 * validation pass these individual state locks cannot expose a partial
	 * bundle to another admission operation.
	 */
	for (index = 0; index < count; index++) {
		spin_lock(&grants[index]->state_lock);
		WARN_ON_ONCE(grants[index]->state != EBPFOS_ADMISSION_FRESH);
		grants[index]->state = EBPFOS_ADMISSION_STAGED;
		spin_unlock(&grants[index]->state_lock);
	}
	return 0;
}

int ebpfos_admission_consume_bundle_locked(
	struct ebpfos_admission **grants, unsigned int count)
{
	unsigned int index;
	u32 state;

	lockdep_assert_held(&ebpfos_publish_gate);
	if (!grants || !count || count > EBPFOS_EXECUTOR_ROOT_MAX_ROLES)
		return -EINVAL;
	for (index = 0; index < count; index++) {
		if (!grants[index])
			return -EINVAL;
		spin_lock(&grants[index]->state_lock);
		state = grants[index]->state;
		spin_unlock(&grants[index]->state_lock);
		if (state != EBPFOS_ADMISSION_STAGED)
			return -ESTALE;
	}
	if (ebpfos_staged_grants < count)
		return -EUCLEAN;
	for (index = 0; index < count; index++) {
		spin_lock(&grants[index]->state_lock);
		grants[index]->state = EBPFOS_ADMISSION_CONSUMED;
		spin_unlock(&grants[index]->state_lock);
	}
	ebpfos_staged_grants -= count;
	return 0;
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
	return ebpfos_admission_owner_recheck(admission);
}

static int ebpfos_admission_order_set(struct ebpfos_admission **grants,
				      unsigned int count,
				      struct ebpfos_admission **ordered)
{
	unsigned int index, position;

	if (!grants || !count || count > EBPFOS_COMPONENT_GRAPH_MAX_ROLES)
		return -EINVAL;
	for (index = 0; index < count; index++) {
		if (!grants[index] || !grants[index]->grant_id)
			return -EINVAL;
		for (position = 0; position < index; position++)
			if (grants[index] == grants[position] ||
			    grants[index]->grant_id == grants[position]->grant_id)
				return -EINVAL;
		position = index;
		while (position &&
		       ordered[position - 1]->grant_id > grants[index]->grant_id) {
			ordered[position] = ordered[position - 1];
			position--;
		}
		ordered[position] = grants[index];
	}
	return 0;
}

static void ebpfos_admission_lock_set(struct ebpfos_admission **ordered,
				      unsigned int count)
{
	unsigned int index;

	spin_lock(&ordered[0]->state_lock);
	for (index = 1; index < count; index++)
		spin_lock_nested(&ordered[index]->state_lock, index);
}

static void ebpfos_admission_unlock_set(struct ebpfos_admission **ordered,
					unsigned int count)
{
	while (count)
		spin_unlock(&ordered[--count]->state_lock);
}

int ebpfos_admission_consume_set_locked(struct ebpfos_admission **grants,
					 unsigned int count)
{
	struct ebpfos_admission *ordered[EBPFOS_COMPONENT_GRAPH_MAX_ROLES] = {};
	unsigned int index;
	int error;

	lockdep_assert_held(&ebpfos_publish_gate);
	error = ebpfos_admission_order_set(grants, count, ordered);
	if (error)
		return error;
	ebpfos_admission_lock_set(ordered, count);
	for (index = 0; index < count; index++)
		if (ordered[index]->state != EBPFOS_ADMISSION_STAGED) {
			error = -ESTALE;
			goto out;
		}
	if (ebpfos_staged_grants < count) {
		error = -EUCLEAN;
		goto out;
	}
	for (index = 0; index < count; index++)
		ordered[index]->state = EBPFOS_ADMISSION_CONSUMED;
	ebpfos_staged_grants -= count;
	error = 0;
out:
	ebpfos_admission_unlock_set(ordered, count);
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
		admission->state = EBPFOS_ADMISSION_BURNED;
		if (WARN_ON_ONCE(!ebpfos_staged_grants)) {
			/* Preserve the terminal grant state despite bad accounting. */
		} else {
			ebpfos_staged_grants--;
		}
	}
	spin_unlock(&admission->state_lock);
}

void ebpfos_admission_burn_set_locked(struct ebpfos_admission **grants,
				      unsigned int count)
{
	unsigned int index;

	lockdep_assert_held(&ebpfos_publish_gate);
	if (!grants)
		return;
	/*
	 * Cleanup is deliberately tolerant where consume is atomic and strict:
	 * nulls, duplicate pointers, duplicate IDs, and a partially invalid set
	 * must still drive every reachable staged grant to a terminal state.  A
	 * grant is locked separately, so duplicates never cause recursive locks.
	 */
	for (index = 0; index < count; index++)
		ebpfos_admission_burn_locked(grants[index]);
}
