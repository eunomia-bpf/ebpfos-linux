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
#define EBPFOS_CAP_KPROG_TERMINAL_ROOT BIT_ULL(4)
#define EBPFOS_CAP_KPROG_BOUNDED_MEMORY BIT_ULL(5)
#define EBPFOS_EFFECT_KPROG_MACHINE_STATE BIT_ULL(6)
#define EBPFOS_EFFECT_KPROG_TERMINAL_WAIT BIT_ULL(7)
#define EBPFOS_EFFECT_KPROG_MEMORY_WRITE BIT_ULL(8)
#define EBPFOS_CAP_KPROG_COMPILER_BARRIER BIT_ULL(9)
#define EBPFOS_EFFECT_KPROG_COMPILER_ORDERING BIT_ULL(10)

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
/*
 * The call drives a private continuation session instead of one provider.  The
 * flag selects the session path, so a caller that does not set it keeps exactly
 * the single-provider behaviour it had before.
 */
#define EBPFOS_EXECUTOR_CALL_F_CONTINUATION BIT(1)

/*
 * Continuation sessions.
 *
 * One logical OS operation may span several independently verified component
 * programs, each published as its own role.  A source loop whose trip count
 * exceeds the verifier's unroll budget cannot be one program, so it becomes a
 * sequence of transitions through a private continuation session.
 *
 * The session is kernel-private for one top-level dispatcher call.  It is
 * deliberately not a userspace- or BPF-visible registry: a handle a caller could
 * retain and replay would be forgeable authority, not a sealed token.  What
 * crosses a program boundary is only an authenticated relation -- an ordinal, a
 * boundary identity, a source and destination identity, and bounded scalars.
 *
 * P2 carries no live mapping.  kmap_local_page() establishes task/CPU-local
 * mapping state with nesting and lifetime constraints, so a mapping cannot be
 * retained across a return from one independently invoked provider and resumed
 * in another; hiding its address behind a token would not make that lifetime
 * valid.  A later extraction must cut only at a mapping-free boundary, or keep
 * acquire/use/kunmap inside one synchronous provider.
 */
/*
 * The caller's metadata map carries two frozen records: the import manifest at
 * key 0 and, for a caller that takes authenticated continuation transitions,
 * the continuation edge manifest at key 1.  The keys are ABI, so the parent
 * serializer and the kernel cannot disagree about where an edge list lives.  A
 * map with only the import entry is valid: it declares no continuation edges,
 * and a call that claims one against that absence is refused.
 */
#define EBPFOS_EXECUTOR_METADATA_KEY_IMPORT 0U
#define EBPFOS_EXECUTOR_METADATA_KEY_CONTINUATION 1U

#define EBPFOS_CONTINUATION_ABI_VERSION 1U

/*
 * Generic dispositions.  A disposition says only how the operation continues,
 * never what the operation is about: a page step, an argument step and a
 * finalization step are all CONTINUE until they are COMPLETE.  Workload- or
 * subsystem-specific vocabulary belongs in authenticated component data, not in
 * the kernel ABI, so no component may be recognized by its disposition.
 */
#define EBPFOS_CONTINUATION_DISPOSITION_CONTINUE 1U
#define EBPFOS_CONTINUATION_DISPOSITION_COMPLETE 2U
#define EBPFOS_CONTINUATION_DISPOSITION_ERROR 3U

/*
 * Transport kinds.  Only values with an authenticated meaning in another
 * program's frame are admitted.  Live pointers and local mappings are absent.
 * An arena range is not a pointer: both endpoint programs must reference
 * exactly one identical loaded arena map covering the declared extent, and
 * every returned offset and length is checked before the next program enters.
 * Kernel-object pointers still require stable object handles and are not
 * representable by the arena kind.
 */
#define EBPFOS_CONTINUATION_TRANSPORT_SCALAR 1U
#define EBPFOS_CONTINUATION_TRANSPORT_ARENA_RANGE 2U

#define EBPFOS_CONTINUATION_EDGE_MAX_ENTRIES 64U
#define EBPFOS_CONTINUATION_SCALAR_SLOTS 4U

/*
 * One authenticated continuation edge.
 *
 * `source_component_id` is the identity that must have just executed and
 * `destination_component_id` the identity the step must resolve to; both are
 * compared against the pinned provider's own authenticated identity at
 * resolution time.  `boundary_digest` is the continuation boundary the whole
 * chain belongs to, so a caller cannot mix edges from two boundaries.
 *
 * `scalar_limit` bounds the cursor values a step may report.  It is a *range*,
 * not a capability bitmap: range validation and authority validation are
 * separate domains and are never compared against each other.
 * For ARENA_RANGE, scalar_limit[0] is the admitted extent in bytes, and
 * scalar_limit[1] is the maximum range
 * length, and response scalar[0:1] carry offset and length.  Slots 2 and 3
 * remain ordinary bounded scalars.
 */
struct ebpfos_continuation_edge {
	u64 ordinal;
	/*
	 * Full component identities, not a truncated word.  The descriptor
	 * carries component_id as 16 bytes, and a 64-bit alias of it would name
	 * a different identity than the one the kernel authenticates, so the
	 * edge stores what the descriptor stores.
	 */
	u8 source_component_id[16];
	u8 destination_component_id[16];
	u64 destination_role_type;
	u32 destination_method_id;
	u32 disposition;
	u32 transport_kind;
	/* Reserved; zero for every transport kind. */
	u32 reserved;
	/*
	 * Upper bounds on the scalars a step may report.  Zero means the slot is
	 * unused and its returned value must be zero; a nonzero limit bounds the
	 * value inclusively.
	 */
	u64 scalar_limit[EBPFOS_CONTINUATION_SCALAR_SLOTS];
	u8 boundary_digest[32];
	u8 destination_content_digest[32];
	u8 destination_contract_digest[32];
};

struct ebpfos_continuation_manifest {
	u32 version;
	u32 edge_count;
	u32 flags;
	u32 reserved;
	u8 session_digest[32];
	struct ebpfos_continuation_edge
		edges[EBPFOS_CONTINUATION_EDGE_MAX_ENTRIES];
};

/*
 * What the caller asks for: the identity the chain starts from, the boundary it
 * belongs to, and the disposition it wants the entry step to attempt.  This is
 * untrusted input and is range-checked before it selects anything.
 */
struct ebpfos_continuation_request {
	u8 component_id[16];
	u32 requested_disposition;
	u32 reserved;
	u8 boundary_digest[32];
};

/*
 * The record the kernel writes before each step and reads back after it.  The
 * ordinal, generation, disposition and transport kind are *distinct* fields:
 * an epoch is not a component identity, a generation is not an ordinal, and
 * reusing one for another is how a caller would smuggle a value across
 * meanings.  The scalars are the bounded cursor values the step reports.
 */
/*
 * The transition record, which is both the request the kernel writes and the
 * response the provider writes back.
 *
 * The kernel clears it, fills the request fields, and requires on read-back that
 * the provider set `magic` and `response_size` itself.  Without an explicit
 * marker a provider that wrote nothing would leave the kernel's own prewritten
 * record in place, and a no-op would be indistinguishable from a completed
 * step: silence must be a protocol failure, not a silent success.
 *
 * `ordinal` and `generation` are echoed so the response is bound to the exact
 * step it answers -- a stale or duplicated response names a step that is not
 * the one running.
 */
struct ebpfos_continuation_transition {
	u64 magic;
	u64 ordinal;
	u64 generation;
	u64 scalar[EBPFOS_CONTINUATION_SCALAR_SLOTS];
	u32 disposition;
	u32 transport_kind;
	u32 response_size;
	s32 result;
	u32 reserved;
	u32 reserved2;
};

#define EBPFOS_CONTINUATION_RESPONSE_MAGIC 0x454250434f4e5452ULL
#define EBPFOS_CONTINUATION_RESPONSE_SIZE 	((u32)sizeof(struct ebpfos_continuation_transition))

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
/*
 * Validate one continuation edge manifest against the caller it describes.
 * Exposed so the KUnit suite can exercise manifest corruption directly; the
 * sealer is its only production caller.
 */
int ebpfos_continuation_manifest_validate(
	const struct ebpfos_continuation_manifest *manifest,
	const struct ebpfos_component_desc_v1 *caller);
int ebpfos_admission_continuation_count(struct bpf_prog_aux *aux, u32 *count);
int ebpfos_admission_continuation_edge(struct bpf_prog_aux *aux, u32 index,
				       struct ebpfos_continuation_edge *edge);
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

struct exception_table_entry;

/* The registry of placed native code regions and their fault fixups.
 *
 * It is configured on its own, without the placement mechanism, because a
 * successor image needs the lookup and nothing else: it has to resolve faults
 * in code it did not place and has no BPF, no kallsyms and no component
 * runtime to do it with.
 */
#ifdef CONFIG_EBPFOS_JIT_FAULT_REGIONS
/* A placed region, resolvable both before and after a handoff.
 *
 * A donor adds records at run time; an image builder publishes them
 * statically by filling one of ebpfos_jit_static_fault_regions and linking
 * ebpfos_jit_fault_regions to it, because after handoff nothing is running
 * that would add them.  The layout is read from DWARF rather than restated.
 */
struct ebpfos_jit_fault_region {
	struct list_head node;
	unsigned long start;
	unsigned long end;
	const struct exception_table_entry *extable;
	size_t num_exentries;
	struct rcu_head rcu;
};

#define EBPFOS_JIT_STATIC_FAULT_REGIONS 8U
extern struct list_head ebpfos_jit_fault_regions;
extern struct ebpfos_jit_fault_region
	ebpfos_jit_static_fault_regions[EBPFOS_JIT_STATIC_FAULT_REGIONS];

/* Consulted by search_exception_tables() after the kernel, module and BPF
 * tables.  Unlike search_bpf_extables() this needs neither CONFIG_BPF_JIT nor
 * kallsyms, so a placed region resolves its faults on both sides of a handoff.
 */
const struct exception_table_entry *ebpfos_jit_search_extables(unsigned long addr);

int ebpfos_jit_record_fault_region(void *image, u32 image_len,
				   const struct exception_table_entry *extable,
				   u32 num_exentries);
void ebpfos_jit_forget_fault_region(void *image);
#else
static inline const struct exception_table_entry *
ebpfos_jit_search_extables(unsigned long addr)
{
	return NULL;
}
#endif

#ifdef CONFIG_EBPFOS_JIT_PLACE
long ebpfos_jit_place_ioctl(void __user *argp);

/* Install a region of placed native code into the fault path Linux already
 * has: fixup_exception() -> search_exception_tables() -> search_bpf_extables()
 * finds the owning program with bpf_prog_ksym_find() and searches its
 * aux->extable.  The region becomes fault-handling because a kallsyms-visible
 * program covers it and carries its exception entries, not because anything
 * was appended to it.  It is recorded in the registry above as well, which is
 * the arm that keeps answering after a handoff.  Retire the returned owner
 * once nobody can still be inside the region.
 */
struct bpf_prog *ebpfos_jit_install_fault_region(
	u32 prog_type, void *image, u32 image_len,
	struct exception_table_entry *extable, u32 num_exentries);
void ebpfos_jit_remove_fault_region(struct bpf_prog *owner);
#endif

#endif /* _LINUX_EBPFOS_H */
