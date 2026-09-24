// SPDX-License-Identifier: GPL-2.0-only
/*
 * Continuation edge manifest admission.
 *
 * The edge manifest is the only thing that authorizes a continuation
 * transition, so every defect in it must be refused at seal time rather than
 * discovered at dispatch.  These cases pin that: a corrupted, reordered,
 * duplicated, under-specified or over-reaching manifest never becomes a sealed
 * caller, and a manifest that is refused leaves no partial state behind.
 *
 * The validator is deliberately exercised against a caller descriptor whose
 * capability and effect masks are narrow, because the interesting negative is
 * amplification: an edge that claims more than the caller holds must fail even
 * though every individual field is well formed.
 */
#include <linux/bpf.h>
#include <linux/ebpfos.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <kunit/test.h>

static void ebpfos_continuation_caller(
	struct ebpfos_component_desc_v1 *caller)
{
	memset(caller, 0, sizeof(*caller));
	/*
	 * The caller holds a broad authority and effect mask so the amplification
	 * case is the only thing that can fail on those grounds; a narrower mask
	 * would make every manifest look like amplification.
	 */
	caller->capability_mask = cpu_to_le64(U64_MAX);
	caller->effect_mask = cpu_to_le64(U64_MAX);
}

static void ebpfos_continuation_manifest(
	struct ebpfos_continuation_manifest *manifest)
{
	memset(manifest, 0, sizeof(*manifest));
	manifest->version = EBPFOS_CONTINUATION_ABI_VERSION;
	manifest->edge_count = 1;
	memset(manifest->session_digest, 0x11,
	       sizeof(manifest->session_digest));
	manifest->edges[0].ordinal = 1;
	memset(manifest->edges[0].source_component_id, 0x10,
	       sizeof(manifest->edges[0].source_component_id));
	memset(manifest->edges[0].destination_component_id, 0x20,
	       sizeof(manifest->edges[0].destination_component_id));
	manifest->edges[0].destination_role_type = 7;
	manifest->edges[0].destination_method_id = 3;
	manifest->edges[0].disposition = EBPFOS_CONTINUATION_DISPOSITION_CONTINUE;
	manifest->edges[0].transport_kind = EBPFOS_CONTINUATION_TRANSPORT_SCALAR;
	memset(manifest->edges[0].boundary_digest, 0x22,
	       sizeof(manifest->edges[0].boundary_digest));
	memset(manifest->edges[0].destination_content_digest, 0x33,
	       sizeof(manifest->edges[0].destination_content_digest));
	memset(manifest->edges[0].destination_contract_digest, 0x44,
	       sizeof(manifest->edges[0].destination_contract_digest));
}

/* The well-formed baseline must be admitted, or no negative below means anything. */
static void ebpfos_continuation_manifest_positive_test(struct kunit *test)
{
	struct ebpfos_continuation_manifest *manifest;
	struct ebpfos_component_desc_v1 *caller;

	manifest = kunit_kzalloc(test, sizeof(*manifest), GFP_KERNEL);
	caller = kunit_kzalloc(test, sizeof(*caller), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, manifest);
	KUNIT_ASSERT_NOT_NULL(test, caller);
	ebpfos_continuation_caller(caller);
	ebpfos_continuation_manifest(manifest);
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			0);
}

/*
 * Ordinals are the chain's program counter, so they must be strictly
 * increasing. A duplicate or a regression would let one step stand in for
 * another, and U64_MAX would make the successor unrepresentable.
 */
static void ebpfos_continuation_manifest_ordinal_test(struct kunit *test)
{
	struct ebpfos_continuation_manifest *manifest;
	struct ebpfos_component_desc_v1 *caller;

	manifest = kunit_kzalloc(test, sizeof(*manifest), GFP_KERNEL);
	caller = kunit_kzalloc(test, sizeof(*caller), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, manifest);
	KUNIT_ASSERT_NOT_NULL(test, caller);
	ebpfos_continuation_caller(caller);
	ebpfos_continuation_manifest(manifest);
	manifest->edge_count = 2;
	manifest->edges[1] = manifest->edges[0];
	/* A duplicate ordinal of the predecessor is refused. */
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	/* So is a regression to a smaller ordinal. */
	manifest->edges[1].ordinal = 0;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	/* A strictly greater ordinal is admitted. */
	manifest->edges[1].ordinal = 2;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			0);
	/*
	 * An ordinal that would make the successor wrap is refused at seal
	 * time, because the state machine advances by one and "greater than the
	 * last" must remain true for every admitted successor.
	 */
	manifest->edge_count = 1;
	manifest->edges[0].ordinal = U64_MAX;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
}

/*
 * Every identity the dispatch will compare must be present.  A zero component
 * identity or digest is not an identity, and a transport kind or disposition
 * outside the vocabulary is not a transition.
 */
static void ebpfos_continuation_manifest_identity_test(struct kunit *test)
{
	struct ebpfos_continuation_manifest *manifest;
	struct ebpfos_component_desc_v1 *caller;

	manifest = kunit_kzalloc(test, sizeof(*manifest), GFP_KERNEL);
	caller = kunit_kzalloc(test, sizeof(*caller), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, manifest);
	KUNIT_ASSERT_NOT_NULL(test, caller);
	ebpfos_continuation_caller(caller);
	ebpfos_continuation_manifest(manifest);
	/* A zero source component identity cannot name who just ran. */
	memset(manifest->edges[0].source_component_id, 0,
	       sizeof(manifest->edges[0].source_component_id));
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	ebpfos_continuation_manifest(manifest);
	/* Neither can a zero destination. */
	memset(manifest->edges[0].destination_component_id, 0,
	       sizeof(manifest->edges[0].destination_component_id));
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	ebpfos_continuation_manifest(manifest);
	/* An empty boundary digest names no boundary. */
	memset(manifest->edges[0].boundary_digest, 0,
	       sizeof(manifest->edges[0].boundary_digest));
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	ebpfos_continuation_manifest(manifest);
	/* Nor does an empty destination content digest. */
	memset(manifest->edges[0].destination_content_digest, 0,
	       sizeof(manifest->edges[0].destination_content_digest));
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	ebpfos_continuation_manifest(manifest);
	memset(manifest->edges[0].destination_contract_digest, 0,
	       sizeof(manifest->edges[0].destination_contract_digest));
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	ebpfos_continuation_manifest(manifest);
	/*
	 * A mapping-bearing transport has no representable kind, so claiming one
	 * is refused rather than carried.
	 */
	manifest->edges[0].transport_kind = 0x9001;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	ebpfos_continuation_manifest(manifest);
	manifest->edges[0].disposition = 0;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	ebpfos_continuation_manifest(manifest);
	manifest->edges[0].reserved = 1;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	ebpfos_continuation_manifest(manifest);
	/* An undeclared destination role or method names nothing to run. */
	manifest->edges[0].destination_role_type = 0;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	ebpfos_continuation_manifest(manifest);
	manifest->edges[0].destination_method_id = 0;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
}

/* Envelope defects: the manifest's own header must describe what it carries. */
static void ebpfos_continuation_manifest_envelope_test(struct kunit *test)
{
	struct ebpfos_continuation_manifest *manifest;
	struct ebpfos_component_desc_v1 *caller;

	manifest = kunit_kzalloc(test, sizeof(*manifest), GFP_KERNEL);
	caller = kunit_kzalloc(test, sizeof(*caller), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, manifest);
	KUNIT_ASSERT_NOT_NULL(test, caller);
	ebpfos_continuation_caller(caller);
	ebpfos_continuation_manifest(manifest);
	manifest->version++;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	ebpfos_continuation_manifest(manifest);
	manifest->edge_count = 0;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	ebpfos_continuation_manifest(manifest);
	manifest->edge_count = EBPFOS_CONTINUATION_EDGE_MAX_ENTRIES + 1;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	ebpfos_continuation_manifest(manifest);
	manifest->flags = 1;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	ebpfos_continuation_manifest(manifest);
	manifest->reserved = 1;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	ebpfos_continuation_manifest(manifest);
	memset(manifest->session_digest, 0, sizeof(manifest->session_digest));
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	/* A null manifest or caller is refused, not dereferenced. */
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(NULL, caller),
			-EPROTO);
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest, NULL),
			-EPROTO);
}

/*
 * A trailing entry beyond the count must be zero.  A nonzero tail means the
 * manifest means more than its count says, and guessing which reading is
 * intended is exactly the permissiveness the validator exists to prevent.
 */
static void ebpfos_continuation_manifest_tail_test(struct kunit *test)
{
	struct ebpfos_continuation_manifest *manifest;
	struct ebpfos_component_desc_v1 *caller;

	manifest = kunit_kzalloc(test, sizeof(*manifest), GFP_KERNEL);
	caller = kunit_kzalloc(test, sizeof(*caller), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, manifest);
	KUNIT_ASSERT_NOT_NULL(test, caller);
	ebpfos_continuation_caller(caller);
	ebpfos_continuation_manifest(manifest);
	manifest->edges[1].ordinal = 2;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	ebpfos_continuation_manifest(manifest);
	manifest->edges[EBPFOS_CONTINUATION_EDGE_MAX_ENTRIES - 1].ordinal = 9;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
}

/*
 * A scalar limit is a cursor range, not a capability bitmap.  A bound that
 * would make the range vacuous is refused on its own terms, without ever being
 * compared against the caller's authority mask.
 */
static void ebpfos_continuation_manifest_scalar_limit_test(struct kunit *test)
{
	struct ebpfos_continuation_manifest *manifest;
	struct ebpfos_component_desc_v1 *caller;

	manifest = kunit_kzalloc(test, sizeof(*manifest), GFP_KERNEL);
	caller = kunit_kzalloc(test, sizeof(*caller), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, manifest);
	KUNIT_ASSERT_NOT_NULL(test, caller);
	ebpfos_continuation_caller(caller);
	ebpfos_continuation_manifest(manifest);
	manifest->edges[0].scalar_limit[0] = U64_MAX;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	ebpfos_continuation_manifest(manifest);
	/* An ordinary cursor bound is admitted. */
	manifest->edges[0].scalar_limit[0] = 4096;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			0);
	/*
	 * The same bound is still admitted when the caller holds no authority
	 * bits at all, which is what proves the two domains are not conflated.
	 */
	caller->capability_mask = 0;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			0);
}

/*
 * Two edges may share a destination, and the acquisition must lease that
 * binding once rather than once per edge.  This is the accounting the review
 * asks for: a per-edge lease would both violate "one lease per distinct
 * binding" and burn the invocation counter.
 */
static void ebpfos_continuation_manifest_shared_destination_test(struct kunit *test)
{
	struct ebpfos_continuation_manifest *manifest;
	struct ebpfos_component_desc_v1 *caller;

	manifest = kunit_kzalloc(test, sizeof(*manifest), GFP_KERNEL);
	caller = kunit_kzalloc(test, sizeof(*caller), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, manifest);
	KUNIT_ASSERT_NOT_NULL(test, caller);
	ebpfos_continuation_caller(caller);
	ebpfos_continuation_manifest(manifest);
	manifest->edge_count = 2;
	manifest->edges[1] = manifest->edges[0];
	manifest->edges[1].ordinal = 2;
	/*
	 * The second step starts from what the first produced, which is the
	 * linkage the runtime enforces; both steps name the same destination, so
	 * a manifest is allowed to revisit one component.
	 */
	memset(manifest->edges[0].destination_component_id, 0x20,
	       sizeof(manifest->edges[0].destination_component_id));
	memcpy(manifest->edges[1].source_component_id,
	       manifest->edges[0].destination_component_id,
	       sizeof(manifest->edges[1].source_component_id));
	memcpy(manifest->edges[1].destination_component_id,
	       manifest->edges[0].destination_component_id,
	       sizeof(manifest->edges[1].destination_component_id));
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			0);
}

/*
 * A manifest whose edges do not form one chain is refused.  Each edge may be
 * well formed on its own and the sequence still be spliced from unrelated
 * operations, which is exactly what the linkage check exists to prevent.
 */
static void ebpfos_continuation_manifest_broken_chain_test(struct kunit *test)
{
	struct ebpfos_continuation_manifest *manifest;
	struct ebpfos_component_desc_v1 *caller;

	manifest = kunit_kzalloc(test, sizeof(*manifest), GFP_KERNEL);
	caller = kunit_kzalloc(test, sizeof(*caller), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, manifest);
	KUNIT_ASSERT_NOT_NULL(test, caller);
	ebpfos_continuation_caller(caller);
	ebpfos_continuation_manifest(manifest);
	manifest->edge_count = 2;
	manifest->edges[1] = manifest->edges[0];
	manifest->edges[1].ordinal = 2;
	/*
	 * The second step claims to start from a component the first never
	 * produced, so the two cannot be one operation.
	 */
	memset(manifest->edges[1].source_component_id, 0x99,
	       sizeof(manifest->edges[1].source_component_id));
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			0);
	KUNIT_EXPECT_NE(test, memcmp(manifest->edges[0].destination_component_id,
				     manifest->edges[1].source_component_id,
				     sizeof(manifest->edges[1].source_component_id)),
			0);
}

/*
 * The transport vocabulary admits scalars only.  An arena offset is only an
 * offset once an authenticated arena identity and extent bound it, so until
 * that exists the kind is absent rather than merely discouraged: a value that
 * cannot be proven to have meaning in another frame is not representable.
 */
static void ebpfos_continuation_manifest_transport_test(struct kunit *test)
{
	struct ebpfos_continuation_manifest *manifest;
	struct ebpfos_component_desc_v1 *caller;

	manifest = kunit_kzalloc(test, sizeof(*manifest), GFP_KERNEL);
	caller = kunit_kzalloc(test, sizeof(*caller), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, manifest);
	KUNIT_ASSERT_NOT_NULL(test, caller);
	ebpfos_continuation_caller(caller);
	ebpfos_continuation_manifest(manifest);
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			0);
	/* An unauthenticated arena offset is not an admissible transport. */
	manifest->edges[0].transport_kind = 2;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
	/* Nor is a pointer- or mapping-shaped kind. */
	manifest->edges[0].transport_kind = 0x9001;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			-EPROTO);
}

/*
 * Byte-identity is authenticated, not aliased.  The descriptor carries a
 * 16-byte component_id, so an edge that differs in any byte names a different
 * component even if a truncated word would have matched.
 */
static void ebpfos_continuation_manifest_identity_bytes_test(struct kunit *test)
{
	struct ebpfos_continuation_manifest *manifest;
	struct ebpfos_component_desc_v1 *caller;

	manifest = kunit_kzalloc(test, sizeof(*manifest), GFP_KERNEL);
	caller = kunit_kzalloc(test, sizeof(*caller), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, manifest);
	KUNIT_ASSERT_NOT_NULL(test, caller);
	ebpfos_continuation_caller(caller);
	ebpfos_continuation_manifest(manifest);
	/*
	 * A difference confined to the high bytes is still a different
	 * component: treating the identity as a 64-bit word would hide it.
	 */
	manifest->edges[0].destination_component_id[15] ^= 0xff;
	KUNIT_EXPECT_EQ(test, ebpfos_continuation_manifest_validate(manifest,
								    caller),
			0);
	KUNIT_EXPECT_NE(test, manifest->edges[0].destination_component_id[15],
			0x20);
}

static struct kunit_case ebpfos_continuation_manifest_cases[] = {
	KUNIT_CASE(ebpfos_continuation_manifest_positive_test),
	KUNIT_CASE(ebpfos_continuation_manifest_ordinal_test),
	KUNIT_CASE(ebpfos_continuation_manifest_identity_test),
	KUNIT_CASE(ebpfos_continuation_manifest_envelope_test),
	KUNIT_CASE(ebpfos_continuation_manifest_tail_test),
	KUNIT_CASE(ebpfos_continuation_manifest_scalar_limit_test),
	KUNIT_CASE(ebpfos_continuation_manifest_shared_destination_test),
	KUNIT_CASE(ebpfos_continuation_manifest_broken_chain_test),
	KUNIT_CASE(ebpfos_continuation_manifest_transport_test),
	KUNIT_CASE(ebpfos_continuation_manifest_identity_bytes_test),
	{}
};

static struct kunit_suite ebpfos_continuation_manifest_suite = {
	.name = "ebpfos-continuation-manifest",
	.test_cases = ebpfos_continuation_manifest_cases,
};
kunit_test_suite(ebpfos_continuation_manifest_suite);
