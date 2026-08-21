// SPDX-License-Identifier: GPL-2.0-only
/* Generic generated KOperation verifier-to-native execution cell. */
#include <crypto/sha2.h>
#include <linux/atomic.h>
#include <linux/bpf.h>
#include <linux/ebpfos.h>
#include <linux/err.h>
#include <linux/filter.h>
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include <asm/page.h>
#include <asm/processor-flags.h>

struct ebpfos_koperation_descriptor {
	u32 operation_id;
	const struct bpf_insn *proof_insns;
	u32 proof_insn_count;
	u32 proof_imm64_insn;
	u32 shadow_source;
	u64 (*native_emit)(void);
	u32 native_body_size;
	u8 semantic_sha256[SHA256_DIGEST_SIZE];
	u8 proof_template_sha256[SHA256_DIGEST_SIZE];
	u8 native_sha256[SHA256_DIGEST_SIZE];
	u8 equivalence_sha256[SHA256_DIGEST_SIZE];
};

#define EBPFOS_KOPERATION_SHADOW_CURRENT_MM_PGD 1U

#include "koperation-generated.h"

struct ebpfos_koperation_txn {
	const struct ebpfos_koperation_descriptor *descriptor;
	u64 transaction_id;
	u64 staged_shadow;
	u64 native_result;
	u32 status;
	int error;
	u8 proof_program_sha256[SHA256_DIGEST_SIZE];
};

static atomic64_t ebpfos_koperation_next_transaction = ATOMIC64_INIT(0);
static atomic64_t ebpfos_koperation_attempts = ATOMIC64_INIT(0);
static atomic64_t ebpfos_koperation_commits = ATOMIC64_INIT(0);
static atomic64_t ebpfos_koperation_rejects = ATOMIC64_INIT(0);

static const struct ebpfos_koperation_descriptor *
ebpfos_koperation_find(u32 operation_id)
{
	unsigned int index;

	for (index = 0; index < ARRAY_SIZE(ebpfos_koperation_descriptors);
	     index++) {
		if (ebpfos_koperation_descriptors[index].operation_id ==
		    operation_id)
			return &ebpfos_koperation_descriptors[index];
	}
	return NULL;
}

static int
ebpfos_koperation_shadow(const struct ebpfos_koperation_descriptor *descriptor,
			 u64 *shadow)
{
	/*
	 * This is donor-observed input state, not the operation implementation.
	 * The generated native sequence independently reads hardware CR3.
	 */
	if (descriptor->shadow_source !=
	    EBPFOS_KOPERATION_SHADOW_CURRENT_MM_PGD || !current->mm)
		return -EOPNOTSUPP;
	*shadow = __pa(current->mm->pgd) & CR3_ADDR_MASK;
	return 0;
}

static void ebpfos_koperation_counters(u64 *attempts, u64 *commits,
				       u64 *rejects)
{
	*attempts = atomic64_read(&ebpfos_koperation_attempts);
	*commits = atomic64_read(&ebpfos_koperation_commits);
	*rejects = atomic64_read(&ebpfos_koperation_rejects);
}

static void ebpfos_koperation_burn(struct ebpfos_koperation_txn *txn,
				   int error)
{
	txn->status = EBPFOS_KOPERATION_STATUS_BURNED;
	txn->error = error;
	atomic64_inc(&ebpfos_koperation_rejects);
}

static bool ebpfos_koperation_native_matches(
	const struct ebpfos_koperation_descriptor *descriptor)
{
	u8 actual[SHA256_DIGEST_SIZE];
	const u8 *start = (const u8 *)descriptor->native_emit;
	size_t size;

	size = descriptor->native_body_size;
	if (!size || size > 64)
		return false;
	sha256(start, size, actual);
	return !memcmp(actual, descriptor->native_sha256, sizeof(actual));
}

static bool ebpfos_koperation_proof_template_matches(
	const struct ebpfos_koperation_descriptor *descriptor)
{
	u8 actual[SHA256_DIGEST_SIZE];
	size_t size;

	if (!descriptor->proof_insn_count)
		return false;
	size = array_size(descriptor->proof_insn_count,
			  sizeof(struct bpf_insn));
	sha256((const u8 *)descriptor->proof_insns, size, actual);
	return !memcmp(actual, descriptor->proof_template_sha256,
		       sizeof(actual));
}

static int ebpfos_koperation_proof_matches(
	const struct ebpfos_koperation_descriptor *descriptor,
	const struct bpf_prog *prog, u64 staged_shadow,
	u8 program_sha256[SHA256_DIGEST_SIZE])
{
	struct bpf_insn *expected;
	u32 immediate;
	size_t size;
	int error = -EPROTO;

	if (prog->len != descriptor->proof_insn_count ||
	    descriptor->proof_imm64_insn + 1 >= descriptor->proof_insn_count)
		return -EPROTO;
	size = array_size(descriptor->proof_insn_count,
			  sizeof(struct bpf_insn));
	expected = kmemdup(descriptor->proof_insns, size, GFP_KERNEL);
	if (!expected)
		return -ENOMEM;
	immediate = descriptor->proof_imm64_insn;
	expected[immediate].imm = lower_32_bits(staged_shadow);
	expected[immediate + 1].imm = upper_32_bits(staged_shadow);
	if (!memcmp(expected, prog->insnsi, size)) {
		sha256((const u8 *)prog->insnsi, size, program_sha256);
		error = 0;
	}
	kfree(expected);
	return error;
}

long ebpfos_koperation_prepare_ioctl(void __user *argp, void **txn_slot)
{
	struct ebpfos_koperation_prepare request;
	const struct ebpfos_koperation_descriptor *descriptor;
	struct ebpfos_koperation_txn *old = *txn_slot;
	struct ebpfos_koperation_txn *txn;
	int error;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.version != EBPFOS_KOPERATION_ABI_VERSION || request.flags ||
	    request.reserved0)
		return -EINVAL;
	if (old && old->status == EBPFOS_KOPERATION_STATUS_STAGED)
		return -EBUSY;
	descriptor = ebpfos_koperation_find(request.operation_id);
	if (!descriptor)
		return -EOPNOTSUPP;
	txn = kzalloc_obj(*txn, GFP_KERNEL);
	if (!txn)
		return -ENOMEM;
	txn->descriptor = descriptor;
	txn->transaction_id =
		atomic64_inc_return(&ebpfos_koperation_next_transaction);
	error = ebpfos_koperation_shadow(descriptor, &txn->staged_shadow);
	if (error) {
		kfree(txn);
		return error;
	}
	txn->status = EBPFOS_KOPERATION_STATUS_STAGED;

	request.transaction_id = txn->transaction_id;
	request.staged_shadow = txn->staged_shadow;
	memcpy(request.semantic_sha256, descriptor->semantic_sha256,
	       sizeof(request.semantic_sha256));
	memcpy(request.proof_template_sha256,
	       descriptor->proof_template_sha256,
	       sizeof(request.proof_template_sha256));
	memcpy(request.native_sha256, descriptor->native_sha256,
	       sizeof(request.native_sha256));
	memcpy(request.equivalence_sha256, descriptor->equivalence_sha256,
	       sizeof(request.equivalence_sha256));
	ebpfos_koperation_counters(&request.attempts,
				     &request.commits, &request.rejects);
	/* A failed reply cannot leave a hidden staged operation. */
	if (copy_to_user(argp, &request, sizeof(request))) {
		kfree(txn);
		return -EFAULT;
	}
	kfree(old);
	*txn_slot = txn;
	return 0;
}

long ebpfos_koperation_execute_ioctl(void __user *argp, void **txn_slot)
{
	struct ebpfos_koperation_execute request;
	struct ebpfos_koperation_txn *txn = *txn_slot;
	struct bpf_prog *prog;
	u64 trusted_shadow;
	u64 native_result;
	int error;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (!txn || txn->status != EBPFOS_KOPERATION_STATUS_STAGED)
		return -EINVAL;
	if (request.version != EBPFOS_KOPERATION_ABI_VERSION || request.flags) {
		ebpfos_koperation_burn(txn, -EINVAL);
		return -EINVAL;
	}
	if (request.operation_id != txn->descriptor->operation_id ||
	    request.transaction_id != txn->transaction_id ||
	    request.expected_shadow != txn->staged_shadow) {
		ebpfos_koperation_burn(txn, -ESTALE);
		return -ESTALE;
	}
	error = ebpfos_koperation_shadow(txn->descriptor, &trusted_shadow);
	if (error || trusted_shadow != txn->staged_shadow) {
		error = error ?: -ESTALE;
		ebpfos_koperation_burn(txn, error);
		return error;
	}
	if (!ebpfos_koperation_proof_template_matches(txn->descriptor)) {
		ebpfos_koperation_burn(txn, -EKEYREJECTED);
		return -EKEYREJECTED;
	}
	prog = bpf_prog_get_type_dev(request.proof_prog_fd,
				     BPF_PROG_TYPE_SOCKET_FILTER, false);
	if (IS_ERR(prog)) {
		error = PTR_ERR(prog);
		ebpfos_koperation_burn(txn, error);
		return error;
	}
	error = ebpfos_koperation_proof_matches(txn->descriptor, prog,
						txn->staged_shadow,
						txn->proof_program_sha256);
	bpf_prog_put(prog);
	if (error) {
		ebpfos_koperation_burn(txn, error);
		return error;
	}
	if (!ebpfos_koperation_native_matches(txn->descriptor)) {
		ebpfos_koperation_burn(txn, -EKEYREJECTED);
		return -EKEYREJECTED;
	}

	/*
	 * Unique execution point: the exact verifier-admitted expansion and the
	 * generated text hash have passed.  No fallible user copy follows it.
	 */
	atomic64_inc(&ebpfos_koperation_attempts);
	native_result = txn->descriptor->native_emit();
	txn->native_result = native_result;
	if (native_result != txn->staged_shadow) {
		ebpfos_koperation_burn(txn, -EREMOTEIO);
		return -EREMOTEIO;
	}
	txn->status = EBPFOS_KOPERATION_STATUS_COMPLETE;
	txn->error = 0;
	atomic64_inc(&ebpfos_koperation_commits);
	return 0;
}

long ebpfos_koperation_result_ioctl(void __user *argp, void **txn_slot)
{
	struct ebpfos_koperation_txn *txn = *txn_slot;
	struct ebpfos_koperation_result result = { 0 };

	if (!txn)
		return -ENOENT;
	result.version = EBPFOS_KOPERATION_ABI_VERSION;
	result.operation_id = txn->descriptor->operation_id;
	result.status = txn->status;
	result.error = txn->error;
	result.transaction_id = txn->transaction_id;
	result.staged_shadow = txn->staged_shadow;
	result.native_result = txn->native_result;
	memcpy(result.semantic_sha256, txn->descriptor->semantic_sha256,
	       sizeof(result.semantic_sha256));
	memcpy(result.proof_program_sha256, txn->proof_program_sha256,
	       sizeof(result.proof_program_sha256));
	memcpy(result.native_sha256, txn->descriptor->native_sha256,
	       sizeof(result.native_sha256));
	memcpy(result.equivalence_sha256,
	       txn->descriptor->equivalence_sha256,
	       sizeof(result.equivalence_sha256));
	ebpfos_koperation_counters(&result.attempts,
				     &result.commits, &result.rejects);
	return copy_to_user(argp, &result, sizeof(result)) ? -EFAULT : 0;
}

void ebpfos_koperation_release(void **txn_slot)
{
	kfree(*txn_slot);
	*txn_slot = NULL;
}
