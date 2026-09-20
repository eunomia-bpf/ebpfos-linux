// SPDX-License-Identifier: GPL-2.0
/*
 * Run a verified program's own JIT output from a second address.
 *
 * The successor has to execute code the upstream verifier and JIT produced, at
 * an address that is not where they produced it. Everything that makes that
 * sound already exists here: the JIT records where it wrote the operands only it
 * can resolve, the program owns an exception table for its arena faults, and a
 * program registered in kallsyms is what makes fixup lookup find that table.
 *
 * This places a copy of a live program's image, rebinds only what the move
 * changes, rebuilds the fault fixups at the new address, runs the program from
 * there, and puts it back. No bytes come from userspace: the source is a program
 * this kernel verified and JITed, and the copy differs from it only in the
 * displacements the move changes. Nothing is interpreted, re-encoded, or
 * substituted, and no address is special-cased.
 */
#include <linux/bpf.h>
#include <linux/ebpfos.h>
#include <linux/filter.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/extable.h>
#include <crypto/sha2.h>

#define EBPFOS_JIT_PLACE_MAX_CONTEXT 4096

static DEFINE_MUTEX(ebpfos_jit_place_lock);

/* The frozen export's ABI, as cmd/ebpfos-upstream-jit-compiler.c writes it. The
 * export is read only to check that it describes the program this kernel holds:
 * every byte that ends up executing comes from that program's own image.
 */
#define EBPFOS_JIT_ARTIFACT_MAGIC "EBPFJIT4"
#define EBPFOS_JIT_ARTIFACT_VERSION 4U
#define EBPFOS_JIT_ARTIFACT_MAX (16U << 20)

struct ebpfos_jit_artifact_header {
	unsigned char magic[8];
	__u32 version;
	__u32 header_bytes;
	__u32 compiler_calls;
	__u32 flags;
	__u32 program_id;
	__u32 reserved;
	__u64 request_bytes;
	__u64 xlated_bytes;
	__u64 jited_bytes;
	__u64 jited_address;
	__u64 cpu_features[4];
	unsigned char program_tag[8];
	unsigned char request_sha256[32];
	unsigned char xlated_sha256[32];
	unsigned char jited_sha256[32];
	char verifier_source_sha256[65];
	char x86_jit_source_sha256[65];
	unsigned char reserved_tail[6];
	__u32 function_count;
	__u32 function_record_bytes;
	unsigned char functions_sha256[32];
	__u32 relocation_count;
	__u32 relocation_record_bytes;
	unsigned char relocations_sha256[32];
	__u32 exception_count;
	__u32 exception_record_bytes;
	unsigned char exceptions_sha256[32];
};

struct ebpfos_jit_artifact_function {
	__u64 address;
	__u64 offset;
	__u32 bytes;
	__u32 reserved;
};

static int ebpfos_jit_artifact_digest(const void *data, size_t len,
				      const unsigned char *expected)
{
	unsigned char digest[SHA256_DIGEST_SIZE];

	sha256(data, len, digest);
	return memcmp(digest, expected, sizeof(digest)) ? -EBADMSG : 0;
}

/* Does this export describe the program this kernel is holding? Nothing is read
 * out of it into the placement; it either matches what the kernel already has,
 * or the placement is refused.
 */
static int ebpfos_jit_artifact_authenticate(const struct bpf_prog *prog,
					    const void *artifact, size_t size)
{
	const struct ebpfos_jit_artifact_header *header = artifact;
	const struct ebpfos_jit_artifact_function *functions;
	const struct bpf_jit_reloc *relocations;
	const struct bpf_jit_exentry *exceptions;
	size_t functions_bytes, relocations_bytes, exceptions_bytes;
	size_t code_start, code_end, translated_end;
	const u8 *entry = (const u8 *)prog->bpf_func;
	u32 index;
	int error;

	if (size < sizeof(*header) || size > EBPFOS_JIT_ARTIFACT_MAX)
		return -EINVAL;
	if (memcmp(header->magic, EBPFOS_JIT_ARTIFACT_MAGIC,
		   sizeof(header->magic)) ||
	    header->version != EBPFOS_JIT_ARTIFACT_VERSION ||
	    header->header_bytes != sizeof(*header))
		return -EINVAL;
	if (header->function_record_bytes != sizeof(*functions) ||
	    header->relocation_record_bytes != sizeof(*relocations) ||
	    header->exception_record_bytes != sizeof(*exceptions))
		return -EINVAL;
	functions_bytes = (size_t)header->function_count * sizeof(*functions);
	relocations_bytes = (size_t)header->relocation_count * sizeof(*relocations);
	exceptions_bytes = (size_t)header->exception_count * sizeof(*exceptions);
	code_start = sizeof(*header) + functions_bytes;
	if (code_start < sizeof(*header) || header->jited_bytes > size)
		return -EINVAL;
	code_end = code_start + header->jited_bytes;
	translated_end = code_end + header->xlated_bytes;
	if (code_end < code_start || translated_end < code_end ||
	    translated_end + relocations_bytes + exceptions_bytes != size)
		return -EINVAL;

	/* the image */
	if (header->program_id != prog->aux->id ||
	    header->jited_bytes != prog->jited_len ||
	    header->jited_address != (u64)(unsigned long)entry ||
	    header->function_count != 1)
		return -EBADMSG;
	functions = artifact + sizeof(*header);
	if (functions[0].address != (u64)(unsigned long)entry ||
	    functions[0].offset || functions[0].bytes != prog->jited_len ||
	    functions[0].reserved)
		return -EBADMSG;
	error = ebpfos_jit_artifact_digest(functions, functions_bytes,
					   header->functions_sha256);
	if (error)
		return error;
	error = ebpfos_jit_artifact_digest(artifact + code_start,
					   header->jited_bytes,
					   header->jited_sha256);
	if (error)
		return error;
	if (memcmp(artifact + code_start, entry, prog->jited_len))
		return -EBADMSG;

	/* the tables it will be placed with */
	if (header->relocation_count != prog->jit_reloc_cnt ||
	    header->exception_count != prog->aux->num_exentries)
		return -EBADMSG;
	relocations = artifact + translated_end;
	error = ebpfos_jit_artifact_digest(relocations, relocations_bytes,
					   header->relocations_sha256);
	if (error)
		return error;
	for (index = 0; index < header->relocation_count; index++)
		if (memcmp(&relocations[index], &prog->jit_relocs[index],
			   sizeof(*relocations)))
			return -EBADMSG;
	exceptions = (const void *)relocations + relocations_bytes;
	error = ebpfos_jit_artifact_digest(exceptions, exceptions_bytes,
					   header->exceptions_sha256);
	if (error)
		return error;
	for (index = 0; index < header->exception_count; index++) {
		const struct exception_table_entry *live =
			&prog->aux->extable[index];
		const u8 *faulting = (const u8 *)&live->insn + live->insn;

		if (exceptions[index].insn_offset != (u32)(faulting - entry) ||
		    exceptions[index].fixup != live->fixup ||
		    exceptions[index].data != live->data ||
		    exceptions[index].function_index)
			return -EBADMSG;
	}
	return 0;
}



static void ebpfos_jit_place_fill(void *area, unsigned int size)
{
	memset(area, 0xcc, size);
}

/* Rebind one recorded operand for the move. An operand whose value is an
 * address in this kernel keeps that value; what changes is every displacement
 * whose site or target moved.
 */
static int ebpfos_jit_place_reloc(u8 *rw_image, const u8 *source_entry,
				  const u8 *placed_entry, u32 jited_len,
				  const struct bpf_jit_reloc *reloc)
{
	const u8 *source_site;
	const u8 *placed_site;
	s64 target;
	s64 displacement;
	s32 stored;

	switch (reloc->kind) {
	case BPF_JIT_RELOC_HELPER_CALL:
	case BPF_JIT_RELOC_KFUNC_CALL:
	case BPF_JIT_RELOC_INTERNAL_CALL:
	case BPF_JIT_RELOC_THUNK_JUMP:
		break;
	case BPF_JIT_RELOC_ARENA_BASE:
	case BPF_JIT_RELOC_ARENA_USER_BASE:
	case BPF_JIT_RELOC_PERCPU_OFFSET:
	case BPF_JIT_RELOC_PSEUDO_IMM64:
	case BPF_JIT_RELOC_PRIV_STACK:
		/* An absolute address of this kernel, and this is this kernel. */
		return 0;
	default:
		/* A KOperation sequence or an emission the table cannot
		 * describe: refuse rather than move bytes blindly.
		 */
		return -EOPNOTSUPP;
	}
	if (reloc->width != 4 || reloc->offset + 4 > jited_len)
		return -EINVAL;
	source_site = source_entry + reloc->offset;
	placed_site = placed_entry + reloc->offset;
	memcpy(&stored, rw_image + reloc->offset, sizeof(stored));
	target = (s64)(unsigned long)source_site + 4 + stored;
	if (target != (s64)reloc->value)
		return -EBADFD;
	if (target >= (s64)(unsigned long)source_entry &&
	    target < (s64)(unsigned long)source_entry + jited_len)
		/* The target moved with the code. */
		target += placed_entry - source_entry;
	displacement = target - ((s64)(unsigned long)placed_site + 4);
	if (displacement < S32_MIN || displacement > S32_MAX)
		return -ERANGE;
	stored = (s32)displacement;
	memcpy(rw_image + reloc->offset, &stored, sizeof(stored));
	return 0;
}

/* Rebuild the program's fault fixups for the address the copy runs at. The
 * fixup and data encodings carry no address, so only the self-relative
 * reference to the faulting instruction is recomputed.
 */
static void ebpfos_jit_place_extable(struct exception_table_entry *placed_table,
				     const struct exception_table_entry *source_table,
				     u32 count, const u8 *source_entry,
				     const u8 *placed_entry,
				     struct exception_table_entry *rw_table)
{
	u32 index;

	for (index = 0; index < count; index++) {
		const struct exception_table_entry *source = &source_table[index];
		const u8 *faulting = (const u8 *)&source->insn + source->insn;
		const u8 *moved = placed_entry + (faulting - source_entry);

		rw_table[index].insn =
			moved - (const u8 *)&placed_table[index].insn;
		rw_table[index].fixup = source->fixup;
		rw_table[index].data = source->data;
	}
}

static bool ebpfos_jit_place_supported(const struct bpf_prog *prog)
{
	return prog->jited && prog->jited_len && prog->bpf_func &&
	       !prog->aux->func_cnt && !prog->jit_reloc_incomplete &&
	       !bpf_prog_was_classic(prog);
}

struct ebpfos_jit_placement {
	struct bpf_binary_header *header;
	struct bpf_binary_header *rw_header;
	u8 *image;
	u8 *rw_image;
	struct exception_table_entry *extable;
	u32 image_bytes;
};

static void ebpfos_jit_place_release(struct ebpfos_jit_placement *placement)
{
	if (placement->header)
		bpf_jit_binary_pack_free(placement->header, placement->rw_header);
	memset(placement, 0, sizeof(*placement));
}

static int ebpfos_jit_place_build(struct bpf_prog *prog,
				  struct ebpfos_jit_placement *placement)
{
	u32 align = __alignof__(struct exception_table_entry);
	u32 exentries = prog->aux->num_exentries;
	const u8 *source_entry = (const u8 *)prog->bpf_func;
	u32 table_offset = roundup(prog->jited_len, align);
	struct exception_table_entry *rw_table = NULL;
	u32 total = table_offset + exentries * sizeof(*rw_table);
	u32 index;
	int error;

	memset(placement, 0, sizeof(*placement));
	placement->header = bpf_jit_binary_pack_alloc(total, &placement->image,
						      align,
						      &placement->rw_header,
						      &placement->rw_image,
						      ebpfos_jit_place_fill,
						      false);
	if (!placement->header)
		return -ENOMEM;
	placement->image_bytes = total;
	memcpy(placement->rw_image, source_entry, prog->jited_len);
	for (index = 0; index < prog->jit_reloc_cnt; index++) {
		error = ebpfos_jit_place_reloc(placement->rw_image, source_entry,
					       placement->image, prog->jited_len,
					       &prog->jit_relocs[index]);
		if (error)
			goto out_free;
	}
	if (exentries) {
		placement->extable = (void *)placement->image + table_offset;
		rw_table = (void *)placement->rw_image + table_offset;
		ebpfos_jit_place_extable(placement->extable, prog->aux->extable,
					 exentries, source_entry,
					 placement->image, rw_table);
	}
	error = bpf_jit_binary_pack_finalize(placement->header,
					     placement->rw_header);
	if (error)
		goto out_free;
	placement->rw_header = NULL;
	return 0;

out_free:
	ebpfos_jit_place_release(placement);
	return error;
}

/* Point the program at an image and let fixup lookup find it there.
 *
 * bpf_ksym_del() unlinks with list_del_rcu(), which deliberately leaves the
 * node's forward pointer intact so a concurrent reader can finish walking. The
 * node therefore cannot be reused until those readers are gone, and re-adding it
 * before that is what bpf_ksym_add()'s warning is about. Waiting for the grace
 * period and reinitialising the node is what makes a second registration legal.
 */
static void ebpfos_jit_place_resymbolise(struct bpf_prog *prog, bpf_func_t entry,
					 struct exception_table_entry *extable)
{
	bpf_prog_kallsyms_del(prog);
	synchronize_rcu();
	INIT_LIST_HEAD(&prog->aux->ksym.lnode);
	prog->bpf_func = entry;
	prog->aux->extable = extable;
	bpf_prog_kallsyms_add(prog);
}

/* Swap the program onto the placed image, run it once from there, and put it
 * back. The program's maps, arena and reference counts are its own throughout,
 * so what is measured is the placed bytes and nothing else.
 */
static void ebpfos_jit_place_run(struct bpf_prog *prog,
				 struct ebpfos_jit_placement *placement,
				 void *context, u32 *retval)
{
	struct exception_table_entry *saved_extable = prog->aux->extable;
	bpf_func_t saved_func = prog->bpf_func;

	ebpfos_jit_place_resymbolise(prog, (bpf_func_t)placement->image,
				     placement->extable);

	migrate_disable();
	rcu_read_lock_trace();
	*retval = bpf_prog_run_pin_on_cpu(prog, context);
	rcu_read_unlock_trace();
	migrate_enable();

	ebpfos_jit_place_resymbolise(prog, saved_func, saved_extable);
}

long ebpfos_jit_place_ioctl(void __user *argp)
{
	struct ebpfos_jit_placement placement = {};
	struct ebpfos_ioc_jit_place request;
	struct bpf_prog *prog;
	void *context = NULL;
	u32 retval = 0;
	int error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.version != EBPFOS_JIT_PLACE_VERSION ||
	    (request.flags & ~EBPFOS_JIT_PLACE_F_NO_ARTIFACT) ||
	    request.authenticated || request.reserved ||
	    (request.artifact_size &&
	     (request.flags & EBPFOS_JIT_PLACE_F_NO_ARTIFACT)) ||
	    request.context_size > EBPFOS_JIT_PLACE_MAX_CONTEXT)
		return -EINVAL;
	prog = bpf_prog_get(request.prog_fd);
	if (IS_ERR(prog))
		return PTR_ERR(prog);
	if (!ebpfos_jit_place_supported(prog)) {
		error = -EOPNOTSUPP;
		goto out_put;
	}
	if (request.arena_map_fd != -1) {
		/* The placed code carries the arena base the JIT resolved, so
		 * the caller may only name the arena the program already uses.
		 */
		struct bpf_map *arena = bpf_map_get(request.arena_map_fd);

		if (IS_ERR(arena)) {
			error = PTR_ERR(arena);
			goto out_put;
		}
		/* aux->arena is the same object as the map, as the verifier
		 * itself stores it.
		 */
		error = (void *)arena == (void *)prog->aux->arena ? 0 : -EXDEV;
		bpf_map_put(arena);
		if (error)
			goto out_put;
	}
	if (request.artifact_size) {
		void *artifact = memdup_user(u64_to_user_ptr(request.artifact),
					     request.artifact_size);

		if (IS_ERR(artifact)) {
			error = PTR_ERR(artifact);
			goto out_put;
		}
		error = ebpfos_jit_artifact_authenticate(prog, artifact,
							 request.artifact_size);
		kfree(artifact);
		if (error)
			goto out_put;
		request.authenticated = 1;
	} else if (!(request.flags & EBPFOS_JIT_PLACE_F_NO_ARTIFACT)) {
		error = -EINVAL;
		goto out_put;
	}
	if (request.context_size < prog->aux->max_ctx_offset) {
		error = -EINVAL;
		goto out_put;
	}
	if (request.context_size) {
		context = memdup_user(u64_to_user_ptr(request.context),
				      request.context_size);
		if (IS_ERR(context)) {
			error = PTR_ERR(context);
			context = NULL;
			goto out_put;
		}
	}
	mutex_lock(&ebpfos_jit_place_lock);
	error = ebpfos_jit_place_build(prog, &placement);
	if (!error) {
		ebpfos_jit_place_run(prog, &placement, context, &retval);
		request.placed_address = (u64)(unsigned long)placement.image;
		request.jited_bytes = prog->jited_len;
		request.relocations = prog->jit_reloc_cnt;
		request.exentries = prog->aux->num_exentries;
		request.retval = retval;
		ebpfos_jit_place_release(&placement);
		request.source_address = (u64)(unsigned long)prog->bpf_func;
	}
	mutex_unlock(&ebpfos_jit_place_lock);
	if (!error && request.context_size &&
	    copy_to_user(u64_to_user_ptr(request.context), context,
			 request.context_size))
		error = -EFAULT;
	if (!error && copy_to_user(argp, &request, sizeof(request)))
		error = -EFAULT;
out_put:
	kfree(context);
	bpf_prog_put(prog);
	return error;
}
