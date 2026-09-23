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
#include <linux/ktime.h>
#include <linux/rcupdate_trace.h>

#define EBPFOS_JIT_PLACE_MAX_CONTEXT 4096

static DEFINE_MUTEX(ebpfos_jit_place_lock);

/* The canonical program is a forest: the verifier splits it into subprograms and
 * the JIT compiles each into its own image. Everything below works on that
 * forest, with a single-function program as the one-element case.
 */
static u32 ebpfos_jit_place_count(const struct bpf_prog *prog)
{
	return prog->aux->func_cnt ? : 1;
}

static struct bpf_prog *ebpfos_jit_place_function(struct bpf_prog *prog,
						  u32 index)
{
	return prog->aux->func_cnt ? prog->aux->func[index] : prog;
}

static bool ebpfos_jit_place_supported(struct bpf_prog *prog)
{
	u32 index;

	if (!prog->jited || !prog->bpf_func || bpf_prog_was_classic(prog))
		return false;
	for (index = 0; index < ebpfos_jit_place_count(prog); index++) {
		const struct bpf_prog *function =
			ebpfos_jit_place_function(prog, index);

		if (!function->jited || !function->jited_len ||
		    !function->bpf_func || function->jit_reloc_incomplete)
			return false;
	}
	return true;
}

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
static int ebpfos_jit_artifact_authenticate(struct bpf_prog *prog,
					    const void *artifact, size_t size)
{
	const struct ebpfos_jit_artifact_header *header = artifact;
	const struct ebpfos_jit_artifact_function *functions;
	const struct bpf_jit_reloc *relocations;
	const struct bpf_jit_exentry *exceptions;
	size_t functions_bytes, relocations_bytes, exceptions_bytes;
	size_t code_start, code_end, translated_end;
	const u8 *entry = (const u8 *)prog->bpf_func;
	u32 index, offset, relocation, exception;
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

	/* the image, function by function in the order the export lists them */
	if (header->program_id != prog->aux->id ||
	    header->jited_address != (u64)(unsigned long)entry ||
	    header->function_count != ebpfos_jit_place_count(prog))
		return -EBADMSG;
	functions = artifact + sizeof(*header);
	error = ebpfos_jit_artifact_digest(functions, functions_bytes,
					   header->functions_sha256);
	if (error)
		return error;
	error = ebpfos_jit_artifact_digest(artifact + code_start,
					   header->jited_bytes,
					   header->jited_sha256);
	if (error)
		return error;
	for (index = 0, offset = 0, relocation = 0, exception = 0;
	     index < header->function_count; index++) {
		struct bpf_prog *function = ebpfos_jit_place_function(prog, index);
		const u8 *function_entry = (const u8 *)function->bpf_func;

		if (functions[index].address != (u64)(unsigned long)function_entry ||
		    functions[index].offset != offset ||
		    functions[index].bytes != function->jited_len ||
		    functions[index].reserved)
			return -EBADMSG;
		if (offset + function->jited_len > header->jited_bytes ||
		    memcmp(artifact + code_start + offset, function_entry,
			   function->jited_len))
			return -EBADMSG;
		offset += function->jited_len;
		relocation += function->jit_reloc_cnt;
		exception += function->aux->num_exentries;
	}
	if (offset != header->jited_bytes ||
	    header->relocation_count != relocation ||
	    header->exception_count != exception)
		return -EBADMSG;

	/* the tables it will be placed with, likewise per function */
	relocations = artifact + translated_end;
	error = ebpfos_jit_artifact_digest(relocations, relocations_bytes,
					   header->relocations_sha256);
	if (error)
		return error;
	exceptions = (const void *)relocations + relocations_bytes;
	error = ebpfos_jit_artifact_digest(exceptions, exceptions_bytes,
					   header->exceptions_sha256);
	if (error)
		return error;
	for (index = 0, relocation = 0, exception = 0;
	     index < header->function_count; index++) {
		struct bpf_prog *function = ebpfos_jit_place_function(prog, index);
		const u8 *function_entry = (const u8 *)function->bpf_func;
		u32 entry_index;

		for (entry_index = 0; entry_index < function->jit_reloc_cnt;
		     entry_index++, relocation++) {
			struct bpf_jit_reloc expected =
				function->jit_relocs[entry_index];

			expected.function_index = index;
			if (memcmp(&relocations[relocation], &expected,
				   sizeof(expected)))
				return -EBADMSG;
		}
		for (entry_index = 0;
		     entry_index < function->aux->num_exentries;
		     entry_index++, exception++) {
			const struct exception_table_entry *live =
				&function->aux->extable[entry_index];
			const u8 *faulting = (const u8 *)&live->insn + live->insn;

			if (exceptions[exception].insn_offset !=
				    (u32)(faulting - function_entry) ||
			    exceptions[exception].fixup != live->fixup ||
			    exceptions[exception].data != live->data ||
			    exceptions[exception].function_index != index)
				return -EBADMSG;
		}
	}
	return 0;
}



static void ebpfos_jit_place_fill(void *area, unsigned int size)
{
	memset(area, 0xcc, size);
}

struct ebpfos_jit_placed_function {
	struct bpf_binary_header *header;
	struct bpf_binary_header *rw_header;
	u8 *image;
	u8 *rw_image;
	struct exception_table_entry *extable;
	bpf_func_t saved_func;
	struct bpf_prog *owner;
};

struct ebpfos_jit_placement {
	struct ebpfos_jit_placed_function *functions;
	u32 count;
};

static void ebpfos_jit_place_release(struct ebpfos_jit_placement *placement)
{
	u32 index;

	for (index = 0; index < placement->count; index++) {
		struct ebpfos_jit_placed_function *function =
			&placement->functions[index];

		if (function->header)
			bpf_jit_binary_pack_free(function->header,
						 function->rw_header);
	}
	kfree(placement->functions);
	memset(placement, 0, sizeof(*placement));
}

/* Where a function's code ended up, for an address that pointed into it. */
static const u8 *ebpfos_jit_place_moved(struct bpf_prog *prog,
					const struct ebpfos_jit_placement *placement,
					u64 address)
{
	u32 index;

	for (index = 0; index < placement->count; index++) {
		const struct bpf_prog *function =
			ebpfos_jit_place_function(prog, index);
		u64 start = (u64)(unsigned long)function->bpf_func;

		if (address >= start && address < start + function->jited_len)
			return placement->functions[index].image +
			       (address - start);
	}
	return NULL;
}

/* Rebind one recorded operand for the move. An operand whose value is an
 * address in this kernel keeps that value; what changes is every displacement
 * whose site or target moved.
 */
static int ebpfos_jit_place_reloc(struct bpf_prog *prog,
				  const struct ebpfos_jit_placement *placement,
				  u8 *rw_image, const u8 *source_entry,
				  const u8 *placed_entry, u32 jited_len,
				  const struct bpf_jit_reloc *reloc)
{
	const u8 *moved;
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
	case BPF_JIT_RELOC_KOP_CALL_PIC:
		/* The emitter that owns these bytes says they mean the same
		 * thing elsewhere, so they move unchanged.
		 */
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
	/* A target inside any of the program's own functions moved with it; a
	 * target outside them is kernel text and stays where it is.
	 */
	moved = ebpfos_jit_place_moved(prog, placement, (u64)target);
	if (moved)
		target = (s64)(unsigned long)moved;
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

static int ebpfos_jit_place_build(struct bpf_prog *prog,
				  struct ebpfos_jit_placement *placement)
{
	u32 align = __alignof__(struct exception_table_entry);
	u32 count = ebpfos_jit_place_count(prog);
	u32 index, entry;
	int error;

	memset(placement, 0, sizeof(*placement));
	placement->functions = kcalloc(count, sizeof(*placement->functions),
				       GFP_KERNEL);
	if (!placement->functions)
		return -ENOMEM;
	placement->count = count;

	/* Allocate and copy every function first: a call between two of them
	 * cannot be rebound until both have addresses.
	 */
	for (index = 0; index < count; index++) {
		struct bpf_prog *function = ebpfos_jit_place_function(prog, index);
		struct ebpfos_jit_placed_function *placed =
			&placement->functions[index];
		u32 exentries = function->aux->num_exentries;
		u32 table_offset = roundup(function->jited_len, align);
		u32 total = table_offset +
			exentries * sizeof(struct exception_table_entry);

		placed->header = bpf_jit_binary_pack_alloc(total, &placed->image,
							   align,
							   &placed->rw_header,
							   &placed->rw_image,
							   ebpfos_jit_place_fill,
							   false);
		if (!placed->header) {
			error = -ENOMEM;
			goto out_free;
		}
		memcpy(placed->rw_image, (const u8 *)function->bpf_func,
		       function->jited_len);
		if (exentries)
			placed->extable = (void *)placed->image + table_offset;
	}

	for (index = 0; index < count; index++) {
		struct bpf_prog *function = ebpfos_jit_place_function(prog, index);
		struct ebpfos_jit_placed_function *placed =
			&placement->functions[index];
		const u8 *source_entry = (const u8 *)function->bpf_func;
		u32 exentries = function->aux->num_exentries;

		for (entry = 0; entry < function->jit_reloc_cnt; entry++) {
			error = ebpfos_jit_place_reloc(prog, placement,
						       placed->rw_image,
						       source_entry, placed->image,
						       function->jited_len,
						       &function->jit_relocs[entry]);
			if (error)
				goto out_free;
		}
		if (exentries) {
			u32 table_offset = roundup(function->jited_len, align);

			ebpfos_jit_place_extable(placed->extable,
						 function->aux->extable,
						 exentries, source_entry,
						 placed->image,
						 (void *)placed->rw_image +
							 table_offset);
		}
		error = bpf_jit_binary_pack_finalize(placed->header,
						     placed->rw_header);
		if (error)
			goto out_free;
		placed->rw_header = NULL;
	}
	return 0;

out_free:
	ebpfos_jit_place_release(placement);
	return error;
}

/* Make fixup lookup find the copy, without ever taking it away from the
 * original.
 *
 * search_bpf_extables() resolves a faulting address to the program that owns it
 * through kallsyms, so an image that is executing must always have a symbol. The
 * program's own symbol keeps covering the image the JIT produced; each copy gets
 * a symbol of its own, carrying that copy's fixups, registered before anything
 * points at it and removed only once nobody can still be inside it. That leaves
 * no instant where an arena fault in either image has nowhere to land -- which
 * is exactly what a four-vCPU guest finds if there is one.
 */
/* Install one region of placed native code into the fault path Linux already
 * has.
 *
 * fixup_exception() -> search_exception_tables() -> search_bpf_extables()
 * resolves a faulting address with bpf_prog_ksym_find() and then searches that
 * program's aux->extable. So a region becomes fault-handling by owning a
 * kallsyms-visible bpf_prog whose image covers it and whose extable is the
 * region's own -- nothing else, and no bytes appended to the region itself.
 *
 * The shell carries no instructions: bpf_prog_alloc(1) because a zero size
 * rounds to a zero-byte allocation, which fails.
 *
 * Returns the owner, which the caller retires with
 * ebpfos_jit_remove_fault_region() once nobody can still be inside the region.
 */
struct bpf_prog *ebpfos_jit_install_fault_region(
	enum bpf_prog_type type, void *image, u32 image_len,
	struct exception_table_entry *extable, u32 num_exentries)
{
	struct bpf_prog *owner;

	if (!image || !image_len || (num_exentries && !extable))
		return ERR_PTR(-EINVAL);
	owner = bpf_prog_alloc(1, GFP_KERNEL);
	if (!owner)
		return ERR_PTR(-ENOMEM);
	owner->type = type;
	owner->jited = 1;
	owner->jited_len = image_len;
	owner->bpf_func = (bpf_func_t)image;
	owner->aux->extable = extable;
	owner->aux->num_exentries = num_exentries;
	strscpy(owner->aux->name, "ebpfos_placed", sizeof(owner->aux->name));
	bpf_prog_kallsyms_add(owner);
	return owner;
}

void ebpfos_jit_remove_fault_region(struct bpf_prog *owner)
{
	if (IS_ERR_OR_NULL(owner))
		return;
	bpf_prog_kallsyms_del(owner);
	/* the region's memory belongs to whoever placed it, not to the shell,
	 * so the shell is emptied before it is freed
	 */
	owner->jited = 0;
	owner->bpf_func = NULL;
	owner->aux->extable = NULL;
	owner->aux->num_exentries = 0;
	bpf_prog_free(owner);
}

static int ebpfos_jit_place_publish_symbols(struct bpf_prog *prog,
					    struct ebpfos_jit_placement *placement)
{
	u32 index;

	for (index = 0; index < placement->count; index++) {
		struct bpf_prog *function = ebpfos_jit_place_function(prog, index);
		struct ebpfos_jit_placed_function *slot =
			&placement->functions[index];
		struct bpf_prog *owner = ebpfos_jit_install_fault_region(
			function->type, slot->image, function->jited_len,
			slot->extable, function->aux->num_exentries);

		if (IS_ERR(owner))
			return PTR_ERR(owner);
		slot->owner = owner;
	}
	return 0;
}

static void ebpfos_jit_place_retire_symbols(struct ebpfos_jit_placement *placement)
{
	u32 index;

	for (index = 0; index < placement->count; index++) {
		struct bpf_prog *owner = placement->functions[index].owner;

		ebpfos_jit_remove_fault_region(owner);
		placement->functions[index].owner = NULL;
	}
}

/* Swap every function of the program onto its placed image, run it once from
 * there, and put them all back. The program's maps, arena and reference counts
 * are its own throughout, so what is measured is the placed bytes and nothing
 * else.
 */
static int ebpfos_jit_place_run(struct bpf_prog *prog,
				struct ebpfos_jit_placement *placement,
				void *context, u32 *retval)
{
	bpf_func_t saved_entry = prog->bpf_func;
	u32 index;
	int error;

	error = ebpfos_jit_place_publish_symbols(prog, placement);
	if (error) {
		ebpfos_jit_place_retire_symbols(placement);
		return error;
	}
	for (index = 0; index < placement->count; index++) {
		struct bpf_prog *function = ebpfos_jit_place_function(prog, index);
		struct ebpfos_jit_placed_function *slot =
			&placement->functions[index];

		slot->saved_func = function->bpf_func;
		function->bpf_func = (bpf_func_t)slot->image;
	}
	/* A split program enters through its first function; an unsplit one is
	 * that function.
	 */
	prog->bpf_func = (bpf_func_t)placement->functions[0].image;

	migrate_disable();
	rcu_read_lock_trace();
	*retval = bpf_prog_run_pin_on_cpu(prog, context);
	rcu_read_unlock_trace();
	migrate_enable();

	for (index = 0; index < placement->count; index++) {
		struct bpf_prog *function = ebpfos_jit_place_function(prog, index);

		function->bpf_func = placement->functions[index].saved_func;
	}
	prog->bpf_func = saved_entry;

	/* Putting the program back does not get anyone out of the copy: a
	 * caller that read bpf_func before the swap back can still be inside
	 * those bytes, and on more than one CPU it will be. Wait for both entry
	 * paths -- sleepable programs run under RCU tasks trace, the rest under
	 * classic RCU -- before the copy and its symbol may go away.
	 */
	synchronize_rcu_tasks_trace();
	synchronize_rcu();
	ebpfos_jit_place_retire_symbols(placement);
	return 0;
}

long ebpfos_jit_place_ioctl(void __user *argp)
{
	struct ebpfos_jit_placement placement = {};
	struct ebpfos_ioc_jit_place request;
	struct bpf_prog *prog;
	void *context = NULL;
	u32 retval = 0;
	u32 index;
	ktime_t started;
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
	started = ktime_get();
	error = ebpfos_jit_place_build(prog, &placement);
	if (!error) {
		error = ebpfos_jit_place_run(prog, &placement, context, &retval);
		if (!error) {
			request.place_ns =
				ktime_to_ns(ktime_sub(ktime_get(), started));
			request.placed_address =
				(u64)(unsigned long)placement.functions[0].image;
			request.source_address =
				(u64)(unsigned long)prog->bpf_func;
			request.jited_bytes = 0;
			request.relocations = 0;
			request.exentries = 0;
			for (index = 0; index < placement.count; index++) {
				struct bpf_prog *function =
					ebpfos_jit_place_function(prog, index);

				request.jited_bytes += function->jited_len;
				request.relocations += function->jit_reloc_cnt;
				request.exentries +=
					function->aux->num_exentries;
			}
			request.functions = placement.count;
			request.retval = retval;
		}
		ebpfos_jit_place_release(&placement);
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
