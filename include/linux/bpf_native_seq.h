/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_BPF_NATIVE_SEQ_H
#define _LINUX_BPF_NATIVE_SEQ_H

#include <linux/bpf.h>

/* runtime/link/native-sequence.md, version 1. No byte semantics are proved. */
struct bpf_native_seq {
	u32 magic, size;
	u16 version, header_size;
	u32 flags, elf_offset, elf_size;
	u32 bindings_offset, bindings_count;
	u32 gotos_offset, gotos_count;
	u16 read_mask, write_mask, clobber_mask, scratch_mask;
	u32 reserved[4];
};

struct bpf_native_goto {
	u32 ordinal;
	s32 delta;
};

static inline bool bpf_native_seq_insn(const struct bpf_insn *insn)
{
	return insn->code == (BPF_JMP | BPF_CALL) &&
	       insn->src_reg == BPF_PSEUDO_NATIVE_SEQ;
}

static inline struct bpf_native_seq *bpf_native_seq_get(const struct bpf_prog *prog, u32 offset)
{
	struct bpf_prog_aux *aux = prog->aux->main_prog_aux ?: prog->aux;
	struct bpf_native_seq *seq;

	if (offset % 8 || offset > aux->native_seqs_size ||
	    aux->native_seqs_size - offset < sizeof(*seq))
		return NULL;
	seq = aux->native_seqs + offset;
	if (seq->magic != 0x3151534e || seq->version != 1 ||
	    seq->header_size != sizeof(*seq) || seq->size % 8 ||
	    seq->size < sizeof(*seq) || seq->size > aux->native_seqs_size - offset ||
	    seq->elf_offset < sizeof(*seq) || seq->elf_offset % 8 ||
	    seq->elf_offset > seq->size || seq->elf_size > seq->size - seq->elf_offset ||
	    seq->gotos_offset % 8 || seq->gotos_offset > seq->size ||
	    seq->gotos_count > (seq->size - seq->gotos_offset) / sizeof(struct bpf_native_goto) ||
	    seq->bindings_offset % 8 || seq->bindings_offset > seq->size ||
	    seq->bindings_count > (seq->size - seq->bindings_offset) / 8 ||
	    seq->flags & ~15U || memchr_inv(seq->reserved, 0, sizeof(seq->reserved)))
		return NULL;
	return seq;
}

/* Each marker owns its goto deltas. The same source record may be referenced
 * more than once, but instruction rewriting can move those instances apart.
 */
static inline int bpf_native_seq_clone_records(struct bpf_prog *prog)
{
	size_t size = 0;
	u32 i, offset = 0;
	u8 *copy;

	for (i = 0; i < prog->len; i++) {
		struct bpf_native_seq *seq;

		if (!bpf_native_seq_insn(&prog->insnsi[i]))
			continue;
		seq = bpf_native_seq_get(prog, prog->insnsi[i].imm);
		if (!seq || seq->size > U32_MAX - size)
			return -EINVAL;
		size += seq->size;
	}
	if (!size)
		return 0;
	copy = kvmalloc(size, GFP_KERNEL);
	if (!copy)
		return -ENOMEM;
	for (i = 0; i < prog->len; i++) {
		struct bpf_native_seq *seq;

		if (!bpf_native_seq_insn(&prog->insnsi[i]))
			continue;
		seq = bpf_native_seq_get(prog, prog->insnsi[i].imm);
		memcpy(copy + offset, seq, seq->size);
		prog->insnsi[i].imm = offset;
		offset += seq->size;
	}
	kvfree(prog->aux->native_seqs);
	prog->aux->native_seqs = copy;
	prog->aux->native_seqs_size = size;
	return 0;
}

#endif
