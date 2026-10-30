/* SPDX-License-Identifier: GPL-2.0-only */
/* Native inline-assembly records are trusted compiler input. This is part of
 * the x86 BPF JIT, not an interpreter or another executable-code cache.
 */
#include <linux/bpf_native_seq.h>
#include <linux/moduleloader.h>
#include <linux/module.h>
#include <linux/unaligned.h>

struct native_sequence {
	struct bpf_native_seq *record;
	const Elf64_Ehdr *elf;
	const Elf64_Shdr *sections;
	const Elf64_Sym *symbols;
	const char *strings, *names;
	u32 strings_size, names_size, symbol_count;
	u32 insn, text, *offsets, *gotos;
	u32 *output_sections, *output_offsets;
	unsigned long *values;
	struct module **modules;
	u16 scratch;
	s32 spill_offset;
};

struct bpf_native_image {
	struct native_sequence *sequences;
	u32 count, max_emit, spill_size;
	struct module_section_image *module;
	Elf64_Ehdr *header;
	Elf64_Shdr *sections;
	void **section_sources;
	u32 section_count, charged;
	bool finalized;
};

static bool native_range(u64 offset, u64 size, u64 total)
{
	return offset <= total && size <= total - offset;
}

static const void *native_section_data(const struct native_sequence *seq, u32 section)
{
	return (const void *)seq->elf + seq->sections[section].sh_offset;
}

static const char *native_section_name(const struct native_sequence *seq, u32 section)
{
	u32 off = seq->sections[section].sh_name;

	return off < seq->names_size && memchr(seq->names + off, 0, seq->names_size - off) ?
		seq->names + off : NULL;
}

static const char *native_symbol_name(const struct native_sequence *seq, u32 index)
{
	u32 off = seq->symbols[index].st_name;

	return off < seq->strings_size && memchr(seq->strings + off, 0, seq->strings_size - off) ?
		seq->strings + off : NULL;
}

static void native_image_release(void *owner)
{
	struct bpf_native_image *native = owner;
	u32 i, j;

	if (native->charged)
		bpf_jit_uncharge_modmem(native->charged);
	if (native->section_sources)
		for (i = 0; i < native->section_count; i++)
			kvfree(native->section_sources[i]);
	kvfree(native->section_sources);
	kvfree(native->sections);
	kvfree(native->header);
	for (i = 0; i < native->count; i++) {
		struct native_sequence *seq = &native->sequences[i];

		if (seq->modules)
			for (j = 0; j < seq->symbol_count; j++)
				module_put(seq->modules[j]);
		kfree(seq->modules);
		kfree(seq->values);
		kfree(seq->offsets);
		kfree(seq->gotos);
		kfree(seq->output_sections);
		kfree(seq->output_offsets);
	}
	kfree(native->sequences);
	kfree(native);
}

static void native_image_free(struct bpf_native_image *native)
{
	if (!native)
		return;
	if (native->module)
		module_section_image_free(native->module, native_image_release, native);
	else
		native_image_release(native);
}

static int native_parse_sequence(struct bpf_prog *prog, struct native_sequence *seq, u32 insn)
{
	struct bpf_native_seq *record = bpf_native_seq_get(prog, prog->insnsi[insn].imm);
	const Elf64_Shdr *symbols = NULL, *strings, *names;
	const Elf64_Ehdr *elf;
	u32 i;

	if (!record || record->elf_size < sizeof(*elf))
		return -EINVAL;
	seq->record = record;
	seq->insn = insn;
	if (record->flags & 8) {
		pr_err("bpf_jit: native sequence align-stack needs a native frame contract\n");
		return -EOPNOTSUPP;
	}
	if (prog->aux->native_frame && prog->aux->native_stack_align > 8 &&
	    record->read_mask & BIT(BPF_REG_FP)) {
		pr_err("bpf_jit: native sequence RBP binding cannot address a realigned BPF frame\n");
		return -EOPNOTSUPP;
	}
	seq->scratch = record->scratch_mask | (record->clobber_mask & (BIT(10) | BIT(11) | BIT(12)));
	if (seq->scratch & ~(BIT(10) | BIT(11) | BIT(12)))
		return -EINVAL;
	elf = (void *)record + record->elf_offset;
	if (memcmp(elf->e_ident, ELFMAG, SELFMAG) || elf->e_ident[EI_CLASS] != ELFCLASS64 ||
	    elf->e_ident[EI_DATA] != ELFDATA2LSB || elf->e_machine != EM_X86_64 ||
	    elf->e_type != ET_REL || elf->e_shentsize != sizeof(Elf64_Shdr) ||
	    !elf->e_shnum || elf->e_shstrndx >= elf->e_shnum || elf->e_shoff % 8 ||
	    !native_range(elf->e_shoff, elf->e_shnum * sizeof(Elf64_Shdr), record->elf_size))
		return -ENOEXEC;
	seq->elf = elf;
	seq->sections = (void *)elf + elf->e_shoff;
	for (i = 0; i < elf->e_shnum; i++) {
		const Elf64_Shdr *section = &seq->sections[i];

		if (section->sh_type != SHT_NOBITS &&
		    !native_range(section->sh_offset, section->sh_size, record->elf_size))
			return -ENOEXEC;
		if (section->sh_type == SHT_SYMTAB) {
			if (symbols || section->sh_entsize != sizeof(Elf64_Sym) ||
			    section->sh_size % sizeof(Elf64_Sym) || section->sh_link >= elf->e_shnum ||
			    section->sh_offset % 8)
				return -ENOEXEC;
			symbols = section;
		}
		if (section->sh_flags & SHF_ALLOC) {
			if (section->sh_size > INT_MAX ||
			    (section->sh_addralign && !is_power_of_2(section->sh_addralign)))
				return -EOPNOTSUPP;
		}
	}
	if (!symbols)
		return -ENOEXEC;
	names = &seq->sections[elf->e_shstrndx];
	strings = &seq->sections[symbols->sh_link];
	if (names->sh_type != SHT_STRTAB || strings->sh_type != SHT_STRTAB)
		return -ENOEXEC;
	seq->names = native_section_data(seq, elf->e_shstrndx);
	seq->names_size = names->sh_size;
	seq->strings = (void *)elf + strings->sh_offset;
	seq->strings_size = strings->sh_size;
	seq->symbols = (void *)elf + symbols->sh_offset;
	seq->symbol_count = symbols->sh_size / sizeof(Elf64_Sym);
	seq->offsets = kmalloc_array(elf->e_shnum, sizeof(u32), GFP_KERNEL);
	seq->gotos = kcalloc(record->gotos_count, sizeof(u32), GFP_KERNEL);
	seq->values = kcalloc(seq->symbol_count, sizeof(*seq->values), GFP_KERNEL);
	seq->modules = kcalloc(seq->symbol_count, sizeof(*seq->modules), GFP_KERNEL);
	if (!seq->offsets || (!seq->gotos && record->gotos_count) || !seq->values || !seq->modules)
		return -ENOMEM;
	memset(seq->offsets, 0xff, elf->e_shnum * sizeof(u32));
	for (i = 1; i < elf->e_shnum; i++) {
		const char *name = native_section_name(seq, i);

		if (!name)
			return -ENOEXEC;
		if (!strcmp(name, ".text"))
			seq->text = i;
	}
	if (!seq->text || !(seq->sections[seq->text].sh_flags & SHF_EXECINSTR))
		return -ENOEXEC;
	if (seq->sections[seq->text].sh_size > INT_MAX - BPF_MAX_INSN_SIZE)
		return -E2BIG;

	for (i = 1; i < seq->symbol_count; i++)
		if (!native_symbol_name(seq, i))
			return -ENOEXEC;

	return 0;
}

static const Elf64_Sym *native_definition(const struct bpf_native_image *native,
					const char *name, u32 *owner)
{
	const Elf64_Sym *weak = NULL;
	u32 i, j;

	for (i = 0; i < native->count; i++) {
		const struct native_sequence *seq = &native->sequences[i];

		for (j = 1; j < seq->symbol_count; j++) {
			const Elf64_Sym *sym = &seq->symbols[j];

			if (sym->st_shndx == SHN_UNDEF || !ELF64_ST_BIND(sym->st_info) ||
			    strcmp(name, native_symbol_name(seq, j)))
				continue;
			if (ELF64_ST_BIND(sym->st_info) == STB_GLOBAL) {
				*owner = i;
				return sym;
			}
			if (!weak) {
				weak = sym;
				*owner = i;
			}
		}
	}
	return weak;
}

static int native_resolve_symbols(struct bpf_native_image *native)
{
	u32 n, i, owner;

	for (n = 0; n < native->count; n++) {
		struct native_sequence *seq = &native->sequences[n];

		for (i = 1; i < seq->symbol_count; i++) {
			const Elf64_Sym *sym = &seq->symbols[i];
			const char *name = native_symbol_name(seq, i);
			struct module *mod;
			unsigned long address;

			if (sym->st_shndx != SHN_UNDEF || !strncmp(name, "__bpf_native_goto_", 18) ||
			    native_definition(native, name, &owner))
				continue;
			/* Pin the containing module in the lookup's RCU read section. */
			rcu_read_lock();
			address = kallsyms_lookup_name(name);
			mod = __module_address(address);
			if ((!address && ELF64_ST_BIND(sym->st_info) != STB_WEAK) || !try_module_get(mod)) {
				rcu_read_unlock();
				pr_err("bpf_jit: native sequence unresolved symbol %s\n", name);
				return -ENOENT;
			}
			seq->values[i] = address;
			seq->modules[i] = mod;
			rcu_read_unlock();
		}
	}
	return 0;
}

static int native_image_prepare(struct bpf_prog *prog)
{
	struct bpf_native_image *native;
	u32 i, count = 0;
	int err;

	if (prog->aux->native_image)
		return 0;
	for (i = 0; i < prog->len; i++)
		count += bpf_native_seq_insn(&prog->insnsi[i]);
	if (!count)
		return 0;
	if (!prog->aux->trusted_kernel)
		return -EACCES;
	native = kzalloc(sizeof(*native), GFP_KERNEL);
	if (!native)
		return -ENOMEM;
	native->sequences = kcalloc(count, sizeof(*native->sequences), GFP_KERNEL);
	if (!native->sequences) {
		kfree(native);
		return -ENOMEM;
	}
	for (i = 0; i < prog->len; i++) {
		struct native_sequence *seq;

		if (!bpf_native_seq_insn(&prog->insnsi[i]))
			continue;
		seq = &native->sequences[native->count++];
		err = native_parse_sequence(prog, seq, i);
		if (err)
			goto fail;
		if (seq->scratch)
			native->spill_size = 32;
		native->max_emit = max_t(u32, native->max_emit, seq->sections[seq->text].sh_size + 64);
	}
	err = native_resolve_symbols(native);
	if (err)
		goto fail;
	prog->aux->native_image = native;
	return 0;
fail:
	native_image_free(native);
	return err;
}

static void native_scratch(u8 **pprog, const struct native_sequence *seq, bool restore)
{
	u8 *prog = *pprog;
	int i;

	/* Reserved frame slots keep both flags and the source's RSP unchanged. */
	for (i = 0; i < 3; i++) {
		u8 reg = restore ? 12 - i : 10 + i;

		if (seq->scratch & BIT(reg)) {
			/* mov r10/r11/r12, disp32(rbp), or the reverse */
			EMIT3_off32(0x4c, restore ? 0x8b : 0x89,
				    0x85 | ((reg - 8) << 3), seq->spill_offset - (reg - 10) * 8);
		}
	}
	*pprog = prog;
}

static bool native_needs_exit(const struct native_sequence *seq)
{
	return seq->scratch;
}

static void native_enter(u8 **pprog, const struct native_sequence *seq)
{
	native_scratch(pprog, seq, false);
}

static void native_exit(u8 **pprog, const struct native_sequence *seq)
{
	native_scratch(pprog, seq, true);
}

static int native_emit(struct bpf_prog *bpf_prog, u32 insn, u32 offset, u8 **pprog)
{
	struct bpf_native_image *native = bpf_prog->aux->native_image;
	u8 *prog = *pprog, *start = prog;
	u32 i;

	for (i = 0; native && i < native->count; i++) {
		struct native_sequence *seq = &native->sequences[i];
		u32 size;

		if (seq->insn != insn)
			continue;
		native_enter(&prog, seq);
		seq->offsets[seq->text] = offset + prog - start;
		size = seq->sections[seq->text].sh_size;
		memcpy(prog, native_section_data(seq, seq->text), size);
		prog += size;
		native_exit(&prog, seq);
		*pprog = prog;
		return 0;
	}
	return -EINVAL;
}

static int native_layout(struct bpf_native_image *native, u32 code_size)
{
	u64 cursor = code_size;
	u32 i, j;

	if (!native)
		return code_size;
	for (i = 0; i < native->count; i++) {
		struct native_sequence *seq = &native->sequences[i];

		for (j = 1; j < seq->elf->e_shnum; j++) {
			const Elf64_Shdr *section = &seq->sections[j];

			if (j == seq->text || !(section->sh_flags & SHF_ALLOC))
				continue;
			cursor = ALIGN(cursor, section->sh_addralign ?: 1);
			if (cursor > INT_MAX || section->sh_size > INT_MAX - cursor)
				return -E2BIG;
			seq->offsets[j] = cursor;
			cursor += section->sh_size;
		}
		for (j = 0; j < seq->record->gotos_count; j++) {
			seq->gotos[j] = cursor;
			if (native_needs_exit(seq))
				cursor += hweight16(seq->scratch) * 7 + 5;
		}
	}
	return cursor > INT_MAX ? -E2BIG : cursor;
}

static int native_goto_target(const struct native_sequence *seq, u32 index,
			      const struct bpf_prog *prog, const int *addrs, u32 *offset)
{
	const struct bpf_native_goto *targets = (void *)seq->record + seq->record->gotos_offset;
	s64 target = (s64)seq->insn + 1 + targets[index].delta;

	if (target < 0 || target >= prog->len ||
	    (!prog->insnsi[target].code && target && bpf_is_ldimm64(&prog->insnsi[target - 1])))
		return -EINVAL;
	*offset = addrs[target];
	return 0;
}

static u8 *native_address(const struct bpf_native_image *native,
			  const struct native_sequence *seq, u32 section, const u8 *image)
{
	if (native->module && section != seq->text)
		return (void *)native->sections[seq->output_sections[section]].sh_addr +
			seq->output_offsets[section];
	return (u8 *)image + seq->offsets[section];
}

static int native_symbol_value(const struct native_sequence *seq, u32 index,
			        const struct bpf_prog *prog, const int *addrs,
			        const u8 *image, u64 *value)
{
	const Elf64_Sym *sym;

	if (index >= seq->symbol_count)
		return -ENOEXEC;
	sym = &seq->symbols[index];
	if (sym->st_shndx == SHN_ABS) {
		*value = sym->st_value;
	} else if (sym->st_shndx == SHN_UNDEF) {
		const char *name = native_symbol_name(seq, index);
		u32 ordinal, j;

		if (!strncmp(name, "__bpf_native_goto_", 18)) {
			const struct bpf_native_goto *targets = (void *)seq->record + seq->record->gotos_offset;

			if (kstrtou32(name + 18, 10, &ordinal))
				return -ENOEXEC;
			for (j = 0; j < seq->record->gotos_count; j++) {
				u32 offset;
				int err;

				if (targets[j].ordinal != ordinal)
					continue;
				err = native_goto_target(seq, j, prog, addrs, &offset);
				if (err)
					return err;
				*value = (u64)image + (native_needs_exit(seq) ? seq->gotos[j] : offset);
				return 0;
			}
			return -ENOEXEC;
		}
		{
			struct bpf_native_image *native = prog->aux->native_image;
			u32 owner;
			const Elf64_Sym *definition = native_definition(native, name, &owner);

			if (definition) {
				const struct native_sequence *source = &native->sequences[owner];

				return native_symbol_value(source, definition - source->symbols,
						prog, addrs, image, value);
			}
			*value = seq->values[index];
		}
	} else {
		if (sym->st_shndx >= seq->elf->e_shnum || seq->offsets[sym->st_shndx] == U32_MAX ||
		    sym->st_value > seq->sections[sym->st_shndx].sh_size)
			return -ENOEXEC;
		if (prog->aux->native_image->module && sym->st_shndx != seq->text)
			*value = module_section_image_symbol(prog->aux->native_image->module,
					seq->output_sections[sym->st_shndx]) +
				seq->output_offsets[sym->st_shndx] + sym->st_value;
		else
			*value = (u64)image + seq->offsets[sym->st_shndx] + sym->st_value;
	}
	return 0;
}

static int native_relocate(const struct native_sequence *seq, const struct bpf_prog *prog,
			   const int *addrs, u8 *image, u8 *rw_image)
{
	u32 i, j;

	for (i = 1; i < seq->elf->e_shnum; i++) {
		const Elf64_Shdr *section = &seq->sections[i];
		const Elf64_Rela *relocs;

		if (section->sh_type != SHT_RELA)
			continue;
		if (section->sh_info >= seq->elf->e_shnum || section->sh_entsize != sizeof(*relocs) ||
		    section->sh_size % sizeof(*relocs) || section->sh_offset % 8)
			return -ENOEXEC;
		if (!(seq->sections[section->sh_info].sh_flags & SHF_ALLOC))
			continue;
		relocs = native_section_data(seq, i);
		for (j = 0; j < section->sh_size / sizeof(*relocs); j++) {
			const Elf64_Rela *rel = &relocs[j];
			u32 type = ELF64_R_TYPE(rel->r_info), width;
			u64 symbol, value, place;
			u8 *dest;
			int err;

			if (type == R_X86_64_NONE)
				continue;
			width = type == R_X86_64_64 || type == R_X86_64_PC64 ? 8 : 4;
			if (!native_range(rel->r_offset, width, seq->sections[section->sh_info].sh_size))
				return -ENOEXEC;
			err = native_symbol_value(seq, ELF64_R_SYM(rel->r_info), prog, addrs, image, &symbol);
			if (err)
				return err;
			place = (u64)native_address(prog->aux->native_image, seq, section->sh_info, image) + rel->r_offset;
			dest = native_address(prog->aux->native_image, seq, section->sh_info, rw_image) + rel->r_offset;
			value = symbol + rel->r_addend;
			switch (type) {
			case R_X86_64_PC32:
			case R_X86_64_PLT32:
				value -= place;
				fallthrough;
			case R_X86_64_32S:
				if ((s64)value != (s32)value)
					return -ERANGE;
				put_unaligned((u32)value, (u32 *)dest);
				break;
			case R_X86_64_32:
				if (value > U32_MAX)
					return -ERANGE;
				put_unaligned((u32)value, (u32 *)dest);
				break;
			case R_X86_64_PC64:
				value -= place;
				fallthrough;
			case R_X86_64_64:
				put_unaligned(value, (u64 *)dest);
				break;
			default:
				pr_err("bpf_jit: native sequence unsupported x86 relocation %u\n", type);
				return -EOPNOTSUPP;
			}
		}
	}
	return 0;
}

static int native_finish(struct bpf_prog *bpf_prog, int *addrs, u8 *image, u8 *rw_image,
			 bool aot)
{
	struct bpf_native_image *native = bpf_prog->aux->native_image;
	u32 i, j;
	int err;

	if (!native)
		return 0;
	for (i = 0; i < native->count; i++) {
		struct native_sequence *seq = &native->sequences[i];

		for (j = 1; j < seq->elf->e_shnum; j++) {
			const Elf64_Shdr *section = &seq->sections[j];

			if (native->module || j == seq->text || !(section->sh_flags & SHF_ALLOC))
				continue;
			if (section->sh_type == SHT_NOBITS)
				memset(rw_image + seq->offsets[j], 0, section->sh_size);
			else
				memcpy(rw_image + seq->offsets[j], native_section_data(seq, j), section->sh_size);
		}
		for (j = 0; j < seq->record->gotos_count; j++) {
			u32 offset;
			s32 delta;
			u8 *prog = rw_image + seq->gotos[j];

			err = native_goto_target(seq, j, bpf_prog, addrs, &offset);
			if (err)
				return err;
			if (!native_needs_exit(seq))
				continue;
			native_exit(&prog, seq);
			delta = offset - ((prog - rw_image) + 5);
			EMIT1_off32(0xe9, delta);
		}
		/* The final ELF linker applies symbolic relocations in AOT output. */
		if (!aot) {
			err = native_relocate(seq, bpf_prog, addrs, image, rw_image);
			if (err)
				return err;
		}
	}
	return 0;
}

/* Merge by ELF identity, preserving each input's alignment and symbol base.
 * Standard Linux module section handling owns all section-kind semantics.
 */
static int native_image_alloc(struct bpf_prog *prog, u32 length, u8 **image)
{
	struct bpf_native_image *native = prog->aux->native_image;
	Elf64_Shdr *out;
	char *names;
	u64 capacity = 4, names_size = 64;
	u32 i, j, names_used = 1;
	int err;

	for (i = 0; i < native->count; i++) {
		struct native_sequence *seq = &native->sequences[i];

		capacity += seq->elf->e_shnum;
		names_size += seq->names_size;
	}
	if (capacity > U16_MAX || names_size > U32_MAX)
		return -E2BIG;
	native->header = kvzalloc(sizeof(*native->header) + names_size, GFP_KERNEL);
	native->sections = kvcalloc(capacity, sizeof(*out), GFP_KERNEL);
	native->section_sources = kvcalloc(capacity, sizeof(void *), GFP_KERNEL);
	if (!native->header || !native->sections || !native->section_sources)
		return -ENOMEM;
	out = native->sections;
	names = (void *)(native->header + 1);
	memcpy(native->header->e_ident, ELFMAG, SELFMAG);
	native->header->e_ident[EI_CLASS] = ELFCLASS64;
	native->header->e_ident[EI_DATA] = ELFDATA2LSB;
	native->header->e_type = ET_REL;
	native->header->e_machine = EM_X86_64;
	native->header->e_shentsize = sizeof(*out);
	strscpy(names + names_used, ".text", names_size - names_used);
	out[1] = (Elf64_Shdr) { .sh_name = names_used, .sh_type = SHT_NOBITS,
		.sh_flags = SHF_ALLOC | SHF_EXECINSTR, .sh_addralign = BPF_IMAGE_ALIGNMENT,
		.sh_size = length };
	names_used += sizeof(".text");
	strscpy(names + names_used, ".bpf.jit.extable", names_size - names_used);
	out[2] = (Elf64_Shdr) { .sh_name = names_used, .sh_type = SHT_NOBITS,
		.sh_flags = SHF_ALLOC, .sh_addralign = __alignof__(struct exception_table_entry),
		.sh_size = prog->aux->num_exentries * sizeof(struct exception_table_entry) };
	names_used += sizeof(".bpf.jit.extable");
	native->section_count = 3;
	for (i = 0; i < native->count; i++) {
		struct native_sequence *seq = &native->sequences[i];

		seq->output_sections = kcalloc(seq->elf->e_shnum, sizeof(u32), GFP_KERNEL);
		seq->output_offsets = kcalloc(seq->elf->e_shnum, sizeof(u32), GFP_KERNEL);
		if (!seq->output_sections || !seq->output_offsets)
			return -ENOMEM;
		for (j = 1; j < seq->elf->e_shnum; j++) {
			const Elf64_Shdr *source = &seq->sections[j];
			const char *name = native_section_name(seq, j);
			Elf64_Shdr *section;
			u64 offset;
			u32 k;

			if (j == seq->text || !(source->sh_flags & SHF_ALLOC))
				continue;
			for (k = 3; k < native->section_count; k++)
				if (!strcmp(names + out[k].sh_name, name) &&
				    out[k].sh_flags == source->sh_flags && out[k].sh_type == source->sh_type)
					break;
			section = &out[k];
			if (k == native->section_count) {
				*section = *source;
				section->sh_name = names_used;
				section->sh_size = 0;
				section->sh_addr = section->sh_offset = 0;
				strscpy(names + names_used, name, names_size - names_used);
				names_used += strlen(name) + 1;
				native->section_count++;
			}
			offset = ALIGN(section->sh_size, source->sh_addralign ?: 1);
			if (offset > INT_MAX || source->sh_size > INT_MAX - offset)
				return -E2BIG;
			section->sh_size = offset + source->sh_size;
			section->sh_addralign = max(section->sh_addralign, source->sh_addralign);
			seq->output_sections[j] = k;
			seq->output_offsets[j] = offset;
		}
	}
	for (i = 3; i < native->section_count; i++) {
		if (out[i].sh_type == SHT_NOBITS)
			continue;
		out[i].sh_offset = (unsigned long)kvzalloc(out[i].sh_size, GFP_KERNEL);
		out[i].sh_addr = out[i].sh_offset;
		native->section_sources[i] = (void *)out[i].sh_offset;
		if (!out[i].sh_addr && out[i].sh_size)
			return -ENOMEM;
	}
	for (i = 0; i < native->count; i++) {
		struct native_sequence *seq = &native->sequences[i];

		for (j = 1; j < seq->elf->e_shnum; j++) {
			const Elf64_Shdr *source = &seq->sections[j];
			Elf64_Shdr *section = &out[seq->output_sections[j]];

			if (!seq->output_sections[j])
				continue;
			if (source->sh_type != SHT_NOBITS)
				memcpy((void *)section->sh_addr + seq->output_offsets[j],
				       native_section_data(seq, j), source->sh_size);
			if (source->sh_flags & SHF_LINK_ORDER) {
				if (source->sh_link >= seq->elf->e_shnum)
					return -ENOEXEC;
				section->sh_link = source->sh_link == seq->text ? 1 :
					seq->output_sections[source->sh_link];
			}
			if (source->sh_flags & SHF_INFO_LINK) {
				if (source->sh_info >= seq->elf->e_shnum)
					return -ENOEXEC;
				section->sh_info = source->sh_info == seq->text ? 1 :
					seq->output_sections[source->sh_info];
			}
		}
	}
	native->header->e_shstrndx = native->section_count++;
	out[native->header->e_shstrndx] = (Elf64_Shdr) { .sh_type = SHT_STRTAB,
		.sh_offset = sizeof(*native->header), .sh_size = names_used,
		.sh_addr = (unsigned long)names };
	native->header->e_shnum = native->section_count;
	native->module = module_section_image_alloc(native->header, out, names);
	if (IS_ERR(native->module)) {
		err = PTR_ERR(native->module);
		native->module = NULL;
		return err;
	}
	err = bpf_jit_charge_modmem(module_section_image_size(native->module));
	if (err)
		return err;
	native->charged = module_section_image_size(native->module);
	*image = (void *)out[1].sh_addr;
	jit_fill_hole(*image, length);
	prog->aux->extable = (void *)out[2].sh_addr;
	return 0;
}

static int native_finalize(struct bpf_prog *prog)
{
	struct bpf_native_image *native = prog->aux->native_image;
	int err;

	if (!native || native->finalized)
		return 0;
	err = module_section_image_finalize(native->module);
	if (!err)
		native->finalized = true;
	return err;
}

static int native_register(struct bpf_prog *prog)
{
	struct bpf_native_image *native = prog->aux->native_image;

	return native ? module_section_image_register(native->module) : 0;
}

/* A1's object finisher carries the original ELF sections and relocations into
 * the output. The locations here come from this JIT, never source byte offsets.
 */
static int native_aot_data(struct bpf_prog *prog, int *addrs, struct bpf_aot_context *aot)
{
	struct bpf_native_image *native = prog->aux->native_image;
	size_t size = 16;
	u32 *cursor, i, j;

	if (!native)
		return 0;
	for (i = 0; i < native->count; i++) {
		struct native_sequence *seq = &native->sequences[i];

		size += 16 + 4 * seq->elf->e_shnum + 4 * seq->record->gotos_count + seq->record->size;
	}
	if (size > U32_MAX)
		return -E2BIG;
	aot->native_data = kvzalloc(size, GFP_KERNEL);
	if (!aot->native_data)
		return -ENOMEM;
	aot->native_size = size;
	cursor = aot->native_data;
	*cursor++ = 0x314a534e; /* NSJ1 */
	*cursor++ = 1;
	*cursor++ = native->count;
	*cursor++ = 0;
	for (i = 0; i < native->count; i++) {
		struct native_sequence *seq = &native->sequences[i];

		*cursor++ = seq->insn;
		*cursor++ = seq->record->size;
		*cursor++ = seq->elf->e_shnum;
		*cursor++ = seq->record->gotos_count;
		for (j = 0; j < seq->elf->e_shnum; j++)
			*cursor++ = seq->offsets[j];
		for (j = 0; j < seq->record->gotos_count; j++) {
			u32 target;
			int err = native_goto_target(seq, j, prog, addrs, &target);

			if (err)
				return err;
			*cursor++ = native_needs_exit(seq) ? seq->gotos[j] : target;
		}
		memcpy(cursor, seq->record, seq->record->size);
		cursor = (void *)cursor + seq->record->size;
	}
	return 0;
}
