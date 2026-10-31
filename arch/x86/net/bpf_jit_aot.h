/* SPDX-License-Identifier: GPL-2.0-only */
/* ELF support for the x86 JIT. Included in its translation unit so AOT and
 * load-time compilation use the same instruction encoders and frame layout.
 */
#include <linux/bpf_aot.h>
#include <linux/btf.h>
#include <linux/elf.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/elf.h>

struct bpf_aot_record {
	Elf64_Rela rela;
	char name[BPF_AOT_SYMBOL_LEN];
};

struct bpf_aot_context {
	struct bpf_prog *root;
	struct bpf_prog *source;
	struct bpf_aot_reloc *operands;
	u32 nr_operands;
	struct bpf_aot_record *records;
	u32 nr_records, capacity;
	u8 *image;
	struct exception_table_entry *extable;
	u32 nr_exentries;
	void *native_data;
	u32 native_size;
	bool final;
	bool patchable_jumps;
	bool position_independent;
	const char *section;
	int error;
};

static const char *aot_function_name(const struct bpf_prog *prog)
{
	const struct bpf_prog_aux *aux = prog->aux;
	const struct btf_type *type;

	if (!aux->btf || !aux->func_info || aux->func_idx >= aux->func_info_cnt)
		return NULL;
	type = btf_type_by_id(aux->btf, aux->func_info[aux->func_idx].type_id);
	return type && btf_type_is_func(type) ? btf_name_by_offset(aux->btf, type->name_off) : NULL;
}

/* Frozen, read-only source constants receive final-image section bindings.
 * Mutable storage and map objects retain their load-instance identity and
 * cannot be exported as constants. This runs only during AOT export.
 */
static int aot_map_name(struct bpf_aot_context *aot, u64 address,
                        char *name, s64 *addend)
{
	struct bpf_prog_aux *aux = aot->root->aux;
	struct bpf_prog_aux *source = aot->source->aux;
	const struct btf_type *fn;
	u32 i;

	for (i = 0; i < aux->used_map_cnt; i++) {
		struct bpf_map *map = aux->used_maps[i];
		const struct btf_type *type;
		const char *section, *symbol;
		char prefix[BPF_AOT_SYMBOL_LEN];
		u64 base;

		if (address == (unsigned long)map)
			return -EOPNOTSUPP;
		if (!map->ops->map_direct_value_addr ||
		    map->ops->map_direct_value_addr(map, &base, 0) ||
		    address < base || address - base > map->value_size * (u64)map->max_entries)
			continue;
		if (!map->frozen || !(map->map_flags & BPF_F_RDONLY_PROG) ||
		    map->max_entries != 1 || !map->btf || !source->btf ||
		    !source->func_info || source->func_idx >= source->func_info_cnt)
			return -EOPNOTSUPP;
		type = btf_type_by_id(map->btf, map->btf_value_type_id);
		if (!type || btf_kind(type) != BTF_KIND_DATASEC)
			return -EOPNOTSUPP;
		section = btf_name_by_offset(map->btf, type->name_off);
		if (snprintf(prefix, sizeof(prefix), "aot:constant-pool:%s:", section) >= sizeof(prefix))
			return -ENAMETOOLONG;
		fn = btf_type_by_id(source->btf, source->func_info[source->func_idx].type_id);
		if (!fn || !btf_type_is_func(fn))
			return -EINVAL;
		symbol = btf_find_decl_tag_value(source->btf, fn, -1, prefix);
		if (IS_ERR(symbol))
			return PTR_ERR(symbol);
		if (!*symbol || strscpy(name, symbol, BPF_AOT_SYMBOL_LEN) < 0)
			return -ENAMETOOLONG;
		*addend = address - base;
		return 0;
	}
	return -ENOENT;
}

static int aot_address_name(struct bpf_aot_context *aot, unsigned long address,
			    char *name, s64 *addend)
{
	struct bpf_prog *root = aot->root;
	unsigned long size, offset;
	const char *found;
	char buffer[KSYM_NAME_LEN];
	char *module;
	u32 i;
	int err = aot_map_name(aot, address, name, addend);

	if (err != -ENOENT)
		return err;
	for (i = 0; i < (root->aux->func_cnt ?: 1); i++) {
		struct bpf_prog *func = root->aux->func_cnt ? root->aux->func[i] : root;

		if (address < (unsigned long)func->bpf_func ||
		    address >= (unsigned long)func->bpf_func + func->jited_len)
			continue;
		found = aot_function_name(func);
		if (!found)
			return -ENOENT;
		strscpy(name, found, BPF_AOT_SYMBOL_LEN);
		*addend = address - (unsigned long)func->bpf_func;
		return 0;
	}
	found = kallsyms_lookup(address, &size, &offset, &module, buffer);
	if (!found || offset >= size)
		return -ENOENT;
	if (strscpy(name, found, BPF_AOT_SYMBOL_LEN) < 0)
		return -ENAMETOOLONG;
	*addend = offset;
	return 0;
}

/* Symbolic operands describe the value the verifier actually saw. They
 * cannot turn an arbitrary scalar or pointer into a different build input.
 */
static int aot_validate_operand(const struct bpf_aot_reloc *operand,
				const struct bpf_insn *insn)
{
	static const struct { const char *prefix; u8 kind; } ids[] = {
		{ "__ebpfos_btf_id_func__", BTF_KIND_FUNC },
		{ "__ebpfos_btf_id_struct__", BTF_KIND_STRUCT },
		{ "__ebpfos_btf_id_union__", BTF_KIND_UNION },
		{ "__ebpfos_btf_id_var__", BTF_KIND_VAR },
		{ "__ebpfos_btf_id_typedef__", BTF_KIND_TYPEDEF },
		{ "__ebpfos_btf_id_enum__", BTF_KIND_ENUM },
	};
	u64 value;
	u32 i;

	if (insn->code == (BPF_LD | BPF_IMM | BPF_DW))
		value = ((u64)(u32)insn[1].imm << 32) | (u32)insn->imm;
	else if (BPF_CLASS(insn->code) == BPF_ALU)
		value = (u32)insn->imm;
	else
		value = (s64)insn->imm;
	if (operand->type == R_X86_64_64) {
		unsigned long address = kallsyms_lookup_name(operand->symbol);
		unsigned long size, offset;

		if (!address || operand->addend < 0 || address + operand->addend != value)
			return -EINVAL;
		if (!operand->addend)
			return 0;
		return kallsyms_lookup_size_offset(address, &size, &offset) && !offset &&
		       operand->addend <= size ? 0 : -EINVAL;
	}
	if (operand->type != R_X86_64_32 || operand->addend)
		return -EINVAL;
	for (i = 0; i < ARRAY_SIZE(ids); i++) {
		const char *name = str_has_prefix(operand->symbol, ids[i].prefix) ?
			operand->symbol + strlen(ids[i].prefix) : NULL;
		struct btf *btf;
		s32 id;

		if (!name || !*name)
			continue;
		btf = bpf_get_btf_vmlinux();
		if (IS_ERR_OR_NULL(btf))
			return -ENOENT;
		id = btf_find_by_name_kind(btf, name, ids[i].kind);
		return id > 0 && (u64)id == value ? 0 : -EINVAL;
	}
	return -EINVAL;
}


static int aot_record(struct bpf_aot_context *aot, u32 offset, u32 type,
		      const char *name, s64 addend)
{
	struct bpf_aot_record *record;

	if (!aot->final)
		return 0;
	if (aot->nr_records == aot->capacity) {
		u32 capacity = aot->capacity ? aot->capacity * 2 : 32;
		void *records = kvrealloc(aot->records, capacity * sizeof(*record), GFP_KERNEL);

		if (!records)
			return aot->error = -ENOMEM;
		aot->records = records;
		aot->capacity = capacity;
	}
	record = &aot->records[aot->nr_records++];
	memset(record, 0, sizeof(*record));
	record->rela.r_offset = offset;
	record->rela.r_info = (u64)type;
	record->rela.r_addend = addend;
	if (strscpy(record->name, name, sizeof(record->name)) < 0)
		return aot->error = -ENAMETOOLONG;
	return 0;
}

static int aot_record_address(struct bpf_aot_context *aot, u32 offset,
			      u32 type, unsigned long address, s64 bias)
{
	char name[BPF_AOT_SYMBOL_LEN];
	s64 addend;
	int err;

	if (!aot->final)
		return 0;
	err = aot_address_name(aot, address, name, &addend);
	if (err)
		return aot->error = err;
	return aot_record(aot, offset, type, name, addend + bias);
}

/* Every record has a symbol. Duplicates are legal ELF symbols and leave the
 * emission path independent of symbol-table ordering and allocation addresses.
 */
static int aot_build_elf(struct bpf_aot_context *aot, const char *function,
			 u8 *text, u32 text_size, int *offsets, u32 nr_offsets,
			 void **object, u32 *object_size)
{
	enum { NULL_SEC, TEXT, RELA, STRTAB, SYMTAB, SHSTRTAB, OFFSETS, STACK, EXTAB, EXRELA, NATIVE, NR_SECS };
	static const char shstrings[] = "\0.rela.text\0.strtab\0.symtab\0.shstrtab\0.bpf.aot.offsets\0.note.GNU-stack\0.text.";
	size_t strings_size = 1 + strlen(function) + 1;
	size_t shstrings_size = sizeof(shstrings) + strlen(function) + 1 + sizeof("__ex_table") + sizeof(".rela__ex_table") + sizeof(".bpf.aot.native");
	u32 nr_symbols = aot->nr_records + 3;
	size_t cursor = sizeof(Elf64_Ehdr);
	u32 i, names;
	Elf64_Ehdr *header;
	Elf64_Shdr *sections;
	Elf64_Sym *symbols;
	Elf64_Rela *relocations;
	size_t positions[NR_SECS] = {}, sizes[NR_SECS] = {};
	u32 nr_exrelocs = 0;
	u8 *data;

	if (aot->section)
		shstrings_size += 2 * (strlen(aot->section) + 1) + strlen(".rela");
	for (i = 0; i < aot->nr_records; i++)
		strings_size += strlen(aot->records[i].name) + 1;
	sizes[TEXT] = text_size;
	sizes[RELA] = aot->nr_records * sizeof(Elf64_Rela);
	sizes[STRTAB] = strings_size;
	sizes[SYMTAB] = nr_symbols * sizeof(Elf64_Sym);
	sizes[SHSTRTAB] = shstrings_size;
	sizes[OFFSETS] = nr_offsets * sizeof(u32);
	for (i = 0; i < aot->nr_exentries; i++) {
		nr_exrelocs++;
		if ((aot->extable[i].data & 0xff) != EX_TYPE_BPF)
			nr_exrelocs++;
	}
	sizes[EXTAB] = aot->nr_exentries * sizeof(*aot->extable);
	sizes[EXRELA] = nr_exrelocs * sizeof(Elf64_Rela);
	sizes[NATIVE] = aot->native_size;
	for (i = 1; i < NR_SECS; i++) {
		cursor = ALIGN(cursor, i == TEXT ? 16 : 8);
		positions[i] = cursor;
		cursor += sizes[i];
	}
	cursor = ALIGN(cursor, 8);
	if (cursor > U32_MAX - NR_SECS * sizeof(Elf64_Shdr))
		return -E2BIG;
	*object_size = cursor + NR_SECS * sizeof(Elf64_Shdr);
	data = kvzalloc(*object_size, GFP_KERNEL);
	if (!data)
		return -ENOMEM;
	header = (void *)data;
	memcpy(header->e_ident, ELFMAG, SELFMAG);
	header->e_ident[EI_CLASS] = ELFCLASS64;
	header->e_ident[EI_DATA] = ELFDATA2LSB;
	header->e_ident[EI_VERSION] = EV_CURRENT;
	header->e_type = ET_REL;
	header->e_machine = EM_X86_64;
	header->e_version = EV_CURRENT;
	header->e_ehsize = sizeof(*header);
	header->e_shoff = cursor;
	header->e_shentsize = sizeof(Elf64_Shdr);
	header->e_shnum = NR_SECS;
	header->e_shstrndx = SHSTRTAB;
	sections = (void *)(data + cursor);
	for (i = 1; i < NR_SECS; i++) {
		sections[i].sh_type = SHT_PROGBITS;
		sections[i].sh_offset = positions[i];
		sections[i].sh_size = sizes[i];
		sections[i].sh_addralign = 1;
	}
	sections[TEXT].sh_name = sizeof(shstrings) - sizeof(".text.");
	sections[TEXT].sh_flags = SHF_ALLOC | SHF_EXECINSTR;
	sections[TEXT].sh_addralign = 16;
	sections[RELA].sh_name = 1;
	sections[RELA].sh_type = SHT_RELA;
	sections[RELA].sh_entsize = sizeof(Elf64_Rela);
	sections[RELA].sh_link = SYMTAB;
	sections[RELA].sh_info = TEXT;
	sections[RELA].sh_addralign = 8;
	sections[STRTAB].sh_name = 12;
	sections[STRTAB].sh_type = SHT_STRTAB;
	sections[SYMTAB].sh_name = 20;
	sections[SYMTAB].sh_type = SHT_SYMTAB;
	sections[SYMTAB].sh_link = STRTAB;
	sections[SYMTAB].sh_info = 2;
	sections[SYMTAB].sh_entsize = sizeof(Elf64_Sym);
	sections[SYMTAB].sh_addralign = 8;
	sections[SHSTRTAB].sh_name = 28;
	sections[SHSTRTAB].sh_type = SHT_STRTAB;
	sections[OFFSETS].sh_name = 38;
	sections[OFFSETS].sh_entsize = sizeof(u32);
	sections[OFFSETS].sh_addralign = 4;
	sections[STACK].sh_name = 55;
	sections[EXTAB].sh_name = sizeof(shstrings) + strlen(function);
	sections[EXTAB].sh_flags = SHF_ALLOC;
	sections[EXTAB].sh_addralign = 4;
	sections[EXRELA].sh_name = sections[EXTAB].sh_name + sizeof("__ex_table");
	sections[EXRELA].sh_type = SHT_RELA;
	sections[EXRELA].sh_entsize = sizeof(Elf64_Rela);
	sections[EXRELA].sh_link = SYMTAB;
	sections[EXRELA].sh_info = EXTAB;
	sections[EXRELA].sh_addralign = 8;
	sections[NATIVE].sh_name = sections[EXRELA].sh_name + sizeof(".rela__ex_table");
	sections[NATIVE].sh_addralign = 8;
	if (aot->native_size)
		memcpy(data + positions[NATIVE], aot->native_data, aot->native_size);
	memcpy(data + positions[TEXT], text, text_size);
	for (i = 0; i < nr_offsets; i++)
		((u32 *)(data + positions[OFFSETS]))[i] = offsets[i] < 0 ? U32_MAX : offsets[i];
	memcpy(data + positions[SHSTRTAB], shstrings, sizeof(shstrings) - 1);
	strcpy(data + positions[SHSTRTAB] + sizeof(shstrings) - 1, function);
	strcpy(data + positions[SHSTRTAB] + sections[EXTAB].sh_name, "__ex_table");
	strcpy(data + positions[SHSTRTAB] + sections[EXRELA].sh_name, ".rela__ex_table");
	strcpy(data + positions[SHSTRTAB] + sections[NATIVE].sh_name, ".bpf.aot.native");
	if (aot->section) {
		/* Source placement is an emission property, independent of tier.
		 * Keep the exact compiler spelling, including explicit subsections.
		 */
		sections[TEXT].sh_name = sections[NATIVE].sh_name + sizeof(".bpf.aot.native");
		sections[RELA].sh_name = sections[TEXT].sh_name + strlen(aot->section) + 1;
		strcpy(data + positions[SHSTRTAB] + sections[TEXT].sh_name, aot->section);
		strcpy(data + positions[SHSTRTAB] + sections[RELA].sh_name, ".rela");
		strcat(data + positions[SHSTRTAB] + sections[RELA].sh_name, aot->section);
	}
	symbols = (void *)(data + positions[SYMTAB]);
	symbols[1].st_info = ((STB_LOCAL << 4) | STT_SECTION);
	symbols[1].st_shndx = TEXT;
	symbols[2].st_info = ((STB_GLOBAL << 4) | STT_FUNC);
	symbols[2].st_shndx = TEXT;
	symbols[2].st_name = 1;
	symbols[2].st_size = text_size;
	strcpy(data + positions[STRTAB] + 1, function);
	names = strlen(function) + 2;
	relocations = (void *)(data + positions[RELA]);
	for (i = 0; i < aot->nr_records; i++) {
		struct bpf_aot_record *record = &aot->records[i];

		relocations[i] = record->rela;
		relocations[i].r_info = ((u64)(i + 3) << 32) | ELF64_R_TYPE(record->rela.r_info);
		symbols[i + 3].st_info = ((STB_GLOBAL << 4) | STT_NOTYPE);
		symbols[i + 3].st_name = names;
		strcpy(data + positions[STRTAB] + names, record->name);
		names += strlen(record->name) + 1;
	}
	{
		struct exception_table_entry *entries = (void *)(data + positions[EXTAB]);
		Elf64_Rela *rels = (void *)(data + positions[EXRELA]);
		u32 next = 0;

		for (i = 0; i < aot->nr_exentries; i++) {
			const struct exception_table_entry *entry = &aot->extable[i];
			u32 base = i * sizeof(*entry);

			entries[i].data = entry->data;
			rels[next].r_offset = base;
			rels[next].r_info = ((u64)1 << 32) | R_X86_64_PC32;
			rels[next++].r_addend = (u8 *)&entry->insn + entry->insn - aot->image;
			if ((entry->data & 0xff) == EX_TYPE_BPF) {
				entries[i].fixup = entry->fixup;
			} else {
				rels[next].r_offset = base + 4;
				rels[next].r_info = ((u64)1 << 32) | R_X86_64_PC32;
				rels[next++].r_addend = (u8 *)&entry->fixup + entry->fixup - aot->image;
			}
		}
	}
	*object = data;
	return 0;
}
