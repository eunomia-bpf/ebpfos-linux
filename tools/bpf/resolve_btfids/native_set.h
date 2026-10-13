/* SPDX-License-Identifier: GPL-2.0-only */
/* Preserve the original callable ABI; assembler entries borrow a source member's ABI. */
struct native_set_entry {
	const char *native;
	const char *record;
	const char *field;
};

#define NATIVE_FUNCTION(source, native, flags) { #native, NULL, NULL },
#define NATIVE_PROTOTYPE(source)
#define NATIVE_INLINE_FUNCTION(source, native, flags) { #native, NULL, NULL },
#define NATIVE_STATIC_CALL(source, native, record, field, flags) { #native, #record, #field },
#define NATIVE_ALIAS(source, native)
#define NATIVE_ARG(native, index, tag)
#define NATIVE_ENUM_MAX(native, index, record, sentinel)
#define NATIVE_COUNT_MAX(native, index, count)
#define NATIVE_POINTEE_TAG(native, index, tag)
static const struct native_set_entry native_set_entries[] = {
#include "../../../include/linux/ebpfos_native_set.def"
};
#undef NATIVE_FUNCTION
#undef NATIVE_PROTOTYPE
#undef NATIVE_INLINE_FUNCTION
#undef NATIVE_STATIC_CALL
#undef NATIVE_ALIAS
#undef NATIVE_ARG
#undef NATIVE_ENUM_MAX
#undef NATIVE_COUNT_MAX
#undef NATIVE_POINTEE_TAG

enum native_contract_kind {
	NATIVE_CONTRACT_ARG,
	NATIVE_CONTRACT_ENUM_MAX,
	NATIVE_CONTRACT_COUNT_MAX,
	NATIVE_CONTRACT_POINTEE_TAG,
};

struct native_set_contract {
	const char *native;
	int index;
	enum native_contract_kind kind;
	const char *tag;
	const char *record;
	const char *sentinel;
};

#define NATIVE_FUNCTION(source, native, flags)
#define NATIVE_PROTOTYPE(source)
#define NATIVE_INLINE_FUNCTION(source, native, flags)
#define NATIVE_STATIC_CALL(source, native, record, field, flags)
#define NATIVE_ALIAS(source, native)
#define NATIVE_ARG(native, index, tag) { #native, index, NATIVE_CONTRACT_ARG, tag, NULL, NULL },
#define NATIVE_ENUM_MAX(native, index, record, sentinel) \
	{ #native, index, NATIVE_CONTRACT_ENUM_MAX, NULL, #record, #sentinel },
#define NATIVE_COUNT_MAX(native, index, count) \
	{ #native, index, NATIVE_CONTRACT_COUNT_MAX, NULL, "ebpfos_native_scalar_counts", "__native_count_" #native "_" #index },
#define NATIVE_POINTEE_TAG(native, index, tag) \
	{ #native, index, NATIVE_CONTRACT_POINTEE_TAG, tag, NULL, NULL },
static const struct native_set_contract native_set_contracts[] = {
#include "../../../include/linux/ebpfos_native_set.def"
};
#undef NATIVE_FUNCTION
#undef NATIVE_PROTOTYPE
#undef NATIVE_INLINE_FUNCTION
#undef NATIVE_STATIC_CALL
#undef NATIVE_ALIAS
#undef NATIVE_ARG
#undef NATIVE_ENUM_MAX
#undef NATIVE_COUNT_MAX
#undef NATIVE_POINTEE_TAG

static int native_unique_type(const struct btf *btf, const char *name, u32 kind)
{
	int found = -ENOENT;
	u32 id;

	for (id = 1; id < btf__type_cnt(btf); id++) {
		const struct btf_type *t = btf__type_by_id(btf, id);

		if (btf_kind(t) != kind || strcmp(btf__name_by_offset(btf, t->name_off), name))
			continue;
		if (found >= 0)
			return -EEXIST;
		found = id;
	}
	return found;
}

static int native_code_symbol(struct object *obj, const char *name)
{
	Elf_Data *symbols = obj->efile.symbols;
	size_t i, count;
	bool found = false;

	if (!symbols || !symbols->d_buf)
		return -ENOENT;
	count = symbols->d_size / gelf_fsize(obj->efile.elf, ELF_T_SYM, 1, EV_CURRENT);
	for (i = 0; i < count; i++) {
		GElf_Sym sym;
		GElf_Shdr section;
		unsigned int kind;
		const char *symbol_name;
		Elf_Scn *scn;

		if (!gelf_getsym(symbols, i, &sym))
			return -EINVAL;
		symbol_name = elf_strptr(obj->efile.elf, obj->efile.strtabidx, sym.st_name);
		if (!symbol_name || strcmp(symbol_name, name) || sym.st_shndx == SHN_UNDEF)
			continue;
		kind = GELF_ST_TYPE(sym.st_info);
		scn = elf_getscn(obj->efile.elf, sym.st_shndx);
		if (found || !scn || !gelf_getshdr(scn, &section) ||
		    !(section.sh_flags & SHF_EXECINSTR) ||
		    (kind != STT_FUNC && kind != STT_NOTYPE) || !sym.st_size)
			return -EINVAL;
		found = true;
	}
	return found ? 0 : -ENOENT;
}

static int native_member_proto(const struct btf *btf, const char *record, const char *field)
{
	const struct btf_type *t;
	const struct btf_member *m;
	int id, proto = -ENOENT;
	u32 i;

	id = native_unique_type(btf, record, BTF_KIND_STRUCT);
	if (id < 0)
		return id;
	t = btf__type_by_id(btf, id);
	m = btf_members(t);
	for (i = 0; i < btf_vlen(t); i++) {
		const struct btf_type *p;

		if (strcmp(btf__name_by_offset(btf, m[i].name_off), field))
			continue;
		if (proto >= 0 || btf_member_bitfield_size(t, i))
			return -EINVAL;
		id = btf__resolve_type(btf, m[i].type);
		p = btf__type_by_id(btf, id);
		if (!p || !btf_is_ptr(p))
			return -EINVAL;
		id = btf__resolve_type(btf, p->type);
		p = btf__type_by_id(btf, id);
		if (!p || !btf_is_func_proto(p))
			return -EINVAL;
		proto = id;
	}
	return proto;
}

static int native_decl_tag(struct btf *btf, int id, int index, const char *tag)
{
	u32 i;

	for (i = 1; i < btf__type_cnt(btf); i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);

		if (btf_is_decl_tag(t) && t->type == id &&
		    btf_decl_tag(t)->component_idx == index &&
		    !strcmp(btf__name_by_offset(btf, t->name_off), tag))
			return 0;
	}
	return btf__add_decl_tag(btf, tag, id, index) < 0 ? -EINVAL : 0;
}

static int native_enum_max(const struct btf *btf, const struct native_set_contract *c,
			   u32 arg_type, char *tag, size_t size)
{
	const struct btf_type *t;
	unsigned long long value = 0;
	bool found = false;
	int id;
	u32 i;

	id = btf__resolve_type(btf, arg_type);
	t = btf__type_by_id(btf, id);
	if (c->kind == NATIVE_CONTRACT_COUNT_MAX) {
		if (!t || (!btf_is_int(t) && !btf_is_enum(t) && !btf_is_enum64(t)) ||
		    (t->size != sizeof(u32) && t->size != sizeof(u64)))
			return -EINVAL;
		id = native_unique_type(btf, c->record, BTF_KIND_ENUM);
		if (id == -ENOENT)
			id = native_unique_type(btf, c->record, BTF_KIND_ENUM64);
		if (id < 0)
			return id;
		t = btf__type_by_id(btf, id);
	}
	if (!t || (!btf_is_enum(t) && !btf_is_enum64(t)) ||
	    strcmp(btf__name_by_offset(btf, t->name_off), c->record))
		return -EINVAL;
	for (i = 0; i < btf_vlen(t); i++) {
		u32 name_off = btf_is_enum(t) ? btf_enum(t)[i].name_off : btf_enum64(t)[i].name_off;

		if (strcmp(btf__name_by_offset(btf, name_off), c->sentinel))
			continue;
		if (found)
			return -EINVAL;
		if (btf_is_enum(t)) {
			if (btf_enum(t)[i].val <= 0)
				return -EINVAL;
			value = btf_enum(t)[i].val;
		} else {
			value = btf_enum64_value(&btf_enum64(t)[i]);
			if (!value || (btf_kflag(t) && (long long)value < 0))
				return -EINVAL;
		}
		found = true;
	}
	if (!found || (c->kind == NATIVE_CONTRACT_COUNT_MAX && value - 1 > UINT_MAX) ||
	    snprintf(tag, size, "arg:max:%llu", value - 1) >= (int)size)
		return -EINVAL;
	return 0;
}

static int native_pointee_tag(struct btf *btf, int func, int index, const char *tag)
{
	const struct btf_type *f = btf__type_by_id(btf, func);
	const struct btf_type *proto = btf__type_by_id(btf, f->type);
	const struct btf_type *ptr = btf__type_by_id(btf, btf_params(proto)[index].type);
	struct btf_param *params;
	u32 ret = proto->type, count = btf_vlen(proto), pointee;
	int new_tag, new_ptr, new_proto, err = -EINVAL;
	u32 i;

	if (!ptr || !btf_is_ptr(ptr))
		return -EINVAL;
	pointee = ptr->type;
	while (pointee) {
		const struct btf_type *t = btf__type_by_id(btf, pointee);

		if (!t)
			return -EINVAL;
		if (btf_is_type_tag(t) && !strcmp(btf__name_by_offset(btf, t->name_off), tag))
			return 0;
		if (!btf_is_mod(t))
			break;
		pointee = t->type;
	}
	params = malloc(count * sizeof(*params));
	if (!params)
		return -ENOMEM;
	memcpy(params, btf_params(proto), count * sizeof(*params));
	pointee = ptr->type;
	new_tag = btf__add_type_tag(btf, tag, pointee);
	if (new_tag < 0)
		goto out;
	new_ptr = btf__add_ptr(btf, new_tag);
	if (new_ptr < 0)
		goto out;
	params[index].type = new_ptr;
	new_proto = btf__add_func_proto(btf, ret);
	if (new_proto < 0)
		goto out;
	for (i = 0; i < count; i++) {
		/* Appending a type can relocate both the type and string buffers. */
		char *name = strdup(btf__name_by_offset(btf, params[i].name_off));

		if (!name) {
			err = -ENOMEM;
			goto out;
		}
		err = btf__add_func_param(btf, name, params[i].type);
		free(name);
		if (err < 0)
			goto out;
	}
	((struct btf_type *)btf__type_by_id(btf, func))->type = new_proto;
	err = 0;
out:
	free(params);
	return err;
}

static int native_set_btf(struct object *obj)
{
	struct btf *btf = obj->btf;
	size_t i;

	if (obj->base_btf)
		return -EINVAL;
	for (i = 0; i < sizeof(native_set_entries) / sizeof(native_set_entries[0]); i++) {
		const struct native_set_entry *e = &native_set_entries[i];
		int func, proto;

		if (native_code_symbol(obj, e->native)) {
			fprintf(stderr, "native set: missing original code symbol %s\n", e->native);
			return -EINVAL;
		}
		func = native_unique_type(btf, e->native, BTF_KIND_FUNC);
		if (e->record) {
			proto = native_member_proto(btf, e->record, e->field);
			if (proto < 0)
				return proto;
			if (func == -ENOENT)
				func = btf__add_func(btf, e->native, BTF_FUNC_GLOBAL, proto);
			else if (func >= 0 && btf__type_by_id(btf, func)->type != proto)
				return -EINVAL;
		}
		/* Assembly has no DWARF function body. Borrow only the original C
		 * declaration retained by NATIVE_PROTOTYPE, never a guessed ABI.
		 * An ambiguous existing FUNC is still an error.
		 */
		if (func == -ENOENT && !e->record) {
			char record[256];
			int length = snprintf(record, sizeof(record),
					      "ebpfos_native_proto_%s", e->native);
			if (length < 0 || (size_t)length >= sizeof(record))
				return -EINVAL;
			proto = native_member_proto(btf, record, "fn");
			if (proto >= 0)
				func = btf__add_func(btf, e->native, BTF_FUNC_GLOBAL, proto);
		}
		if (func < 0) {
			fprintf(stderr, "native set: missing unique FUNC prototype %s\n", e->native);
			return func;
		}
		if (!btf_is_func_proto(btf__type_by_id(btf, btf__type_by_id(btf, func)->type)) ||
		    native_decl_tag(btf, func, -1, "bpf_kfunc"))
			return -EINVAL;
	}
	for (i = 0; i < sizeof(native_set_contracts) / sizeof(native_set_contracts[0]); i++) {
		const struct native_set_contract *c = &native_set_contracts[i];
		int func = native_unique_type(btf, c->native, BTF_KIND_FUNC), err;
		const struct btf_type *proto;
		char tag[64];

		if (func < 0)
			return func;
		proto = btf__type_by_id(btf, btf__type_by_id(btf, func)->type);
		if (c->index < 0 || c->index >= btf_vlen(proto))
			return -EINVAL;
		if (c->kind == NATIVE_CONTRACT_POINTEE_TAG) {
			err = native_pointee_tag(btf, func, c->index, c->tag);
		} else if (c->kind == NATIVE_CONTRACT_ENUM_MAX || c->kind == NATIVE_CONTRACT_COUNT_MAX) {
			err = native_enum_max(btf, c, btf_params(proto)[c->index].type, tag, sizeof(tag));
			if (!err)
				err = native_decl_tag(btf, func, c->index, tag);
		} else {
			err = native_decl_tag(btf, func, c->index, c->tag);
		}
		if (err) {
			fprintf(stderr, "native set: invalid contract for %s argument %d\n", c->native, c->index);
			return err;
		}
	}
	return 0;
}
