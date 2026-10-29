/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef RESOLVE_BTFIDS_STORAGE_VARS_H
#define RESOLVE_BTFIDS_STORAGE_VARS_H
/* Match native storage to ELF before publishing VAR/DATASEC descriptions.
 * LTO can shrink allocations or retain several DWARF views of one object.
 * Invalid declarations must disappear too: a stale VAR must not supply a
 * larger allocation to a later compiler or linker. */
struct storage_allocation {
 const char *section, *name;
 unsigned long long offset, size, section_size;
};
struct storage_section { unsigned int count, size; struct btf_var_secinfo *cells; };
static int storage_allocation_compare(const void *left, const void *right)
{
 const struct storage_allocation *a = left, *b = right;
 int order = strcmp(a->section, b->section);
 if (order) return order;
 if (a->offset != b->offset) return a->offset < b->offset ? -1 : 1;
 return strcmp(a->name, b->name);
}
static bool storage_type_id(__u32 *id, const unsigned int *ids, unsigned int count)
{
 if (*id >= count || (*id && !ids[*id])) return false;
 *id = ids[*id];return true;
}
static bool storage_type_refs(struct btf_type *type, const unsigned int *ids, unsigned int count)
{
 unsigned int i, kind = btf_kind(type);
 if (kind == BTF_KIND_PTR || kind == BTF_KIND_TYPEDEF || kind == BTF_KIND_CONST ||
     kind == BTF_KIND_VOLATILE || kind == BTF_KIND_RESTRICT || kind == BTF_KIND_FUNC ||
     kind == BTF_KIND_FUNC_PROTO || kind == BTF_KIND_VAR || kind == BTF_KIND_DECL_TAG ||
     kind == BTF_KIND_TYPE_TAG)
  if (!storage_type_id(&type->type, ids, count)) return false;
 if (btf_is_array(type)) {
  struct btf_array *array = (void *)(type + 1);
  if (!storage_type_id(&array->type, ids, count) || !storage_type_id(&array->index_type, ids, count)) return false;
 }
 if (btf_is_struct(type) || btf_is_union(type)) {
  struct btf_member *members = (void *)(type + 1);
  for (i = 0; i < btf_vlen(type); ++i) if (!storage_type_id(&members[i].type, ids, count)) return false;
 }
 if (btf_is_func_proto(type)) {
  struct btf_param *parameters = (void *)(type + 1);
  for (i = 0; i < btf_vlen(type); ++i) if (!storage_type_id(&parameters[i].type, ids, count)) return false;
 }
 return true;
}
/* A flexible initializer enlarges the allocation, not its nominal C type.
 * Every by-value element must have a complete fixed stride. Pointees do not
 * contribute to that stride; an embedded incomplete array does. */
static bool storage_fixed_element(const struct btf *btf, unsigned int id, unsigned int depth)
{
 const struct btf_type *type;
 int resolved = btf__resolve_type(btf, id);
 unsigned int i;
 if (resolved <= 0 || depth > 64 || btf__resolve_size(btf, resolved) <= 0) return false;
 type = btf__type_by_id(btf, resolved);
 if (btf_is_ptr(type) || btf_is_int(type) || btf_is_enum(type) || btf_is_enum64(type)) return true;
 if (btf_is_array(type))
  return btf_array(type)->nelems && storage_fixed_element(btf, btf_array(type)->type, depth + 1);
 if (!btf_is_struct(type) && !btf_is_union(type)) return false;
 for (i = 0; i < btf_vlen(type); ++i)
  if (!storage_fixed_element(btf, btf_members(type)[i].type, depth + 1)) return false;
 return true;
}
static bool storage_flexible_extent(const struct btf *btf, unsigned int id,
                                    unsigned long long bytes)
{
 const struct btf_type *record, *tail;
 unsigned int last, element;
 long long width;
 int resolved = btf__resolve_type(btf, id);
 if (resolved <= 0) return false;
 record = btf__type_by_id(btf, resolved);
 if (!btf_is_struct(record) || !record->size || !btf_vlen(record) || bytes <= record->size) return false;
 last = btf_vlen(record) - 1;
 if (btf_member_bitfield_size(record, last) ||
     btf_member_bit_offset(record, last) != (unsigned long long)record->size * 8) return false;
 resolved = btf__resolve_type(btf, btf_members(record)[last].type);
 if (resolved <= 0) return false;
 tail = btf__type_by_id(btf, resolved);
 if (!btf_is_array(tail) || btf_array(tail)->nelems) return false;
 element = btf_array(tail)->type;width = btf__resolve_size(btf, element);
 return width > 0 && storage_fixed_element(btf, element, 0) &&
        !((bytes - record->size) % (unsigned long long)width);
}
static int normalize_storage_vars(struct object *obj)
{
 struct storage_allocation *allocations = NULL;
 struct storage_section *sections = NULL;
 struct btf *input = obj->btf, *output = NULL;
 unsigned char *remove = NULL, *live = NULL;
 unsigned int *ids = NULL;
 GElf_Shdr symbols;
 Elf_Scn *scn;
 size_t strings, count = 0, total, i;
 unsigned int first = obj->base_btf ? btf__type_cnt(obj->base_btf) : 1;
 unsigned int types = btf__type_cnt(input), id, kept = 0, omitted = 0, removed = 0, next;
 int error = -EINVAL;
 if (obj->efile.symbols_shndx < 0) return 0;
 scn = elf_getscn(obj->efile.elf, obj->efile.symbols_shndx);
 if (!scn || !gelf_getshdr(scn, &symbols) || !symbols.sh_entsize ||
     elf_getshdrstrndx(obj->efile.elf, &strings)) return -EINVAL;
 if (!btf__pointer_size(input) && btf__set_pointer_size(input,
     gelf_getclass(obj->efile.elf) == ELFCLASS32 ? 4 : 8)) return -EINVAL;
 total = symbols.sh_size / symbols.sh_entsize;
 allocations = calloc(total, sizeof(*allocations));
 sections = calloc(types, sizeof(*sections));remove = calloc(types, 1);live = calloc(types, 1);
 ids = calloc(types, sizeof(*ids));
 if (!allocations || !sections || !remove || !live || !ids) {error = -ENOMEM;goto out;}
 for (i = 0; i < total; ++i) {
  GElf_Sym symbol;
  GElf_Shdr area;
  const char *name, *section;
  if (!gelf_getsym(obj->efile.symbols, i, &symbol)) goto out;
  if (GELF_ST_TYPE(symbol.st_info) != STT_OBJECT || !symbol.st_size ||
      symbol.st_shndx == SHN_UNDEF || symbol.st_shndx >= SHN_LORESERVE) continue;
  scn = elf_getscn(obj->efile.elf, symbol.st_shndx);
  if (!scn || !gelf_getshdr(scn, &area)) goto out;
  name = elf_strptr(obj->efile.elf, symbols.sh_link, symbol.st_name);
  section = elf_strptr(obj->efile.elf, strings, area.sh_name);
  if (!name || !section || symbol.st_value < area.sh_addr ||
      symbol.st_value - area.sh_addr > area.sh_size ||
      symbol.st_size > area.sh_size - (symbol.st_value - area.sh_addr)) continue;
  allocations[count++] = (struct storage_allocation){section, name,
   symbol.st_value - area.sh_addr, symbol.st_size, area.sh_size};
 }
 qsort(allocations, count, sizeof(*allocations), storage_allocation_compare);
 for (id = first; id < types; ++id) {
  const struct btf_type *type = btf__type_by_id(input, id);
  const char *section = btf__name_by_offset(input, type->name_off);
  const struct btf_var_secinfo *cells;
  unsigned long long end = 0;
  unsigned int j;
  if (!btf_is_datasec(type)) continue;
  sections[id].cells = calloc(btf_vlen(type) ?: 1, sizeof(*cells));
  if (!sections[id].cells) {error = -ENOMEM;goto out;}
  cells = btf_var_secinfos(type);sections[id].size = type->size;
  for (j = 0; j < btf_vlen(type); ++j) {
   struct btf_var_secinfo extent = cells[j];
   const struct btf_var_secinfo *cell = &extent;
   const struct btf_type *variable = btf__type_by_id(input, cell->type);
   struct storage_allocation key, *allocation;
   long long bytes;
   bool valid;
   if (!variable || !btf_is_var(variable) || cell->type >= types) goto out;
   key = (struct storage_allocation){section,
    btf__name_by_offset(input, variable->name_off), cell->offset, cell->size, type->size};
   allocation = bsearch(&key, allocations, count, sizeof(*allocations), storage_allocation_compare);
   bytes = btf__resolve_size(input, variable->type);
   /* Pahole reports sizeof(C record), while ELF includes its initialized
    * flexible tail. Expand only this exact object's span, without changing
    * the type, inventing storage or accepting aliases of the extra bytes. */
   if (allocation && bytes > 0 && (unsigned long long)bytes == cell->size &&
       allocation->size > cell->size && allocation->size <= UINT_MAX &&
       allocation->section_size <= UINT_MAX && type->size <= allocation->section_size &&
       (btf_var(variable)->linkage == BTF_VAR_STATIC ||
        btf_var(variable)->linkage == BTF_VAR_GLOBAL_ALLOCATED) &&
       storage_flexible_extent(input, variable->type, allocation->size)) {
    size_t k;
    bool distinct = true;
    for (k = 0; k < count; ++k) {
     const struct storage_allocation *other = &allocations[k];
     if (other == allocation || strcmp(other->section, allocation->section)) continue;
     if (other->offset < allocation->offset + allocation->size &&
         allocation->offset < other->offset + other->size) {distinct = false;break;}
    }
    if (distinct) {
     extent.size = allocation->size;
     sections[id].size = allocation->section_size;
    }
   }
   /* The existing per-CPU pass owns its whole-section allocation alias. */
   valid = !strcmp(section, ".data..percpu") ||
    (allocation && allocation->size == cell->size && bytes >= 0 &&
     (unsigned long long)bytes <= cell->size && cell->size && cell->offset >= end &&
     cell->offset < sections[id].size && cell->size <= sections[id].size - cell->offset);
   if (!valid) {
    pr_debug("storage BTF: omit %s:%s offset=%u size=%u; no distinct matching ELF allocation\n",
     section, key.name, cell->offset, cell->size);
    remove[cell->type] = 1;++omitted;continue;
   }
   sections[id].cells[sections[id].count++] = *cell;
   live[cell->type] = 1;end = (unsigned long long)cell->offset + cell->size;++kept;
  }
 }
 for (id = first; id < types; ++id) if (live[id]) remove[id] = 0;
 /* Declaration annotations cannot outlive a removed allocation. */
 for (id = first; id < types; ++id) {
  const struct btf_type *type = btf__type_by_id(input, id);
  if ((btf_is_decl_tag(type) || btf_is_type_tag(type)) && type->type < types && remove[type->type])
   remove[id] = 1;
 }
 next = first;
 for (id = 1; id < first; ++id) ids[id] = id;
 for (id = first; id < types; ++id) if (!remove[id]) ids[id] = next++;else ++removed;
 output = btf__new_empty_split(obj->base_btf);
 if (libbpf_get_error(output)) {error = libbpf_get_error(output);output = NULL;goto out;}
 if (btf__set_pointer_size(output, btf__pointer_size(input)) ||
     btf__set_endianness(output, btf__endianness(input))) goto out;
 for (id = first; id < types; ++id) {
  const struct btf_type *type = btf__type_by_id(input, id);
  int added;
  if (remove[id]) continue;
  if (btf_is_datasec(type)) {
   unsigned int j;
   added = btf__add_datasec(output, btf__name_by_offset(input, type->name_off), sections[id].size);
   for (j = 0; added >= 0 && j < sections[id].count; ++j) {
    struct btf_var_secinfo cell = sections[id].cells[j];
    if (!storage_type_id(&cell.type, ids, types) ||
        btf__add_datasec_var_info(output, cell.type, cell.offset, cell.size)) goto out;
   }
  } else added = btf__add_type(output, input, type);
  if (added < 0 || (unsigned int)added != ids[id] ||
      !storage_type_refs((struct btf_type *)btf__type_by_id(output, added), ids, types)) goto out;
 }
 obj->btf = output;output = NULL;btf__free(input);error = 0;
 if (omitted) fprintf(stderr, "storage BTF: retained %u cells; omitted %u cells and %u invalid declarations\n", kept, omitted, removed);
out:
 btf__free(output);
 for (id = 0; sections && id < types; ++id) free(sections[id].cells);
 free(sections);free(allocations);free(remove);free(live);free(ids);return error;
}
#endif
