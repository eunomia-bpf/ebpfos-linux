/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_SCALAR_RECORD_ABI_H
#define EBPFOS_FUNCTION_SCALAR_RECORD_ABI_H
/* x86-64 INTEGER input records occupying complete argument-register words.
 * This is cold ABI matching, not a verifier or a pointer capability rule.
 */
static const struct btf_type *cell_record_type(const struct btf *btf, u32 id)
{
 unsigned int depth;
 for (depth = 0; depth < 32; depth++) {
  const struct btf_type *t = btf_type_by_id(btf, id);
  if (!t || BTF_INFO_KIND(t->info) != BTF_KIND_TYPEDEF) return t;
  id = t->type;
 }
 return NULL;
}
static bool cell_record_tags(const struct btf *btf, const struct btf_type *target, bool parameter)
{
 u32 id;
 for (id = 1; ; id++) {
  const struct btf_type *tag = btf_type_by_id(btf, id);
  if (!tag) break;
  if (BTF_INFO_KIND(tag->info) == BTF_KIND_DECL_TAG &&
      btf_type_by_id(btf, tag->type) == target &&
      (!parameter || btf_decl_tag(tag)->component_idx >= 0)) return true;
 }
 return false;
}
static bool cell_record_type_tags(const struct btf *btf, u32 id)
{
 unsigned int depth;
 for (depth = 0; depth < 32; depth++) {
  const struct btf_type *t = btf_type_by_id(btf, id);
  if (cell_record_tags(btf, t, false)) return true;
  if (!t || BTF_INFO_KIND(t->info) != BTF_KIND_TYPEDEF) return false;
  id = t->type;
 }
 return true;
}
static bool cell_record_word(const struct btf_type *t)
{
 u32 value;
 if (!t || t->size != 8) return false;
 if (BTF_INFO_KIND(t->info) == BTF_KIND_ENUM64) return true;
 if (BTF_INFO_KIND(t->info) != BTF_KIND_INT) return false;
 value = *(const u32 *)(t + 1);
 return BTF_INT_BITS(value) == 64 && !BTF_INT_OFFSET(value) &&
        !(BTF_INT_ENCODING(value) & BTF_INT_BOOL);
}
static bool cell_native_result2_type(const struct btf *btf, u32 id)
{
 const struct btf_type *t = cell_record_type(btf, id);
 const struct btf_member *m;
 unsigned int i;
 if (cell_record_type_tags(btf, id) || !t || BTF_INFO_KIND(t->info) != BTF_KIND_STRUCT ||
     t->size != 16 || BTF_INFO_VLEN(t->info) != 2) return false;
 m = (const struct btf_member *)(t + 1);
 for (i = 0; i < 2; i++)
  if (btf_member_bit_offset(t, i) != i * 64 || btf_member_bitfield_size(t, i) ||
      cell_record_type_tags(btf, m[i].type) || !cell_record_word(cell_record_type(btf, m[i].type))) return false;
 return true;
}
/* Naturally aligned integer leaves fit one x86 INTEGER eightbyte. Padding
 * carries no field authority; pointer/floating/qualified/bitfield layouts and
 * every field contract remain excluded. This is only native ABI matching.
 */
static unsigned int cell_integer_record_alignment(const struct btf *btf, u32 id,
 unsigned int *bytes, unsigned int depth)
{
 const struct btf_type *t;
 unsigned int i, alignment = 1, end = 0;
 if (cell_record_type_tags(btf, id)) return 0;
 t = cell_record_type(btf, id);
 if (!t) return 0;
 if (BTF_INFO_KIND(t->info) == BTF_KIND_INT ||
     BTF_INFO_KIND(t->info) == BTF_KIND_ENUM || BTF_INFO_KIND(t->info) == BTF_KIND_ENUM64) {
  u32 value;
  *bytes = t->size;
  if (*bytes != 1 && *bytes != 2 && *bytes != 4 && *bytes != 8) return 0;
  if (BTF_INFO_KIND(t->info) != BTF_KIND_INT) return *bytes;
  value = *(const u32 *)(t + 1);
  return BTF_INT_BITS(value) == *bytes * 8 && !BTF_INT_OFFSET(value) ? *bytes : 0;
 }
 if (depth > 16) return 0;
 if (BTF_INFO_KIND(t->info) == BTF_KIND_ARRAY) {
  const struct btf_array *a = btf_array(t);
  unsigned int size = 0;
  alignment = cell_integer_record_alignment(btf, a->type, &size, depth + 1);
  if (!alignment || !a->nelems || size > 8 / a->nelems ||
      (a->nelems > 1 && size % alignment)) return 0;
  *bytes = size * a->nelems;
  return alignment;
 }
 if ((BTF_INFO_KIND(t->info) != BTF_KIND_STRUCT && BTF_INFO_KIND(t->info) != BTF_KIND_UNION) ||
     !t->size || t->size > 8 || !BTF_INFO_VLEN(t->info)) return 0;
 for (i = 0; i < BTF_INFO_VLEN(t->info); i++) {
  const struct btf_member *m = (const struct btf_member *)(t + 1);
  unsigned int size = 0, offset = btf_member_bit_offset(t, i), member;
  if (btf_member_bitfield_size(t, i)) return 0;
  member = cell_integer_record_alignment(btf, m[i].type, &size, depth + 1);
  if (!member || offset % (member * 8) || offset > t->size * 8 ||
      size * 8 > t->size * 8 - offset ||
      (BTF_INFO_KIND(t->info) == BTF_KIND_UNION ? offset != 0 : offset < end)) return 0;
  end = offset + size * 8;
  if (member > alignment) alignment = member;
 }
 *bytes = t->size;
 return alignment;
}
static unsigned int cell_single_scalar_record_bits(const struct btf *btf, u32 id,
 unsigned int depth)
{
 const struct btf_type *t = cell_record_type(btf, id);
 unsigned int bytes = 0;
 if (!t || (BTF_INFO_KIND(t->info) != BTF_KIND_STRUCT && BTF_INFO_KIND(t->info) != BTF_KIND_UNION) ||
     (t->size != 4 && t->size != 8)) return 0;
 return cell_integer_record_alignment(btf, id, &bytes, depth) ? bytes * 8 : 0;
}
static bool cell_single_scalar_record_register(const struct btf *native, u32 id,
 const struct btf *compiled, u32 actual)
{
 const struct btf_type *type;
 unsigned int bits = cell_single_scalar_record_bits(native, id, 0);
 u32 value;
 if (!bits || cell_record_type_tags(compiled, actual)) return false;
 type = cell_record_type(compiled, actual);
 if (!type || BTF_INFO_KIND(type->info) != BTF_KIND_INT) return false;
 value = *(const u32 *)(type + 1);
 return type->size * 8 == bits && BTF_INT_BITS(value) == bits &&
        !BTF_INT_OFFSET(value) && !(BTF_INT_ENCODING(value) & BTF_INT_BOOL);
}
static bool cell_scalar_record_inputs(struct btf *native, const struct btf_type *nf,
 struct btf *compiled, const struct btf_type *cf, bool result2)
{
 const struct btf_type *np, *cp, *result;
 const struct btf_param *args, *actual;
 unsigned int i, j, word = 0;
 bool record = false;
 if (!nf || !cf || BTF_INFO_KIND(nf->info) != BTF_KIND_FUNC ||
     BTF_INFO_KIND(cf->info) != BTF_KIND_FUNC ||
     cell_record_tags(native, nf, true) || cell_record_tags(compiled, cf, true)) return false;
 np = btf_type_by_id(native, nf->type);cp = btf_type_by_id(compiled, cf->type);
 if (!np || !cp || BTF_INFO_KIND(np->info) != BTF_KIND_FUNC_PROTO ||
     BTF_INFO_KIND(cp->info) != BTF_KIND_FUNC_PROTO || BTF_INFO_VLEN(cp->info) > 5) return false;
 result = cell_record_type(native, np->type);
 if (np->type && !(result2 && cell_native_result2_type(native, np->type)) && (!result || (BTF_INFO_KIND(result->info) != BTF_KIND_INT &&
     BTF_INFO_KIND(result->info) != BTF_KIND_ENUM && BTF_INFO_KIND(result->info) != BTF_KIND_ENUM64) ||
     !result->size || result->size > 8)) return false;
 args = (const struct btf_param *)(np + 1);actual = (const struct btf_param *)(cp + 1);
 for (i = 0; i < BTF_INFO_VLEN(np->info); i++) {
  const struct btf_type *t = cell_record_type(native, args[i].type);
  unsigned int words;
  if (cell_record_type_tags(native, args[i].type)) return false;
  if (cell_record_word(t)) words = 1;
  else {
   const struct btf_member *members;
   if (!t || BTF_INFO_KIND(t->info) != BTF_KIND_STRUCT || (t->size != 8 && t->size != 16) ||
       BTF_INFO_VLEN(t->info) != t->size / 8) return false;
   members = (const struct btf_member *)(t + 1);words = t->size / 8;
   for (j = 0; j < words; j++)
    if (btf_member_bit_offset(t, j) != j * 64 || btf_member_bitfield_size(t, j) ||
        cell_record_type_tags(native, members[j].type) ||
        !cell_record_word(cell_record_type(native, members[j].type))) return false;
   record = true;
  }
  for (j = 0; j < words; j++, word++)
   if (word >= BTF_INFO_VLEN(cp->info) ||
       cell_record_type_tags(compiled, actual[word].type) ||
       !cell_record_word(cell_record_type(compiled, actual[word].type))) return false;
 }
 return record && word == BTF_INFO_VLEN(cp->info);
}
#endif
