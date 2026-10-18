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
static bool cell_scalar_record_inputs(struct btf *native, const struct btf_type *nf,
 struct btf *compiled, const struct btf_type *cf)
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
 if (np->type && (!result || (BTF_INFO_KIND(result->info) != BTF_KIND_INT &&
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
