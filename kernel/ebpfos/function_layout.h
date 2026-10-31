// SPDX-License-Identifier: GPL-2.0-only
#ifndef EBPFOS_FUNCTION_LAYOUT_H
#define EBPFOS_FUNCTION_LAYOUT_H
/* One cold layout comparison for kernel publication, source planning and
 * choosing the load context of an already named callback. This is metadata
 * matching; it neither verifies a body nor selects an export by its type.
 */
#ifdef __KERNEL__
#include <linux/btf.h>
#include <linux/string.h>
#define cell_layout_type btf_type_by_id
#define cell_layout_name btf_name_by_offset
#define cell_layout_count btf_nr_types
#else
#include <bpf/btf.h>
#include <stdbool.h>
#include <string.h>
#define cell_layout_type btf__type_by_id
#define cell_layout_name btf__name_by_offset
#define cell_layout_count btf__type_cnt
#endif
/* BTF represents C ellipsis as an unnamed trailing type-zero parameter, not
 * a physical argument. Share the shape check with compiler and call readers.
 */
static inline bool cell_function_parameters(const struct btf_type *prototype,
 unsigned int *fixed, bool *variadic)
{
 unsigned int i, count;
 if (!prototype || BTF_INFO_KIND(prototype->info) != BTF_KIND_FUNC_PROTO) return false;
 count = BTF_INFO_VLEN(prototype->info);
 *fixed = count; *variadic = false;
 for (i = 0; i < count; ++i) if (!btf_params(prototype)[i].type) {
  if (i + 1 != count || btf_params(prototype)[i].name_off) return false;
  --*fixed; *variadic = true;
 }
 return true;
}
/* This provider-body guarantee is emitted only after the complete Native
 * footprint proof. It grants no type or extent to an anonymous value.
 */
static inline bool cell_variadic_tail_unused(const struct btf *btf,
 const struct btf_type *function)
{
 const struct btf_type *prototype;
 unsigned int id, count;
 bool variadic;
 if (!function || BTF_INFO_KIND(function->info) != BTF_KIND_FUNC) return false;
 prototype = cell_layout_type(btf, function->type);
 if (!cell_function_parameters(prototype, &count, &variadic) || !variadic) return false;
 for (id = 1; id < cell_layout_count(btf); ++id) {
  const struct btf_type *tag = cell_layout_type(btf, id);
  if (tag && BTF_INFO_KIND(tag->info) == BTF_KIND_DECL_TAG &&
      !BTF_INFO_KFLAG(tag->info) && cell_layout_type(btf, tag->type) == function &&
      btf_decl_tag(tag)->component_idx == -1 &&
      !strcmp(cell_layout_name(btf, tag->name_off), "native:variadic_tail_unused")) return true;
 }
 return false;
}
static inline bool cell_variadic_tail_compatible(const struct btf *native,
 const struct btf_type *nf, const struct btf *compiled, const struct btf_type *cf)
{
 return !cell_variadic_tail_unused(native, nf) || cell_variadic_tail_unused(compiled, cf);
}
/* A record's alignment is C type information, not its byte size. In
 * particular a packed i128 and a naturally aligned i128 wrapper can have
 * identical BTF members. Keep the frontend fact in an ordinary declaration
 * tag. Zero means absent legacy metadata; ~0U means malformed/conflicting.
 */
static inline unsigned int cell_abi_alignment_tag(const char *name)
{
 unsigned int value = 0;
 const char *p = name;
 if (strncmp(p, "bpf:abi-align:", 14)) return 0;
 p += 14;
 if (*p < '1' || *p > '9') return ~0U;
 for (; *p; ++p) {
  unsigned int digit = *p - '0';
  if (digit > 9 || value > (~0U - digit) / 10) return ~0U;
  value = value * 10 + digit;
 }
 return value && !(value & (value - 1)) ? value : ~0U;
}
static inline bool cell_abi_record_value(const struct btf *types, __u32 id)
{
 unsigned int depth;
 for (depth = 0; depth < 64; ++depth) {
  const struct btf_type *type = cell_layout_type(types, id);
  unsigned int kind;
  if (!type) return false;
  kind = BTF_INFO_KIND(type->info);
  if (kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION) return true;
  if (kind != BTF_KIND_TYPEDEF && kind != BTF_KIND_CONST &&
      kind != BTF_KIND_VOLATILE && kind != BTF_KIND_RESTRICT) return false;
  id = type->type;
 }
 return false;
}
static inline unsigned int cell_abi_decl_alignment(const struct btf *types,
 const struct btf_type *tag)
{
 unsigned int alignment;
 if (!tag || BTF_INFO_KIND(tag->info) != BTF_KIND_DECL_TAG) return 0;
 alignment = cell_abi_alignment_tag(cell_layout_name(types, tag->name_off));
 if (!alignment) return 0;
 if (alignment == ~0U || BTF_INFO_KFLAG(tag->info) ||
     btf_decl_tag(tag)->component_idx != -1 ||
     !cell_abi_record_value(types, tag->type)) return ~0U;
 return alignment;
}
static inline unsigned int cell_abi_type_alignment(const struct btf *types, __u32 id)
{
 unsigned int depth;
 for (depth = 0; depth < 64; ++depth) {
  const struct btf_type *type = cell_layout_type(types, id);
  unsigned int alignment = 0;
  __u32 tag_id;
  if (!type) return ~0U;
  for (tag_id = 1; tag_id < cell_layout_count(types); ++tag_id) {
   const struct btf_type *tag = cell_layout_type(types, tag_id);
   unsigned int next;
   if (!tag || BTF_INFO_KIND(tag->info) != BTF_KIND_DECL_TAG || tag->type != id) continue;
   next = cell_abi_decl_alignment(types, tag);
   if (!next) continue;
   if (next == ~0U || (alignment && alignment != next)) return ~0U;
   alignment = next;
  }
  if (alignment) return cell_abi_record_value(types, id) ? alignment : ~0U;
  switch (BTF_INFO_KIND(type->info)) {
  case BTF_KIND_TYPEDEF: case BTF_KIND_CONST: case BTF_KIND_VOLATILE: case BTF_KIND_RESTRICT:
   id = type->type; break;
  default: return 0;
  }
 }
 return ~0U;
}
static inline bool cell_abi_value_alignment(const struct btf *a, __u32 ai,
 const struct btf *b, __u32 bi)
{
 if (!ai || !bi) return ai == bi;
 /* Pointer pointee alignment does not change the pointer's calling class. */
 if (cell_abi_record_value(a, ai) && cell_abi_record_value(b, bi)) {
  unsigned int left = cell_abi_type_alignment(a, ai), right = cell_abi_type_alignment(b, bi);
  return left != ~0U && right != ~0U && left == right;
 }
 return true;
}
/* A flexible member's type size is only its prefix. A concrete VAR's DATASEC
 * entry describes its allocated storage; neither a neighboring variable nor
 * an arbitrary caller-supplied extent can complete that allocation. */
static inline __u32 cell_storage_extent(const struct btf *types, __u32 variable)
{
 __u32 id, bytes = 0;
 const struct btf_type *var = cell_layout_type(types, variable);
 if (!var || BTF_INFO_KIND(var->info) != BTF_KIND_VAR) return 0;
 for (id = 1; id < cell_layout_count(types); ++id) {
  const struct btf_type *section = cell_layout_type(types, id);
  const struct btf_var_secinfo *entries;
  unsigned int i;
  if (!section || BTF_INFO_KIND(section->info) != BTF_KIND_DATASEC) continue;
  entries = (const struct btf_var_secinfo *)(section + 1);
  for (i = 0; i < BTF_INFO_VLEN(section->info); ++i) {
   if (entries[i].type != variable) continue;
   if (!entries[i].size || entries[i].offset > section->size ||
       entries[i].size > section->size - entries[i].offset ||
       (bytes && bytes != entries[i].size)) return 0;
   bytes = entries[i].size;
  }
 }
 return bytes;
}
/* Compare the actual storage passed through this call. Pointer-valued record
 * fields keep nominal pointee identities; their unrelated reachable objects
 * are not part of the argument object's layout. Qualifiers remain significant.
 */
static inline bool cell_layout(const struct btf *a, __u32 ai, const struct btf *b, __u32 bi,
 unsigned int depth, bool nominal)
{
 const struct btf_type *x = cell_layout_type(a, ai), *y = cell_layout_type(b, bi);
 unsigned int i, kind, ykind;
 if (!ai || !bi) return ai == bi;
 if (!x || !y || depth > 64) return false;
 kind = BTF_INFO_KIND(x->info);ykind = BTF_INFO_KIND(y->info);
 if (nominal && (kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION || kind == BTF_KIND_FWD) &&
     (ykind == BTF_KIND_STRUCT || ykind == BTF_KIND_UNION || ykind == BTF_KIND_FWD)) {
  bool xu = kind == BTF_KIND_UNION || (kind == BTF_KIND_FWD && BTF_INFO_KFLAG(x->info));
  bool yu = ykind == BTF_KIND_UNION || (ykind == BTF_KIND_FWD && BTF_INFO_KFLAG(y->info));
  return xu == yu && !strcmp(cell_layout_name(a, x->name_off), cell_layout_name(b, y->name_off));
 }
 if (kind == BTF_KIND_TYPEDEF) return cell_layout(a, x->type, b, bi, depth + 1, nominal);
 if (ykind == BTF_KIND_TYPEDEF) return cell_layout(a, ai, b, y->type, depth + 1, nominal);
 if (kind != ykind) return false;
 if ((kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION || kind == BTF_KIND_TYPE_TAG) &&
     strcmp(cell_layout_name(a, x->name_off), cell_layout_name(b, y->name_off))) return false;
 switch (kind) {
 case BTF_KIND_TYPEDEF: case BTF_KIND_CONST: case BTF_KIND_VOLATILE:
 case BTF_KIND_RESTRICT: case BTF_KIND_TYPE_TAG:
  return cell_layout(a, x->type, b, y->type, depth + 1, nominal);
 case BTF_KIND_PTR:
  return cell_layout(a, x->type, b, y->type, depth + 1, true);
 case BTF_KIND_FUNC_PROTO: {
  const struct btf_param *xp = btf_params(x), *yp = btf_params(y);
  if (BTF_INFO_VLEN(x->info) != BTF_INFO_VLEN(y->info) ||
      !cell_abi_value_alignment(a, x->type, b, y->type) ||
      !cell_layout(a, x->type, b, y->type, depth + 1, false)) return false;
  for (i = 0; i < BTF_INFO_VLEN(x->info); ++i)
   if (!cell_abi_value_alignment(a, xp[i].type, b, yp[i].type) ||
       !cell_layout(a, xp[i].type, b, yp[i].type, depth + 1, false)) return false;
  return true;
 }
 case BTF_KIND_STRUCT: case BTF_KIND_UNION: {
  const struct btf_member *xm = btf_members(x), *ym = btf_members(y);
  if (x->size != y->size) return false;
  if (nominal) return true;
  if (BTF_INFO_VLEN(x->info) != BTF_INFO_VLEN(y->info)) return false;
  for (i = 0; i < BTF_INFO_VLEN(x->info); ++i)
   if (strcmp(cell_layout_name(a, xm[i].name_off), cell_layout_name(b, ym[i].name_off)) ||
       btf_member_bit_offset(x, i) != btf_member_bit_offset(y, i) ||
       btf_member_bitfield_size(x, i) != btf_member_bitfield_size(y, i) ||
       !cell_layout(a, xm[i].type, b, ym[i].type, depth + 1, false)) return false;
  return true;
 }
 case BTF_KIND_ARRAY: {
  const struct btf_array *xa = btf_array(x), *ya = btf_array(y);
  return xa->nelems == ya->nelems && cell_layout(a, xa->type, b, ya->type, depth + 1, false);
 }
 case BTF_KIND_INT:
  return x->size == y->size && *(const __u32 *)(x + 1) == *(const __u32 *)(y + 1);
 case BTF_KIND_ENUM: case BTF_KIND_ENUM64:
  return x->size == y->size && BTF_INFO_KFLAG(x->info) == BTF_INFO_KFLAG(y->info);
 default: return false;
 }
}
#undef cell_layout_type
#undef cell_layout_name
#undef cell_layout_count
#endif
