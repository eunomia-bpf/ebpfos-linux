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
#else
#include <bpf/btf.h>
#include <stdbool.h>
#include <string.h>
#define cell_layout_type btf__type_by_id
#define cell_layout_name btf__name_by_offset
#endif
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
      !cell_layout(a, x->type, b, y->type, depth + 1, false)) return false;
  for (i = 0; i < BTF_INFO_VLEN(x->info); ++i)
   if (!cell_layout(a, xp[i].type, b, yp[i].type, depth + 1, false)) return false;
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
#endif
