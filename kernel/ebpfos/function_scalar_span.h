/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_SCALAR_SPAN_H
#define EBPFOS_FUNCTION_SCALAR_SPAN_H
/* Cold ABI subtyping only. Every byte of native storage must be scalar;
 * pointer-bearing,qualified,tagged or undersized storage cannot supply a
 * writable byte view. Loaded-program and argument requirements stay separate.
 */
static bool cell_scalar_storage(struct btf *types,u32 id,u64 *bytes,unsigned int depth)
{
 const struct btf_type *t,*tag;
 u32 i,kind;
 if (!id || depth>64) return false;
 t=btf_type_by_id(types,id);if (!t) return false;
 kind=BTF_INFO_KIND(t->info);
 for (i=1;(tag=btf_type_by_id(types,i));++i)
  if (BTF_INFO_KIND(tag->info)==BTF_KIND_DECL_TAG && tag->type==id) return false;
 if (kind==BTF_KIND_TYPEDEF) return cell_scalar_storage(types,t->type,bytes,depth+1);
 if (kind==BTF_KIND_INT || kind==BTF_KIND_ENUM || kind==BTF_KIND_ENUM64) {
  *bytes=t->size;return *bytes>0;
 }
 if (kind==BTF_KIND_ARRAY) {
  const struct btf_array *a=(const struct btf_array *)(t+1);
  u64 element;
  if (!a->nelems || !cell_scalar_storage(types,a->type,&element,depth+1) ||
      element>U32_MAX/a->nelems) return false;
  *bytes=element*a->nelems;return true;
 }
 if ((kind!=BTF_KIND_STRUCT && kind!=BTF_KIND_UNION) || !t->size) return false;
 for (i=0;i<BTF_INFO_VLEN(t->info);++i) {
  const struct btf_member *m=(const struct btf_member *)(t+1);
  u64 member;
  if (!cell_scalar_storage(types,m[i].type,&member,depth+1)) return false;
 }
 *bytes=t->size;return true;
}
static bool cell_scalar_span(struct btf *native,u32 object,struct btf *compiled,u32 view)
{
 const struct btf_type *a=btf_type_by_id(compiled,view),*element;
 const struct btf_array *array;
 u64 available=0;
 while (a && BTF_INFO_KIND(a->info)==BTF_KIND_TYPEDEF) a=btf_type_by_id(compiled,a->type);
 if (!a || BTF_INFO_KIND(a->info)!=BTF_KIND_ARRAY) return false;
 array=(const struct btf_array *)(a+1);if (!array->nelems) return false;
 element=btf_type_by_id(compiled,array->type);
 while (element && BTF_INFO_KIND(element->info)==BTF_KIND_TYPEDEF)
  element=btf_type_by_id(compiled,element->type);
 if (!element || BTF_INFO_KIND(element->info)!=BTF_KIND_INT || element->size!=1 ||
     BTF_INT_BITS(*(const u32 *)(element+1))!=8 || BTF_INT_OFFSET(*(const u32 *)(element+1)) ||
     (BTF_INT_ENCODING(*(const u32 *)(element+1))&BTF_INT_BOOL)) return false;
 return cell_scalar_storage(native,object,&available,0) && array->nelems<=available;
}
#endif
