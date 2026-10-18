/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_REGISTER_PREFIX_H
#define EBPFOS_FUNCTION_REGISTER_PREFIX_H
/* Cold register ABI matching. The omitted suffix creates no BPF inputs;
 * surviving argument requirements and native-context checks remain separate.
 */
static bool cell_native_register_inputs(struct btf *native,const struct btf_type *prototype)
{
 const struct btf_param *args=(const struct btf_param *)(prototype+1);
 unsigned int i,depth,kind;
 for(i=0;i<BTF_INFO_VLEN(prototype->info);i++) {
  const struct btf_type *type=btf_type_by_id(native,args[i].type);
  for(depth=0;type && depth<32;depth++) {
   kind=BTF_INFO_KIND(type->info);
   if(kind!=BTF_KIND_TYPEDEF && kind!=BTF_KIND_CONST && kind!=BTF_KIND_VOLATILE && kind!=BTF_KIND_RESTRICT)break;
   type=btf_type_by_id(native,type->type);
  }
  if(!type)return false;
  kind=BTF_INFO_KIND(type->info);
  if(kind!=BTF_KIND_PTR && ((kind!=BTF_KIND_INT && kind!=BTF_KIND_ENUM && kind!=BTF_KIND_ENUM64) || !type->size || type->size>8))return false;
 }
 return true;
}
static bool cell_native_prefix(struct btf *native,const struct btf_type *n,const struct btf_type *c)
{
 return BTF_INFO_VLEN(c->info)<BTF_INFO_VLEN(n->info) && BTF_INFO_VLEN(c->info)<=5 && cell_native_register_inputs(native,n);
}
#endif
