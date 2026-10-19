/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_UNTRUSTED_ADDRESS_H
#define EBPFOS_FUNCTION_UNTRUSTED_ADDRESS_H
/* Native pointer bits can satisfy an independently verified, zero-extent
 * untrusted void address. This grants no object, writable bytes or lifetime.
 * Qualified addresses must retain their distinct address-space contract.
 */
static const struct btf_type *cell_address_type(const struct btf *btf, u32 id)
{
 unsigned int depth;
 for (depth = 0; depth < 32; depth++) {
  const struct btf_type *t = btf_type_by_id(btf, id);
  unsigned int kind;
  if (!t) return NULL;
  kind = BTF_INFO_KIND(t->info);
  if (kind != BTF_KIND_TYPEDEF && kind != BTF_KIND_CONST &&
      kind != BTF_KIND_VOLATILE && kind != BTF_KIND_RESTRICT) return t;
  id = t->type;
 }
 return NULL;
}
static bool cell_untrusted_address_input(const struct btf *native, u32 input,
 const struct btf *compiled, u32 actual, u32 function, unsigned int argument)
{
 const struct btf_type *n = cell_address_type(native, input);
 const struct btf_type *c = cell_address_type(compiled, actual);
 unsigned int depth;
 u32 id;
 bool untrusted = false;
 if (!n || !c || BTF_INFO_KIND(n->info) != BTF_KIND_PTR ||
     BTF_INFO_KIND(c->info) != BTF_KIND_PTR || c->type) return false;
 id = n->type;
 for (depth = 0; id && depth < 32; depth++) {
  const struct btf_type *t = btf_type_by_id(native, id);
  unsigned int kind;
  if (!t) return false;
  kind = BTF_INFO_KIND(t->info);
  if (kind == BTF_KIND_TYPE_TAG) return false;
  if (kind != BTF_KIND_TYPEDEF && kind != BTF_KIND_CONST &&
      kind != BTF_KIND_VOLATILE && kind != BTF_KIND_RESTRICT) break;
  id = t->type;
 }
 if (depth == 32) return false;
 for (id = 1; ; id++) {
  const struct btf_type *t = btf_type_by_id(compiled, id);
  const char *name;
  if (!t) break;
  if (BTF_INFO_KIND(t->info) != BTF_KIND_DECL_TAG || t->type != function ||
      btf_decl_tag(t)->component_idx != argument) continue;
  name = btf_name_by_offset(compiled, t->name_off);
  if (strncmp(name, "arg:", 4)) continue;
  if (!strcmp(name, "arg:untrusted")) untrusted = true;
  else if (strcmp(name, "arg:nonnull")) return false;
 }
 return untrusted;
}
#endif
