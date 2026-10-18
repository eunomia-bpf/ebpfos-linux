/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_ARGUMENTS_H
#define EBPFOS_FUNCTION_ARGUMENTS_H
/* Bare native calls do not pass through the BPF call checker. Any additional
 * argument requirement of the verified export must already belong to the
 * native interface. This is cold metadata matching, not another verifier.
 */
static inline bool cell_argument_tag(const struct btf *btf, const struct btf_type *function, int argument,
 const char *name)
{
 u32 id;
 for (id = 1; ; ++id) {
  const struct btf_type *type = btf_type_by_id(btf, id);
  if (!type) break;
  if (BTF_INFO_KIND(type->info) == BTF_KIND_DECL_TAG && btf_type_by_id(btf, type->type) == function &&
      btf_decl_tag(type)->component_idx == argument &&
      !strcmp(btf_name_by_offset(btf, type->name_off), name)) return true;
 }
 return false;
}
static inline bool cell_argument_nullable(const struct btf *btf, const struct btf_type *function,
 const struct btf_param *parameters, unsigned int argument)
{
 const char *name = btf_name_by_offset(btf, parameters[argument].name_off);
 size_t length = strlen(name);
 return cell_argument_tag(btf, function, argument, "arg:nullable") ||
        (length >= 10 && !strcmp(name + length - 10, "__nullable"));
}
static inline bool cell_argument_requirements(struct btf *native, const struct btf_type *nf,
 struct btf *compiled, u32 compiled_id)
{
 const struct btf_type *cf = btf_type_by_id(compiled, compiled_id);
 const struct btf_type *np, *cp;
 const struct btf_param *parameters;
 u32 id;
 if (!nf || !cf || !btf_type_is_func(nf) || !btf_type_is_func(cf)) return false;
 np = btf_type_by_id(native, nf->type);cp = btf_type_by_id(compiled, cf->type);
 if (!np || !cp || !btf_type_is_func_proto(np) || !btf_type_is_func_proto(cp) ||
     btf_type_vlen(np) < btf_type_vlen(cp)) return false;
 parameters = (const struct btf_param *)(np + 1);
 for (id = 1; ; ++id) {
  const struct btf_type *type = btf_type_by_id(compiled, id);
  const char *tag;
  int argument;
  if (!type) break;
  if (BTF_INFO_KIND(type->info) != BTF_KIND_DECL_TAG || type->type != compiled_id) continue;
  argument = btf_decl_tag(type)->component_idx;
  tag = btf_name_by_offset(compiled, type->name_off);
  if (argument < 0 || strncmp(tag, "arg:", 4)) continue;
  if (argument >= btf_type_vlen(cp)) return false;
  /* These require a BPF execution context or address space, not merely a
   * pointer with the native storage layout. */
  if (!strcmp(tag, "arg:ctx") || !strcmp(tag, "arg:arena")) return false;
  if (!strcmp(tag, "arg:nullable") || !strcmp(tag, "arg:untrusted") ||
      !strcmp(tag, "arg:readonly")) continue;
  if (!strcmp(tag, "arg:trusted") || !strcmp(tag, "arg:nonnull")) {
   if (!strcmp(tag, "arg:trusted") &&
       cell_argument_tag(native, nf, argument, "arg:untrusted")) return false;
   if (cell_argument_nullable(native, nf, parameters, argument) &&
       !cell_argument_tag(compiled, cf, argument, "arg:nullable")) return false;
   continue;
  }
  /* Bounds, byte-count pairings, interior offsets and future argument
   * requirements are not implied by equal register widths or record sizes.
   * Preserve them exactly; more general implication is deliberately absent.
   */
  if (!cell_argument_tag(native, nf, argument, tag)) return false;
 }
 return true;
}
#endif
