/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_CONTEXT_REQUIREMENTS_H
#define EBPFOS_FUNCTION_CONTEXT_REQUIREMENTS_H
/* A register-compatible entry is not necessarily context-compatible. Retain
 * the native interface's declared requirements and transfers at every cold
 * binding, including name-resolved later generations and record transports.
 * Equality supplies no held lock, RCU scope or reference to the verifier.
 */
static inline bool cell_context_direction(const struct btf *from,
 const struct btf_type *function, const struct btf *to,
 const struct btf_type *other)
{
 u32 id;
 for (id = 1; ; id++) {
  const struct btf_type *tag = btf_type_by_id(from, id);
  const char *name;
  if (!tag) break;
  if (BTF_INFO_KIND(tag->info) != BTF_KIND_DECL_TAG ||
      btf_type_by_id(from, tag->type) != function) continue;
  name = btf_name_by_offset(from, tag->name_off);
  if (strncmp(name, "context_", 8)) continue;
  if (btf_decl_tag(tag)->component_idx != -1 ||
      !cell_argument_tag(to, other, -1, name)) return false;
 }
 return true;
}
static inline bool cell_context_requirements(const struct btf *native,
 const struct btf_type *nf, const struct btf *compiled,
 const struct btf_type *cf)
{
 return cell_context_direction(native, nf, compiled, cf) &&
        cell_context_direction(compiled, cf, native, nf);
}
#endif
