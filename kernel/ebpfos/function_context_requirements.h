/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_CONTEXT_REQUIREMENTS_H
#define EBPFOS_FUNCTION_CONTEXT_REQUIREMENTS_H
/* A register-compatible entry is not necessarily context-compatible. Retain
 * the native interface's declared requirements and transfers at every cold
 * binding, including name-resolved later generations and record transports.
 * A replacement may weaken preconditions. Source state transfers have no
 * verified implementation summary yet: even matching declarations cannot
 * authorize them. Matching supplies no held lock, RCU scope or reference.
 */
static inline bool cell_context_precondition(const char *name)
{
 return !strncmp(name, "context_require:", sizeof("context_require:") - 1) ||
        !strncmp(name, "context_require_shared:", sizeof("context_require_shared:") - 1) ||
        !strncmp(name, "context_exclude:", sizeof("context_exclude:") - 1);
}
static inline bool cell_context_direction(const struct btf *from,
 const struct btf_type *function, const struct btf *to,
 const struct btf_type *other, bool native_requirements)
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
  if (btf_decl_tag(tag)->component_idx != -1) return false;
  if (!cell_context_precondition(name)) return false;
  if (native_requirements && cell_context_precondition(name)) continue;
  if (!cell_argument_tag(to, other, -1, name)) return false;
 }
 return true;
}
static inline bool cell_context_requirements(const struct btf *native,
 const struct btf_type *nf, const struct btf *compiled,
 const struct btf_type *cf)
{
 return cell_context_direction(native, nf, compiled, cf, true) &&
        cell_context_direction(compiled, cf, native, nf, false);
}
#endif
