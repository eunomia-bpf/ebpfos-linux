// SPDX-License-Identifier: GPL-2.0-only
#ifndef EBPFOS_FUNCTION_CONTRACT_H
#define EBPFOS_FUNCTION_CONTRACT_H
/* Cold native-call contract shared by direct entries and owned ops tables.
 * Callers retain the loaded program for the full lifetime of published code.
 */
/* Compare the actual storage passed through this call. Pointer-valued record
 * fields keep nominal pointee identities; their unrelated reachable objects
 * are not part of the argument object's layout. Qualifiers remain significant.
 */
static bool cell_layout(struct btf *a, u32 ai, struct btf *b, u32 bi,
 unsigned int depth, bool nominal)
{
 const struct btf_type *x = btf_type_by_id(a, ai), *y = btf_type_by_id(b, bi);
 unsigned int i, kind, ykind;
 if (!ai || !bi) return ai == bi;
 if (!x || !y || depth > 64) return false;
 kind = BTF_INFO_KIND(x->info);ykind = BTF_INFO_KIND(y->info);
 if (nominal && (kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION || kind == BTF_KIND_FWD) &&
     (ykind == BTF_KIND_STRUCT || ykind == BTF_KIND_UNION || ykind == BTF_KIND_FWD)) {
  bool xu = kind == BTF_KIND_UNION || (kind == BTF_KIND_FWD && btf_type_kflag(x));
  bool yu = ykind == BTF_KIND_UNION || (ykind == BTF_KIND_FWD && btf_type_kflag(y));
  return xu == yu && !strcmp(btf_name_by_offset(a, x->name_off), btf_name_by_offset(b, y->name_off));
 }
 if (kind == BTF_KIND_TYPEDEF) return cell_layout(a, x->type, b, bi, depth + 1, nominal);
 if (ykind == BTF_KIND_TYPEDEF) return cell_layout(a, ai, b, y->type, depth + 1, nominal);
 if (kind != ykind) return false;
 if ((kind == BTF_KIND_STRUCT || kind == BTF_KIND_UNION || kind == BTF_KIND_TYPE_TAG) &&
     strcmp(btf_name_by_offset(a, x->name_off), btf_name_by_offset(b, y->name_off))) return false;
 switch (kind) {
 case BTF_KIND_TYPEDEF: case BTF_KIND_CONST: case BTF_KIND_VOLATILE:
 case BTF_KIND_RESTRICT: case BTF_KIND_TYPE_TAG:
  return cell_layout(a, x->type, b, y->type, depth + 1, nominal);
 case BTF_KIND_PTR:
  return cell_layout(a, x->type, b, y->type, depth + 1, true);
 case BTF_KIND_FUNC_PROTO: {
  const struct btf_param *xp = (const void *)(x + 1), *yp = (const void *)(y + 1);
  if (btf_type_vlen(x) != btf_type_vlen(y) ||
      !cell_layout(a, x->type, b, y->type, depth + 1, false)) return false;
  for (i = 0; i < btf_type_vlen(x); ++i)
   if (!cell_layout(a, xp[i].type, b, yp[i].type, depth + 1, false)) return false;
  return true;
 }
 case BTF_KIND_STRUCT: case BTF_KIND_UNION: {
  const struct btf_member *xm = btf_members(x), *ym = btf_members(y);
  if (x->size != y->size) return false;
  if (nominal) return true;
  if (btf_type_vlen(x) != btf_type_vlen(y)) return false;
  for (i = 0; i < btf_type_vlen(x); ++i)
   if (strcmp(btf_name_by_offset(a, xm[i].name_off), btf_name_by_offset(b, ym[i].name_off)) ||
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
  return x->size == y->size && *(const u32 *)(x + 1) == *(const u32 *)(y + 1);
 case BTF_KIND_ENUM: case BTF_KIND_ENUM64:
  return x->size == y->size && btf_type_kflag(x) == btf_type_kflag(y);
 default: return false;
 }
}
/* Scalar-input globals acquire no pointer capability from a native address.
 * Pointer consumers and pointer returns retain the complete root layout.
 */
static bool cell_register_type(struct btf *native, u32 a, struct btf *compiled,
 u32 b, bool input)
{
 const struct btf_type *x = btf_type_skip_modifiers(native, a, NULL);
 const struct btf_type *y = btf_type_skip_modifiers(compiled, b, NULL);
 if (!a || !b) return a == b;
 if (!x || !y) return false;
 if (btf_type_is_ptr(x)) {
  if (input && btf_type_is_int(y) && y->size == sizeof(void *)) return true;
  if (!btf_type_is_ptr(y)) return false;
  return cell_layout(native, x->type, compiled, y->type, 0, false);
 }
 if (!btf_type_is_int(x) && !btf_is_any_enum(x)) return false;
 if (!btf_type_is_int(y) && !btf_is_any_enum(y)) return false;
 return x->size == y->size;
}
static bool cell_callable(struct btf *native, const struct btf_type *native_function,
 struct bpf_prog *parent, u32 id, unsigned long *address)
{
 const struct btf_type *function, *prototype;
 const struct btf_type *n = btf_type_by_id(native, native_function->type);
 const struct btf_param *a, *b;
 struct bpf_prog_aux *aux = parent->aux;
 unsigned int i, index;
 if (!aux->btf || !aux->func || !aux->func_info_aux || !aux->func_info) return false;
 for (index = 1; index < aux->func_cnt && index < aux->func_info_cnt; ++index)
  if (aux->func_info[index].type_id == id) break;
 if (index >= aux->func_cnt || index >= aux->func_info_cnt ||
     !aux->func_info_aux[index].verified || aux->func_info_aux[index].unreliable) return false;
 function = btf_type_by_id(aux->btf, id);
 if (!function || !btf_type_is_func(function) || btf_func_linkage(function) != BTF_FUNC_GLOBAL ||
     !aux->func[index]->jited || strcmp(btf_name_by_offset(native, native_function->name_off),
       btf_name_by_offset(aux->btf, function->name_off))) return false;
 prototype = btf_type_by_id(aux->btf, function->type);
 if (!prototype || !btf_type_is_func_proto(prototype) || btf_type_vlen(prototype) != btf_type_vlen(n) ||
     !cell_register_type(native, n->type, aux->btf, prototype->type, false)) return false;
 a = (const void *)(n + 1); b = (const void *)(prototype + 1);
 for (i = 0; i < btf_type_vlen(n); ++i)
  if (!a[i].type || !b[i].type || !cell_register_type(native, a[i].type, aux->btf, b[i].type, true)) return false;
 *address = (unsigned long)aux->func[index]->bpf_func;
 return true;
}


/* A binding leases a verified function and its complete program graph. An
 * object owner may publish address in an existing operations table, then
 * release the lease only after the object and all its callbacks are dead.
 * This first common form admits context-free functions: no helper, kfunc,
 * tail call, timed-loop helper or private JIT stack can require bpf_run_ctx.
 */
#include "function_binding.h"
static inline int ebpfos_function_binding_open_pure(
 struct ebpfos_function_binding *out, u32 fd, enum bpf_prog_type type,
 struct btf *native, const struct btf_type *function, u32 compiled_id)
{
 struct bpf_prog *program;
 unsigned int i, j;
 unsigned long address;
 if (!IS_ENABLED(CONFIG_X86_64) || IS_ENABLED(CONFIG_CFI)) return -EOPNOTSUPP;
 if (out->program || out->address || !native || !function || !btf_type_is_func(function))
  return -EINVAL;
 program = bpf_prog_get_type_dev(fd, type, false);
 if (IS_ERR(program)) return PTR_ERR(program);
 if (program->sleepable || !program->aux->func || !program->aux->func_cnt) goto invalid;
 for (i = 0; i < program->aux->func_cnt; ++i) {
  struct bpf_prog *f = program->aux->func[i];
  if (!f || !f->jited || f->aux->priv_stack_ptr) goto invalid;
  for (j = 0; j < f->len; ++j) {
   const struct bpf_insn *insn = &f->insnsi[j];
   if (insn->code == (BPF_JMP | BPF_TAIL_CALL) ||
       (insn->code == (BPF_JMP | BPF_CALL) && insn->src_reg != BPF_PSEUDO_CALL))
    goto invalid;
  }
 }
 if (!cell_callable(native, function, program, compiled_id, &address)) goto invalid;
 out->program = program;out->address = address;
 return 0;
invalid:
 bpf_prog_put(program);return -EPROTOTYPE;
}
static inline void ebpfos_function_binding_put(struct ebpfos_function_binding *binding)
{
 if (binding->program) bpf_prog_put(binding->program);
 binding->program = NULL;binding->address = 0;
}
#endif
