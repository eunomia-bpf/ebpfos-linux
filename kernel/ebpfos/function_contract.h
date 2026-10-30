// SPDX-License-Identifier: GPL-2.0-only
#ifndef EBPFOS_FUNCTION_CONTRACT_H
#define EBPFOS_FUNCTION_CONTRACT_H
#include "function_arguments.h"
#include "function_untrusted_address.h"
#include "function_context_requirements.h"
#include "function_scalar_span.h"
#include "function_scalar_record_abi.h"
#include "native_result_abi.h"
#include "../bpf/btf_record_return.h"
#include "function_register_prefix.h"
#include <linux/module.h>
#include <linux/bpf_native_abi.h>
/* Cold native-call contract shared by direct entries and owned ops tables.
 * Callers retain the loaded program for the full lifetime of published code.
 */
#include "function_layout.h"
/* Scalar-input globals acquire no pointer capability from a native address.
 * Stock global-subprogram verification proves scalar returns only. A pointer
 * spelling in BTF is not a proven pointer result for a native caller.
 */
static bool cell_register_type(struct btf *native, u32 a, struct btf *compiled,
 u32 b, bool input)
{
 const struct btf_type *x = btf_type_skip_modifiers(native, a, NULL);
 const struct btf_type *y = btf_type_skip_modifiers(compiled, b, NULL);
 if (!a || !b) return a == b;
 if (IS_ENABLED(CONFIG_X86_64) &&
     cell_single_scalar_record_register(native, a, compiled, b)) return true;
 if (!x || !y) return false;
 if (!input && btf_scalar_record_return(native, a) &&
     btf_scalar_record_return(compiled, b))
  return cell_layout(native, a, compiled, b, 0, false);
 if (btf_type_is_ptr(x)) {
  if (!input) return false;
  if (input && btf_type_is_int(y) && y->size == sizeof(void *)) return true;
  if (!btf_type_is_ptr(y)) return false;
  return cell_layout(native, x->type, compiled, y->type, 0, false) ||
   (input && cell_scalar_span(native,x->type,compiled,y->type));
 }
 if (!btf_type_is_int(x) && !btf_is_any_enum(x)) return false;
 if (!btf_type_is_int(y) && !btf_is_any_enum(y)) return false;
 return x->size == y->size;
}
/* A compiler-selected source entry can have a different final native name.
 * This selects an export only; its ABI/context/proof checks remain below. */
static bool cell_export_name(const char *name, struct btf *compiled, u32 id, bool native_aliases)
{
 const struct btf_type *function = btf_type_by_id(compiled, id), *tag;
 u32 at;
 if (!function || !btf_type_is_func(function)) return false;
 if (!strcmp(name, btf_name_by_offset(compiled, function->name_off))) return true;
 if (!native_aliases) return false;
 for (at = 1; (tag = btf_type_by_id(compiled, at)); ++at) {
  const char *text;
  if (BTF_INFO_KIND(tag->info) != BTF_KIND_DECL_TAG || tag->type != id ||
      btf_decl_tag(tag)->component_idx != -1) continue;
  text = btf_name_by_offset(compiled, tag->name_off);
  if (!strncmp(text, "component.target/", 17) && !strcmp(text + 17, name)) return true;
 }
 return false;
}
/* Trusted source calls an implicit-argument kfunc through its complete C
 * interface. The retained prototype can express metadata as an opaque pointer.
 * Compare scalar register/stack conventions without claiming pointer safety.
 */
static bool cell_trusted_native_scalar_proto(struct btf *native, const struct btf_type *n,
 struct btf *compiled, const struct btf_type *c, bool framed)
{
 struct btf_func_model a, b;
 unsigned int i;
 if (btf_distill_native_func_proto(NULL, native, n, NULL, &a, false) ||
     btf_distill_native_func_proto(NULL, compiled, c, NULL, &b, false) ||
     a.nr_args != b.nr_args || a.ret_size != b.ret_size || a.ret_flags != b.ret_flags ||
     a.native_stack != b.native_stack || (a.ret_flags & BTF_FMODEL_STRUCT_ARG) ||
     (!framed && (a.native_stack || a.nr_args > MAX_BPF_FUNC_REG_ARGS))) return false;
 for (i = 0; i < a.nr_args; i++)
  if (a.arg_size[i] != b.arg_size[i] || a.arg_flags[i] != b.arg_flags[i] ||
      (a.arg_flags[i] & BTF_FMODEL_STRUCT_ARG)) return false;
 return true;
}
/* Independently checked NULL or permanent read-only results may cross the
 * native pointer-result boundary. Program-held map storage is too short-lived.
 */
static bool cell_checked_pointer_result(struct btf *native, const struct btf_type *n,
 struct btf *compiled, const struct btf_type *function)
{
 const struct btf_type *prototype = btf_type_by_id(compiled, function->type);
 const struct btf_type *result = btf_type_skip_modifiers(native, n->type, NULL);
 const char *tag = btf_find_decl_tag_value(compiled, function, -1, "ret:ro_kernel_mem:");
 u32 bytes, size;
 bool described = !IS_ERR(tag) && !kstrtou32(tag, 10, &bytes) && bytes;
 if (described) {
  const struct btf_type *source = btf_type_skip_modifiers(compiled, prototype->type, NULL);
  const struct btf_type *pointee;
  if (!result || !btf_type_is_ptr(result) || !source || !btf_type_is_ptr(source)) return false;
  pointee = btf_type_skip_modifiers(native, result->type, NULL);
  /* Native callers use the complete declared object. A source pointer's
   * nominal record name alone cannot justify its size or pointer fields.
   */
  if (!pointee || IS_ERR(btf_resolve_size(native, pointee, &size)) || !size || size > bytes ||
      !btf_type_is_scalar_region(native, result->type, 0, size) ||
      !cell_layout(native, result->type, compiled, source->type, 0, false)) return false;
 }
 if (!described) {
  tag = btf_find_decl_tag_value(compiled, function, -1, "ret:ro_kernel_btf");
  if (!IS_ERR(tag) && !*tag) {
   const struct btf_type *source = btf_type_skip_modifiers(compiled, prototype->type, NULL);
   const struct btf_type *object = result && btf_type_is_ptr(result) ?
    btf_type_skip_modifiers(native, result->type, NULL) : NULL;
   /* Compare the complete native pointee, rather than a pointer's nominal
    * record name. The independently verified body proved core lifetime.
    */
   if (!object || !btf_type_is_struct(object) || !source || !btf_type_is_ptr(source) ||
       !cell_layout(native, result->type, compiled, source->type, 0, false)) return false;
   described = true;
  }
 }
 if (!described) {
  tag = btf_find_decl_tag_value(compiled, function, -1, "ret:null");
  described = !IS_ERR(tag) && !*tag;
 }
 return result && btf_type_is_ptr(result) && described &&
  cell_layout(native, n->type, compiled, prototype->type, 0, false);
}
static bool cell_callable_proto(struct btf *native, u32 native_type,
 const struct btf_type *native_function, const char *native_name,
 struct bpf_prog *parent, u32 id, unsigned long *address)
{
 const struct btf_type *function, *prototype;
 const struct btf_type *n = btf_type_by_id(native, native_type);
 const struct btf_param *a, *b;
 struct bpf_prog_aux *aux = parent->aux;
 unsigned int i, index;
 int native_proto_id = native_type;
 bool scalar_records, result2, kernel_result = false;
#ifdef BPF_F_TRUSTED_KERNEL
 bool trusted = aux->trusted_kernel;
#else
 bool trusted = false;
#endif
 if (!n || !btf_type_is_func_proto(n)) return false;
 if (trusted && native_function) {
  int native_id = btf_find_by_name_kind(native,
    native_name, BTF_KIND_FUNC);
  if (native_id <= 0 || btf_type_by_id(native, native_id) != native_function) return false;
  native_proto_id = btf_native_func_proto_id(native, native_id, parent);
  if (native_proto_id < 0) return false;
  n = btf_type_by_id(native, native_proto_id);
 }
 if (!aux->btf || !aux->func || !aux->func_info_aux || !aux->func_info) return false;
 for (index = 1; index < aux->func_cnt && index < aux->func_info_cnt; ++index)
  if (aux->func_info[index].type_id == id) break;
 if (index >= aux->func_cnt || index >= aux->func_info_cnt ||
     (!trusted && (!aux->func_info_aux[index].verified || aux->func_info_aux[index].unreliable))) return false;
 function = btf_type_by_id(aux->btf, id);
 if (!function || !btf_type_is_func(function) || btf_func_linkage(function) != BTF_FUNC_GLOBAL ||
     !aux->func[index]->jited || !cell_export_name(native_name, aux->btf, id, true)) return false;
 prototype = btf_type_by_id(aux->btf, function->type);
 if (!prototype || !btf_type_is_func_proto(prototype)) return false;
 /* Trusted unmodified source retains Linux's context transfers under its
  * source/compiler assumption. Its annotations do not provide independently
  * verified transfer summaries. Keep that requirement in the verified tier.
  */
 if (!trusted && !cell_context_requirements(native, native_function, aux->btf, function))
  return false;

 /* Source contract preparation can refine an opaque pointer to its
  * source record. Trusted code carries no pointer proof: preserve its native
  * value ABI without treating verifier-only pointer assumptions as native
  * caller requirements, or requiring the old
  * and refined pointee layouts to be identical. Verified exports continue
  * through the full pointer/record checks below.
  */
 if (trusted) {
  if (cell_trusted_native_scalar_proto(native, n, aux->btf, prototype,
        aux->func[index]->aux->native_frame)) goto compatible;
  if (native_proto_id != native_type) return false;
 }

 if (!trusted) {
  const struct btf_type *result = btf_type_skip_modifiers(native, n->type, NULL);
  if (result && btf_type_is_ptr(result)) {
   kernel_result = cell_checked_pointer_result(native, n, aux->btf, function);
   if (!kernel_result) return false;
  }
 }

 /* Framed functions retain their complete logical native value ABI. The
  * ordinary verifier checked that ABI independently; no wrapper executes.
  */
 if (IS_ENABLED(CONFIG_X86_64) && aux->func[index]->aux->native_frame &&
     cell_layout(native, native_type, aux->btf, function->type, 0, false)) {
  /* Preserve field-level non-NULL and const requirements at bare native
   * entries, which bypass the BPF call-site argument checker.
   */
  if (!trusted)
   for (i = 0; i < btf_type_vlen(prototype); i++) {
    u32 type = btf_params(prototype)[i].type;
    const struct btf_type *value = btf_type_skip_modifiers(aux->btf, type, NULL);
    if (btf_type_is_struct(value) && !btf_native_scalar_storage(aux->btf, type, 0) &&
        !btf_native_record_entry_contract(aux->btf, type)) return false;
   }
  if (!trusted && !cell_argument_requirements(native, native_function, n, aux->btf, id)) return false;
  goto compatible;
 }
 result2 = IS_ENABLED(CONFIG_X86_64) && cell_native_result2_type(native, n->type) &&
           !cell_record_type_tags(aux->btf, prototype->type) &&
           cell_record_word(cell_record_type(aux->btf, prototype->type)) &&
           ebpfos_prog_native_result2(aux->func[index]);
 if (!result2 && !kernel_result && !cell_register_type(native, n->type, aux->btf, prototype->type, false)) {
  const struct btf_type *x = btf_type_skip_modifiers(native, n->type, NULL);
  const struct btf_type *y = btf_type_skip_modifiers(aux->btf, prototype->type, NULL);
  /* A trusted source body may return a native address in RAX. This is ABI
   * compatibility only; the verified tier still requires a proven result. */
  if (!trusted || !x || !y || !btf_type_is_ptr(x) ||
      !((btf_type_is_ptr(y) && cell_layout(native, x->type, aux->btf, y->type, 0, false)) ||
        (btf_type_is_int(y) && y->size == sizeof(void *)))) return false;
 }
 scalar_records = IS_ENABLED(CONFIG_X86_64) &&
                  cell_scalar_record_inputs(native, native_function, n, aux->btf, function, result2);
 /* This form carries scalar bits only and rejects every parameter contract. */
 if (scalar_records) goto compatible;
 if (btf_type_vlen(prototype) != btf_type_vlen(n)) {
  if (!IS_ENABLED(CONFIG_X86_64) || !cell_native_prefix(native,n,prototype)) return false;
 }
 a = (const void *)(n + 1); b = (const void *)(prototype + 1);
 for (i = 0; i < btf_type_vlen(prototype); ++i)
  if (!a[i].type || !b[i].type ||
      (!cell_register_type(native, a[i].type, aux->btf, b[i].type, true) &&
       !cell_untrusted_address_input(native, a[i].type, aux->btf, b[i].type, id, i))) return false;
 /* Native callers bypass BPF's call-site argument checker. Keep bounds,
  * address spaces and context requirements in the common callable contract,
  * including exports resolved by name in a replacement generation. */
 if (!trusted && !cell_argument_requirements(native, native_function, n, aux->btf, id)) return false;
compatible:
 *address = (unsigned long)aux->func[index]->bpf_func;
 return true;
}

static bool cell_callable(struct btf *native, const struct btf_type *function,
 struct bpf_prog *parent, u32 id, unsigned long *address)
{
 return cell_callable_proto(native, function->type, function,
  btf_name_by_offset(native, function->name_off), parent, id, address);
}


/* A binding leases a verified function and its complete program graph. An
 * object owner may publish address in an existing operations table, then
 * release the lease only after the object and all its callbacks are dead.
 * This first common form admits context-free functions: no helper, kfunc,
 * tail call or private JIT stack can require bpf_run_ctx. The stock timed
 * backedge operation uses the current function's initialized stack slots.
 */
#include "function_binding.h"
#include "function_native_context.h"
static inline int ebpfos_function_binding_open_pure(
 struct ebpfos_function_binding *out, u32 fd, enum bpf_prog_type type,
 struct btf *native, const struct btf_type *function, u32 compiled_id)
{
 struct bpf_prog *program;
 unsigned long address;
 if (!IS_ENABLED(CONFIG_X86_64) || IS_ENABLED(CONFIG_CFI)) return -EOPNOTSUPP;
 if (out->program || out->module || out->address || !native || !function || !btf_type_is_func(function))
  return -EINVAL;
 program = bpf_prog_get_type_dev(fd, type, false);
 if (IS_ERR(program)) return PTR_ERR(program);
 if (program->sleepable || !program->aux->func || !program->aux->func_cnt) goto invalid;
 if (!cell_callable(native, function, program, compiled_id, &address)) goto invalid;
 if (!entry_context_pure(program, address)) goto invalid;
 out->program = program;out->address = address;
 return 0;
invalid:
 bpf_prog_put(program);return -EPROTOTYPE;
}
static inline void ebpfos_function_binding_put(struct ebpfos_function_binding *binding)
{
 if (binding->program) bpf_prog_put(binding->program);
 module_put(binding->module);
 binding->program = NULL;binding->module = NULL;binding->address = 0;
}
#endif
