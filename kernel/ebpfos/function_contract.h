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

/* A compiler-selected source entry can have a different final native name.
 * This selects an export only; its ABI/context/proof checks remain below. */
static bool cell_export_name(const char *name, struct btf *compiled, u32 id, bool native_aliases)
{
 const struct btf_type *function = btf_type_by_id(compiled, id);
 unsigned int cursor = 0;
 const char *text;
 if (!function || !btf_type_is_func(function)) return false;
 if (!strcmp(name, btf_name_by_offset(compiled, function->name_off))) return true;
 if (!native_aliases) return false;
 while ((text = cell_next_decl_tag(compiled, function, -1, &cursor))) {
  const char *target = cell_component_target(text, strlen(text));
  if (target && !strcmp(target, name)) return true;
 }
 return false;
}
/* Trusted source calls an implicit-argument kfunc through its complete C
 * interface. The retained prototype can express metadata as an opaque pointer.
 * Compare scalar register/stack conventions without claiming pointer safety.
 */

/* Independently checked input-relative, NULL or permanent read-only results
 * may cross the native pointer-result boundary. A borrowed result retains the
 * native caller's input lifetime; it cannot expose a new program-local object.
 */

static bool cell_callable_proto(struct btf *native, u32 native_type,
 const struct btf_type *native_function, const char *native_name,
 struct bpf_prog *parent, u32 id, unsigned long *address)
{
 struct bpf_prog_aux *aux = parent->aux;
 unsigned int index;
 if (!aux->btf || !aux->func || !aux->func_info_aux || !aux->func_info) return false;
 for (index = bpf_native_func_entry(parent) ? 0 : 1; index < aux->func_cnt && index < aux->func_info_cnt; ++index)
  if (aux->func_info[index].type_id == id) break;
 if (index >= aux->func_cnt || index >= aux->func_info_cnt) return false;
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
 program = bpf_prog_get_type_dev(fd, type, false);
 if (IS_ERR(program)) return PTR_ERR(program);
 if (!cell_callable(native, function, program, compiled_id, &address)) goto invalid;
 out->program = program;out->address = address;
 return 0;
invalid:
 bpf_prog_put(program);return -EPROTOTYPE;
}
static inline void ebpfos_function_binding_put(struct ebpfos_function_binding *binding)
{
 if (binding->program) bpf_prog_put(binding->program);
 module_put(binding->module);
 module_put(binding->source_module);
 binding->program = NULL;binding->module = NULL;binding->source_module = NULL;
 binding->address = 0;binding->native_address = 0;
}
#endif
