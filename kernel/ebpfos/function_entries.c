// SPDX-License-Identifier: GPL-2.0-only
/* Typed native entry linking through Linux's existing batch direct ftrace API.
 * Only cold preparation/publication runs here. Ordinary callers execute the
 * installed direct jump and the verified JIT body, with no invocation gate.
 */
#include <linux/anon_inodes.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/filter.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include "syscall_kfuncs.h"
struct ebpfos_function_entry { u32 native_function, compiled_function; };
struct entry_set {
 struct list_head retained;
 struct bpf_prog *program[2];
 struct ftrace_ops operations;
 struct ftrace_hash *hash[2];
 unsigned long *locations;
 unsigned int count, active;
 bool published;
};
static DEFINE_MUTEX(entry_lock);
/* A stopped CPU does not prove every suspended old frame has returned. Keep
 * actual published graphs alive until their owners can prove retirement. */
static LIST_HEAD(entry_retained);
static const struct file_operations entry_operations;
/* Bare native ABI calls have no bpf_run_ctx. These standard helpers depend
 * only on explicit operands or the native CPU/task, not on such a frame.
 * Keep this cold eligibility check outside the call path. */
static bool entry_context(struct bpf_prog *parent)
{
 const enum bpf_func_id helpers[] = { BPF_FUNC_per_cpu_ptr, BPF_FUNC_this_cpu_ptr,
  BPF_FUNC_get_current_task_btf, BPF_FUNC_loop };
 unsigned int i, j, k;
 if (!parent->aux->func || !parent->aux->func_cnt) return false;
 for (i = 0; i < parent->aux->func_cnt; ++i) {
  struct bpf_prog *function = parent->aux->func[i];
  if (!function || !function->jited || function->aux->priv_stack_ptr) return false;
  for (j = 0; j < function->len; ++j) {
   const struct bpf_insn *insn = &function->insnsi[j];
   unsigned long target;
   if (insn->code != (BPF_JMP | BPF_CALL) || insn->src_reg) continue;
   target = (unsigned long)__bpf_call_base + insn->imm;
   for (k = 0; k < ARRAY_SIZE(helpers); ++k) {
    const struct bpf_func_proto *prototype = bpf_base_func_proto(helpers[k], parent);
    if (prototype && target == (unsigned long)prototype->func) break;
   }
   if (k == ARRAY_SIZE(helpers)) return false;
  }
 }
 return true;
}

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

static int entry_publication_point(void *unused) { return 0; }
static int entry_apply(struct entry_set *set, unsigned int from, unsigned int to)
{
 if (!from) return update_ftrace_direct_add(&set->operations, set->hash[to - 1]);
 if (!to) return update_ftrace_direct_del(&set->operations, set->hash[from - 1]);
 return update_ftrace_direct_mod(&set->operations, set->hash[to - 1], true);
}
static int entry_switch(struct entry_set *set, unsigned int from, unsigned int to)
{
 int error, recovery;
 if (from > 2 || to > 2 || from != set->active) return -ESTALE;
 if (from == to) return 0;
 /* The stock x86 text-poke batch performs its own CPU synchronization and
  * breakpoint-safe instruction update. Never call it with CPUs stopped: its
  * cross-CPU synchronizations must run. One following stop-machine point
  * establishes that the entire installed set is visible before completion.
  * Unchanged layouts and retained old code permit in-flight old frames.
  */
 error = entry_apply(set, from, to);
 if (error) return error;
 set->active = to;set->published |= to != 0;
 error = stop_machine(entry_publication_point, NULL, NULL);
 if (error) {
  recovery = entry_apply(set, to, from);
  if (!recovery) set->active = from;
 }
 return error;
}
static void entry_free(struct entry_set *set)
{
 if (set->program[0]) bpf_prog_put(set->program[0]);
 if (set->program[1]) bpf_prog_put(set->program[1]);
 free_ftrace_hash(set->hash[0]);free_ftrace_hash(set->hash[1]);kvfree(set->locations);kfree(set);
}
static int entry_release(struct inode *inode, struct file *file)
{
 struct entry_set *set = file->private_data;
 int error;
 mutex_lock(&entry_lock);error = entry_switch(set, set->active, 0);
 if (set->published || error) list_add_tail(&set->retained, &entry_retained);
 mutex_unlock(&entry_lock);
 if (!set->published && !error) entry_free(set);
 return error;
}
static const struct file_operations entry_operations = { .release = entry_release, .llseek = noop_llseek };
__bpf_kfunc_start_defs();
__bpf_kfunc int bpf_ebpfos_function_entries_open(u32 first, u32 second,
 const struct ebpfos_function_entry *entries, u32 entries__sz)
{
 struct entry_set *set;
 struct ebpfos_function_entry *snapshot;
 struct btf *btf = bpf_get_btf_vmlinux();
 unsigned int i,j;
 int error = -EINVAL;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (!IS_ENABLED(CONFIG_DYNAMIC_FTRACE_WITH_JMP) ||
     !IS_ENABLED(CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS)) return -EOPNOTSUPP;
 if (!entries__sz || entries__sz % sizeof(*entries) || IS_ERR_OR_NULL(btf)) return -EINVAL;
 snapshot = kmemdup(entries, entries__sz, GFP_KERNEL);
 if (!snapshot) return -ENOMEM;
 set = kzalloc(sizeof(*set), GFP_KERNEL);
 if (!set) { kfree(snapshot);return -ENOMEM; }
 set->count = entries__sz / sizeof(*entries);
 set->locations = kvcalloc(set->count, sizeof(*set->locations), GFP_KERNEL);
 if (!set->locations) {error = -ENOMEM;goto fail;}
 set->hash[0] = alloc_ftrace_hash(FTRACE_HASH_DEFAULT_BITS);
 set->hash[1] = alloc_ftrace_hash(FTRACE_HASH_DEFAULT_BITS);
 if (!set->hash[0] || !set->hash[1]) { error = -ENOMEM;goto fail; }
 set->program[0] = bpf_prog_get_type_dev(first, BPF_PROG_TYPE_TRACING, false);
 if (IS_ERR(set->program[0])) {error = PTR_ERR(set->program[0]);set->program[0] = NULL;goto fail;}
 set->program[1] = bpf_prog_get_type_dev(second, BPF_PROG_TYPE_TRACING, false);
 if (IS_ERR(set->program[1])) {error = PTR_ERR(set->program[1]);set->program[1] = NULL;goto fail;}
 for (j = 0; j < 2; ++j)
  if (set->program[j]->sleepable || set->program[j]->expected_attach_type != BPF_TRACE_REPLACE ||
      !set->program[j]->aux->ebpfos_component || !entry_context(set->program[j])) {error = -EOPNOTSUPP;goto fail;}
 for (i = 0; i < set->count; ++i) {
  const struct ebpfos_function_entry *entry = &snapshot[i];
  const struct btf_type *function = btf_type_by_id(btf, entry->native_function);
  unsigned long address,ip,target;
  if (!function || !btf_type_is_func(function)) goto fail;
  address = kallsyms_lookup_name(btf_name_by_offset(btf, function->name_off));
  if (!address || !core_kernel_text(address) || !(ip = ftrace_location(address))) {error = -ENOENT;goto fail;}
  for (j = 0; j < i; ++j) if (set->locations[j] == ip) goto fail;
  set->locations[i] = ip;
  for (j = 0; j < 2; ++j) {
   if (!cell_callable(btf, function, set->program[j], entry->compiled_function, &target)) {error = -EPROTOTYPE;goto fail;}
   if (target & 1) goto fail;
   if (!add_ftrace_hash_entry_direct(set->hash[j], ip, ftrace_jmp_set(target))) {error = -ENOMEM;goto fail;}
  }
 }
 error = anon_inode_getfd("ebpfos-function-entries", &entry_operations, set, O_CLOEXEC | O_RDWR);
 if (error >= 0) {kfree(snapshot);return error;}
fail:
 kfree(snapshot);entry_free(set);return error;
}
__bpf_kfunc int bpf_ebpfos_function_entries_switch(u32 fd, u32 from, u32 to)
{
 struct fd file = fdget(fd);int error;
 if (fd_empty(file)) return -EBADF;
 if (fd_file(file)->f_op != &entry_operations) {fdput(file);return -EINVAL;}
 mutex_lock(&entry_lock);error = entry_switch(fd_file(file)->private_data, from, to);
 mutex_unlock(&entry_lock);fdput(file);return error;
}
__bpf_kfunc int bpf_ebpfos_function_entries_state(u32 fd)
{
 struct fd file = fdget(fd);int active;
 if (fd_empty(file)) return -EBADF;
 if (fd_file(file)->f_op != &entry_operations) {fdput(file);return -EINVAL;}
 mutex_lock(&entry_lock);active = ((struct entry_set *)fd_file(file)->private_data)->active;
 mutex_unlock(&entry_lock);fdput(file);return active;
}
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(entry_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_open, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_switch, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_state, KF_SLEEPABLE)
BTF_KFUNCS_END(entry_ids)
static const struct btf_kfunc_id_set entry_kfuncs;
static int entry_filter(const struct bpf_prog *prog, u32 id)
{const struct btf_kfunc_id_set *sets[] = { &entry_kfuncs };return ebpfos_syscall_kfunc_filter(prog,id,sets,ARRAY_SIZE(sets));}
static const struct btf_kfunc_id_set entry_kfuncs = { .set = &entry_ids, .filter = entry_filter };
static int __init entry_init(void)
{return register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,&entry_kfuncs);}
late_initcall(entry_init);
