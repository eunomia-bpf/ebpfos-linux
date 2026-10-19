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
#include <linux/memory.h>
#include <asm/text-patching.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include "syscall_kfuncs.h"
struct ebpfos_function_entry { u32 native_function, compiled_function; };
/* Each symbol may come from a separately admitted object. Program references
 * and all symbol/ABI/context checks belong to cold linking, never invocation.
 */
struct ebpfos_function_link {
 u32 native_function, compiled_function, first, second;
};
struct entry_set {
 struct list_head retained;
 struct bpf_prog **programs;
 struct ftrace_ops operations;
 struct ftrace_hash *hash[2];
 struct entry_native_slot *slots;
 unsigned int slot_count;
 bool has_ftrace, poisoned;
 /* Native IDs follow the count locations, preserving each caller contract. */
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
#include "function_native_context.h"

#include "function_contract.h"

/* Independent graphs have independent BTF ordinals. Resolve the second
 * generation by its exported symbol, then apply the same complete native
 * callable contract. Only loaded functions count; duplicate exports refuse.
 * The retained graph owns the resolved address for the journal's lifetime.
 */
static bool entry_export(struct btf *native, const struct btf_type *function,
 struct bpf_prog *program, unsigned long *address)
{
 struct bpf_prog_aux *aux = program->aux;
 const char *name = btf_name_by_offset(native, function->name_off);
 unsigned int i;
 bool found = false;
 if (!aux->btf || !aux->func_info || !aux->func) return false;
 for (i = 1; i < aux->func_cnt && i < aux->func_info_cnt; ++i) {
  u32 id = aux->func_info[i].type_id;
  const struct btf_type *candidate = btf_type_by_id(aux->btf, id);
  if (!candidate || !btf_type_is_func(candidate) ||
      strcmp(name, btf_name_by_offset(aux->btf, candidate->name_off))) continue;
  if (found || !cell_callable(native, function, program, id, address)) return false;
  found = true;
 }
 return found;
}

#include "function_entry_slots.h"

static int entry_publication_point(void *unused) { return 0; }
static int entry_ftrace_apply(struct entry_set *set, unsigned int from, unsigned int to)
{
 if (!set->has_ftrace) return 0;
 if (!from) return update_ftrace_direct_add(&set->operations, set->hash[to - 1]);
 if (!to) return update_ftrace_direct_del(&set->operations, set->hash[from - 1]);
 return update_ftrace_direct_mod(&set->operations, set->hash[to - 1], true);
}
static int entry_apply(struct entry_set *set, unsigned int from, unsigned int to)
{
 struct entry_set *owner;
 unsigned int i, j;
 int error;
 if (set->poisoned) return -EUCLEAN;
 /* Each reserved instruction has one active journal. Retained generations
  * keep executable ownership even if an exceptional rollback cannot finish. */
 list_for_each_entry(owner, &entry_retained, retained) {
  if (owner == set || (!owner->active && !owner->poisoned)) continue;
  for (i = 0; i < set->slot_count; ++i)
   for (j = 0; j < owner->slot_count; ++j)
    if (set->slots[i].ip == owner->slots[j].ip) return -EBUSY;
 }
 error = entry_native_apply(set->slots, set->slot_count, from, to);
 if (error) return error;
 /* A successful patch can already have entered either generation. Retain
  * both graphs before an ensuing ftrace/publication failure is recoverable. */
 if (to && !set->published) {
  set->published = true;
  list_add_tail(&set->retained, &entry_retained);
 }
 error = entry_ftrace_apply(set, from, to);
 if (error && entry_native_apply(set->slots, set->slot_count, to, from)) {
  set->poisoned = true;
  return -EUCLEAN;
 }
 return error;
}
static int entry_switch(struct entry_set *set, unsigned int from, unsigned int to)
{
 int error, recovery;
 if (set->poisoned) return -EUCLEAN;
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
 set->active = to;
 error = stop_machine(entry_publication_point, NULL, NULL);
 if (error) {
  recovery = entry_apply(set, to, from);
  if (!recovery) set->active = from;
  else {set->poisoned = true;error = -EUCLEAN;}
 }
 return error;
}
static void entry_free(struct entry_set *set)
{
 unsigned int i;
 if (set->programs)
  for (i = 0; i < set->count * 2; ++i)
   if (set->programs[i]) bpf_prog_put(set->programs[i]);
 kvfree(set->programs);
 free_ftrace_hash(set->hash[0]);free_ftrace_hash(set->hash[1]);kvfree(set->slots);kvfree(set->locations);kfree(set);
}
static int entry_release(struct inode *inode, struct file *file)
{
 struct entry_set *set = file->private_data;
 int error;
 mutex_lock(&entry_lock);error = entry_switch(set, set->active, 0);
 if (!set->published && error) list_add_tail(&set->retained, &entry_retained);
 mutex_unlock(&entry_lock);
 if (!set->published && !error) entry_free(set);
 return error;
}
static const struct file_operations entry_operations = { .release = entry_release, .llseek = noop_llseek };
static struct entry_set *entry_prepare(const struct ebpfos_function_link *entries,
 unsigned int count)
{
 struct entry_set *set;
 struct btf *btf = bpf_get_btf_vmlinux();
 unsigned int i,j;
 int error = -EINVAL;
 if (!capable(CAP_SYS_ADMIN)) return ERR_PTR(-EPERM);
 if (!IS_ENABLED(CONFIG_DYNAMIC_FTRACE_WITH_JMP) ||
     !IS_ENABLED(CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS)) return ERR_PTR(-EOPNOTSUPP);
 if (!count || IS_ERR_OR_NULL(btf)) return ERR_PTR(-EINVAL);
 set = kzalloc(sizeof(*set), GFP_KERNEL);
 if (!set) return ERR_PTR(-ENOMEM);
 set->count = count;
 set->programs = kvcalloc(count, 2 * sizeof(*set->programs), GFP_KERNEL);
 if (!set->programs) {error = -ENOMEM;goto fail;}
 set->locations = kvcalloc(set->count, 2 * sizeof(*set->locations), GFP_KERNEL);
 if (!set->locations) {error = -ENOMEM;goto fail;}
 set->slots = kvcalloc(count, sizeof(*set->slots), GFP_KERNEL);
 if (!set->slots) {error = -ENOMEM;goto fail;}
 set->hash[0] = alloc_ftrace_hash(FTRACE_HASH_DEFAULT_BITS);
 set->hash[1] = alloc_ftrace_hash(FTRACE_HASH_DEFAULT_BITS);
 if (!set->hash[0] || !set->hash[1]) { error = -ENOMEM;goto fail; }
 for (i = 0; i < set->count; ++i) {
  const struct ebpfos_function_link *entry = &entries[i];
  const struct btf_type *function = btf_type_by_id(btf, entry->native_function);
  unsigned long address,ip,target;
  struct entry_native_slot *slot = NULL;
  if (!function || !btf_type_is_func(function)) goto fail;
  address = kallsyms_lookup_name(btf_name_by_offset(btf, function->name_off));
  if (!address || !core_kernel_text(address)) {error = -ENOENT;goto fail;}
  ip = ftrace_location(address);
#ifdef FTRACE_MCOUNT_MAX_OFFSET
  /* ftrace_location() includes disabled records. Mirror stock ftrace's
   * validity bound before choosing it over an immutable native reservation.
   * Entry padding can move __fentry__ beyond that bound.
   */
  if (ip && (ip < address || ip - address > FTRACE_MCOUNT_MAX_OFFSET)) ip = 0;
#endif
  if (!ip) {
   ip = entry_native_location(address);
   if (!ip) {error = -ENOENT;goto fail;}
   slot = &set->slots[set->slot_count++];slot->ip = ip;
  } else set->has_ftrace = true;
  for (j = 0; j < i; ++j) if (set->locations[j] == ip) goto fail;
  set->locations[i] = ip;
  set->locations[set->count + i] = entry->native_function;
  for (j = 0; j < 2; ++j) {
   struct bpf_prog *program = bpf_prog_get_type_dev(j ? entry->second : entry->first,
      BPF_PROG_TYPE_TRACING, false);
   if (IS_ERR(program)) {error = PTR_ERR(program);goto fail;}
   set->programs[i * 2 + j] = program;
   if (program->sleepable || program->expected_attach_type != BPF_TRACE_REPLACE ||
       !program->aux->ebpfos_component) {error = -EOPNOTSUPP;goto fail;}
   if (!(j ? entry_export(btf, function, program, &target) :
       cell_callable(btf, function, program, entry->compiled_function, &target))) {error = -EPROTOTYPE;goto fail;}
   if (!entry_context(program, target)) {error = -EOPNOTSUPP;goto fail;}
   if (target & 1) goto fail;
   if (slot) {
    u8 instruction[5];
    if (!entry_native_jump(ip, target, instruction)) {error = -ERANGE;goto fail;}
    slot->target[j] = target;
   } else if (!add_ftrace_hash_entry_direct(set->hash[j], ip, ftrace_jmp_set(target))) {error = -ENOMEM;goto fail;}
  }
 }
 return set;
fail:
 entry_free(set);return ERR_PTR(error);
}
static int entry_open(const struct ebpfos_function_link *entries,
 unsigned int count)
{
 struct entry_set *set = entry_prepare(entries, count);
 int descriptor;
 if (IS_ERR(set)) return PTR_ERR(set);
 descriptor = anon_inode_getfd("ebpfos-function-entries", &entry_operations, set, O_CLOEXEC | O_RDWR);
 if (descriptor < 0) entry_free(set);
 return descriptor;
}
__bpf_kfunc_start_defs();
__bpf_kfunc int bpf_ebpfos_function_entries_open_many(
 const struct ebpfos_function_link *entries, u32 entries__sz)
{
 struct ebpfos_function_link *snapshot;
 int error;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (!entries__sz || entries__sz % sizeof(*entries)) return -EINVAL;
 snapshot = kmemdup(entries, entries__sz, GFP_KERNEL);
 if (!snapshot) return -ENOMEM;
 error = entry_open(snapshot, entries__sz / sizeof(*entries));
 kfree(snapshot);return error;
}
__bpf_kfunc int bpf_ebpfos_function_entries_open(u32 first, u32 second,
 const struct ebpfos_function_entry *entries, u32 entries__sz)
{
 struct ebpfos_function_entry *snapshot;
 struct ebpfos_function_link *links;
 unsigned int i, count;
 int error;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (!entries__sz || entries__sz % sizeof(*entries)) return -EINVAL;
 count = entries__sz / sizeof(*entries);
 snapshot = kmemdup(entries, entries__sz, GFP_KERNEL);
 if (!snapshot) return -ENOMEM;
 links = kvmalloc_array(count, sizeof(*links), GFP_KERNEL);
 if (!links) {kfree(snapshot);return -ENOMEM;}
 for (i = 0; i < count; ++i)
  links[i] = (struct ebpfos_function_link){snapshot[i].native_function,
    snapshot[i].compiled_function, first, second};
 error = entry_open(links, count);
 kvfree(links);kfree(snapshot);return error;
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
 mutex_lock(&entry_lock);
 active = ((struct entry_set *)fd_file(file)->private_data)->poisoned ? -EUCLEAN :
  ((struct entry_set *)fd_file(file)->private_data)->active;
 mutex_unlock(&entry_lock);fdput(file);return active;
}
/* Rebind the inactive generation of an existing journal. All native callable
 * checks finish before changing its targets; ordinary calls still use the
 * active immutable graph. Retain displaced published graphs for old frames.
 */
__bpf_kfunc int bpf_ebpfos_function_entries_prepare(u32 fd, u32 from,
 const struct ebpfos_function_link *entries, u32 entries__sz)
{
 struct ebpfos_function_link *snapshot;
 struct entry_set *set, *prepared;
 struct fd file;
 unsigned int i, j, slot;
 int error;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (from != 1 && from != 2) return -EINVAL;
 if (!entries__sz || entries__sz % sizeof(*entries)) return -EINVAL;
 file = fdget(fd);
 if (fd_empty(file)) return -EBADF;
 if (fd_file(file)->f_op != &entry_operations) { error = -EINVAL;goto out_file; }
 snapshot = kmemdup(entries, entries__sz, GFP_KERNEL);
 if (!snapshot) { error = -ENOMEM;goto out_file; }
 prepared = entry_prepare(snapshot, entries__sz / sizeof(*entries));
 kfree(snapshot);
 if (IS_ERR(prepared)) { error = PTR_ERR(prepared);goto out_file; }
 set = fd_file(file)->private_data;
 mutex_lock(&entry_lock);
 error = -ESTALE;
 if (set->poisoned || set->active != from) goto out_unlock;
 error = -EINVAL;
 if (set->count != prepared->count || set->slot_count != prepared->slot_count ||
     set->has_ftrace != prepared->has_ftrace) goto out_unlock;
 for (i = 0; i < set->count; ++i) {
  for (j = 0; j < prepared->count; ++j)
   if (set->locations[i] == prepared->locations[j]) break;
  if (j == prepared->count) goto out_unlock;
  /* An address alias must not exchange the original caller's ABI/contract. */
  if (set->locations[set->count + i] != prepared->locations[prepared->count + j]) goto out_unlock;
 }
 slot = from == 1 ? 1 : 0;
 /* Native slots and program references must follow their symbol when a
  * caller reorders the complete set. Validate the entire join before swaps. */
 for (i = 0; i < set->slot_count; ++i) {
  for (j = 0; j < prepared->slot_count; ++j)
   if (set->slots[i].ip == prepared->slots[j].ip) break;
  if (j == prepared->slot_count) goto out_unlock;
 }
 for (i = 0; i < set->slot_count; ++i) {
  for (j = 0; j < prepared->slot_count; ++j)
   if (set->slots[i].ip == prepared->slots[j].ip) break;
  swap(set->slots[i].target[slot], prepared->slots[j].target[slot]);
 }
 swap(set->hash[slot], prepared->hash[slot]);
 for (i = 0; i < set->count; ++i) {
  for (j = 0; j < prepared->count; ++j)
   if (set->locations[i] == prepared->locations[j]) break;
  swap(set->programs[i * 2 + slot], prepared->programs[j * 2 + slot]);
 }
 /* The detached preparation has never owned a text patch. It now retains
  * the displaced slot; that code may still have suspended old frames. */
 list_add_tail(&prepared->retained, &entry_retained);
 prepared = NULL;
 error = 0;
out_unlock:
 mutex_unlock(&entry_lock);
 if (prepared) entry_free(prepared);
out_file:
 fdput(file);
 return error;
}
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(entry_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_open, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_open_many, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_switch, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_state, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_prepare, KF_SLEEPABLE)
BTF_KFUNCS_END(entry_ids)
static const struct btf_kfunc_id_set entry_kfuncs;
static int entry_filter(const struct bpf_prog *prog, u32 id)
{const struct btf_kfunc_id_set *sets[] = { &entry_kfuncs };return ebpfos_syscall_kfunc_filter(prog,id,sets,ARRAY_SIZE(sets));}
static const struct btf_kfunc_id_set entry_kfuncs = { .set = &entry_ids, .filter = entry_filter };
static int __init entry_init(void)
{return register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,&entry_kfuncs);}
late_initcall(entry_init);
