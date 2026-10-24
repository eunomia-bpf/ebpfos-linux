// SPDX-License-Identifier: GPL-2.0-only
/* Typed native entry linking through Linux's existing batch direct ftrace API.
 * Only cold preparation/publication runs here. Ordinary callers execute the
 * installed direct jump and its native or verified body, with no invocation gate.
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
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/signal.h>
#include <linux/stacktrace.h>
#include <linux/workqueue.h>
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
 struct list_head retained, generations, generation_node;
 struct delayed_work release_work;
 u32 generation_id, next_generation;
 bool retired[2];
 struct module **modules;
 struct bpf_prog **programs;
 struct ftrace_ops operations;
 struct ftrace_hash *hash[2];
 struct entry_native_slot *slots;
 unsigned int slot_count;
 bool has_ftrace, poisoned, native_targets;
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

/* Logical generation IDs never reuse an older ID. Initial IDs 1 and 2 keep
 * the existing API; later entries own an ordinary prepared set, not a cache. */
static struct entry_set *entry_generation(struct entry_set *set, unsigned int id)
{
 struct entry_set *generation;
 if (id <= 2) return id && !set->retired[id - 1] ? set : NULL;
 list_for_each_entry(generation, &set->generations, generation_node)
  if (generation->generation_id == id) return generation;
 return NULL;
}
static unsigned int entry_generation_slot(unsigned int id)
{ return id <= 2 ? id - 1 : 0; }
static int entry_publication_point(void *unused) { return 0; }
static int entry_ftrace_apply(struct entry_set *set, unsigned int from, unsigned int to)
{
 if (!set->has_ftrace) return 0;
 if (!from) return update_ftrace_direct_add(&set->operations,
  entry_generation(set, to)->hash[entry_generation_slot(to)]);
 if (!to) return update_ftrace_direct_del(&set->operations,
  entry_generation(set, from)->hash[entry_generation_slot(from)]);
 return update_ftrace_direct_mod(&set->operations,
  entry_generation(set, to)->hash[entry_generation_slot(to)], true);
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
 error = entry_native_apply(from ? entry_generation(set, from)->slots : set->slots,
  to ? entry_generation(set, to)->slots : set->slots, set->slot_count,
  from ? entry_generation_slot(from) + 1 : 0, to ? entry_generation_slot(to) + 1 : 0);
 if (error) return error;
 /* A successful patch can already have entered either generation. Retain
  * both graphs before an ensuing ftrace/publication failure is recoverable. */
 if (to && !set->published) {
  set->published = true;
  list_add_tail(&set->retained, &entry_retained);
 }
 error = entry_ftrace_apply(set, from, to);
 if (error && entry_native_apply(to ? entry_generation(set, to)->slots : set->slots,
     from ? entry_generation(set, from)->slots : set->slots, set->slot_count,
     to ? entry_generation_slot(to) + 1 : 0, from ? entry_generation_slot(from) + 1 : 0)) {
  set->poisoned = true;
  return -EUCLEAN;
 }
 return error;
}
static int entry_switch(struct entry_set *set, unsigned int from, unsigned int to)
{
 int error, recovery;
 if (set->poisoned) return -EUCLEAN;
 if (from != set->active || (from && !entry_generation(set, from)) ||
     (to && !entry_generation(set, to))) return -ESTALE;
 if (from == to) return 0;
 /* The stock x86 text-poke batch performs its own CPU synchronization and
  * breakpoint-safe instruction update. Never call it with CPUs stopped: its
  * cross-CPU synchronizations must run. Legacy ftrace sets also keep their
  * following stop-machine point; reserved transactions already publish once.
  * Unchanged layouts and retained old code permit in-flight old frames.
  */
 error = entry_apply(set, from, to);
 if (error) return error;
 set->active = to;
 /* Reserved entries have one common publication inside the stock text
  * patcher's INT3 phase. It already serializes instruction visibility. */
 if (!set->has_ftrace) return 0;
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
 struct entry_set *generation, *next;
 unsigned int i;
 list_for_each_entry_safe(generation, next, &set->generations, generation_node) {
  list_del(&generation->generation_node);entry_free(generation);
 }
 if (set->modules)
  for (i = 0; i < set->count * 2; ++i) module_put(set->modules[i]);
 kvfree(set->modules);
 if (set->programs)
  for (i = 0; i < set->count * 2; ++i)
   if (set->programs[i]) bpf_prog_put(set->programs[i]);
 kvfree(set->programs);
 free_ftrace_hash(set->hash[0]);free_ftrace_hash(set->hash[1]);kvfree(set->slots);kvfree(set->locations);kfree(set);
}
/* An RCU-tasks grace period drains entry selection, but a sleeping frame can
 * cross that period. Use Linux's reliable stack walker as well. Refuse an
 * unreliable or running task; never infer safety from a guessed stack. */
struct entry_stack_check { struct entry_set *generation; unsigned int slot; };
static bool entry_stack_address(void *opaque, unsigned long ip)
{
 struct entry_stack_check *check = opaque;
 struct entry_set *set = check->generation;
 unsigned int i, j;
 for (i = 0; i < set->count; ++i) {
  struct module *module = set->modules[i * 2 + check->slot];
  struct bpf_prog *program = set->programs[i * 2 + check->slot];
  if (module && within_module_mem_type(ip, module, MOD_TEXT)) return false;
  if (!program) continue;
  if (ip >= (unsigned long)program->bpf_func &&
      ip < (unsigned long)program->bpf_func + program->jited_len) return false;
  for (j = 0; program->aux->func && j < program->aux->func_cnt; ++j) {
   struct bpf_prog *subprogram = program->aux->func[j];
   if (subprogram && ip >= (unsigned long)subprogram->bpf_func &&
       ip < (unsigned long)subprogram->bpf_func + subprogram->jited_len) return false;
  }
 }
 return true;
}
static int entry_stack_task(struct task_struct *task, void *check)
{
 int error;
 if (task != current && task_curr(task)) return -EBUSY;
 if (!try_get_task_stack(task)) return 0;
 error = arch_stack_walk_reliable(entry_stack_address, check, task);
 put_task_stack(task);
 return error ? -EBUSY : 0;
}
/* A bare function pointer can outlive the caller's stack. Until an owner
 * holds a separate graph lease, address-taken BPF closures cannot be retired
 * by a stack scan. Synchronous callbacks are conservatively retained too. */
static bool entry_program_addresses(struct bpf_prog *program)
{
 unsigned int i, j;
 if (!program) return false;
 for (j = 0; j < program->len; ++j)
  if (bpf_pseudo_func(&program->insnsi[j])) return true;
 for (i = 0; program->aux->func && i < program->aux->func_cnt; ++i) {
  struct bpf_prog *function = program->aux->func[i];
  if (!function) continue;
  for (j = 0; j < function->len; ++j)
   if (bpf_pseudo_func(&function->insnsi[j])) return true;
 }
 return false;
}
static int entry_quiescent(struct entry_set *set, unsigned int slot)
{
 struct entry_stack_check check = { set, slot };
 struct task_struct *group, *task;
 int error = 0;
 unsigned int i;
 bool executable = false;
 for (i = 0; i < set->count; ++i) {
  if (entry_program_addresses(set->programs[i * 2 + slot])) return -EOPNOTSUPP;
  executable |= set->programs[i * 2 + slot] || set->modules[i * 2 + slot];
 }
 if (!executable) {synchronize_rcu_tasks();return 0;}
 if (!IS_ENABLED(CONFIG_HAVE_RELIABLE_STACKTRACE) ||
     !IS_ENABLED(CONFIG_TASKS_RCU)) return -EOPNOTSUPP;
 /* Drain non-task interrupt readers as well, including interrupts from idle. */
 synchronize_rcu();
 synchronize_rcu_tasks();
 rcu_read_lock();
 for_each_process_thread(group, task) {
  error = task_call_func(task, entry_stack_task, &check);
  if (error) break;
 }
 rcu_read_unlock();
 return error;
}
static int entry_all_quiescent(struct entry_set *set)
{
 struct entry_set *generation;
 int error;
 unsigned int slot;
 for (slot = 0; slot < 2; ++slot) {
  if (set->retired[slot]) continue;
  error = entry_quiescent(set, slot);if (error) return error;
 }
 list_for_each_entry(generation, &set->generations, generation_node) {
  error = entry_quiescent(generation, 0);if (error) return error;
 }
 return 0;
}
static void entry_release_work(struct work_struct *work)
{
 struct entry_set *set = container_of(to_delayed_work(work), struct entry_set, release_work);
 int error;
 mutex_lock(&entry_lock);
 error = set->poisoned || set->active ? -EBUSY : entry_all_quiescent(set);
 if (!error && set->published) list_del(&set->retained);
 mutex_unlock(&entry_lock);
 if (!error) entry_free(set);
 else schedule_delayed_work(&set->release_work, HZ / 10);
}
static int entry_release(struct inode *inode, struct file *file)
{
 struct entry_set *set = file->private_data;
 int error;
 mutex_lock(&entry_lock);error = entry_switch(set, set->active, 0);
 mutex_unlock(&entry_lock);
 if (!set->published && !error) entry_free(set);
 else schedule_delayed_work(&set->release_work, 0);
 return error;
}
static const struct file_operations entry_operations = { .release = entry_release, .llseek = noop_llseek };
/* Pahole labels ordinary C globals STATIC in module BTF. The loaded ELF
 * symbol table supplies the actual linkage; require a unique global FUNC
 * so LLVM's private calling conventions cannot cross a native entry. */
static unsigned long entry_module_symbol(struct module *module, const char *name)
{
 unsigned long target = 0;
#if defined(CONFIG_MODULES) && defined(CONFIG_KALLSYMS)
 struct mod_kallsyms *symbols;
 unsigned int i;
 rcu_read_lock();
 symbols = rcu_dereference(module->kallsyms);
 for (i = 0; symbols && i < symbols->num_symtab; ++i) {
  const Elf_Sym *symbol = &symbols->symtab[i];
  if (strcmp(name, symbols->strtab + symbol->st_name)) continue;
  if (target || ELF_ST_BIND(symbol->st_info) != STB_GLOBAL ||
      ELF_ST_TYPE(symbol->st_info) != STT_FUNC || symbol->st_shndx == SHN_UNDEF) {
   target = 0;break;
  }
  target = kallsyms_symbol_value(symbol);
 }
 rcu_read_unlock();
#endif
 return target;
}
static struct entry_set *entry_prepare(const struct ebpfos_function_link *entries,
 unsigned int count, bool native_targets)
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
 INIT_LIST_HEAD(&set->generations);
 INIT_LIST_HEAD(&set->generation_node);
 INIT_DELAYED_WORK(&set->release_work, entry_release_work);
 set->next_generation = 3;
 set->count = count;
 set->native_targets = native_targets;
 set->modules = kvcalloc(count, 2 * sizeof(*set->modules), GFP_KERNEL);
 if (!set->modules) {error = -ENOMEM;goto fail;}
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
   if (native_targets) {
    struct btf *replacement_btf = btf;
    struct module *module = NULL;
    const struct btf_type *replacement;
    if (entry->compiled_function) {
     replacement_btf = btf_get_by_fd(entry->compiled_function - 1);
     if (IS_ERR(replacement_btf)) {error = PTR_ERR(replacement_btf);goto fail;}
     module = btf_try_get_module(replacement_btf);
     if (!module) {btf_put(replacement_btf);error = -ENOENT;goto fail;}
     set->modules[i * 2 + j] = module;
    }
    replacement = btf_type_by_id(replacement_btf, j ? entry->second : entry->first);
    if (!replacement || !btf_type_is_func(replacement) ||
        (module && (j ? entry->second : entry->first) < btf_nr_types(btf)) ||
        !cell_layout(btf, function->type, replacement_btf, replacement->type, 0, false)) {
     error = -EPROTOTYPE;goto native_out;
    }
    if (module) {
     target = entry_module_symbol(module, btf_name_by_offset(replacement_btf, replacement->name_off));
     if (!target || !within_module_mem_type(target, module, MOD_TEXT)) error = -ENOENT;
     else error = 0;
    } else {
     target = kallsyms_lookup_name(btf_name_by_offset(replacement_btf, replacement->name_off));
     error = !target || !core_kernel_text(target) || target == address ? -ENOENT : 0;
    }
native_out:
    if (entry->compiled_function) btf_put(replacement_btf);
    if (error) goto fail;
   } else {
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
   }
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
 unsigned int count, bool native_targets)
{
 struct entry_set *set = entry_prepare(entries, count, native_targets);
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
 error = entry_open(snapshot, entries__sz / sizeof(*entries), false);
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
 error = entry_open(links, count, false);
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
/* Unlike the legacy mixed ftrace/reservation operation, this entry point
 * promises one publication for the complete set, or no text change.
 */
__bpf_kfunc int bpf_ebpfos_function_entries_switch_atomic(u32 fd, u32 from, u32 to)
{
 struct fd file = fdget(fd);int error;
 struct entry_set *set;
 if (fd_empty(file)) return -EBADF;
 if (fd_file(file)->f_op != &entry_operations) {fdput(file);return -EINVAL;}
 set = fd_file(file)->private_data;
 mutex_lock(&entry_lock);
 error = set->has_ftrace ? -EOPNOTSUPP : entry_switch(set, from, to);
 mutex_unlock(&entry_lock);fdput(file);return error;
}
struct ebpfos_native_function_link { u32 native_function, first_function, second_function; };
__bpf_kfunc int bpf_ebpfos_function_entries_open_native(
 const struct ebpfos_native_function_link *entries, u32 entries__sz)
{
 struct ebpfos_native_function_link *snapshot;
 struct ebpfos_function_link *links;
 unsigned int count, i;
 int error;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (!entries__sz || entries__sz % sizeof(*entries)) return -EINVAL;
 count = entries__sz / sizeof(*entries);
 snapshot = kmemdup(entries, entries__sz, GFP_KERNEL);
 if (!snapshot) return -ENOMEM;
 links = kvmalloc_array(count, sizeof(*links), GFP_KERNEL);
 if (!links) {kfree(snapshot);return -ENOMEM;}
 for (i = 0; i < count; ++i)
  links[i] = (struct ebpfos_function_link){snapshot[i].native_function, 0,
    snapshot[i].first_function, snapshot[i].second_function};
 error = entry_open(links, count, true);
 kvfree(links);kfree(snapshot);return error;
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
 * active immutable graph. Drain displaced frames before dropping their leases.
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
 set = fd_file(file)->private_data;
 prepared = entry_prepare(snapshot, entries__sz / sizeof(*entries), set->native_targets);
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
 if (set->published) {error = entry_quiescent(set, slot);if (error) goto out_unlock;}
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
  swap(set->modules[i * 2 + slot], prepared->modules[j * 2 + slot]);
 }
 /* The displaced inactive code has passed both retirement checks. */
 set->retired[slot] = false;
 error = 0;
out_unlock:
 mutex_unlock(&entry_lock);
 if (prepared) entry_free(prepared);
out_file:
 fdput(file);
 return error;
}
/* Append immutable logical generations. Failed preparation changes neither
 * text nor journal; IDs are never recycled after retirement. */
static int entry_append(u32 fd, struct entry_set *prepared)
{
 struct entry_set *set;
 struct fd file;
 unsigned int i;
 int error;
 file = fdget(fd);
 if (fd_empty(file)) {error = -EBADF;goto out;}
 if (fd_file(file)->f_op != &entry_operations) {error = -EINVAL;goto out_file;}
 set = fd_file(file)->private_data;
 mutex_lock(&entry_lock);
 error = -EINVAL;
 if (set->count != prepared->count || set->slot_count != prepared->slot_count ||
     set->has_ftrace != prepared->has_ftrace) goto unlock;
 /* Require exactly the journal's complete ordered unit. The runtime emits
  * this order automatically; partial or reordered appends cannot mutate it. */
 for (i = 0; i < set->count * 2; ++i)
  if (set->locations[i] != prepared->locations[i]) goto unlock;
 if (set->next_generation > INT_MAX) {error = -EOVERFLOW;goto unlock;}
 error = prepared->generation_id = set->next_generation++;
 list_add_tail(&prepared->generation_node, &set->generations);
 prepared = NULL;
unlock:
 mutex_unlock(&entry_lock);
out_file:
 fdput(file);
out:
 if (prepared) entry_free(prepared);
 return error;
}
__bpf_kfunc int bpf_ebpfos_function_entries_append_many(u32 fd,
 const struct ebpfos_function_link *entries, u32 entries__sz)
{
 struct ebpfos_function_link *snapshot;
 struct entry_set *prepared;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (!entries__sz || entries__sz % sizeof(*entries)) return -EINVAL;
 snapshot = kmemdup(entries, entries__sz, GFP_KERNEL);
 if (!snapshot) return -ENOMEM;
 prepared = entry_prepare(snapshot, entries__sz / sizeof(*entries), false);
 kfree(snapshot);
 return IS_ERR(prepared) ? PTR_ERR(prepared) : entry_append(fd, prepared);
}
__bpf_kfunc int bpf_ebpfos_function_entries_append_native(u32 fd, u32 btf_fd,
 const struct ebpfos_native_function_link *entries, u32 entries__sz)
{
 struct ebpfos_native_function_link *snapshot;
 struct ebpfos_function_link *links;
 struct entry_set *prepared;
 unsigned int count, i;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (!entries__sz || entries__sz % sizeof(*entries)) return -EINVAL;
 count = entries__sz / sizeof(*entries);
 snapshot = kmemdup(entries, entries__sz, GFP_KERNEL);
 if (!snapshot) return -ENOMEM;
 links = kvmalloc_array(count, sizeof(*links), GFP_KERNEL);
 if (!links) {kfree(snapshot);return -ENOMEM;}
 for (i = 0; i < count; ++i)
  links[i] = (struct ebpfos_function_link){snapshot[i].native_function, btf_fd + 1,
   snapshot[i].first_function, snapshot[i].first_function};
 prepared = entry_prepare(links, count, true);
 kvfree(links);kfree(snapshot);
 return IS_ERR(prepared) ? PTR_ERR(prepared) : entry_append(fd, prepared);
}
__bpf_kfunc int bpf_ebpfos_function_entries_retire(u32 fd, u32 id)
{
 struct fd file = fdget(fd);
 struct entry_set *set, *generation;
 unsigned int i, slot;
 int error = -ESTALE;
 if (fd_empty(file)) return -EBADF;
 if (fd_file(file)->f_op != &entry_operations) {fdput(file);return -EINVAL;}
 set = fd_file(file)->private_data;
 mutex_lock(&entry_lock);
 generation = entry_generation(set, id);
 if (!generation) goto unlock;
 if (set->poisoned || set->active == id) {error = -EBUSY;goto unlock;}
 slot = entry_generation_slot(id);
 error = entry_quiescent(generation, slot);
 if (error) goto unlock;
 if (id > 2) {
  list_del(&generation->generation_node);entry_free(generation);
 } else {
  for (i = 0; i < set->count; ++i) {
   if (set->programs[i * 2 + slot]) bpf_prog_put(set->programs[i * 2 + slot]);
   set->programs[i * 2 + slot] = NULL;
   module_put(set->modules[i * 2 + slot]);set->modules[i * 2 + slot] = NULL;
  }
  set->retired[slot] = true;
 }
unlock:
 mutex_unlock(&entry_lock);fdput(file);return error;
}
/* Measurement control: identical atomic publication plus the old extra
 * stop-machine synchronization. No invocation-path work is added. */
__bpf_kfunc int bpf_ebpfos_function_entries_switch_atomic_sync(u32 fd, u32 from, u32 to)
{
 int error = bpf_ebpfos_function_entries_switch_atomic(fd, from, to);
 return error ? error : stop_machine(entry_publication_point, NULL, NULL);
}
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(entry_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_open, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_open_many, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_switch, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_switch_atomic, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_open_native, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_state, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_prepare, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_append_many, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_append_native, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_retire, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_switch_atomic_sync, KF_SLEEPABLE)
BTF_KFUNCS_END(entry_ids)
static const struct btf_kfunc_id_set entry_kfuncs;
static int entry_filter(const struct bpf_prog *prog, u32 id)
{const struct btf_kfunc_id_set *sets[] = { &entry_kfuncs };return ebpfos_syscall_kfunc_filter(prog,id,sets,ARRAY_SIZE(sets));}
static const struct btf_kfunc_id_set entry_kfuncs = { .set = &entry_ids, .filter = entry_filter };
static int __init entry_init(void)
{return register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,&entry_kfuncs);}
late_initcall(entry_init);
