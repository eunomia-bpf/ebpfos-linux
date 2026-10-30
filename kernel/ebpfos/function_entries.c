// SPDX-License-Identifier: GPL-2.0-only
/* Typed multi-target BPF links over Linux's batched text update.
 * Only cold preparation/publication runs here. Ordinary callers execute the
 * installed direct jump and its native or verified body, with no invocation gate.
 */
#include <linux/bpf.h>
#include <linux/btf.h>
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
#include <linux/cpu.h>
#include <linux/smp.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/bpf_entry.h>
#include <linux/bpf_operations.h>
#include <asm/text-patching.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include "function_native.h"
struct entry_member { u32 native_function, program; };
/* Each symbol may come from a separately admitted object. Program references
 * and all symbol/ABI/context checks belong to cold linking, never invocation.
 */
struct entry_set {
 struct list_head retained, generations, generation_node, sharing;
 struct delayed_work release_work, retire_work;
 bool closing, epoch_mode;
 struct bpf_prog *migration, *reverse;
 unsigned long migration_address, reverse_address;
 u32 generation_id, next_generation;
 bool retired[2];
 struct module *source_module;
 struct btf *source_btf;
 struct bpf_prog **programs;
 struct bpf_operations_set *tables;
 struct ftrace_text_reservation *ftrace;
 struct entry_native_slot *slots;
 unsigned int slot_count;
 bool poisoned, call_sites;
 /* Native IDs follow the count locations, preserving each caller contract. */
 unsigned long *locations, *addresses;
 unsigned int count, active, table_count;
 bool published;
};
static int entry_epoch_apply(struct entry_set *, unsigned int, unsigned int, unsigned long);
static DEFINE_MUTEX(entry_lock);
/* A stopped CPU does not prove every suspended old frame has returned. Keep
 * actual published graphs alive until their owners can prove retirement. */
static LIST_HEAD(entry_retained);
/* All live journals, including cgroup and operations-only bindings. */
static LIST_HEAD(entry_sharing_sets);

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
static bool entry_export(struct btf *native, u32 prototype,
 const struct btf_type *function, const char *name, bool source_name,
 struct bpf_prog *program, unsigned long *address)
{
 struct bpf_prog_aux *aux = program->aux;
 unsigned int i;
 bool found = false;
 if (!aux->btf || !aux->func_info || !aux->func) return false;
 for (i = 1; i < aux->func_cnt && i < aux->func_info_cnt; ++i) {
  u32 id = aux->func_info[i].type_id;
  const struct btf_type *candidate = btf_type_by_id(aux->btf, id);
  if (!candidate || !btf_type_is_func(candidate) ||
      !cell_export_name(name, aux->btf, id, !source_name)) continue;
  if (found || !cell_callable_proto(native, prototype, function, name, program, id, address)) return false;
  found = true;
 }
 return found;
}

#include "function_entry_slots.h"
#include "function_entry_calls.h"
static int entry_callers_stopped(struct entry_set *set);

/* One cold native-call contract for direct entries and generated tables. */
static int entry_program_address(struct btf *btf, u32 prototype,
 const struct btf_type *function, const char *name, bool source_name, struct bpf_prog *program,
 bool task, unsigned long *target)
{
 if (program->type == BPF_PROG_TYPE_NATIVE) {
  struct btf *replacement_btf = program->aux->attach_btf;
  const struct btf_type *replacement = btf_type_by_id(replacement_btf, program->aux->attach_btf_id);
  if (!replacement || !btf_type_is_func(replacement) ||
      !cell_layout(btf, prototype, replacement_btf, replacement->type, 0, false)) return -EPROTOTYPE;
  *target = (unsigned long)program->bpf_func;
  return 0;
 }
 if (!program->aux->ebpfos_component ||
     !((program->type == BPF_PROG_TYPE_TRACING && !program->sleepable &&
        program->expected_attach_type == BPF_TRACE_REPLACE) ||
       (task && program->type == BPF_PROG_TYPE_SYSCALL && program->sleepable &&
        !program->expected_attach_type))) return -EOPNOTSUPP;
 if (!entry_export(btf, prototype, function, name, source_name, program, target)) {
  pr_warn("BPF entry '%s': compiled callable is incompatible\n",
          name);
  return -EPROTOTYPE;
 }
 return entry_context(program, *target) ? 0 : -EOPNOTSUPP;
}

int bpf_entry_program_address(struct btf *btf, u32 id, struct bpf_prog *program,
 bool task, unsigned long *target)
{
 const struct btf_type *function = btf_type_by_id(btf, id);
 if (!function || !btf_type_is_func(function)) return -EINVAL;
 return entry_program_address(btf, function->type, function,
  btf_name_by_offset(btf, function->name_off), false, program, task, target);
}

/* A field retains its native call contract even when its private callback has
 * no FUNC record. A non-NULL native address supplies the export identity;
 * an empty field uses the selected component root's exact source callable.
 * Missing function annotations grant no additional verified preconditions.
 */
int bpf_method_program_address(struct btf *btf, u32 prototype, const char *name,
 struct bpf_prog *program, unsigned long *target)
{
 const struct btf_type *type = btf_type_skip_modifiers(btf, prototype, &prototype), *function = NULL;
 int id = name ? btf_find_by_name_kind(btf, name, BTF_KIND_FUNC) : 0;
 bool source_name = !name;
 if (!type || !btf_type_is_func_proto(type)) return -EINVAL;
 if (id > 0) {
  function = btf_type_by_id(btf, id);
  if (!cell_layout(btf, function->type, btf, prototype, 0, false)) return -EPROTOTYPE;
  prototype = function->type;
 }
 if (!name && program->type != BPF_PROG_TYPE_NATIVE) {
  struct bpf_prog_aux *aux = program->aux;
  const struct btf_type *root;
  if (!aux->btf || !aux->func_info || !aux->func_info_cnt) return -EPROTOTYPE;
  root = btf_type_by_id(aux->btf, aux->func_info[0].type_id);
  if (!root || !btf_type_is_func(root)) return -EPROTOTYPE;
  name = btf_find_decl_tag_value(aux->btf, root, -1, "component.entry/");
  if (IS_ERR(name) || !*name) return -EPROTOTYPE;
 }
 return entry_program_address(btf, prototype, function, name, source_name, program, false, target);
}

/* Every appended generation owns an immutable prepared set. Revision IDs
 * are never recycled after retirement. */
static struct entry_set *entry_generation(struct entry_set *set, unsigned int id)
{
 struct entry_set *generation;
 if (!id) return NULL;
 if (id == 1) return !set->retired[0] ? set : NULL;
 list_for_each_entry(generation, &set->generations, generation_node)
  if (generation->generation_id == id) return generation;
 return NULL;
}
static unsigned int entry_generation_slot(unsigned int id)
{ return 0; }
#include "function_entry_side.h"
static int entry_ownership(struct entry_set *set)
{
 struct entry_set *owner;
 unsigned int i, j;
 if (set->poisoned) return -EUCLEAN;
 /* Each reserved instruction has one active journal. Retained generations
  * keep executable ownership even if an exceptional rollback cannot finish. */
 list_for_each_entry(owner, &entry_retained, retained) {
  if (owner == set || (!owner->active && !owner->poisoned)) continue;
  if (set->source_module && set->source_module == owner->source_module &&
      (set->epoch_mode || owner->epoch_mode)) return -EBUSY;
  for (i = 0; i < set->slot_count; ++i)
   for (j = 0; j < owner->slot_count; ++j)
    if (set->slots[i].ip == owner->slots[j].ip) return -EBUSY;
 }
 return 0;
}
/* Publish the table default and every direct entry in the same stopped
 * interval. Existing same-layout calls/objects retain their old code/maps.
 * As with owned-state epochs, source contracts exclude NMI and transaction
 * users: stopping task/IRQ creators does not stop NMI execution.
 */
struct entry_tables_publication {
 struct entry_set *set;
 struct bpf_operations_global_update *tables;
 bool published;
};
static int entry_tables_publish(void *opaque)
{
 struct entry_tables_publication *publication = opaque;
 int error = publication->set->call_sites ? entry_callers_stopped(publication->set) : 0;
 if (error) return error;
 /* The cold update holds both complete selection snapshots. No allocation
  * or last-reference release occurs while CPUs are stopped. */
 bpf_operations_global_publish(publication->tables);
 publication->published = true;
 return 0;
}
static void entry_tables_undo(void *opaque)
{
 struct entry_tables_publication *publication = opaque;
 if (publication->published)
  bpf_operations_global_undo(publication->tables);
}
static int entry_tables_apply(struct entry_set *set, unsigned int from, unsigned int to,
 struct bpf_operations_global_update *tables)
{
 struct entry_tables_publication publication = { .set = set, .tables = tables };
 struct text_poke_pair *pairs;
 int error;
 pairs = entry_native_pairs(from ? entry_generation(set, from)->slots : set->slots,
  to ? entry_generation(set, to)->slots : set->slots, set->slot_count,
  from ? entry_generation_slot(from) + 1 : 0, to ? entry_generation_slot(to) + 1 : 0);
 if (IS_ERR(pairs)) return PTR_ERR(pairs);
 error = smp_text_poke_quiescent_transaction(pairs, set->slot_count,
  entry_tables_publish, entry_tables_undo, &publication);
 kvfree(pairs);
 if (!error && to && !set->published) {
  set->published = true;list_add_tail(&set->retained, &entry_retained);
 }
 return error;
}
static int entry_apply(struct entry_set *set, unsigned int from, unsigned int to)
{
 struct bpf_operations_set *old_tables = from ? entry_generation(set, from)->tables : NULL;
 struct bpf_operations_set *next_tables = to ? entry_generation(set, to)->tables : NULL;
 struct bpf_operations_global_update tables;
 int error = entry_ownership(set);
 if (!error && !to && set->reverse) return entry_epoch_apply(set, from, to, set->reverse_address);
 if (error) return error;
 error = bpf_operations_global_prepare(&tables, next_tables, old_tables);
 if (error) return error;
 if (set->call_sites || (set->count && set->table_count)) {
  error = entry_tables_apply(set, from, to, &tables);goto done;
 }
 error = entry_native_apply(from ? entry_generation(set, from)->slots : set->slots,
  to ? entry_generation(set, to)->slots : set->slots, set->slot_count,
  from ? entry_generation_slot(from) + 1 : 0, to ? entry_generation_slot(to) + 1 : 0);
 if (error) goto done;
 /* A successful patch may already have entered either generation. Keep
  * both program graphs through stack-checked retirement. */
 if (to && !set->published) {
  set->published = true;
  list_add_tail(&set->retained, &entry_retained);
 }
 bpf_operations_global_publish(&tables);
done:
 bpf_operations_global_release(&tables);return error;
}
static int entry_switch(struct entry_set *set, unsigned int from, unsigned int to)
{
 int error;
 if (set->poisoned) return -EUCLEAN;
 if (from != set->active || (from && !entry_generation(set, from)) ||
     (to && !entry_generation(set, to))) return -ESTALE;
 if (from == to) return 0;
 error = entry_apply(set, from, to);
 if (!error) set->active = to;
 return error;
}
static void entry_free(struct entry_set *set)
{
 struct entry_set *generation, *next;
 unsigned int i;
 list_for_each_entry_safe(generation, next, &set->generations, generation_node) {
  list_del(&generation->generation_node);entry_free(generation);
 }
 if (set->migration) bpf_prog_put(set->migration);
 if (set->reverse) bpf_prog_put(set->reverse);
 ftrace_text_release(set->ftrace);
 module_put(set->source_module);
 if (set->source_btf) btf_put(set->source_btf);
 if (set->programs)
  for (i = 0; i < set->count * 2; ++i)
   if (set->programs[i]) bpf_prog_put(set->programs[i]);
 bpf_operations_set_put(set->tables);
 kvfree(set->programs);
 kvfree(set->slots);kvfree(set->locations);kvfree(set->addresses);kfree(set);
}
#include "function_lifetime.h"
struct entry_lifetime { struct entry_set *generation; unsigned int slot; };
static bool entry_code_contains(void *opaque, unsigned long ip)
{
 struct entry_lifetime *lifetime = opaque;
 struct entry_set *set = lifetime->generation;
 unsigned int i;
 for (i = 0; i < set->count; ++i) {
  struct bpf_prog *program = set->programs[i * 2 + lifetime->slot];
  struct module *module = program && program->type == BPF_PROG_TYPE_NATIVE ? program->aux->mod : NULL;
  if ((module && within_module_mem_type(ip, module, MOD_TEXT)) ||
      ebpfos_program_contains(set->programs[i * 2 + lifetime->slot], ip)) return true;
 }
 return false;
}
#include "function_entry_epoch.h"

static int entry_callers_stopped(struct entry_set *set)
{
 return ebpfos_code_stopped(entry_epoch_contains, set);
}

static int entry_quiescent(struct entry_set *set, unsigned int slot)
{
 struct entry_lifetime lifetime = { .generation = set, .slot = slot };
 unsigned int i;
 bool executable = false;
 for (i = 0; i < set->count; ++i) {
  if (ebpfos_program_addresses(set->programs[i * 2 + slot])) return -EOPNOTSUPP;
  if (set->programs[i * 2 + slot] &&
      (set->programs[i * 2 + slot]->type != BPF_PROG_TYPE_NATIVE ||
       set->programs[i * 2 + slot]->aux->mod)) executable = true;
 }
 if (!executable) {synchronize_rcu_tasks();return 0;}
 return ebpfos_code_quiescent(entry_code_contains, &lifetime);
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
/* Published generations remain immutable. Reclaim only inactive code whose
 * interrupted and sleeping frames have drained, with no call-path counter. */
static void entry_retire_work(struct work_struct *work)
{
 struct entry_set *set = container_of(to_delayed_work(work), struct entry_set, retire_work);
 struct entry_set *generation, *next;
 bool retry = false;
 unsigned int slot, i;
 mutex_lock(&entry_lock);
 if (set->closing || set->poisoned) goto out;
 for (slot = 0; slot < 2; ++slot) {
  if (set->retired[slot] || (!slot && set->active == 1)) continue;
  if (entry_quiescent(set, slot)) {retry = true;continue;}
  for (i = 0; i < set->count; ++i) {
   bpf_prog_put(set->programs[i * 2 + slot]);
   set->programs[i * 2 + slot] = NULL;
  }
  set->retired[slot] = true;
  if (!slot) {bpf_operations_set_put(set->tables);set->tables = NULL;}
 }
 list_for_each_entry_safe(generation, next, &set->generations, generation_node) {
  if (generation->generation_id == set->active) continue;
  if (entry_quiescent(generation, 0)) {retry = true;continue;}
  list_del(&generation->generation_node);
  entry_free(generation);
 }
 if (retry) schedule_delayed_work(&set->retire_work, HZ / 10);
out:
 mutex_unlock(&entry_lock);
}
/* Restored source text and escaped replacement code have separate leases.
 * A private callback can retain the BPF graph after every source frame left;
 * that does not require keeping its original publication module resident.
 * Native imports and Native versions retain their own program module refs. */
static bool entry_source_contains(void *opaque, unsigned long ip)
{
 struct entry_set *set = opaque, *generation;
 if (set->source_module && within_module(ip, set->source_module)) return true;
 list_for_each_entry(generation, &set->generations, generation_node)
  if (generation->source_module && within_module(ip, generation->source_module)) return true;
 return false;
}
static int entry_source_release(struct entry_set *set)
{
 struct entry_set *generation;
 bool resident = set->source_module != NULL;
 int error;
 list_for_each_entry(generation, &set->generations, generation_node)
  resident |= generation->source_module != NULL;
 if (!resident) return 0;
 error = ebpfos_code_quiescent(entry_source_contains, set);
 if (error) return error;
 ftrace_text_release(set->ftrace);set->ftrace = NULL;
 module_put(set->source_module);set->source_module = NULL;
 list_for_each_entry(generation, &set->generations, generation_node) {
  module_put(generation->source_module);generation->source_module = NULL;
 }
 return 0;
}
static void entry_release_work(struct work_struct *work)
{
 struct entry_set *set = container_of(to_delayed_work(work), struct entry_set, release_work);
 int error;
 mutex_lock(&entry_lock);
 error = set->poisoned ? -EUCLEAN : entry_switch(set, set->active, 0);
 if (!error) error = entry_source_release(set);
 if (!error) error = entry_all_quiescent(set);
 if (!error && set->published) list_del(&set->retained);
 if (!error) list_del_init(&set->sharing);
 mutex_unlock(&entry_lock);
 if (!error) entry_free(set);
 else schedule_delayed_work(&set->release_work, HZ / 10);
}
static struct entry_set *entry_prepare(const struct entry_member *entries,
 unsigned int count, struct btf *source, bool task, struct entry_set *owner)
{
 struct entry_set *set;
 struct btf *vmlinux_btf = bpf_get_btf_vmlinux();
 struct btf *btf = source ? source : vmlinux_btf;
 unsigned int i,j;
 int error = -EINVAL;
 if (!capable(CAP_SYS_ADMIN)) return ERR_PTR(-EPERM);
 if (IS_ERR_OR_NULL(btf) || IS_ERR_OR_NULL(vmlinux_btf)) return ERR_PTR(-EINVAL);
 set = kzalloc(sizeof(*set), GFP_KERNEL);
 if (!set) return ERR_PTR(-ENOMEM);
 INIT_LIST_HEAD(&set->sharing);
 INIT_LIST_HEAD(&set->generations);
 INIT_LIST_HEAD(&set->generation_node);
 INIT_DELAYED_WORK(&set->release_work, entry_release_work);
 INIT_DELAYED_WORK(&set->retire_work, entry_retire_work);
 set->next_generation = 2;
 set->count = count;
 if (source) {
  set->source_module = btf_try_get_module(source);
  if (!set->source_module) {error = -ENOENT;goto fail;}
  btf_get(source);set->source_btf = source;
 }

 set->programs = kvcalloc(count, 2 * sizeof(*set->programs), GFP_KERNEL);
 if (!set->programs) {error = -ENOMEM;goto fail;}
 set->locations = kvcalloc(set->count, 2 * sizeof(*set->locations), GFP_KERNEL);
 if (!set->locations) {error = -ENOMEM;goto fail;}
 set->addresses = kvcalloc(count, sizeof(*set->addresses), GFP_KERNEL);
 if (!set->addresses) {error = -ENOMEM;goto fail;}
 set->slots = kvcalloc(count, sizeof(*set->slots), GFP_KERNEL);
 if (!set->slots) {error = -ENOMEM;goto fail;}
 for (i = 0; i < set->count; ++i) {
  const struct entry_member *entry = &entries[i];
  const struct btf_type *function = btf_type_by_id(btf, entry->native_function);
  unsigned long address,ip,target;
  bool call_sites = false, canonical_nop = false;
  struct entry_native_slot *slot = NULL;
  error = -EINVAL;
  if (!function || !btf_type_is_func(function)) goto fail;
  if (source && entry->native_function < btf_nr_types(vmlinux_btf)) goto fail;
  address = ebpfos_native_function(btf, entry->native_function, set->source_module);
  if (!address) {error = -ENOENT;goto fail;}
  ip = address;
  if (!task && source && entry_module_noinstr(set->source_module, address)) {
   /* No entry patch or breakpoint in noinstr text. Replace every decoded
    * direct caller instead, with all tasks and IRQs stopped. */
   call_sites = true;ip = address;
  } else if (!task) {
  ip = ftrace_location(address);
#ifdef FTRACE_MCOUNT_MAX_OFFSET
  /* ftrace_location() includes disabled records. Mirror stock ftrace's
   * validity bound before choosing it over an immutable native reservation.
   * Entry padding can move __fentry__ beyond that bound.
   */
  if (ip && (ip < address || ip - address > FTRACE_MCOUNT_MAX_OFFSET)) ip = 0;
#endif
  if (!ip) {
   ip = source ? entry_module_native_location(set->source_module, address, &canonical_nop) :
    entry_native_location(address, &canonical_nop);
   if (!ip) {
    if (!source) {error = -ENOENT;goto fail;}
    /* An unpadded module entry uses the same closed direct-caller
     * transaction as noinstr text. No reservation is added to its body. */
    call_sites = true;ip = address;
   } else {
    slot = &set->slots[set->slot_count++];slot->ip = ip;
    slot->canonical_nop = canonical_nop;
   }
  } else {slot = &set->slots[set->slot_count++];slot->ip = ip;slot->ftrace = true;}
  }
  for (j = 0; j < i; ++j) if (set->locations[j] == ip) goto fail;
  set->locations[i] = ip;
  set->locations[set->count + i] = entry->native_function;
  for (j = 0; j < 2; ++j) {
   struct bpf_prog *program;
   if (j) {
    program = set->programs[i * 2];
    bpf_prog_inc(program);
   } else {
    program = bpf_prog_get(entry->program);
    if (IS_ERR(program)) {error = PTR_ERR(program);goto fail;}
   }
   set->programs[i * 2 + j] = program;
   error = bpf_entry_program_address(btf, entry->native_function, program, task, &target);
   if (error) {
    pr_warn("BPF entry '%s': callable binding refused (%d)\n",
            btf_name_by_offset(btf, function->name_off), error);
    goto fail;
   }
   if (!task && target == address) {error = -EINVAL;goto fail;}
   set->addresses[i] = target;
   if (call_sites && entry_module_noinstr(set->source_module, address)) {
    if (program->type != BPF_PROG_TYPE_NATIVE || !program->aux->mod ||
        !entry_module_noinstr(program->aux->mod, target)) {error = -EOPNOTSUPP;goto fail;}
   } else if (slot) {
    u8 instruction[5];
    if (!entry_native_jump(ip, target, instruction)) {error = -ERANGE;goto fail;}
    slot->target[j] = target;
   }
  }
  if (call_sites) {
   error = entry_module_calls(set, address, target, owner);
   if (error) goto fail;
   set->call_sites = true;
  }
 }
 if (!task && !owner) {
  unsigned long *ips = kvmalloc_array(set->slot_count, sizeof(*ips), GFP_KERNEL);
  unsigned int count = 0;
  if (!ips) {error = -ENOMEM;goto fail;}
  for (i = 0; i < set->slot_count; ++i) if (set->slots[i].ftrace) ips[count++] = set->slots[i].ip;
  set->ftrace = ftrace_text_reserve(ips, count);kvfree(ips);
  if (IS_ERR(set->ftrace)) {error = PTR_ERR(set->ftrace);set->ftrace = NULL;goto fail;}
 }
 return set;
fail:
 entry_free(set);return ERR_PTR(error);
}

/* Native code is source-built kernel/module text, never an arbitrary user
 * address. BPF_PROG_LOAD creates an ordinary program object and holds both
 * its BTF and its module. This privileged type is an unverified staged tier.
 */
const struct bpf_prog_ops bpf_native_prog_ops = {};
const struct bpf_verifier_ops bpf_native_verifier_ops = {};
int bpf_native_prog_init(struct bpf_prog *prog, const union bpf_attr *attr)
{
 struct btf *btf;
 const struct btf_type *function;
 struct module *module = NULL;
 unsigned long address;
 if (attr->attach_btf_obj_fd) {
  btf = btf_get_by_fd(attr->attach_btf_obj_fd);
  if (IS_ERR(btf)) return PTR_ERR(btf);
  module = btf_try_get_module(btf);
  if (!module) {btf_put(btf);return -EINVAL;}
 } else {
  btf = bpf_get_btf_vmlinux();
  if (IS_ERR_OR_NULL(btf)) return -EOPNOTSUPP;
  btf_get(btf);
 }
 function = btf_type_by_id(btf, attr->attach_btf_id);
 if (!function || !btf_type_is_func(function) ||
     (module && attr->attach_btf_id < btf_nr_types(bpf_get_btf_vmlinux()))) {
  module_put(module);btf_put(btf);return -EINVAL;
 }
 address = ebpfos_native_function(btf, attr->attach_btf_id, module);
 if (!address) {
  module_put(module);btf_put(btf);return -ENOENT;
 }
 prog->aux->attach_btf = btf;
 prog->aux->attach_btf_id = attr->attach_btf_id;
 prog->aux->mod = module;
 prog->gpl_compatible = !module || !(module->taints & (1UL << TAINT_PROPRIETARY_MODULE));
 prog->bpf_func = (void *)address;
 return 0;
}

struct bpf_entry_link {
 struct bpf_link link;
 struct entry_set *set;
 bool detached;
};
static const struct bpf_link_ops entry_link_ops;

static bool entry_link_active(struct bpf_entry_link *entry)
{ return !entry->detached; }
static int entry_link_detach(struct bpf_link *link)
{
 struct bpf_entry_link *entry = container_of(link, struct bpf_entry_link, link);
 int error;
 mutex_lock(&entry_lock);
 error = entry_switch(entry->set, entry->set->active, 0);
 if (!error) {
  ftrace_text_release(entry->set->ftrace);entry->set->ftrace = NULL;
  entry->detached = true;
 }
 mutex_unlock(&entry_lock);
 return error;
}
static void entry_link_release(struct bpf_link *link)
{
 struct bpf_entry_link *entry = container_of(link, struct bpf_entry_link, link);
 /* On an exceptional patch refusal retain the journal, text and every code
  * lease. Never free a version still reachable from a native entry. */
 entry_link_detach(link);
 mutex_lock(&entry_lock);entry->set->closing = true;mutex_unlock(&entry_lock);
 cancel_delayed_work_sync(&entry->set->retire_work);
 schedule_delayed_work(&entry->set->release_work, 0);
}
static void entry_link_dealloc(struct bpf_link *link)
{ kfree(container_of(link, struct bpf_entry_link, link)); }
static void entry_link_fdinfo(const struct bpf_link *link, struct seq_file *seq)
{
 struct bpf_entry_link *entry = container_of(link, struct bpf_entry_link, link);
 struct entry_set *generation;
 unsigned int i, slot;
 mutex_lock(&entry_lock);
 generation = entry_link_active(entry) ? entry_generation(entry->set, entry->set->active) : NULL;
 slot = entry_generation_slot(entry->set->active);
 seq_printf(seq, "count:\t%u\nrevision:\t%u\ndetached:\t%u\n",
  entry->set->count, entry->set->active, !entry_link_active(entry));
 seq_printf(seq, "operations_count:\t%u\n", entry->set->table_count);
 seq_printf(seq, "epoch_flags:\t%u\nmigration_prog_id:\t%u\nreverse_prog_id:\t%u\n",
  entry->set->epoch_mode ? BPF_F_ENTRY_EPOCH : 0,
  entry->set->migration ? entry->set->migration->aux->id : 0,
  entry->set->reverse ? entry->set->reverse->aux->id : 0);
 seq_printf(seq, "cgroup_id:\t%llu\n", 0ULL);
 for (i = 0; i < entry->set->count; ++i)
  seq_printf(seq, "target:\t%lu\t%u\n", entry->set->locations[entry->set->count + i],
   generation ? generation->programs[i * 2 + slot]->aux->id : 0);
 mutex_unlock(&entry_lock);
}
static int entry_link_info(const struct bpf_link *link, struct bpf_link_info *info)
{
 struct bpf_entry_link *entry = container_of(link, struct bpf_entry_link, link);
 struct entry_set *generation;
 u32 __user *targets = u64_to_user_ptr(info->entry.target_btf_ids);
 u32 __user *programs = u64_to_user_ptr(info->entry.prog_ids);
 u32 __user *tables = u64_to_user_ptr(info->entry.operations_ids);
 u32 table_count = info->entry.operations_count;
 unsigned int i, count = info->entry.count, slot;
 int error = 0;
 if (!!targets != !!programs || (!!count != !!targets) || (!!table_count != !!tables)) return -EINVAL;
 mutex_lock(&entry_lock);
 generation = entry_link_active(entry) ? entry_generation(entry->set, entry->set->active) : NULL;
 slot = entry_generation_slot(entry->set->active);
 for (i = 0; i < min(count, entry->set->count); ++i)
  if (put_user((u32)entry->set->locations[entry->set->count + i], targets + i) ||
      put_user(generation ? generation->programs[i * 2 + slot]->aux->id : 0, programs + i)) {
   error = -EFAULT;break;
  }
 info->entry.operations_count = entry->set->table_count;
 for (i = 0; i < min(table_count, info->entry.operations_count); ++i)
  if (put_user(generation ? bpf_operations_set_id(generation->tables, i) : 0, tables + i)) {error = -EFAULT;break;}
 info->entry.epoch_flags = entry->set->epoch_mode ? BPF_F_ENTRY_EPOCH : 0;
 info->entry.migration_prog_id = entry->set->migration ? entry->set->migration->aux->id : 0;
 info->entry.reverse_prog_id = entry->set->reverse ? entry->set->reverse->aux->id : 0;
 info->entry.count = entry->set->count;
 info->entry.target_btf_obj_id = btf_obj_id(entry->set->source_btf ?
  entry->set->source_btf : bpf_get_btf_vmlinux());
 info->entry.revision = entry->set->active;
 info->entry.detached = !entry_link_active(entry);
 info->entry.cgroup_id = 0ULL;
 mutex_unlock(&entry_lock);
 return error;
}
static const struct bpf_link_ops entry_link_ops = {
 .release = entry_link_release,
 .dealloc = entry_link_dealloc,
 .detach = entry_link_detach,
 .show_fdinfo = entry_link_fdinfo,
 .fill_link_info = entry_link_info,
};
int bpf_entry_link_create(const union bpf_attr *attr, bool kernel)
{
 struct bpf_entry_link *entry;
 struct bpf_link_primer primer;
 struct entry_member *members;
 struct entry_set *set;
 struct btf *source = NULL;
 u32 *targets, *programs, count = attr->link_create.entry.count, i;
 u32 operations_count = attr->link_create.entry.operations_count, *operations_fds;
 int error;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (kernel || attr->link_create.attach_type != BPF_TRACE_ENTRY) return -EOPNOTSUPP;
 if (attr->link_create.prog_fd || (attr->link_create.flags & ~BPF_F_ENTRY_EPOCH) ||
     attr->link_create.entry.reserved || attr->link_create.entry.operations_reserved ||
     (!count && !operations_count)) return -EINVAL;
 if ((attr->link_create.flags & BPF_F_ENTRY_EPOCH) &&
     (operations_count || !count || !attr->link_create.target_fd)) return -EOPNOTSUPP;
 targets = vmemdup_array_user(u64_to_user_ptr(attr->link_create.entry.target_btf_ids), count, sizeof(u32));
 if (IS_ERR(targets)) return PTR_ERR(targets);
 programs = vmemdup_array_user(u64_to_user_ptr(attr->link_create.entry.prog_fds), count, sizeof(u32));
 if (IS_ERR(programs)) {error = PTR_ERR(programs);goto free_targets;}
 members = kvmalloc_array(count, sizeof(*members), GFP_KERNEL);
 if (!members) {error = -ENOMEM;goto free_programs;}
 for (i = 0; i < count; ++i) members[i] = (struct entry_member){targets[i], programs[i]};
 if (attr->link_create.target_fd) {
  source = btf_get_by_fd(attr->link_create.target_fd);
  if (IS_ERR(source)) {error = PTR_ERR(source);goto free_members;}
 }
 set = entry_prepare(members, count, source, false, NULL);
 if (source) btf_put(source);
 if (IS_ERR(set)) {error = PTR_ERR(set);goto free_members;}
 operations_fds = vmemdup_array_user(u64_to_user_ptr(attr->link_create.entry.operations_fds), operations_count, sizeof(u32));
 if (IS_ERR(operations_fds)) {error = PTR_ERR(operations_fds);goto free_set;}
 set->tables = bpf_operations_prepare(operations_fds, operations_count);
 set->table_count = operations_count;
 kvfree(operations_fds);
 if (IS_ERR(set->tables)) {error = PTR_ERR(set->tables);set->tables = NULL;goto free_set;}
 set->epoch_mode = attr->link_create.flags & BPF_F_ENTRY_EPOCH;
 entry = kzalloc(sizeof(*entry), GFP_KERNEL);
 if (!entry) {error = -ENOMEM;goto free_set;}
 entry->set = set;
 bpf_link_init(&entry->link, BPF_LINK_TYPE_ENTRY, &entry_link_ops, NULL, attr->link_create.attach_type);
 error = bpf_link_prime(&entry->link, &primer);
 if (error) {kfree(entry);goto free_set;}
 mutex_lock(&entry_lock);
 error=entry_side_compatible(NULL,NULL,0,set,false);
 if (!error) error = entry_switch(set, 0, 1);
 if (!error) list_add_tail(&set->sharing,&entry_sharing_sets);
 mutex_unlock(&entry_lock);
 if (error) {
  bpf_link_cleanup(&primer);
  if (set->published) schedule_delayed_work(&set->release_work, 0);
  else entry_free(set);
  goto free_members;
 }
 error = bpf_link_settle(&primer);
 goto free_members;
free_set:
 entry_free(set);
free_members:
 kvfree(members);
free_programs:
 kvfree(programs);
free_targets:
 kvfree(targets);
 return error;
}
int bpf_entry_link_update(struct bpf_link *link, const union bpf_attr *attr)
{
 struct bpf_entry_link *entry = container_of(link, struct bpf_entry_link, link);
 struct entry_set *set = entry->set, *prepared, *old;
 struct entry_member *members;
 struct bpf_prog **expected = NULL;
 struct bpf_prog *migration = NULL, *reverse = NULL;
 unsigned long migration_address = 0, reverse_address = 0;
 struct bpf_operations_set *expected_tables = NULL;
 u32 operations_count = attr->link_update.entry.operations_count, *operations_fds;
 u32 *programs = NULL, *old_fds = NULL, count = attr->link_update.entry.count;
 unsigned int i, slot, id = 0;
 int error = -EINVAL;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (link->ops != &entry_link_ops || attr->link_update.entry.reserved ||
     attr->link_update.new_prog_fd || attr->link_update.old_prog_fd ||
     attr->link_update.entry.operations_reserved || count != set->count ||
     operations_count != set->table_count || (!count && !operations_count) ||
     ((attr->link_update.flags & BPF_F_REPLACE) ?
       ((count && !attr->link_update.entry.old_prog_fds) ||
        (operations_count && !attr->link_update.entry.old_operations_fds)) :
       (attr->link_update.entry.old_prog_fds || attr->link_update.entry.old_operations_fds))) return -EINVAL;
 if (!!attr->link_update.entry.migration_prog_fd != !!attr->link_update.entry.reverse_prog_fd) return -EINVAL;
 if (attr->link_update.entry.migration_prog_fd) {
  if (!set->epoch_mode || operations_count) return -EOPNOTSUPP;
  migration = entry_epoch_program(set, attr->link_update.entry.migration_prog_fd, &migration_address);
  if (IS_ERR(migration)) return PTR_ERR(migration);
  reverse = entry_epoch_program(set, attr->link_update.entry.reverse_prog_fd, &reverse_address);
  if (IS_ERR(reverse)) {error = PTR_ERR(reverse);reverse = NULL;goto out;}
  if (migration == reverse) {error = -EINVAL;goto out;}
 }
 programs = vmemdup_array_user(u64_to_user_ptr(attr->link_update.entry.prog_fds), count, sizeof(u32));
 if (IS_ERR(programs)) {error = PTR_ERR(programs);programs = NULL;goto out;}
 if ((attr->link_update.flags & BPF_F_REPLACE) && count) {
  old_fds = vmemdup_array_user(u64_to_user_ptr(attr->link_update.entry.old_prog_fds), count, sizeof(u32));
  if (IS_ERR(old_fds)) {error = PTR_ERR(old_fds);old_fds = NULL;goto out;}
  expected = kvcalloc(count, sizeof(*expected), GFP_KERNEL);
  if (!expected) {error = -ENOMEM;goto out;}
  for (i = 0; i < count; ++i) {
   expected[i] = bpf_prog_get(old_fds[i]);
   if (IS_ERR(expected[i])) {error = PTR_ERR(expected[i]);expected[i] = NULL;goto out;}
  }
 }
 members = kvmalloc_array(count, sizeof(*members), GFP_KERNEL);
 if (!members) {error = -ENOMEM;goto out;}
 for (i = 0; i < count; ++i)
  members[i] = (struct entry_member){set->locations[count + i], programs[i]};
 prepared = entry_prepare(members, count, set->source_btf, false, set);
 kvfree(members);
 if (IS_ERR(prepared)) {error = PTR_ERR(prepared);goto out;}
 operations_fds = vmemdup_array_user(u64_to_user_ptr(attr->link_update.entry.operations_fds), operations_count, sizeof(u32));
 if (IS_ERR(operations_fds)) {error = PTR_ERR(operations_fds);entry_free(prepared);goto out;}
 prepared->tables = bpf_operations_prepare(operations_fds, operations_count);
 kvfree(operations_fds);
 if (IS_ERR(prepared->tables)) {error = PTR_ERR(prepared->tables);prepared->tables = NULL;entry_free(prepared);goto out;}
 if ((attr->link_update.flags & BPF_F_REPLACE) && operations_count) {
  operations_fds = vmemdup_array_user(u64_to_user_ptr(attr->link_update.entry.old_operations_fds), operations_count, sizeof(u32));
  if (IS_ERR(operations_fds)) {error = PTR_ERR(operations_fds);entry_free(prepared);goto out;}
  expected_tables = bpf_operations_prepare(operations_fds, operations_count);
  kvfree(operations_fds);
  if (IS_ERR(expected_tables)) {error = PTR_ERR(expected_tables);expected_tables = NULL;entry_free(prepared);goto out;}
 }
 mutex_lock(&entry_lock);
 error = -ENOLINK;
 if (!entry_link_active(entry)) goto unlock;
 error = -EINVAL;
 if (set->slot_count != prepared->slot_count) goto unlock;
 for (i = 0; i < count * 2; ++i)
  if (set->locations[i] != prepared->locations[i]) goto unlock;
 old = entry_generation(set, set->active);
 if (!bpf_operations_set_targets(prepared->tables, old->tables)) goto unlock;
 slot = entry_generation_slot(set->active);
 error = -EPERM;
 if (expected)
  for (i = 0; i < count; ++i)
   if (old->programs[i * 2 + slot] != expected[i]) goto unlock;
 if (expected_tables && !bpf_operations_set_same(old->tables, expected_tables)) goto unlock;
 error=entry_side_compatible(set,old,slot,prepared,migration!=NULL);if(error)goto unlock;
 error = -EBUSY;
 /* One outstanding layout epoch. A reverse update must use the retained
  * inverse, not another conversion with an unrelated population contract. */
 if (migration && set->reverse && (migration != set->reverse || reverse != set->migration)) goto unlock;
 error = -EOVERFLOW;
 if (set->next_generation > INT_MAX) goto unlock;
 id = set->next_generation;
 prepared->generation_id = id;set->next_generation++;
 list_add_tail(&prepared->generation_node, &set->generations);
 if (migration) {
  error = entry_ownership(set);
  if (!error) error = entry_epoch_apply(set, set->active, id, migration_address);
  if (!error) {
   set->active = id;
   if (set->reverse) {
    bpf_prog_put(set->migration);bpf_prog_put(set->reverse);
    set->migration = NULL;set->reverse = NULL;
    set->migration_address = 0;set->reverse_address = 0;
   } else {
    set->migration = migration;set->reverse = reverse;migration = NULL;reverse = NULL;
    set->migration_address = migration_address;set->reverse_address = reverse_address;
   }
  }
 } else error = entry_switch(set, set->active, id);
 if (error && !set->poisoned) list_del(&prepared->generation_node);
 else prepared = NULL; /* Includes poisoned text: keep every possible target. */
 if (!error) schedule_delayed_work(&set->retire_work, 0);
unlock:
 mutex_unlock(&entry_lock);
 if (prepared) entry_free(prepared);
out:
 if (expected)
  for (i = 0; i < count; ++i) if (expected[i]) bpf_prog_put(expected[i]);
 if (migration) bpf_prog_put(migration);
 if (reverse) bpf_prog_put(reverse);
 bpf_operations_set_put(expected_tables);
 kvfree(expected);kvfree(old_fds);kvfree(programs);
 return error;
}
