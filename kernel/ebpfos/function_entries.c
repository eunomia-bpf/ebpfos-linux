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
#include <asm/text-patching.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include "function_native.h"
struct entry_member { u32 native_function, program; };
/* Each symbol may come from a separately admitted object. Program references
 * and all symbol/ABI/context checks belong to cold linking, never invocation.
 */
struct entry_set {
 struct list_head retained, generations, generation_node;
 struct delayed_work release_work, retire_work;
 bool closing;
 u32 generation_id, next_generation;
 bool retired[2];
 struct module *source_module;
 struct btf *source_btf;
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
static int entry_ownership(struct entry_set *set)
{
 struct entry_set *owner;
 unsigned int i, j;
 if (set->poisoned) return -EUCLEAN;
 /* Each reserved instruction has one active journal. Retained generations
  * keep executable ownership even if an exceptional rollback cannot finish. */
 list_for_each_entry(owner, &entry_retained, retained) {
  if (owner == set || (!owner->active && !owner->poisoned)) continue;
  for (i = 0; i < set->slot_count; ++i)
   for (j = 0; j < owner->slot_count; ++j)
    if (set->slots[i].ip == owner->slots[j].ip) return -EBUSY;
 }
 return 0;
}
static int entry_apply(struct entry_set *set, unsigned int from, unsigned int to)
{
 int error = entry_ownership(set);
 if (error) return error;
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
 module_put(set->source_module);
 if (set->source_btf) btf_put(set->source_btf);
 if (set->programs)
  for (i = 0; i < set->count * 2; ++i)
   if (set->programs[i]) bpf_prog_put(set->programs[i]);
 kvfree(set->programs);
 free_ftrace_hash(set->hash[0]);free_ftrace_hash(set->hash[1]);kvfree(set->slots);kvfree(set->locations);kfree(set);
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
static void entry_release_work(struct work_struct *work)
{
 struct entry_set *set = container_of(to_delayed_work(work), struct entry_set, release_work);
 int error;
 mutex_lock(&entry_lock);
 error = set->poisoned ? -EUCLEAN : entry_switch(set, set->active, 0);
 if (!error) error = entry_all_quiescent(set);
 if (!error && set->published) list_del(&set->retained);
 mutex_unlock(&entry_lock);
 if (!error) entry_free(set);
 else schedule_delayed_work(&set->release_work, HZ / 10);
}
static struct entry_set *entry_prepare(const struct entry_member *entries,
 unsigned int count, struct btf *source)
{
 struct entry_set *set;
 struct btf *vmlinux_btf = bpf_get_btf_vmlinux();
 struct btf *btf = source ? source : vmlinux_btf;
 unsigned int i,j;
 int error = -EINVAL;
 if (!capable(CAP_SYS_ADMIN)) return ERR_PTR(-EPERM);
 if (!IS_ENABLED(CONFIG_DYNAMIC_FTRACE_WITH_JMP) ||
     !IS_ENABLED(CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS)) return ERR_PTR(-EOPNOTSUPP);
 if (!count || IS_ERR_OR_NULL(btf) || IS_ERR_OR_NULL(vmlinux_btf)) return ERR_PTR(-EINVAL);
 set = kzalloc(sizeof(*set), GFP_KERNEL);
 if (!set) return ERR_PTR(-ENOMEM);
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
 set->slots = kvcalloc(count, sizeof(*set->slots), GFP_KERNEL);
 if (!set->slots) {error = -ENOMEM;goto fail;}
 set->hash[0] = alloc_ftrace_hash(FTRACE_HASH_DEFAULT_BITS);
 set->hash[1] = alloc_ftrace_hash(FTRACE_HASH_DEFAULT_BITS);
 if (!set->hash[0] || !set->hash[1]) { error = -ENOMEM;goto fail; }
 for (i = 0; i < set->count; ++i) {
  const struct entry_member *entry = &entries[i];
  const struct btf_type *function = btf_type_by_id(btf, entry->native_function);
  unsigned long address,ip,target;
  struct entry_native_slot *slot = NULL;
  error = -EINVAL;
  if (!function || !btf_type_is_func(function)) goto fail;
  if (source && entry->native_function < btf_nr_types(vmlinux_btf)) goto fail;
  address = source ? ebpfos_module_function(set->source_module,
   btf_name_by_offset(btf, function->name_off)) :
   kallsyms_lookup_name(btf_name_by_offset(btf, function->name_off));
  if (!address || (!source && !core_kernel_text(address))) {error = -ENOENT;goto fail;}
  ip = ftrace_location(address);
#ifdef FTRACE_MCOUNT_MAX_OFFSET
  /* ftrace_location() includes disabled records. Mirror stock ftrace's
   * validity bound before choosing it over an immutable native reservation.
   * Entry padding can move __fentry__ beyond that bound.
   */
  if (ip && (ip < address || ip - address > FTRACE_MCOUNT_MAX_OFFSET)) ip = 0;
#endif
  if (!ip) {
   ip = source ? entry_module_native_location(set->source_module, address) :
    entry_native_location(address);
   if (!ip) {error = -ENOENT;goto fail;}
   slot = &set->slots[set->slot_count++];slot->ip = ip;
  } else set->has_ftrace = true;
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
   if (program->type == BPF_PROG_TYPE_NATIVE) {
    struct btf *replacement_btf = program->aux->attach_btf;
    const struct btf_type *replacement = btf_type_by_id(replacement_btf,
     program->aux->attach_btf_id);
    if (!cell_layout(btf, function->type, replacement_btf, replacement->type, 0, false)) {
     error = -EPROTOTYPE;goto fail;
    }
    target = (unsigned long)program->bpf_func;
   } else {
    if (program->type != BPF_PROG_TYPE_TRACING || program->sleepable ||
        program->expected_attach_type != BPF_TRACE_REPLACE ||
        !program->aux->ebpfos_component) {error = -EOPNOTSUPP;goto fail;}
    if (!entry_export(btf, function, program, &target)) {error = -EPROTOTYPE;goto fail;}
    if (!entry_context(program, target)) {error = -EOPNOTSUPP;goto fail;}
   }
   if (target == address) {error = -EINVAL;goto fail;}
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
     (!module && btf_func_linkage(function) != BTF_FUNC_GLOBAL) ||
     (module && attr->attach_btf_id < btf_nr_types(bpf_get_btf_vmlinux()))) {
  module_put(module);btf_put(btf);return -EINVAL;
 }
 address = module ? ebpfos_module_function(module, btf_name_by_offset(btf, function->name_off)) :
  kallsyms_lookup_name(btf_name_by_offset(btf, function->name_off));
 if (!address || (!module && !core_kernel_text(address))) {
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

static int entry_link_detach(struct bpf_link *link)
{
 struct bpf_entry_link *entry = container_of(link, struct bpf_entry_link, link);
 int error;
 mutex_lock(&entry_lock);
 error = entry_switch(entry->set, entry->set->active, 0);
 if (!error) entry->detached = true;
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
 generation = entry_generation(entry->set, entry->set->active);
 slot = entry_generation_slot(entry->set->active);
 seq_printf(seq, "count:\t%u\nrevision:\t%u\ndetached:\t%u\n",
  entry->set->count, entry->set->active, entry->detached);
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
 unsigned int i, count = info->entry.count, slot;
 int error = 0;
 if (!!targets != !!programs || (!!count != !!targets)) return -EINVAL;
 mutex_lock(&entry_lock);
 generation = entry_generation(entry->set, entry->set->active);
 slot = entry_generation_slot(entry->set->active);
 for (i = 0; i < min(count, entry->set->count); ++i)
  if (put_user((u32)entry->set->locations[entry->set->count + i], targets + i) ||
      put_user(generation ? generation->programs[i * 2 + slot]->aux->id : 0, programs + i)) {
   error = -EFAULT;break;
  }
 info->entry.count = entry->set->count;
 info->entry.target_btf_obj_id = btf_obj_id(entry->set->source_btf ?
  entry->set->source_btf : bpf_get_btf_vmlinux());
 info->entry.revision = entry->set->active;
 info->entry.detached = entry->detached;
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
 int error;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (kernel) return -EOPNOTSUPP;
 if (attr->link_create.prog_fd || attr->link_create.flags ||
     attr->link_create.entry.reserved || !count) return -EINVAL;
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
 set = entry_prepare(members, count, source);
 if (source) btf_put(source);
 if (IS_ERR(set)) {error = PTR_ERR(set);goto free_members;}
 /* A reserved-entry batch has one common text publication. Mixed or legacy
  * ftrace updates do not provide this transaction and stay unsupported. */
 if (set->has_ftrace) {error = -EOPNOTSUPP;goto free_set;}
 entry = kzalloc(sizeof(*entry), GFP_KERNEL);
 if (!entry) {error = -ENOMEM;goto free_set;}
 entry->set = set;
 bpf_link_init(&entry->link, BPF_LINK_TYPE_ENTRY, &entry_link_ops, NULL, BPF_TRACE_ENTRY);
 error = bpf_link_prime(&entry->link, &primer);
 if (error) {kfree(entry);goto free_set;}
 mutex_lock(&entry_lock);
 error = entry_switch(set, 0, 1);
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
 u32 *programs, *old_fds = NULL, count = attr->link_update.entry.count;
 unsigned int i, slot, id = 0;
 int error = -EINVAL;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (link->ops != &entry_link_ops || attr->link_update.entry.reserved ||
     attr->link_update.new_prog_fd || attr->link_update.old_prog_fd ||
     count != set->count || !count ||
     (!!(attr->link_update.flags & BPF_F_REPLACE) != !!attr->link_update.entry.old_prog_fds)) return -EINVAL;
 programs = vmemdup_array_user(u64_to_user_ptr(attr->link_update.entry.prog_fds), count, sizeof(u32));
 if (IS_ERR(programs)) return PTR_ERR(programs);
 if (attr->link_update.flags & BPF_F_REPLACE) {
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
 prepared = entry_prepare(members, count, set->source_btf);
 kvfree(members);
 if (IS_ERR(prepared)) {error = PTR_ERR(prepared);goto out;}
 mutex_lock(&entry_lock);
 error = -ENOLINK;
 if (entry->detached) goto unlock;
 error = -EINVAL;
 if (set->slot_count != prepared->slot_count || prepared->has_ftrace) goto unlock;
 for (i = 0; i < count * 2; ++i)
  if (set->locations[i] != prepared->locations[i]) goto unlock;
 old = entry_generation(set, set->active);
 slot = entry_generation_slot(set->active);
 error = -EPERM;
 if (expected)
  for (i = 0; i < count; ++i)
   if (old->programs[i * 2 + slot] != expected[i]) goto unlock;
 error = -EOVERFLOW;
 if (set->next_generation > INT_MAX) goto unlock;
 prepared->generation_id = id = set->next_generation++;
 list_add_tail(&prepared->generation_node, &set->generations);
 error = entry_switch(set, set->active, id);
 if (error && !set->poisoned) list_del(&prepared->generation_node);
 else prepared = NULL; /* Includes poisoned text: keep every possible target. */
 if (!error) schedule_delayed_work(&set->retire_work, 0);
unlock:
 mutex_unlock(&entry_lock);
 if (prepared) entry_free(prepared);
out:
 if (expected)
  for (i = 0; i < count; ++i) if (expected[i]) bpf_prog_put(expected[i]);
 kvfree(expected);kvfree(old_fds);kvfree(programs);
 return error;
}
