// SPDX-License-Identifier: GPL-2.0-only
/* BTF-generated immutable operations objects in the ordinary BPF namespace. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/bpf_entry.h>
#include <linux/bpf_operations.h>
#include <linux/ebpfos_operations.h>
#include <linux/ebpfos_file_view.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <asm/sections.h>
#include "function_binding.h"
#include "function_contract.h"
#include "function_lifetime.h"

struct ebpfos_operations {
 struct bpf_map map;
 struct btf *types;
 struct module *module;
 const void *original;
 void *table, *user;
 struct bpf_prog **programs;
 struct mutex lock;
 struct delayed_work release;
 u32 count;
 bool ready;
};
struct bpf_operations_set {
 refcount_t refs;
 struct rcu_head rcu;
 u32 count;
 struct bpf_map *maps[];
};
static struct bpf_operations_set __rcu *global_operations;

/* Require the actual BTF VAR and its complete storage. No raw addresses or
 * user-supplied data pointers enter a generated kernel operations table. */
static unsigned long operations_storage(struct module *module, const char *name, u32 size)
{
 unsigned long address = 0, bytes, offset;
 if (!module) {
  address = kallsyms_lookup_name(name);
  if (!address ||
      !((address >= (unsigned long)__start_rodata && address < (unsigned long)__end_rodata &&
         size <= (unsigned long)__end_rodata - address) ||
        (address >= (unsigned long)_sdata && address < (unsigned long)_edata &&
         size <= (unsigned long)_edata - address) ||
        (address >= (unsigned long)__bss_start && address < (unsigned long)__bss_stop &&
         size <= (unsigned long)__bss_stop - address)) ||
      !kallsyms_lookup_size_offset(address, &bytes, &offset) || offset || bytes < size)
   return 0;
  return address;
 }
#ifdef CONFIG_MODULES
 rcu_read_lock();
 {
  struct mod_kallsyms *symbols = rcu_dereference(module->kallsyms);
  unsigned int i;
  for (i = 0; symbols && i < symbols->num_symtab; ++i) {
   const Elf_Sym *symbol = &symbols->symtab[i];
   if (strcmp(name, symbols->strtab + symbol->st_name)) continue;
   if (address || ELF_ST_TYPE(symbol->st_info) != STT_OBJECT || symbol->st_size < size) {
    address = 0;break;
   }
   address = kallsyms_symbol_value(symbol);
  }
 }
 rcu_read_unlock();
 {
  enum mod_mem_type type;
  bool valid = false;
  for (type = MOD_DATA; type <= MOD_RO_AFTER_INIT; ++type) {
   if (type == MOD_TEXT) continue;
   if (within_module_mem_type(address, module, type) &&
       size <= module->mem[type].size - (address - (unsigned long)module->mem[type].base)) valid = true;
  }
  if (!valid) address = 0;
 }
#endif
 return address;
}
static int operations_alloc_check(union bpf_attr *attr)
{
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (!IS_ENABLED(CONFIG_HAVE_RELIABLE_STACKTRACE) || !IS_ENABLED(CONFIG_TASKS_RCU)) return -EOPNOTSUPP;
 if (attr->key_size != sizeof(u32) || attr->max_entries != 1 ||
     !attr->value_size || !attr->btf_vmlinux_value_type_id ||
     !attr->map_extra || attr->map_extra > U32_MAX ||
     (attr->map_flags & ~BPF_F_VTYPE_BTF_OBJ_FD) ||
     attr->btf_fd || attr->btf_key_type_id || attr->btf_value_type_id) return -EINVAL;
 return 0;
}
static struct bpf_map *operations_alloc(union bpf_attr *attr)
{
 struct ebpfos_operations *ops;
 const struct btf_type *variable, *record;
 struct btf *btf = bpf_get_btf_vmlinux();
 struct module *module = NULL;
 unsigned long address;
 int error = -EINVAL;
 if (attr->map_flags & BPF_F_VTYPE_BTF_OBJ_FD) {
  btf = btf_get_by_fd(attr->value_type_btf_obj_fd);
  if (IS_ERR(btf)) return ERR_CAST(btf);
  module = btf_try_get_module(btf);
  if (!module) {btf_put(btf);return ERR_PTR(-ENOENT);}
 } else {
  if (IS_ERR_OR_NULL(btf)) return ERR_PTR(-EOPNOTSUPP);
  btf_get(btf);
 }
 variable = btf_type_by_id(btf, attr->map_extra);
 record = btf_type_by_id(btf, attr->btf_vmlinux_value_type_id);
 if (!variable || !btf_type_is_var(variable) || !record || !btf_type_is_struct(record) ||
     record->size != attr->value_size ||
     btf_type_skip_modifiers(btf, variable->type, NULL) != record) goto fail;
 address = operations_storage(module, btf_name_by_offset(btf, variable->name_off), record->size);
 if (!address) {error = -ENOENT;goto fail;}
 ops = kzalloc(sizeof(*ops), GFP_KERNEL);
 if (!ops) {error = -ENOMEM;goto fail;}
 ops->table = kmemdup((void *)address, record->size, GFP_KERNEL);
 ops->user = kzalloc(record->size, GFP_KERNEL);
 ops->programs = kvcalloc(btf_type_vlen(record), sizeof(*ops->programs), GFP_KERNEL);
 if (!ops->table || !ops->user || !ops->programs) {
  kfree(ops->table);kfree(ops->user);kvfree(ops->programs);kfree(ops);error = -ENOMEM;goto fail;
 }
 bpf_map_init_from_attr(&ops->map, attr);
 ops->map.btf_vmlinux_value_type_id = attr->btf_vmlinux_value_type_id;
 ops->types = btf;ops->module = module;ops->original = (void *)address;
 mutex_init(&ops->lock);
 return &ops->map;
fail:
 module_put(module);btf_put(btf);return ERR_PTR(error);
}
long bpf_operations_update(struct bpf_map *map, void *key, void *value, u64 flags)
{
 struct ebpfos_operations *ops = container_of(map, struct ebpfos_operations, map);
 const struct btf_type *record = btf_type_by_id(ops->types, map->btf_vmlinux_value_type_id);
 const struct btf_member *members = btf_members(record);
 struct bpf_prog **programs;
 unsigned long *addresses;
 void *checked;
 u32 i, count = 0;
 int error = -EINVAL;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (*(u32 *)key || (flags != BPF_ANY && flags != BPF_NOEXIST)) return -EINVAL;
 programs = kvcalloc(btf_type_vlen(record), sizeof(*programs), GFP_KERNEL);
 addresses = kvcalloc(btf_type_vlen(record), sizeof(*addresses), GFP_KERNEL);
 checked = kzalloc(map->value_size, GFP_KERNEL);
 if (!programs || !addresses || !checked) {error = -ENOMEM;goto free;}
 for (i = 0; i < btf_type_vlen(record); ++i) {
  const struct btf_type *pointer = btf_type_skip_modifiers(ops->types, members[i].type, NULL);
  const struct btf_type *prototype;
  unsigned long original, bytes, offset;
  char symbol[KSYM_NAME_LEN];
  const char *name;
  u64 fd;
  u32 at = btf_member_bit_offset(record, i) / 8;
  int id;
  if (!pointer || !btf_type_is_ptr(pointer)) continue;
  prototype = btf_type_skip_modifiers(ops->types, pointer->type, NULL);
  if (!prototype || !btf_type_is_func_proto(prototype)) continue;
  if (btf_member_bitfield_size(record, i) || btf_member_bit_offset(record, i) % 8 ||
      at % sizeof(u64) || at > map->value_size || sizeof(u64) > map->value_size - at) goto free;
  memcpy(&fd, value + at, sizeof(fd));
  memcpy(checked + at, &fd, sizeof(fd));
  if (!fd) continue;
  if (fd > INT_MAX) goto free;
  memcpy(&original, ops->original + at, sizeof(original));
  if (!(ops->module ? within_module_mem_type(original, ops->module, MOD_TEXT) :
        core_kernel_text(original))) {error = -ENOENT;goto free;}
  name = original ? kallsyms_lookup(original, &bytes, &offset, NULL, symbol) : NULL;
  if (!name || offset) {error = -ENOENT;goto free;}
  id = btf_find_by_name_kind(ops->types, name, BTF_KIND_FUNC);
  if (id <= 0) {error = -ENOENT;goto free;}
  {
   const struct btf_type *function = btf_type_by_id(ops->types, id);
   if (!cell_layout(ops->types, function->type, ops->types, pointer->type, 0, false)) {
    error = -EPROTOTYPE;goto free;
   }
  }
  programs[i] = bpf_prog_get(fd);
  if (IS_ERR(programs[i])) {error = PTR_ERR(programs[i]);programs[i] = NULL;goto free;}
  error = bpf_entry_program_address(ops->types, id, programs[i], false, &addresses[i]);
  if (error) goto free;
  if (ebpfos_program_addresses(programs[i])) {error = -EOPNOTSUPP;goto free;}
  ++count;
 }
 /* Non-method data (owner pointers, flags, locks, strings) stays native. */
 error = -EINVAL;
 if (!count || memcmp(checked, value, map->value_size)) goto free;
 mutex_lock(&ops->lock);
 if (ops->ready) error = -EBUSY;
 else {
  for (i = 0; i < btf_type_vlen(record); ++i) {
   u32 at = btf_member_bit_offset(record, i) / 8;
   u64 id;
   if (!programs[i]) continue;
   ops->programs[i] = programs[i];programs[i] = NULL;
   memcpy(ops->table + at, &addresses[i], sizeof(addresses[i]));
   id = ops->programs[i]->aux->id;memcpy(ops->user + at, &id, sizeof(id));
  }
  ops->count = count;smp_store_release(&ops->ready, true);error = 0;
 }
 mutex_unlock(&ops->lock);
free:
 if (programs) for (i = 0; i < btf_type_vlen(record); ++i) if (programs[i]) bpf_prog_put(programs[i]);
 kvfree(programs);kvfree(addresses);kfree(checked);return error;
}
static void *operations_lookup(struct bpf_map *map, void *key)
{
 struct ebpfos_operations *ops = container_of(map, struct ebpfos_operations, map);
 return *(u32 *)key || !smp_load_acquire(&ops->ready) ? ERR_PTR(-ENOENT) : ops->user;
}
static void *operations_program_lookup(struct bpf_map *map, void *key) { return NULL; }
static long operations_program_update(struct bpf_map *map, void *key, void *value, u64 flags) { return -EOPNOTSUPP; }
static long operations_delete(struct bpf_map *map, void *key) { return -EOPNOTSUPP; }
static int operations_next(struct bpf_map *map, void *key, void *next)
{
 if (key && !*(u32 *)key) return -ENOENT;
 *(u32 *)next = 0;return 0;
}
static bool operations_contains(void *opaque, unsigned long ip)
{
 struct ebpfos_operations *ops = opaque;
 const struct btf_type *record = btf_type_by_id(ops->types, ops->map.btf_vmlinux_value_type_id);
 u32 i;
 if (ops->module && within_module_mem_type(ip, ops->module, MOD_TEXT)) return true;
 for (i = 0; i < btf_type_vlen(record); ++i) {
  struct bpf_prog *p = ops->programs[i];
  if (ebpfos_program_contains(p, ip) || (p && p->type == BPF_PROG_TYPE_NATIVE &&
      p->aux->mod && within_module_mem_type(ip, p->aux->mod, MOD_TEXT))) return true;
 }
 return false;
}
static void operations_release(struct work_struct *work)
{
 struct ebpfos_operations *ops = container_of(to_delayed_work(work), struct ebpfos_operations, release);
 const struct btf_type *record = btf_type_by_id(ops->types, ops->map.btf_vmlinux_value_type_id);
 u32 i;
 if (ops->ready && ebpfos_code_quiescent(operations_contains, ops)) {
  schedule_delayed_work(&ops->release, HZ / 10);return;
 }
 for (i = 0; i < btf_type_vlen(record); ++i) if (ops->programs[i]) bpf_prog_put(ops->programs[i]);
 module_put(ops->module);btf_put(ops->types);
 kvfree(ops->programs);kfree(ops->table);kfree(ops->user);kfree(ops);
}
static void operations_free(struct bpf_map *map)
{
 struct ebpfos_operations *ops = container_of(map, struct ebpfos_operations, map);
 INIT_DELAYED_WORK(&ops->release, operations_release);schedule_delayed_work(&ops->release, 0);
}
static u64 operations_memory(const struct bpf_map *map)
{
 const struct ebpfos_operations *ops = container_of(map, struct ebpfos_operations, map);
 const struct btf_type *record = btf_type_by_id(ops->types, map->btf_vmlinux_value_type_id);
 return sizeof(*ops) + map->value_size * 2 + btf_type_vlen(record) * sizeof(struct bpf_prog *);
}
const struct bpf_map_ops bpf_operations_map_ops = {
 .map_alloc_check = operations_alloc_check, .map_alloc = operations_alloc,
 .map_free = operations_free, .map_update_elem = operations_program_update,
 .map_lookup_elem_sys_only = operations_lookup, .map_lookup_elem = operations_program_lookup,
 .map_delete_elem = operations_delete, .map_get_next_key = operations_next,
 .map_mem_usage = operations_memory,
};
void bpf_operations_info(struct bpf_map *map, struct bpf_map_info *info)
{
 struct ebpfos_operations *ops = container_of(map, struct ebpfos_operations, map);
 info->btf_vmlinux_id = btf_obj_id(ops->types);
}
struct bpf_operations_set *bpf_operations_prepare(const u32 *fds, u32 count)
{
 struct bpf_operations_set *set;
 u32 i, j;
 int error;
 if (!count) return NULL;
 set = kvzalloc(struct_size(set, maps, count), GFP_KERNEL);
 if (!set) return ERR_PTR(-ENOMEM);
 refcount_set(&set->refs, 1);set->count = count;
 for (i = 0; i < count; ++i) {
  struct ebpfos_operations *ops;
  set->maps[i] = bpf_map_get(fds[i]);
  if (IS_ERR(set->maps[i])) {error = PTR_ERR(set->maps[i]);set->maps[i] = NULL;goto fail;}
  if (set->maps[i]->map_type != BPF_MAP_TYPE_OPERATIONS) {error = -EINVAL;goto fail;}
  ops = container_of(set->maps[i], struct ebpfos_operations, map);
  if (!smp_load_acquire(&ops->ready)) {error = -ENODATA;goto fail;}
  for (j = 0; j < i; ++j)
   if (ops->original == container_of(set->maps[j], struct ebpfos_operations, map)->original) {
    error = -ENOTUNIQ;goto fail;
   }
 }
 return set;
fail:
 bpf_operations_set_put(set);return ERR_PTR(error);
}
struct bpf_operations_set *bpf_operations_set_get(struct bpf_operations_set *set)
{ if (set) refcount_inc(&set->refs);return set; }
static void operations_set_rcu(struct rcu_head *rcu)
{
 struct bpf_operations_set *set = container_of(rcu, struct bpf_operations_set, rcu);
 u32 i;
 for (i = 0; i < set->count; ++i) if (set->maps[i]) bpf_map_put(set->maps[i]);
 kvfree(set);
}
void bpf_operations_set_put(struct bpf_operations_set *set)
{ if (set && refcount_dec_and_test(&set->refs)) call_rcu(&set->rcu, operations_set_rcu); }
u32 bpf_operations_set_count(const struct bpf_operations_set *set) { return set ? set->count : 0; }
u32 bpf_operations_set_id(const struct bpf_operations_set *set, u32 at)
{ return set && at < set->count ? set->maps[at]->id : 0; }
bool bpf_operations_set_same(const struct bpf_operations_set *a, const struct bpf_operations_set *b)
{
 u32 i;
 if (bpf_operations_set_count(a) != bpf_operations_set_count(b)) return false;
 for (i = 0; i < bpf_operations_set_count(a); ++i) if (a->maps[i] != b->maps[i]) return false;
 return true;
}
bool bpf_operations_set_targets(const struct bpf_operations_set *a, const struct bpf_operations_set *b)
{
 u32 i;
 if (bpf_operations_set_count(a) != bpf_operations_set_count(b)) return false;
 for (i = 0; i < bpf_operations_set_count(a); ++i) {
  struct ebpfos_operations *x = container_of(a->maps[i], struct ebpfos_operations, map);
  struct ebpfos_operations *y = container_of(b->maps[i], struct ebpfos_operations, map);
  if (x->original != y->original || x->types != y->types ||
      x->map.btf_vmlinux_value_type_id != y->map.btf_vmlinux_value_type_id) return false;
 }
 return true;
}
static bool operations_set_has(struct bpf_operations_set *set, struct bpf_map *map)
{
 u32 i;
 for (i = 0; set && i < set->count; ++i) if (set->maps[i] == map) return true;
 return false;
}
int bpf_operations_global_prepare(struct bpf_operations_global_update *update,
 struct bpf_operations_set *next, struct bpf_operations_set *old)
{
 /* The entry journal lock serializes preparation through publication.
  * Build an immutable selection before stopping CPUs; objects that reserved
  * an older selection can still resolve against that complete snapshot. */
 struct bpf_operations_set *active = rcu_dereference_protected(global_operations, 1), *merged = NULL;
 u32 i, j, count, at = 0, have = bpf_operations_set_count(active);
 u32 remove = bpf_operations_set_count(old), add = bpf_operations_set_count(next);
 *update = (struct bpf_operations_global_update){};
 for (i = 0; i < remove; ++i)
  if (!operations_set_has(active, old->maps[i])) return -EBUSY;
 for (i = 0; i < add; ++i) {
  struct ebpfos_operations *wanted = container_of(next->maps[i], struct ebpfos_operations, map);
  for (j = 0; j < have; ++j) {
   struct ebpfos_operations *owner = container_of(active->maps[j], struct ebpfos_operations, map);
   if (wanted->original == owner->original && !operations_set_has(old, active->maps[j]))
    return -EBUSY;
  }
 }
 if (bpf_operations_set_same(next, old)) return 0;
 if (remove > have || add > U32_MAX - (have - remove)) return -E2BIG;
 count = have - remove + add;
 if (count) {
  merged = kvzalloc(struct_size(merged, maps, count), GFP_KERNEL);
  if (!merged) return -ENOMEM;
  refcount_set(&merged->refs, 1);merged->count = count;
  for (i = 0; i < have; ++i)
   if (!operations_set_has(old, active->maps[i])) {
    merged->maps[at++] = active->maps[i];bpf_map_inc(active->maps[i]);
   }
  for (i = 0; i < add; ++i) {
   merged->maps[at++] = next->maps[i];bpf_map_inc(next->maps[i]);
  }
 }
 update->before = bpf_operations_set_get(active);update->after = merged;
 return 0;
}
static void operations_global_replace(struct bpf_operations_set *next,
 struct bpf_operations_set *old)
{
 if (next == old) return;
 /* Both snapshots are retained by the cold update, so this put cannot
  * release the last reference inside a stopped-CPU publication callback. */
 rcu_assign_pointer(global_operations, bpf_operations_set_get(next));
 bpf_operations_set_put(old);
}
void bpf_operations_global_publish(struct bpf_operations_global_update *update)
{ operations_global_replace(update->after, update->before); }
void bpf_operations_global_undo(struct bpf_operations_global_update *update)
{ operations_global_replace(update->before, update->after); }
void bpf_operations_global_release(struct bpf_operations_global_update *update)
{ bpf_operations_set_put(update->before);bpf_operations_set_put(update->after); }
static struct ebpfos_operations *operations_find(struct bpf_operations_set *set,
 const void *original, u32 type, size_t size)
{
 u32 i;
 for (i = 0; set && i < set->count; ++i) {
  struct ebpfos_operations *ops = container_of(set->maps[i], struct ebpfos_operations, map);
  if (ops->original == original && ops->map.btf_vmlinux_value_type_id == type && (!size || ops->map.value_size == size))
   return ops;
 }
 return NULL;
}
struct ebpfos_operations *bpf_operations_find(struct bpf_operations_set *set,
 const void *original, u32 type, size_t size)
{
 struct ebpfos_operations *ops = operations_find(set, original, type, size);
 if (ops) bpf_map_inc(&ops->map);
 return ops;
}
struct ebpfos_operations *ebpfos_operations_current(const void *original,
 u32 type, size_t size, struct module *owner)
{
 struct ebpfos_operations *ops = NULL;
 rcu_read_lock();
 if (in_task() && current->mm) ops = bpf_operations_find(ebpfos_task_operations(), original, type, size);
 if (!ops) ops = bpf_operations_find(rcu_dereference(global_operations), original, type, size);
 rcu_read_unlock();return ops;
}
EXPORT_SYMBOL_GPL(ebpfos_operations_current);
struct ebpfos_operations *ebpfos_operations_get(struct ebpfos_operations *ops)
{ if (ops) bpf_map_inc(&ops->map);return ops; }
EXPORT_SYMBOL_GPL(ebpfos_operations_get);
void ebpfos_operations_put(struct ebpfos_operations *ops) { if (ops) bpf_map_put(&ops->map); }
EXPORT_SYMBOL_GPL(ebpfos_operations_put);
const void *ebpfos_operations_table(const struct ebpfos_operations *ops) { return ops->table; }
EXPORT_SYMBOL_GPL(ebpfos_operations_table);
u32 ebpfos_operations_bound(const struct ebpfos_operations *ops) { return ops->count; }
EXPORT_SYMBOL_GPL(ebpfos_operations_bound);
struct ebpfos_operations_owner {
 struct bpf_operations_set *selected, *global;
 struct ebpfos_operations *bound;
 struct rcu_head rcu;
 u32 type;
 bool resolved;
};
static bool operations_type(struct bpf_operations_set *set, u32 type)
{
 u32 i;
 for (i = 0; set && i < set->count; ++i)
  if (set->maps[i]->btf_vmlinux_value_type_id == type) return true;
 return false;
}
struct ebpfos_operations_owner *ebpfos_operations_reserve(u32 type, gfp_t gfp)
{
 struct bpf_operations_set *selected, *global;
 struct ebpfos_operations_owner *owner;
 rcu_read_lock();
 selected = in_task() && current->mm ? ebpfos_task_operations() : NULL;
 global = rcu_dereference(global_operations);
 if (!operations_type(selected, type) && !operations_type(global, type)) {
  rcu_read_unlock();return NULL;
 }
 selected = bpf_operations_set_get(selected);
 /* A removed RCU selection may already have reached zero refs while its
  * memory awaits the grace period. Acquire only a live snapshot, retrying
  * the published pointer before leaving the creation-time RCU section. */
 do {
  global = rcu_dereference(global_operations);
 } while (global && !refcount_inc_not_zero(&global->refs));
 rcu_read_unlock();
 owner = kzalloc(sizeof(*owner), gfp);
 if (!owner) {bpf_operations_set_put(selected);bpf_operations_set_put(global);return ERR_PTR(-ENOMEM);}
 owner->selected = selected;owner->global = global;owner->type = type;return owner;
}
EXPORT_SYMBOL_GPL(ebpfos_operations_reserve);
const void *ebpfos_operations_resolve(struct ebpfos_operations_owner *owner, const void *original)
{
 struct ebpfos_operations *ops;
 if (!owner || owner->resolved) return original;
 owner->resolved = true;
 ops = operations_find(owner->selected, original, owner->type, 0);
 if (!ops) ops = operations_find(owner->global, original, owner->type, 0);
 /* Selection sets are needed only until the actual table is known. Retain
  * the matching map before dropping them; unrelated inodes must not keep
  * every selected module alive until their own eventual destruction.
  * The caller's publication lock serializes resolution with owner release.
  */
 owner->bound = ebpfos_operations_get(ops);
 bpf_operations_set_put(owner->selected);owner->selected = NULL;
 bpf_operations_set_put(owner->global);owner->global = NULL;
 return ops ? ops->table : original;
}
EXPORT_SYMBOL_GPL(ebpfos_operations_resolve);
static void operations_owner_rcu(struct rcu_head *rcu)
{
 struct ebpfos_operations_owner *owner = container_of(rcu, struct ebpfos_operations_owner, rcu);
 ebpfos_operations_put(owner->bound);
 bpf_operations_set_put(owner->selected);bpf_operations_set_put(owner->global);kfree(owner);
}
void ebpfos_operations_owner_put(struct ebpfos_operations_owner *owner)
{ if (owner) call_rcu(&owner->rcu, operations_owner_rcu); }
EXPORT_SYMBOL_GPL(ebpfos_operations_owner_put);

#include <linux/btf_ids.h>
BTF_ID_LIST_SINGLE(operations_file_btf_id, struct, file_operations)
int ebpfos_file_view_open(struct file *file)
{
 struct ebpfos_operations *ops, *old = file->ebpfos_operations;
 if (old && file->f_op == old->table) return 0;
 ops = ebpfos_operations_current(file->f_op, operations_file_btf_id[0], sizeof(*file->f_op), file->f_op->owner);
 file->ebpfos_operations = ops;
 if (ops) file->f_op = ops->table;
 /* An open callback may replace its table before delegating. The old map's
  * existing stack-checked retirement retains any still-running callback. */
 ebpfos_operations_put(old);
 return 0;
}
EXPORT_SYMBOL(ebpfos_file_view_open);
void ebpfos_file_view_free(struct file *file)
{ ebpfos_operations_put(file->ebpfos_operations); }
