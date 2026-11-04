/* SPDX-License-Identifier: GPL-2.0-only */
/* Experimental scope publication in the existing entry journal. All selection
 * data is cold; generated entries use only r10/r11, without a frame or call. */
#include <asm/current.h>
#include <asm/preempt.h>
#include <linux/overflow.h>
#include "function_binding.h"

struct plt_image {
 struct delayed_work retire;
 void *text;
 struct bpf_binary_header *header, *writable;
 u32 size, allocation;
 struct entry_set *code;
 struct module *source;
};
struct plt_entry {
 struct list_head node;
 struct entry_native_slot slot;
 struct module *source;
 struct ftrace_text_reservation *ftrace;
 struct plt_image *image, *next;
};
struct bpf_entry_scope {
 struct list_head node;
 struct delayed_work release;
 refcount_t refs;
 u32 id, count;
 struct ebpfos_function_binding bindings[];
};
static void plt_scope_release(struct work_struct *work);
static LIST_HEAD(plt_entries);
static LIST_HEAD(plt_scopes);
static u32 plt_next_id;
static bool entry_plt_owned(unsigned long ip)
{
 struct plt_entry *entry;
 list_for_each_entry(entry, &plt_entries, node)
  if (entry->slot.ip == ip) return true;
 return false;
}
static bool plt_contains(void *opaque, unsigned long ip)
{
 struct plt_image *image = opaque;
 return ip >= (unsigned long)image->text && ip < (unsigned long)image->text + image->size;
}
static void plt_image_free(struct plt_image *image)
{
 if (!image) return;
 if (image->header) {
  if (image->writable)
   bpf_arch_text_copy(&image->header->size, &image->writable->size, sizeof(image->writable->size));
  bpf_jit_binary_pack_free(image->header, image->writable);
 }
 bpf_entry_code_put(image->code);
 module_put(image->source);
 kfree(image);
}
static void plt_retire(struct work_struct *work)
{
 struct plt_image *image = container_of(to_delayed_work(work), struct plt_image, retire);
 if (ebpfos_code_quiescent(plt_contains, image))
  schedule_delayed_work(&image->retire, HZ / 10);
 else plt_image_free(image);
}
static void plt_holes(void *area, unsigned int size) { memset(area, 0xcc, size); }
static void plt_u32(u8 **p, u32 value) { memcpy(*p, &value, 4);*p += 4; }
static bool plt_rel(u8 **p, u8 *base, unsigned long ip, unsigned long target)
{
 long distance = target - (ip + (*p - base) + 4);
 if (distance != (s32)distance) return false;
 plt_u32(p, distance);return true;
}
static const struct ebpfos_function_binding *plt_binding(struct bpf_entry_scope *scope,
 unsigned long address)
{
 u32 i;
 for (i = 0; i < scope->count; ++i)
  if (scope->bindings[i].native_address == address) return &scope->bindings[i];
 return NULL;
}
/* Preserve Linux's six argument registers, rax (including vararg AL), stack
 * arguments and ENDBR. Only ordinary C entry scratch registers are clobbered.
 * An original jump (including an AOT image body) is the default continuation. */
static struct plt_image *plt_generate(struct plt_entry *entry)
{
 struct bpf_entry_scope *scope;
 struct plt_image *image;
 struct bpf_prog **programs;
 u32 count = 0, i = 0, capacity;
 u8 *buffer, *p, *irq_default, *thread_default;
#ifdef CONFIG_PREEMPT_RT
 u8 *softirq_default;
#endif
 unsigned long ip, fallback = entry->slot.original ?: entry->slot.ip + 5;
 u8 *writable_text;
 int error;
 list_for_each_entry(scope, &plt_scopes, node)
  if (plt_binding(scope, entry->slot.target[1])) ++count;
 if (!count) return NULL;
 image = kzalloc(sizeof(*image), GFP_KERNEL);
 buffer = kmalloc(capacity, GFP_KERNEL);
 programs = kvmalloc_array(count, sizeof(*programs), GFP_KERNEL);
 if (!image || !buffer || !programs) {kfree(image);kfree(buffer);kvfree(programs);return ERR_PTR(-ENOMEM);}
 image->header = bpf_jit_binary_pack_alloc(capacity, (u8 **)&image->text, 8,
  &image->writable, &writable_text, plt_holes, false);
 if (!image->header) {kfree(image);kfree(buffer);kvfree(programs);return ERR_PTR(-ENOMEM);}
 image->allocation = image->writable->size;
 image->source = entry->source;
 if (image->source) __module_get(image->source);
 INIT_DELAYED_WORK(&image->retire, plt_retire);
 p = buffer;ip = (unsigned long)image->text;
 #define PLT_BYTES(...) do { const u8 bytes[] = {__VA_ARGS__};memcpy(p, bytes, sizeof(bytes));p += sizeof(bytes); } while (0)
 PLT_BYTES(0xf3,0x0f,0x1e,0xfa); /* endbr64 */
 PLT_BYTES(0x65,0x44,0x8b,0x14,0x25);plt_u32(&p, (unsigned long)&__preempt_count);
 PLT_BYTES(0x41,0xf7,0xc2);plt_u32(&p, NMI_MASK | HARDIRQ_MASK |
  (IS_ENABLED(CONFIG_PREEMPT_RT) ? 0 : SOFTIRQ_OFFSET));
 PLT_BYTES(0x0f,0x85);irq_default = p;p += 4;
 PLT_BYTES(0x65,0x4c,0x8b,0x1c,0x25);plt_u32(&p, (unsigned long)&current_task);
 PLT_BYTES(0x41,0xf7,0x83);plt_u32(&p, offsetof(struct task_struct, flags));plt_u32(&p, PF_KTHREAD);
 PLT_BYTES(0x0f,0x85);thread_default = p;p += 4;
#ifdef CONFIG_PREEMPT_RT
 PLT_BYTES(0x41,0xf7,0x83);plt_u32(&p, offsetof(struct task_struct, softirq_disable_cnt));plt_u32(&p, SOFTIRQ_OFFSET);
 PLT_BYTES(0x0f,0x85);softirq_default = p;p += 4;
#endif
 PLT_BYTES(0x45,0x8b,0x93);plt_u32(&p, offsetof(struct task_struct, ebpfos_version));
 list_for_each_entry(scope, &plt_scopes, node) {
  const struct ebpfos_function_binding *binding = plt_binding(scope, entry->slot.target[1]);
  if (!binding) continue;
  programs[i++] = binding->program;
  PLT_BYTES(0x41,0x81,0xfa);plt_u32(&p, scope->id);
  PLT_BYTES(0x0f,0x84);
  if (!plt_rel(&p, buffer, ip, binding->address)) goto range;
 }
 { u8 *fixup = irq_default;plt_u32(&fixup, p - (irq_default + 4));
   fixup = thread_default;plt_u32(&fixup, p - (thread_default + 4)); }
#ifdef CONFIG_PREEMPT_RT
 { u8 *fixup = softirq_default;plt_u32(&fixup, p - (softirq_default + 4)); }
#endif
 PLT_BYTES(0xe9);
 if (!plt_rel(&p, buffer, ip, fallback)) goto range;
 #undef PLT_BYTES
 image->size = p - buffer;
 image->code = bpf_entry_code_get(programs, count);
 if (IS_ERR(image->code)) {int error = PTR_ERR(image->code);image->code = NULL;schedule_delayed_work(&image->retire, 0);kfree(buffer);kvfree(programs);return ERR_PTR(error);}
 memcpy(writable_text, buffer, image->size);
 error = bpf_jit_binary_pack_finalize(image->header, image->writable);
 image->writable = NULL;
 kfree(buffer);kvfree(programs);
 if (error) {image->header = NULL;schedule_delayed_work(&image->retire, 0);return ERR_PTR(error);}
 return image;
range:
 kfree(buffer);kvfree(programs);schedule_delayed_work(&image->retire, 0);return ERR_PTR(-ERANGE);
}
static void plt_entry_free(struct plt_entry *entry)
{
 list_del(&entry->node);ftrace_text_release(entry->ftrace);module_put(entry->source);kfree(entry);
}
/* Prepare every changed entry before a single existing batched transaction.
 * Tasks receive the new token only after all its direct branches are visible. */
static int plt_publish(void)
{
 struct plt_entry *entry, *next;
 struct text_poke_pair *pairs;
 u32 count = 0, i = 0;
 int error = 0;
 list_for_each_entry(entry, &plt_entries, node) ++count;
 if (!count) return 0;
 pairs = kvmalloc_array(count, sizeof(*pairs), GFP_KERNEL);
 if (!pairs) return -ENOMEM;
 list_for_each_entry(entry, &plt_entries, node) {
  struct entry_native_slot slot = entry->slot;
  entry->next = plt_generate(entry);
  if (IS_ERR(entry->next)) {error = PTR_ERR(entry->next);entry->next = NULL;goto fail;}
  pairs[i].addr = (void *)slot.ip;
  slot.target[0] = (unsigned long)(entry->image ? entry->image->text : NULL);
  entry_native_instruction(&slot, entry->image ? 1 : 0, pairs[i].before);
  
  slot.target[0] = (unsigned long)(entry->next ? entry->next->text : NULL);
  entry_native_instruction(&slot, entry->next ? 1 : 0, pairs[i].after);
  
  ++i;
 }
 sort(pairs, count, sizeof(*pairs), entry_native_pair_order, NULL);
 mutex_lock(&text_mutex);
 error = smp_text_poke_transaction(pairs, count);
 mutex_unlock(&text_mutex);
 if (error) goto fail;
 list_for_each_entry_safe(entry, next, &plt_entries, node) {
  if (entry->image) schedule_delayed_work(&entry->image->retire, 0);
  entry->image = entry->next;entry->next = NULL;
  if (!entry->image) plt_entry_free(entry);
 }
 kvfree(pairs);return 0;
fail:
 list_for_each_entry(entry, &plt_entries, node) {if (entry->next) schedule_delayed_work(&entry->next->retire, 0);entry->next = NULL;}
 kvfree(pairs);return error;
}
struct bpf_entry_scope *bpf_entry_scope_get(const struct ebpfos_function_binding *bindings, u32 count)
{
 struct bpf_entry_scope *scope;
 struct plt_entry *entry, *next;
 u32 i, j;
 int error = 0;
 if (!count) return NULL;
 mutex_lock(&entry_lock);
 list_for_each_entry(scope, &plt_scopes, node) {
  if (scope->count != count) continue;
  for (i = 0; i < count; ++i)
   if (scope->bindings[i].native_address != bindings[i].native_address ||
       scope->bindings[i].address != bindings[i].address) break;
  if (i == count && refcount_inc_not_zero(&scope->refs)) goto out;
 }
 scope = kzalloc(struct_size(scope, bindings, count), GFP_KERNEL);
 if (!scope) {error = -ENOMEM;goto fail;}
 
 scope->id = ++plt_next_id;scope->count = count;refcount_set(&scope->refs, 1);
 memcpy(scope->bindings, bindings, count * sizeof(*bindings));
 for (i = 0; i < count; ++i) {
  bool ftrace, canonical_nop;
  unsigned long ip = bpf_entry_text_location(bindings[i].source_module, bindings[i].native_address, &ftrace, &canonical_nop);
  struct entry_set *owner;
  u8 before[5], expected[5];
  
  
  if (entry_plt_owned(ip)) continue;
  entry = kzalloc(sizeof(*entry), GFP_KERNEL);
  if (!entry) {error = -ENOMEM;goto free_scope;}
  entry->slot.ip = ip;entry->slot.ftrace = ftrace;entry->slot.canonical_nop = canonical_nop;
  /* target[1] is cold lookup identity, never an emitted second branch. */
  entry->slot.target[1] = bindings[i].native_address;
  
  copy_from_kernel_nofault(before, (void *)ip, 5);
  if (before[0] == 0xe9) {s32 displacement;memcpy(&displacement, before + 1, 4);entry->slot.original = ip + 5 + displacement;}
  
  if (ftrace) {
   entry->ftrace = ftrace_text_reserve(&ip, 1, false);
   if (IS_ERR(entry->ftrace)) {error = PTR_ERR(entry->ftrace);kfree(entry);goto free_scope;}
  }
  entry->source = bindings[i].source_module;
  if (entry->source) __module_get(entry->source);
  list_add_tail(&entry->node, &plt_entries);
 }
 list_add_tail(&scope->node, &plt_scopes);
 error = plt_publish();
 if (error) {list_del(&scope->node);goto free_scope;}
 INIT_DELAYED_WORK(&scope->release, plt_scope_release);
 for (i = 0; i < count; ++i) {
  bpf_prog_inc(scope->bindings[i].program);
  if (scope->bindings[i].source_module) __module_get(scope->bindings[i].source_module);
 }
out:
 mutex_unlock(&entry_lock);return scope;
free_scope:
 kfree(scope);
 list_for_each_entry_safe(entry, next, &plt_entries, node)
  if (!entry->image) plt_entry_free(entry);
fail:
 mutex_unlock(&entry_lock);return ERR_PTR(error);
}
u32 bpf_entry_scope_id(const struct bpf_entry_scope *scope) { return scope ? scope->id : 0; }
static void plt_scope_release(struct work_struct *work)
{
 struct bpf_entry_scope *scope = container_of(to_delayed_work(work), struct bpf_entry_scope, release);
 u32 i;
 int error;
 mutex_lock(&entry_lock);
 list_del(&scope->node);
 error = plt_publish();
 if (error) list_add_tail(&scope->node, &plt_scopes);
 mutex_unlock(&entry_lock);
 if (error) {schedule_delayed_work(&scope->release, HZ / 10);return;}
 for (i = 0; i < scope->count; ++i) {
  bpf_prog_put(scope->bindings[i].program);module_put(scope->bindings[i].source_module);
 }
 kfree(scope);
}
void bpf_entry_scope_put(struct bpf_entry_scope *scope)
{
 if (scope && refcount_dec_and_test(&scope->refs)) schedule_delayed_work(&scope->release, 0);
}
