/* Task and file views have the same x86-64 configuration as before. */
#if defined(CONFIG_EBPFOS) && defined(CONFIG_X86_64)

// SPDX-License-Identifier: GPL-2.0-only
/* Task-owned function bindings. Publication and graph leases are cold;
 * selected mappings and syscall slots enter their bodies directly. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/filter.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/pid.h>
#include <linux/resume_user_mode.h>
#include <linux/bitmap.h>
#include <asm/syscall.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/anon_inodes.h>
#include <linux/slab.h>
#include <linux/bpf_operations.h>
#include <linux/bpf_entry.h>
#include <linux/bpf_kernel_rule.h>
#include <linux/ebpfos_task_rule.h>
#include <linux/ebpfos_ptview.h>
#include "function_binding.h"
#include "function_contract.h"
#include <linux/workqueue.h>
#include "function_lifetime.h"
#include "function_native.h"
#include "entry_slot_instruction.h"

struct task_text_entry { unsigned long ip; u8 bytes[sizeof(entry_native_nop)]; bool ftrace; };

struct task_view {
 u64 generation;
 u32 count;
 bool revocable;
 DECLARE_BITMAP(selected, NR_syscalls);
 struct bpf_operations_set *operations;
 struct entry_set *code;
 struct task_text_entry *text;
 u32 text_count;
 struct delayed_work release_work;
 sys_call_ptr_t table[NR_syscalls];
 struct ebpfos_function_binding bindings[];
};

/* Unbound syscall graphs are immutable. Decisions retain them independently
 * of the rule link and of the process which loaded the programs. */
#include <linux/refcount.h>
struct ebpfos_task_view_request {
 refcount_t references;
 struct rcu_head rcu;
 struct file *next;
};
static void task_view_request_rcu(struct rcu_head *rcu)
{
 struct ebpfos_task_view_request *request = container_of(rcu, struct ebpfos_task_view_request, rcu);
 if (request->next) fput(request->next);
 kfree(request);
}
static void task_view_request_free(struct ebpfos_task_view_request *request)
{
 if (request && refcount_dec_and_test(&request->references))
  call_rcu(&request->rcu, task_view_request_rcu);
}

static void task_view_free(struct task_view *view)
{
 u32 i;
 for (i = 0; i < view->count; ++i)
  ebpfos_function_binding_put(&view->bindings[i]);
 bpf_operations_set_put(view->operations);
 bpf_entry_code_put(view->code);
 kvfree(view->text);
 kvfree(view);
}
static inline void task_view_release_work(struct work_struct *work)
{
 struct task_view *view = container_of(to_delayed_work(work), struct task_view, release_work);
 ebpfos_code_quiescent();
 task_view_free(view);
}
static int task_view_release(struct inode *inode, struct file *file)
{
 struct task_view *view = file->private_data;
 u32 i;
 bool retire = view->revocable;
 /* Revocation may have removed the last file lease inside its own body.
  * Keep the graph through grace periods and every outstanding old frame. */
 for (i = 0; i < view->count; ++i)
  retire |= view->bindings[i].module != NULL;
 if (retire) schedule_delayed_work(&view->release_work, 0);
 else task_view_free(view);
 return 0;
}
static void task_view_fdinfo(struct seq_file *out, struct file *file)
{
 struct task_view *view = file->private_data;
 u32 nr;
 seq_printf(out, "generation:\t%llu\nfunctions:\t%u\n", view->generation, view->count);
 for (nr = 0; nr < NR_syscalls; ++nr)
  if (view->table[nr] != sys_call_table[nr])
   seq_printf(out, "syscall:\t%u\t%px\n", nr, view->table[nr]);
}
static const struct file_operations task_view_ops = {
 .owner = THIS_MODULE, .release = task_view_release,
 .show_fdinfo = task_view_fdinfo, .llseek = noop_llseek,
};

/* Bind syscall exports by their existing table address. Each task retains
 * its own program lease through sleeping calls. */
static inline int task_view_slot(unsigned long address, unsigned long *used, const sys_call_ptr_t *original)
{
 u32 nr;
 for (nr = 0; nr < NR_syscalls; ++nr)
  if ((unsigned long)original[nr] == address) {
   __set_bit(nr, used);
   return nr;
  }
 return -ENOENT;
}
#include <linux/bpf_operations.h>
struct bpf_entry_target {
 struct btf *native;
 struct module *source_module;
 struct bpf_prog *program;
 unsigned long native_address;
 unsigned long address;
};
#ifdef CONFIG_EBPFOS_ENTRY_LINK
static struct ebpfos_task_view_request *task_view_prepare(
 const struct bpf_entry_target *sources, u32 count, u64 generation,
 struct bpf_operations_set *operations)
{
 struct ebpfos_task_view_request *request;
 struct task_view *view;
 struct bpf_prog **programs;
 struct file *file;
 unsigned int i;
 int error;
 
 
 view = kvzalloc(struct_size(view, bindings, count), GFP_KERNEL);
 if (!view) return ERR_PTR(-ENOMEM);
 view->count = count;view->generation = generation;view->revocable = true;
 view->operations = bpf_operations_set_get(operations);
 if (count) {
  view->text = kvcalloc(count, sizeof(*view->text), GFP_KERNEL);
  if (!view->text) {error = -ENOMEM;goto fail;}
 }
 INIT_DELAYED_WORK(&view->release_work, task_view_release_work);
 error = ebpfos_ptview_read_native(view->table, sys_call_table, sizeof(view->table));
 if (error) goto fail;
 bitmap_zero(view->selected, NR_syscalls);
 for (i = 0; i < count; ++i) {
  struct bpf_prog *program = sources[i].program;
  int slot = task_view_slot(sources[i].native_address, view->selected, view->table);
  if (IS_ENABLED(CONFIG_EBPFOS_PLT)) slot = -ENOENT;
  if (slot < 0) {
   bool ftrace, canonical_nop;
   unsigned long ip = bpf_entry_text_location(sources[i].source_module,
    sources[i].native_address, &ftrace, &canonical_nop);
   struct task_text_entry *entry = &view->text[view->text_count];
   /* The selected view patches its private page, not global Native text.
    * Original entry instructions therefore need no reserved NOP. Preserve
    * an IBT landing pad before branching into the replacement body. */
   if (!ip)
    ip = ebpfos_view_entry(sources[i].native_address);
   entry_native_jump(ip, sources[i].address, entry->bytes);
   entry->ip = ip;entry->ftrace = ftrace;++view->text_count;
  }
  bpf_prog_inc(program);
  view->bindings[i].program = program;
  view->bindings[i].address = sources[i].address;
  view->bindings[i].native_address = sources[i].native_address;
  view->bindings[i].syscall_slot = slot;
  if (sources[i].source_module) {
   __module_get(sources[i].source_module);
   view->bindings[i].source_module = sources[i].source_module;
  }
  if (program->type == BPF_PROG_TYPE_NATIVE && program->aux->mod) {
   __module_get(program->aux->mod);
   view->bindings[i].module = program->aux->mod;
  }
 }
 /* Discover against one Native snapshot before replacing any value. */
 for (i = 0; i < count; ++i)
  if (view->bindings[i].syscall_slot >= 0)
   view->table[view->bindings[i].syscall_slot] = (sys_call_ptr_t)view->bindings[i].address;
 
 /* Stored private callbacks can outlive the rule and its last syscall frame.
  * Transfer their independent code lease to the existing entry journal. */
 if (count) {
  programs = kvmalloc_array(count, sizeof(*programs), GFP_KERNEL);
  if (!programs) {error = -ENOMEM;goto fail;}
  for (i = 0; i < count; ++i) programs[i] = view->bindings[i].program;
  view->code = bpf_entry_code_get(programs, count);
  kvfree(programs);
  if (IS_ERR(view->code)) {error = PTR_ERR(view->code);view->code = NULL;goto fail;}
 }
 request = kzalloc(sizeof(*request), GFP_KERNEL);
 if (!request) {error = -ENOMEM;goto fail;}
 file = anon_inode_getfile("bpf-rule-syscall-table", &task_view_ops, view, O_RDONLY);
 if (IS_ERR(file)) {error = PTR_ERR(file);kfree(request);goto fail;}
 refcount_set(&request->references, 1);
 request->next = file;
 return request;
fail:
 task_view_free(view);return ERR_PTR(error);
}
void ebpfos_rule_task_put(struct ebpfos_task_view_request *request)
{ task_view_request_free(request); }
struct ebpfos_task_view_request *ebpfos_rule_task_get(struct ebpfos_task_view_request *request)
{ if (request) refcount_inc(&request->references);return request; }
struct ebpfos_task_view_request *ebpfos_rule_task_prepare(const struct bpf_kernel_rule_version *version)
{
 struct bpf_entry_target *sources;
 struct bpf_kernel_rule_function *targets;
 struct ebpfos_task_view_request *request;
 struct btf *native = bpf_get_btf_vmlinux();
 u32 i, count = version->function_count;
 int error = 0;
 if (!count) return NULL;
 
 
 targets = memdup_array_user(u64_to_user_ptr(version->function_btf_ids), count, sizeof(*targets));
 if (IS_ERR(targets)) return ERR_CAST(targets);
 sources = kvcalloc(count, sizeof(*sources), GFP_KERNEL);
 if (!sources) {kvfree(targets);return ERR_PTR(-ENOMEM);}
 for (i = 0; i < count; ++i) {
  struct btf *types = native;
  sources[i].program = bpf_prog_get(targets[i].prog_fd);
  if (IS_ERR(sources[i].program)) {error = PTR_ERR(sources[i].program);sources[i].program = NULL;break;}
  if (targets[i].btf_obj_fd) {
   types = btf_get_by_fd(targets[i].btf_obj_fd);
   if (IS_ERR(types)) {error = PTR_ERR(types);break;}
   types = ebpfos_binding_btf_owner(types, targets[i].btf_id);
   sources[i].native = types;
   if (types != native) {
    sources[i].source_module = btf_try_get_module(types);
    if (!sources[i].source_module) {error = -ENOENT;break;}
   }
  }
  error = bpf_entry_program_address(types, targets[i].btf_id, sources[i].program, true, &sources[i].address);
  if (error) break;
  sources[i].native_address = ebpfos_native_function(types, targets[i].btf_id, sources[i].source_module);
  if (!sources[i].native_address) {error = -ENOENT;break;}
 }
 request = error ? ERR_PTR(error) : task_view_prepare(sources, count, 0, NULL);
 for (i = 0; i < count; ++i) {
  if (sources[i].program) bpf_prog_put(sources[i].program);
  if (sources[i].native) btf_put(sources[i].native);
  module_put(sources[i].source_module);
 }
 kvfree(sources);kvfree(targets);return request;
}

#ifdef CONFIG_EBPFOS_PLT
int ebpfos_rule_task_bindings(struct ebpfos_task_view_request *request,
 ebpfos_rule_binding_visit visit, void *opaque)
{
 struct task_view *view;
 u32 i;
 int error;
 if (!request) return 0;
 view = request->next->private_data;
 for (i = 0; i < view->count; ++i) {
  bool ftrace, canonical;
  if (view->bindings[i].address == view->bindings[i].native_address) continue;
  if (!bpf_entry_text_location(view->bindings[i].source_module,
       view->bindings[i].native_address, &ftrace, &canonical)) continue;
  error = visit(&view->bindings[i], opaque);
  if (error) return error;
 }
 return 0;
}
#endif

void ebpfos_rule_task_copy(struct ebpfos_task_view_request *request, void *table)
{
 struct task_view *view;
 unsigned int nr;
 if (!request) return;
 view = request->next->private_data;
 for_each_set_bit(nr, view->selected, NR_syscalls) ((sys_call_ptr_t *)table)[nr] = view->table[nr];
}

int ebpfos_rule_task_visit_changes(struct ebpfos_task_view_request *request,
 ebpfos_ptview_visit visit, void *opaque)
{
 struct task_view *view;
 unsigned int i;
 int error;
 if (!request) return 0;
 view = request->next->private_data;
 for (i = 0; i < view->text_count; ++i) {
  error = visit(view->text[i].ip, view->text[i].bytes, sizeof(view->text[i].bytes), opaque);
  if (error) return error;
 }
 return 0;
}

#endif

#endif /* CONFIG_EBPFOS && CONFIG_X86_64 */
