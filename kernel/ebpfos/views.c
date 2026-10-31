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

struct task_text_entry { unsigned long ip; u8 bytes[MCOUNT_INSN_SIZE]; };

struct task_view {
 u64 generation;
 u32 count;
 bool revocable;
 DECLARE_BITMAP(selected, NR_syscalls);
 struct bpf_operations_set *operations;
 struct entry_set *code;
 struct ftrace_text_reservation *text_owner;
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
 ftrace_text_release(view->text_owner);
 kvfree(view->text);
 kvfree(view);
}
static bool task_view_code_contains(void *opaque, unsigned long ip)
{
 struct task_view *view = opaque;
 u32 i;
 for (i = 0; i < view->count; ++i)
  if (ebpfos_program_contains(view->bindings[i].program, ip) ||
      (view->bindings[i].module &&
       within_module_mem_type(ip, view->bindings[i].module, MOD_TEXT)) ||
      (view->bindings[i].source_module &&
       within_module(ip, view->bindings[i].source_module))) return true;
 return false;
}
static inline void task_view_release_work(struct work_struct *work)
{
 struct task_view *view = container_of(to_delayed_work(work), struct task_view, release_work);
 if (!ebpfos_code_quiescent(task_view_code_contains, view)) task_view_free(view);
 else schedule_delayed_work(&view->release_work, HZ / 10);
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

/* Bind actual syscall exports, never a caller-provided address or ordinal.
 * The source descriptor and loaded export supply the complete checked ABI.
 * A native bpf control entry guarantees self-selection has no old-view frame
 * beneath it. Each other task retains its own lease through sleeping calls. */
static inline int task_view_slot(unsigned long address, unsigned long *used, const sys_call_ptr_t *original)
{
 u32 nr, j;
 for (nr = 0; nr < NR_syscalls; ++nr)
  if ((unsigned long)original[nr] == address) break;
 if (nr == NR_syscalls) return -ENOENT;
 if (nr == __NR_bpf) return -EBUSY;
 for (j = nr + 1; j < NR_syscalls; ++j)
  if ((unsigned long)original[j] == address) return -ENOTUNIQ;
 if (test_and_set_bit(nr, used)) return -ENOTUNIQ;
 return nr;
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
 unsigned int i, roots = 0;
 int error;
 if (!count && !operations) return ERR_PTR(-EINVAL);
 if (!IS_ENABLED(CONFIG_HAVE_RELIABLE_STACKTRACE) || !IS_ENABLED(CONFIG_TASKS_RCU))
  return ERR_PTR(-EOPNOTSUPP);
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
  if (slot < 0 && slot != -ENOENT) {error = slot;goto fail;}
  /* A private member can escape into an asynchronous callback. The view
   * proves a task entry only for an actual native syscall-table root.
   */
  if (slot < 0 && bpf_native_func_entry(program) && program->sleepable) {
   error = -EOPNOTSUPP;goto fail;
  }
  if (slot < 0) {
   unsigned long ip = ebpfos_ftrace_entry(sources[i].native_address);
   if (ip) {
    struct task_text_entry *entry = &view->text[view->text_count];
    unsigned int j;
    /* A generic entry can also run outside a task. Its callable cannot
     * acquire syscall-only sleepable authority from this request. */
    if (program->sleepable) {error = -EOPNOTSUPP;goto fail;}
    for (j = 0; j < view->text_count; ++j)
     if (view->text[j].ip == ip) {error = -ENOTUNIQ;goto fail;}
    if (!entry_native_jump(ip, sources[i].address, entry->bytes)) {error = -ERANGE;goto fail;}
    entry->ip = ip;++view->text_count;++roots;
   }
   /* An entry without its own instruction stays private to its holders.
    * Its loaded graph still needs the same independent lifetime lease. */
  }
  bpf_prog_inc(program);
  view->bindings[i].program = program;
  view->bindings[i].address = sources[i].address;
  view->bindings[i].native_address = sources[i].native_address;
  if (sources[i].source_module) {
   __module_get(sources[i].source_module);
   view->bindings[i].source_module = sources[i].source_module;
  }
  if (program->type == BPF_PROG_TYPE_NATIVE && program->aux->mod) {
   __module_get(program->aux->mod);
   view->bindings[i].module = program->aux->mod;
  }
  if (slot >= 0) ++roots;
 }
 /* Discover against one Native snapshot before replacing any value. */
 for (i = 0; i < NR_syscalls; ++i) if (test_bit(i, view->selected)) {
  u32 binding;
  for (binding = 0; binding < count; ++binding)
   if (view->bindings[binding].native_address == (unsigned long)view->table[i]) {
    view->table[i] = (sys_call_ptr_t)view->bindings[binding].address;break;
   }
 }
 if (!roots && !operations) {error = -EOPNOTSUPP;goto fail;}
 if (view->text_count) {
  unsigned long *ips = kvmalloc_array(view->text_count, sizeof(*ips), GFP_KERNEL);
  if (!ips) {error = -ENOMEM;goto fail;}
  for (i = 0; i < view->text_count; ++i) ips[i] = view->text[i].ip;
  view->text_owner = ftrace_text_reserve(ips, view->text_count, true);
  kvfree(ips);
  if (IS_ERR(view->text_owner)) {error = PTR_ERR(view->text_owner);view->text_owner = NULL;goto fail;}
 }
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
 if (IS_ERR_OR_NULL(native)) return ERR_PTR(-EOPNOTSUPP);
 if (version->function_flags & BPF_KERNEL_RULE_SCOPED_FUNCTIONS) {
  if (version->function_prog_fds) return ERR_PTR(-EINVAL);
  targets = memdup_array_user(u64_to_user_ptr(version->function_btf_ids), count, sizeof(*targets));
  if (IS_ERR(targets)) return ERR_CAST(targets);
 } else {
  u32 *ids, *fds;
  ids = memdup_array_user(u64_to_user_ptr(version->function_btf_ids), count, sizeof(u32));
  if (IS_ERR(ids)) return ERR_CAST(ids);
  fds = memdup_array_user(u64_to_user_ptr(version->function_prog_fds), count, sizeof(u32));
  if (IS_ERR(fds)) {kfree(ids);return ERR_CAST(fds);}
  targets = kvcalloc(count, sizeof(*targets), GFP_KERNEL);
  if (!targets) {kfree(ids);kfree(fds);return ERR_PTR(-ENOMEM);}
  for (i = 0; i < count; ++i) {
   targets[i].btf_id = ids[i];targets[i].prog_fd = fds[i];
  }
  kfree(ids);kfree(fds);
 }
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

bool ebpfos_rule_task_overlap(struct ebpfos_task_view_request *a,
 struct ebpfos_task_view_request *b)
{
 struct task_view *x, *y;
 if (!a || !b) return false;
 x = a->next->private_data;y = b->next->private_data;
 {
  u32 i, j;
  for (i = 0; i < x->count; ++i) for (j = 0; j < y->count; ++j)
   if (x->bindings[i].native_address == y->bindings[j].native_address) return true;
 }
 return bitmap_intersects(x->selected, y->selected, NR_syscalls);
}
/* The same syscall slot can be named by a function root or by a BTF table
 * field. Both forms keep the Native control entry and one owner per slot. */
static int task_view_data_change(unsigned long address, const void *bytes, size_t size, void *opaque)
{
 struct task_view *view = opaque;
 unsigned long first = (unsigned long)sys_call_table, end = address + size;
 u32 nr;
 (void)bytes;
 if (end < address) return -EINVAL;
 if (end <= first || address >= first + NR_syscalls * sizeof(*sys_call_table)) return 0;
 for (nr = 0; nr < NR_syscalls; ++nr) {
  unsigned long slot = first + nr * sizeof(*sys_call_table);
  if (address < slot + sizeof(*sys_call_table) && slot < end &&
      (nr == __NR_bpf || (view && test_bit(nr, view->selected)))) return -EBUSY;
 }
 return 0;
}
int ebpfos_rule_task_operations_check(struct ebpfos_task_view_request *request,
 const struct bpf_operations_set *operations)
{
 return bpf_operations_visit_changes(operations, task_view_data_change,
  request ? request->next->private_data : NULL);
}
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
