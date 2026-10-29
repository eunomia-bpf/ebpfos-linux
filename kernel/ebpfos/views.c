/* Task and file views have the same x86-64 configuration as before. */
#if defined(CONFIG_EBPFOS) && defined(CONFIG_X86_64)

// SPDX-License-Identifier: GPL-2.0-only
/* Task-owned syscall bindings. Publication and graph leases are cold; a
 * syscall enters its resolved body directly. No program runner is involved. */
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
#include <linux/ebpfos_task_rule.h>
#include "function_binding.h"
#include "function_contract.h"
#include <linux/workqueue.h>
#include "function_lifetime.h"

struct task_view {
 u64 generation;
 u32 count;
 bool revocable;
 DECLARE_BITMAP(selected, NR_syscalls);
 struct bpf_operations_set *operations;
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
 kvfree(view);
}
static bool task_view_code_contains(void *opaque, unsigned long ip)
{
 struct task_view *view = opaque;
 u32 i;
 for (i = 0; i < view->count; ++i)
  if (ebpfos_program_contains(view->bindings[i].program, ip) ||
      (view->bindings[i].module &&
       within_module_mem_type(ip, view->bindings[i].module, MOD_TEXT))) return true;
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

/* Bind only actual syscall exports, never a caller-provided address or ordinal.
 * The source descriptor and loaded export supply the complete checked ABI.
 * A native bpf control entry guarantees self-selection has no old-view frame
 * beneath it. Each other task retains its own lease through sleeping calls. */
static inline int task_view_slot(struct btf *native, u32 id, unsigned long *used)
{
 const struct btf_type *function = btf_type_by_id(native, id);
 unsigned long address;
 u32 nr, j;
 if (!function || !btf_type_is_func(function)) return -EINVAL;
 address = kallsyms_lookup_name(btf_name_by_offset(native, function->name_off));
 if (!address) return -ENOENT;
 for (nr = 0; nr < NR_syscalls; ++nr)
  if ((unsigned long)sys_call_table[nr] == address) break;
 if (nr == NR_syscalls) return -ENOENT;
 if (nr == __NR_bpf) return -EBUSY;
 for (j = nr + 1; j < NR_syscalls; ++j)
  if ((unsigned long)sys_call_table[j] == address) return -ENOTUNIQ;
 if (test_and_set_bit(nr, used)) return -ENOTUNIQ;
 return nr;
}
#include <linux/bpf_operations.h>
struct bpf_entry_target {
 u32 function;
 struct bpf_prog *program;
 unsigned long address;
};
#ifdef CONFIG_EBPFOS_ENTRY_LINK
static struct ebpfos_task_view_request *task_view_prepare(
 const struct bpf_entry_target *sources, u32 count, u64 generation,
 struct bpf_operations_set *operations)
{
 struct ebpfos_task_view_request *request;
 struct btf *native = bpf_get_btf_vmlinux();
 struct task_view *view;
 struct file *file;
 unsigned int i, roots = 0;
 int error;
 if ((!count && !operations) || IS_ERR_OR_NULL(native)) return ERR_PTR(-EINVAL);
 if (!IS_ENABLED(CONFIG_HAVE_RELIABLE_STACKTRACE) || !IS_ENABLED(CONFIG_TASKS_RCU))
  return ERR_PTR(-EOPNOTSUPP);
 view = kvzalloc(struct_size(view, bindings, count), GFP_KERNEL);
 if (!view) return ERR_PTR(-ENOMEM);
 view->count = count;view->generation = generation;view->revocable = true;
 view->operations = bpf_operations_set_get(operations);
 INIT_DELAYED_WORK(&view->release_work, task_view_release_work);
 memcpy(view->table, sys_call_table, sizeof(view->table));
 bitmap_zero(view->selected, NR_syscalls);
 for (i = 0; i < count; ++i) {
  struct bpf_prog *program = sources[i].program;
  int slot = task_view_slot(native, sources[i].function, view->selected);
  /* Private members retain code with their syscall roots. They acquire no
   * per-process direct-call dispatch of their own. */
  if (slot < 0 && slot != -ENOENT) {error = slot;goto fail;}
  if (ebpfos_program_addresses(program)) {error = -EOPNOTSUPP;goto fail;}
  bpf_prog_inc(program);
  view->bindings[i].program = program;
  view->bindings[i].address = sources[i].address;
  if (program->type == BPF_PROG_TYPE_NATIVE && program->aux->mod) {
   __module_get(program->aux->mod);
   view->bindings[i].module = program->aux->mod;
  }
  if (slot >= 0) {view->table[slot] = (sys_call_ptr_t)sources[i].address;++roots;}
 }
 if (!roots && !operations) {error = -EOPNOTSUPP;goto fail;}
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
struct ebpfos_task_view_request *ebpfos_rule_task_prepare(const u32 *ids,
 const u32 *fds, u32 count)
{
 struct bpf_entry_target *sources;
 struct ebpfos_task_view_request *request;
 struct btf *native = bpf_get_btf_vmlinux();
 u32 i;
 int error = 0;
 if (!count) return NULL;
 if (IS_ERR_OR_NULL(native)) return ERR_PTR(-EOPNOTSUPP);
 sources = kvmalloc_array(count, sizeof(*sources), GFP_KERNEL | __GFP_ZERO);
 if (!sources) return ERR_PTR(-ENOMEM);
 for (i = 0; i < count; ++i) {
  sources[i].function = ids[i];sources[i].program = bpf_prog_get(fds[i]);
  if (IS_ERR(sources[i].program)) {error = PTR_ERR(sources[i].program);sources[i].program = NULL;break;}
  error = bpf_entry_program_address(native, ids[i], sources[i].program, true, &sources[i].address);
  if (error) break;
 }
 request = error ? ERR_PTR(error) : task_view_prepare(sources, count, 0, NULL);
 for (i = 0; i < count; ++i) if (sources[i].program) bpf_prog_put(sources[i].program);
 kvfree(sources);return request;
}
bool ebpfos_rule_task_overlap(struct ebpfos_task_view_request *a,
 struct ebpfos_task_view_request *b)
{
 struct task_view *x, *y;
 if (!a || !b) return false;
 x = a->next->private_data;y = b->next->private_data;
 return bitmap_intersects(x->selected, y->selected, NR_syscalls);
}
void ebpfos_rule_task_copy(struct ebpfos_task_view_request *request, void *table)
{
 struct task_view *view;
 unsigned int nr;
 if (!request) return;
 view = request->next->private_data;
 for_each_set_bit(nr, view->selected, NR_syscalls) ((sys_call_ptr_t *)table)[nr] = view->table[nr];
}
#endif

#endif /* CONFIG_EBPFOS && CONFIG_X86_64 */
