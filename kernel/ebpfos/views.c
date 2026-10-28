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
#include <linux/ebpfos_task_view.h>
#include <linux/pid.h>
#include <linux/resume_user_mode.h>
#include <linux/bitmap.h>
#include <asm/syscall.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <linux/anon_inodes.h>
#include <linux/slab.h>
#include <linux/bpf_operations.h>
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

/* Immutable requests can be shared by every task in a cgroup. The owner
 * and each pending task hold a reference; publication acquires a separate
 * file reference for the task's complete active syscall version. */
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

/* This runs ONLY at return to user mode, never at a general task_work_run()
 * site inside a syscall. The entire syscall graph, including inline copies
 * and nested/sleeping callees, has returned before this boundary. No test or
 * trampoline is added to ordinary selected calls. */
void ebpfos_task_view_resume(void)
{
 struct ebpfos_task_view_request *request;
 struct file *old = NULL;
 task_lock(current);
 request = current->ebpfos_task_view_request;
 if (request) {
  current->ebpfos_task_view_request = NULL;
  old = current->ebpfos_task_view;
  current->ebpfos_task_view = request->next ? get_file(request->next) : NULL;
  current->ebpfos_syscalls = request->next ?
   ((struct task_view *)request->next->private_data)->table : sys_call_table;
 }
 task_unlock(current);
 if (old) fput(old);
 task_view_request_free(request);
}


#ifdef CONFIG_EBPFOS_ENTRY_LINK
struct bpf_operations_set *ebpfos_task_operations(void)
{
 struct file *file = current->ebpfos_task_view;
 return file ? ((struct task_view *)file->private_data)->operations : NULL;
}

#endif

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

void ebpfos_task_view_fork(struct task_struct *task)
{
 /* A request names one task, not future children. A fork within its old
  * syscall inherits the old complete view and its independent code lease. */
 task->ebpfos_task_view_request = NULL;
 if (task->ebpfos_task_view) get_file(task->ebpfos_task_view);

}
void ebpfos_task_view_free(struct task_struct *task)
{
 task_view_request_free(task->ebpfos_task_view_request);
 if (task->ebpfos_task_view) fput(task->ebpfos_task_view);

}

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
#include <linux/cgroup.h>
#include <linux/bpf_entry_cgroup.h>
#if defined(CONFIG_EBPFOS_ENTRY_LINK) && defined(CONFIG_CGROUP_BPF)
struct ebpfos_cgroup_view {
 struct cgroup *group;
 struct ebpfos_task_view_request *request, *effective;
 struct ebpfos_cgroup_view *next;
 struct delayed_work release_work;
 bool attached;
};
/* A permanent owner reference makes restoration allocation-free. */
static struct ebpfos_task_view_request global_request = {
 .references = REFCOUNT_INIT(1),
};
void ebpfos_cgroup_request_put(struct ebpfos_task_view_request *request)
{ task_view_request_free(request); }
struct ebpfos_task_view_request *ebpfos_cgroup_prepare(
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
 file = anon_inode_getfile("bpf-entry-cgroup-table", &task_view_ops, view, O_RDONLY);
 if (IS_ERR(file)) {error = PTR_ERR(file);kfree(request);goto fail;}
 refcount_set(&request->references, 1);
 request->next = file;
 return request;
fail:
 task_view_free(view);return ERR_PTR(error);
}
/* Keep one flat syscall/table selection for the whole cgroup. This work is
 * cold under cgroup_mutex; syscall dispatch and object methods are unchanged.
 * A child with any links still selects its complete view, as before. */
static struct ebpfos_task_view_request *cgroup_compose(struct ebpfos_cgroup_view *head,
 struct ebpfos_cgroup_view *replace, struct ebpfos_task_view_request *replacement)
{
 struct ebpfos_cgroup_view *member;
 struct ebpfos_task_view_request *request;
 struct task_view *view, *part;
 struct file *file;
 unsigned int count = 0, at = 0, i, nr;
 int error;
 for (member = head; member; member = member->next) {
  request = member == replace ? replacement : member->request;
  if (!request) continue;
  part = request->next->private_data;
  if (part->count > U32_MAX - count) return ERR_PTR(-E2BIG);
  count += part->count;
 }
 view = kvzalloc(struct_size(view, bindings, count), GFP_KERNEL);
 if (!view) return ERR_PTR(-ENOMEM);
 view->revocable = true;
 INIT_DELAYED_WORK(&view->release_work, task_view_release_work);
 memcpy(view->table, sys_call_table, sizeof(view->table));
 for (member = head; member; member = member->next) {
  struct bpf_operations_set *operations;
  request = member == replace ? replacement : member->request;
  if (!request) continue;
  part = request->next->private_data;
  if (bitmap_intersects(view->selected, part->selected, NR_syscalls)) {
   error = -EBUSY;goto fail;
  }
  operations = bpf_operations_compose(view->operations, part->operations, NULL);
  if (IS_ERR(operations)) {error = PTR_ERR(operations);goto fail;}
  bpf_operations_set_put(view->operations);view->operations = operations;
  bitmap_or(view->selected, view->selected, part->selected, NR_syscalls);
  for_each_set_bit(nr, part->selected, NR_syscalls) view->table[nr] = part->table[nr];
  for (i = 0; i < part->count; ++i) {
   view->bindings[at] = part->bindings[i];
   bpf_prog_inc(view->bindings[at].program);
   if (view->bindings[at].module) __module_get(view->bindings[at].module);
   ++at;view->count = at;
  }
  view->generation = max(view->generation, part->generation);
 }
 request = kzalloc(sizeof(*request), GFP_KERNEL);
 if (!request) {error = -ENOMEM;goto fail;}
 file = anon_inode_getfile("bpf-entry-cgroup-table", &task_view_ops, view, O_RDONLY);
 if (IS_ERR(file)) {error = PTR_ERR(file);kfree(request);goto fail;}
 refcount_set(&request->references, 1);request->next = file;
 return request;
fail:
 task_view_free(view);return ERR_PTR(error);
}
/* All owner publication, membership movement and fork selection serialize on
 * css_set_lock. Lookup and queueing therefore cannot install an older request
 * after an update has already queued a newer version for the same task. */
static struct ebpfos_task_view_request *cgroup_request_locked(struct task_struct *task)
{
 struct cgroup *group;
 struct ebpfos_cgroup_view *view;
 lockdep_assert_held(&css_set_lock);
 for (group = task_dfl_cgroup(task); group; group = cgroup_parent(group)) {
  view = group->bpf.entry_view;
  if (view) return view->effective;
 }
 return &global_request;
}
void ebpfos_cgroup_task_move(struct task_struct *task)
{
 struct ebpfos_task_view_request *request, *old;
 lockdep_assert_held(&css_set_lock);
 if (task->flags & (PF_KTHREAD | PF_EXITING)) return;
 request = cgroup_request_locked(task);
 task_lock(task);
 if (!task->ebpfos_task_view_request && task->ebpfos_task_view == request->next) {
  task_unlock(task);return;
 }
 refcount_inc(&request->references);
 old = task->ebpfos_task_view_request;
 task->ebpfos_task_view_request = request;
 task_unlock(task);
 task_view_request_free(old);
 set_notify_resume(task);
}
void ebpfos_cgroup_exec(void)
{
 unsigned long flags;
 spin_lock_irqsave(&css_set_lock, flags);
 ebpfos_cgroup_task_move(current);
 spin_unlock_irqrestore(&css_set_lock, flags);
}
static void cgroup_refresh_locked(void)
{
 struct task_struct *leader, *task;
 lockdep_assert_held(&css_set_lock);
 rcu_read_lock();
 for_each_process_thread(leader, task) ebpfos_cgroup_task_move(task);
 rcu_read_unlock();
}
struct ebpfos_cgroup_view *ebpfos_cgroup_view_create(int fd,
 struct ebpfos_task_view_request *request)
{
 struct ebpfos_cgroup_view *view;
 struct cgroup *group = cgroup_get_from_fd(fd);
 if (IS_ERR(group)) return ERR_CAST(group);
 if (group->root != &cgrp_dfl_root) {cgroup_put(group);return ERR_PTR(-EOPNOTSUPP);}
 view = kzalloc(sizeof(*view), GFP_KERNEL);
 if (!view) {cgroup_put(group);return ERR_PTR(-ENOMEM);}
 view->group = group;view->request = request;
 return view;
}
int ebpfos_cgroup_view_attach(struct ebpfos_cgroup_view *view)
{
 struct ebpfos_cgroup_view *head;
 struct ebpfos_task_view_request *merged, *old = NULL;
 unsigned long flags;
 int error = 0;
 cgroup_lock();
 if (cgroup_is_dead(view->group)) {error = -ENOENT;goto out;}
 head = view->group->bpf.entry_view;view->next = head;
 merged = cgroup_compose(view, NULL, NULL);
 if (IS_ERR(merged)) {error = PTR_ERR(merged);view->next = NULL;goto out;}
 spin_lock_irqsave(&css_set_lock, flags);
 if (head) {old = head->effective;head->effective = NULL;}
 view->effective = merged;view->group->bpf.entry_view = view;
 WRITE_ONCE(view->attached, true);
 cgroup_refresh_locked();
 spin_unlock_irqrestore(&css_set_lock, flags);
out:
 cgroup_unlock();task_view_request_free(old);return error;
}
int ebpfos_cgroup_view_update(struct ebpfos_cgroup_view *view,
 struct ebpfos_task_view_request *next)
{
 struct ebpfos_cgroup_view *head;
 struct ebpfos_task_view_request *merged, *old = NULL, *effective = NULL;
 unsigned long flags;
 int error = 0;
 cgroup_lock();
 if (!view->attached) {error = -ENOLINK;goto out;}
 head = view->group->bpf.entry_view;
 merged = cgroup_compose(head, view, next);
 if (IS_ERR(merged)) {error = PTR_ERR(merged);goto out;}
 spin_lock_irqsave(&css_set_lock, flags);
 old = view->request;view->request = next;
 effective = head->effective;head->effective = merged;
 cgroup_refresh_locked();
 spin_unlock_irqrestore(&css_set_lock, flags);
out:
 cgroup_unlock();task_view_request_free(old);task_view_request_free(effective);
 return error;
}
int ebpfos_cgroup_view_detach(struct ebpfos_cgroup_view *view)
{
 struct ebpfos_cgroup_view *head, *member, *next;
 struct ebpfos_task_view_request *merged = NULL, *old = NULL;
 unsigned long flags;
 int error = 0;
 cgroup_lock();
 if (!view->attached) goto out;
 head = view->group->bpf.entry_view;
 next = head == view ? view->next : head;
 if (next) {
  merged = cgroup_compose(head, view, NULL);
  if (IS_ERR(merged)) {error = PTR_ERR(merged);goto out;}
 }
 spin_lock_irqsave(&css_set_lock, flags);
 old = head->effective;head->effective = NULL;
 if (head != view) {
  for (member = head; member->next != view; member = member->next) {}
  member->next = view->next;
 }
 if (next) next->effective = merged;
 view->group->bpf.entry_view = next;view->next = NULL;
 WRITE_ONCE(view->attached, false);
 cgroup_refresh_locked();
 spin_unlock_irqrestore(&css_set_lock, flags);
out:
 cgroup_unlock();task_view_request_free(old);return error;
}
void ebpfos_cgroup_offline(struct cgroup *group)
{
 struct ebpfos_cgroup_view *view, *next;
 struct ebpfos_task_view_request *old = NULL;
 unsigned long flags;
 /* The cgroup lifetime notifier already holds cgroup_mutex. Removing the
  * entire selection needs no allocation, including under memory pressure. */
 spin_lock_irqsave(&css_set_lock, flags);
 view = group->bpf.entry_view;
 if (view) {
  old = view->effective;view->effective = NULL;
  group->bpf.entry_view = NULL;
  for (; view; view = next) {
   next = view->next;view->next = NULL;WRITE_ONCE(view->attached, false);
  }
  cgroup_refresh_locked();
 }
 spin_unlock_irqrestore(&css_set_lock, flags);
 task_view_request_free(old);
}
static void cgroup_view_free(struct ebpfos_cgroup_view *view)
{
 task_view_request_free(view->request);
 cgroup_put(view->group);kfree(view);
}
static void cgroup_view_release_work(struct work_struct *work)
{
 struct ebpfos_cgroup_view *view = container_of(to_delayed_work(work), struct ebpfos_cgroup_view, release_work);
 /* Last-close cannot return an allocation error. Keep the owner and its
  * independent program leases until a complete replacement can be prepared. */
 if (!ebpfos_cgroup_view_detach(view)) cgroup_view_free(view);
 else schedule_delayed_work(&view->release_work, HZ / 10);
}
void ebpfos_cgroup_view_put(struct ebpfos_cgroup_view *view)
{
 if (!view) return;
 if (!ebpfos_cgroup_view_detach(view)) cgroup_view_free(view);
 else {
  INIT_DELAYED_WORK(&view->release_work, cgroup_view_release_work);
  schedule_delayed_work(&view->release_work, HZ / 10);
 }
}
u64 ebpfos_cgroup_view_id(const struct ebpfos_cgroup_view *view)
{ return view ? cgroup_id(view->group) : 0; }
bool ebpfos_cgroup_view_active(const struct ebpfos_cgroup_view *view)
{ return view && READ_ONCE(view->attached); }
#endif


#endif /* CONFIG_EBPFOS && CONFIG_X86_64 */
