/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/bpf_entry.h>
#include <linux/task_work.h>
#include <linux/workqueue.h>
#include "function_binding.h"
struct ebpfos_task_rule {
 struct list_head node;
 refcount_t refs;
 struct work_struct release;
 struct ebpfos_rule_decision *decision;
 struct bpf_entry_scope *scope;
};
static DEFINE_MUTEX(plt_binding_mutex);
static LIST_HEAD(plt_bindings);
void ebpfos_task_rule_claim(void) {}
void ebpfos_task_rule_unclaim(void) {}
static void plt_binding_release(struct work_struct *work)
{
 struct ebpfos_task_rule *binding = container_of(work, struct ebpfos_task_rule, release);
 mutex_lock(&plt_binding_mutex);list_del(&binding->node);mutex_unlock(&plt_binding_mutex);
 bpf_entry_scope_put(binding->scope);
 ebpfos_rule_decision_put(binding->decision);kfree(binding);
}
static void task_rule_put(struct ebpfos_task_rule *binding)
{ if (binding && refcount_dec_and_test(&binding->refs)) schedule_work(&binding->release); }
struct ebpfos_rule_decision *ebpfos_task_rule_decision(void)
{
 struct ebpfos_task_rule *binding;
 if (!in_task() || (current->flags & PF_KTHREAD)) return NULL;
 binding = current->ebpfos_task_rule;
 return binding ? binding->decision : NULL;
}
EXPORT_SYMBOL_GPL(ebpfos_task_rule_decision);
struct plt_binding_input { struct ebpfos_function_binding *items;u32 count, capacity; };
static int plt_collect_binding(const struct ebpfos_function_binding *binding, void *opaque)
{
 struct plt_binding_input *input = opaque;
 if (input->count == input->capacity) {
  u32 capacity = input->capacity ? input->capacity * 2 : 4;
  void *next = krealloc_array(input->items, capacity, sizeof(*input->items), GFP_KERNEL);
  if (!next) return -ENOMEM;
  input->items = next;input->capacity = capacity;
 }
 input->items[input->count++] = *binding;return 0;
}
static struct ebpfos_task_rule *plt_resolve(void)
{
 struct bpf_kernel_rule_ctx context;
 struct ebpfos_rule_decision *decision;
 struct ebpfos_task_rule *binding;
 struct plt_binding_input input = {};
 int error;
 if (!ebpfos_rule_active()) return NULL;
 ebpfos_rule_context(&context, 0, 0);
 decision = ebpfos_rule_resolve(&context, GFP_KERNEL);
 if (IS_ERR(decision)) return ERR_CAST(decision);
 if (!ebpfos_rule_task_choices(decision)) {ebpfos_rule_decision_put(decision);return NULL;}
 mutex_lock(&plt_binding_mutex);
 list_for_each_entry(binding, &plt_bindings, node)
  if (ebpfos_rule_decision_same(binding->decision, decision) && refcount_inc_not_zero(&binding->refs)) {
   mutex_unlock(&plt_binding_mutex);ebpfos_rule_decision_put(decision);return binding;
  }
 binding = kzalloc(sizeof(*binding), GFP_KERNEL);
 if (!binding) {error = -ENOMEM;goto fail;}
 error = ebpfos_rule_selected_bindings(decision, plt_collect_binding, &input);
 if (error) {kfree(binding);goto fail;}
 binding->scope = bpf_entry_scope_get(input.items, input.count);
 if (IS_ERR(binding->scope)) {error = PTR_ERR(binding->scope);kfree(binding);goto fail;}
 binding->decision = decision;refcount_set(&binding->refs, 1);
 INIT_WORK(&binding->release, plt_binding_release);
 list_add_tail(&binding->node, &plt_bindings);
 mutex_unlock(&plt_binding_mutex);kfree(input.items);return binding;
fail:
 mutex_unlock(&plt_binding_mutex);kfree(input.items);ebpfos_rule_decision_put(decision);return ERR_PTR(error);
}
void ebpfos_task_rule_resume(void)
{
 struct ebpfos_task_rule *next, *old;
 u64 epoch;
 if (!READ_ONCE(current->ebpfos_task_rule_pending) || (current->flags & PF_EXITING)) return;
 for (;;) {
  /* A cgroup move need not change the rule epoch. Clear the notification
   * before reading context so a move during resolution requests a retry. */
  task_lock(current);current->ebpfos_task_rule_pending = false;task_unlock(current);
  epoch = ebpfos_rule_epoch();next = plt_resolve();
  if (IS_ERR(next)) {
   task_lock(current);current->ebpfos_task_rule_pending = true;task_unlock(current);
   set_notify_resume(current);return;
  }
  task_lock(current);
  if (epoch != ebpfos_rule_epoch() || current->ebpfos_task_rule_pending) {task_unlock(current);task_rule_put(next);continue;}
  old = current->ebpfos_task_rule;
  current->ebpfos_task_rule = next;
  WRITE_ONCE(current->ebpfos_version, next ? bpf_entry_scope_id(next->scope) : 0);
  current->ebpfos_task_rule_pending = false;
  task_unlock(current);task_rule_put(old);return;
 }
}
/* TWA_RESUME requests a user-return notification but io_uring can drain
 * task work inside a syscall. The existing resume_user_mode_work tail runs
 * the resolver, so an early task-work drain cannot change an in-flight call. */
static void plt_task_work(struct callback_head *work) { kfree(work); }
void ebpfos_task_rule_mark(struct task_struct *task)
{
 struct callback_head *work;
 if (task->flags & (PF_KTHREAD | PF_EXITING)) return;
 if (!ebpfos_rule_active() && !READ_ONCE(task->ebpfos_task_rule)) return;
 task_lock(task);
 if (task->ebpfos_task_rule_pending) {task_unlock(task);return;}
 task->ebpfos_task_rule_pending = true;
 task_unlock(task);
 work = kmalloc(sizeof(*work), GFP_ATOMIC);
 if (work) {
  init_task_work(work, plt_task_work);
  if (task_work_add(task, work, TWA_RESUME)) kfree(work);
 } else {
  /* Existing resume hook retries if notification storage was unavailable. */
  set_notify_resume(task);
 }
}
void ebpfos_task_rules_changed(void)
{
 struct task_struct *group, *task;
 rcu_read_lock();
 for_each_process_thread(group, task) ebpfos_task_rule_mark(task);
 rcu_read_unlock();
}
void ebpfos_task_rule_fork(struct task_struct *task)
{
 struct ebpfos_task_rule *binding = task->ebpfos_task_rule;
 if (binding) refcount_inc(&binding->refs);
 task->ebpfos_task_rule_pending = false;
}
void ebpfos_task_rule_started(struct task_struct *task)
{
 struct ebpfos_task_rule *binding = task->ebpfos_task_rule;
 /* Preserve the normal fork copy in this epoch. A rule scan can miss an
  * unpublished child, so catch that race after it enters the task list. */
 if (binding ? ebpfos_rule_decision_epoch(binding->decision) != ebpfos_rule_epoch() : ebpfos_rule_active())
  ebpfos_task_rule_mark(task);
}
void ebpfos_task_rule_free(struct task_struct *task)
{ task_rule_put(task->ebpfos_task_rule); }
