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
 bpf_entry_scope_put(binding->scope);
 ebpfos_rule_decision_put(binding->decision);kfree(binding);
}
void ebpfos_task_rule_put(struct ebpfos_task_rule *binding)
{ if (binding && refcount_dec_and_test(&binding->refs)) schedule_work(&binding->release); }
EXPORT_SYMBOL_GPL(ebpfos_task_rule_put);
static void task_rule_get(struct ebpfos_task_rule *binding)
{ if (binding) refcount_inc(&binding->refs); }
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
static struct ebpfos_task_rule *plt_resolve(const struct bpf_kernel_rule_ctx *context)
{
 struct ebpfos_rule_decision *decision;
 struct ebpfos_task_rule *binding;
 struct plt_binding_input input = {};
 int error;
 if (!ebpfos_rule_active()) return NULL;
 mutex_lock(&plt_binding_mutex);
 decision = ebpfos_rule_resolve(context, GFP_KERNEL);
 if (IS_ERR(decision)) {mutex_unlock(&plt_binding_mutex);return NULL;}
 if (!ebpfos_rule_task_choices(decision)) {mutex_unlock(&plt_binding_mutex);ebpfos_rule_decision_put(decision);return NULL;}
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
 binding->decision = decision;refcount_set(&binding->refs, 2); /* cache plus returned lease */
 INIT_WORK(&binding->release, plt_binding_release);
 list_add_tail(&binding->node, &plt_bindings);
 mutex_unlock(&plt_binding_mutex);kfree(input.items);return binding;
fail:
 mutex_unlock(&plt_binding_mutex);kfree(input.items);ebpfos_rule_decision_put(decision);return NULL; /* Allocation/publication failure leaves the native choice. */
}
void ebpfos_task_rule_resume(void)
{
 struct ebpfos_task_rule *next, *old;
 struct bpf_kernel_rule_ctx context;
 u64 epoch;
 if (!READ_ONCE(current->ebpfos_task_rule_pending) || (current->flags & PF_EXITING)) return;
 for (;;) {
  /* A cgroup move need not change the rule epoch. Clear the notification
   * before reading context so a move during resolution requests a retry. */
  task_lock(current);current->ebpfos_task_rule_pending = false;task_unlock(current);
  epoch = ebpfos_rule_epoch();ebpfos_rule_context(&context, 0, 0);next = plt_resolve(&context);
  task_lock(current);
  if (epoch != ebpfos_rule_epoch() || current->ebpfos_task_rule_pending) {task_unlock(current);ebpfos_task_rule_put(next);continue;}
  old = current->ebpfos_task_rule;
  current->ebpfos_task_rule = next;
  WRITE_ONCE(current->ebpfos_version, next ? bpf_entry_scope_id(next->scope) : 0);
  current->ebpfos_task_rule_pending = false;
  task_unlock(current);ebpfos_task_rule_put(old);return;
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
 struct ebpfos_task_rule *binding, *next;
 /* Resolution holds this mutex before taking its generation snapshot. */
 mutex_lock(&plt_binding_mutex);
 list_for_each_entry_safe(binding, next, &plt_bindings, node) {
  list_del(&binding->node);ebpfos_task_rule_put(binding);
 }
 mutex_unlock(&plt_binding_mutex);
 rcu_read_lock();
 for_each_process_thread(group, task) ebpfos_task_rule_mark(task);
 rcu_read_unlock();
}
void ebpfos_task_rule_fork(struct task_struct *task)
{
 struct ebpfos_task_rule *binding = task->ebpfos_task_rule;
 task_rule_get(binding);
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
{ ebpfos_task_rule_put(task->ebpfos_task_rule); }

/* Capture native submission scalars once; the request owns the exact
 * generation until completion, independently of the worker that issues it. */
struct ebpfos_task_rule *ebpfos_task_rule_request(u64 object, u64 request, u64 descriptor)
{
 struct bpf_kernel_rule_ctx context;
 ebpfos_rule_context(&context, object, request);
 context.file_descriptor = descriptor;
 return plt_resolve(&context);
}
EXPORT_SYMBOL_GPL(ebpfos_task_rule_request);
struct ebpfos_task_rule_state ebpfos_task_rule_enter(struct ebpfos_task_rule *binding)
{
 struct ebpfos_task_rule_state old;
 task_rule_get(binding);
 task_lock(current);
 old = (struct ebpfos_task_rule_state){current->ebpfos_task_rule,current->ebpfos_version};
 current->ebpfos_task_rule = binding;
 WRITE_ONCE(current->ebpfos_version,binding ? bpf_entry_scope_id(binding->scope) : 0);
 task_unlock(current);return old;
}
EXPORT_SYMBOL_GPL(ebpfos_task_rule_enter);
void ebpfos_task_rule_leave(struct ebpfos_task_rule_state old)
{
 struct ebpfos_task_rule *binding;
 task_lock(current);binding = current->ebpfos_task_rule;
 current->ebpfos_task_rule = old.binding;
 WRITE_ONCE(current->ebpfos_version,old.version);
 /* A rule scan during an inner scope need not see the outer decision.
  * Revisit it at user return, without a new epoch/context guard. */
 current->ebpfos_task_rule_pending = true;
 task_unlock(current);set_notify_resume(current);ebpfos_task_rule_put(binding);
}
EXPORT_SYMBOL_GPL(ebpfos_task_rule_leave);
