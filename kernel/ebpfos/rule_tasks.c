// SPDX-License-Identifier: GPL-2.0-only
/* Only notification, first use, fork and retirement touch rule state. The
 * existing x64 syscall dispatch still performs its single table lookup. */
#include <linux/bpf_kernel_rule.h>
#include <linux/ebpfos_task_rule.h>
#include <linux/export.h>
#include <linux/mutex.h>
#include <linux/resume_user_mode.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <asm/syscall.h>

struct ebpfos_task_rule {
 struct ebpfos_rule_decision *decision;
 sys_call_ptr_t table[NR_syscalls];
};
static DEFINE_MUTEX(task_binding_mutex);
static unsigned int task_rule_links, legacy_links;

int ebpfos_task_rule_claim(bool legacy)
{
 int error = 0;
 mutex_lock(&task_binding_mutex);
 if (legacy ? task_rule_links : legacy_links) error = -EBUSY;
 else if (legacy) ++legacy_links;
 else ++task_rule_links;
 mutex_unlock(&task_binding_mutex);return error;
}
void ebpfos_task_rule_unclaim(bool legacy)
{
 mutex_lock(&task_binding_mutex);
 if (legacy) --legacy_links;
 else --task_rule_links;
 mutex_unlock(&task_binding_mutex);
}
static void task_rule_put(struct ebpfos_task_rule *binding)
{
 if (!binding) return;
 ebpfos_rule_decision_put(binding->decision);kfree(binding);
}
struct ebpfos_rule_decision *ebpfos_task_rule_decision(void)
{
 struct ebpfos_task_rule *binding;
 if (!in_task()) return NULL;
 binding = current->ebpfos_task_rule;
 return binding ? binding->decision : NULL;
}
EXPORT_SYMBOL_GPL(ebpfos_task_rule_decision);

static long task_rule_resolve(const struct pt_regs *regs, unsigned int nr)
{
 struct ebpfos_task_rule *binding;
 struct ebpfos_rule_decision *decision;
 struct bpf_kernel_rule_ctx context;
 binding = kzalloc(sizeof(*binding), GFP_KERNEL);
 if (!binding) return -ENOMEM;
 /* This pointer chooses a complete task table. Its context is stable for
  * that table, rather than whichever syscall happened to resolve first. */
 ebpfos_rule_context(&context, 0, 0);
 decision = ebpfos_rule_resolve(&context, GFP_KERNEL);
 if (IS_ERR(decision)) {kfree(binding);return PTR_ERR(decision);}
 memcpy(binding->table, sys_call_table, sizeof(binding->table));
 ebpfos_rule_task_table(decision, binding->table);
 /* An object-only rule has no enclosing syscall version. Its first object
  * binding still resolves with that object's identity and sampling hash. */
 if (ebpfos_rule_task_choices(decision)) binding->decision = decision;
 else ebpfos_rule_decision_put(decision);
 current->ebpfos_task_rule = binding;
 WRITE_ONCE(current->ebpfos_syscalls, binding->table);
 return binding->table[nr](regs);
}
#define __SYSCALL(nr, sym) \
 static long resolve_##nr(const struct pt_regs *regs) { return task_rule_resolve(regs, nr); }
#define __SYSCALL_NORETURN __SYSCALL
#include <asm/syscalls_64.h>
#undef __SYSCALL
#undef __SYSCALL_NORETURN
static const sys_call_ptr_t task_rule_resolvers[NR_syscalls] = {
#define __SYSCALL(nr, sym) [nr] = resolve_##nr,
#define __SYSCALL_NORETURN __SYSCALL
#include <asm/syscalls_64.h>
#undef __SYSCALL
#undef __SYSCALL_NORETURN
};

void ebpfos_task_rule_mark(struct task_struct *task)
{
 if (task->flags & (PF_KTHREAD | PF_EXITING)) return;
 task_lock(task);task->ebpfos_task_rule_pending = true;task_unlock(task);
 set_notify_resume(task);
}
void ebpfos_task_rules_changed(void)
{
 struct task_struct *group, *task;
 rcu_read_lock();
 for_each_process_thread(group, task) ebpfos_task_rule_mark(task);
 rcu_read_unlock();
}
void ebpfos_task_rule_resume(void)
{
 struct ebpfos_task_rule *old = NULL;
 task_lock(current);
 if (current->ebpfos_task_rule_pending) {
  current->ebpfos_task_rule_pending = false;
  old = current->ebpfos_task_rule;current->ebpfos_task_rule = NULL;
  /* The old L3 publisher is exclusive with syscall rule links. An object
   * rule alone must not replace a task table still owned by L3. */
  if (!current->ebpfos_task_view)
   current->ebpfos_syscalls = READ_ONCE(task_rule_links) ? task_rule_resolvers : sys_call_table;
 }
 task_unlock(current);task_rule_put(old);
}
void ebpfos_task_rule_fork(struct task_struct *task)
{
 task->ebpfos_task_rule = NULL;task->ebpfos_task_rule_pending = false;
 if (READ_ONCE(task_rule_links)) task->ebpfos_syscalls = task_rule_resolvers;
 else if (!task->ebpfos_task_view) task->ebpfos_syscalls = sys_call_table;
}
void ebpfos_task_rule_free(struct task_struct *task)
{ task_rule_put(task->ebpfos_task_rule); }
