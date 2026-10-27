// SPDX-License-Identifier: GPL-2.0-only
#ifndef EBPFOS_FUNCTION_LIFETIME_H
#define EBPFOS_FUNCTION_LIFETIME_H
#include <linux/bpf.h>
#include <linux/cpu.h>
#include <linux/filter.h>
#include <linux/rcupdate.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/stacktrace.h>
/* A grace period alone does not drain sleeping native/BPF frames. Both entry
 * journals and revoked task views use this same reliable stack check. */
static bool ebpfos_program_contains(struct bpf_prog *program, unsigned long ip)
{
 unsigned int j;
 if (!program) return false;
 if (ip >= (unsigned long)program->bpf_func &&
     ip < (unsigned long)program->bpf_func + program->jited_len) return true;
 for (j = 0; program->aux->func && j < program->aux->func_cnt; ++j) {
  struct bpf_prog *function = program->aux->func[j];
  if (function && ip >= (unsigned long)function->bpf_func &&
      ip < (unsigned long)function->bpf_func + function->jited_len) return true;
 }
 return false;
}
struct ebpfos_running_stack { struct task_struct *task; int error; };
struct ebpfos_stack_check {
 bool (*contains)(void *, unsigned long);
 void *owner;
 struct ebpfos_running_stack *running;
 bool found;
};
static bool ebpfos_stack_address(void *opaque, unsigned long ip)
{
 struct ebpfos_stack_check *check = opaque;
 if (check->contains(check->owner, ip)) {check->found = true;return false;}
 return true;
}
static int ebpfos_stack_walk(struct task_struct *task, struct ebpfos_stack_check *check)
{
 int error;
 if (!try_get_task_stack(task)) return 0;
 check->found = false;
 error = arch_stack_walk_reliable(ebpfos_stack_address, check, task);
 put_task_stack(task);
 return check->found ? -EADDRINUSE : error ? -EBUSY : 0;
}
static void ebpfos_stack_running(void *opaque)
{
 struct ebpfos_stack_check check = *(struct ebpfos_stack_check *)opaque;
 struct ebpfos_running_stack *running = &check.running[smp_processor_id()];
 get_task_struct(current);
 running->task = current;
 running->error = ebpfos_stack_walk(current, &check);
}
static int ebpfos_stack_task(struct task_struct *task, void *opaque)
{
 struct ebpfos_stack_check *check = opaque;
 int cpu;
 if (task_curr(task)) {
  /* After disconnection and grace periods, a task with a clear stack
   * cannot re-enter this generation through the removed entry. A task
   * that woke after the CPU snapshot still needs its own reliable check. */
  for_each_online_cpu(cpu)
   if (check->running[cpu].task == task) return check->running[cpu].error;
  return -EBUSY;
 }
 return ebpfos_stack_walk(task, check);
}
/* A bare function pointer can outlive the caller's stack. Until an owner
 * holds a separate graph lease, address-taken BPF closures cannot be retired
 * by a stack scan. Synchronous callbacks are conservatively retained too. */
static bool ebpfos_program_addresses(struct bpf_prog *program)
{
 unsigned int i, j;
 if (!program) return false;
 for (j = 0; j < program->len; ++j)
  if (bpf_pseudo_func(&program->insnsi[j])) return true;
 for (i = 0; program->aux->func && i < program->aux->func_cnt; ++i) {
  struct bpf_prog *function = program->aux->func[i];
  if (!function) continue;
  for (j = 0; j < function->len; ++j)
   if (bpf_pseudo_func(&function->insnsi[j])) return true;
 }
 return false;
}
static int ebpfos_code_quiescent(bool (*contains)(void *, unsigned long), void *owner)
{
 struct ebpfos_stack_check check = { .contains = contains, .owner = owner };
 struct task_struct *group, *task;
 int error = 0, cpu;
 if (!IS_ENABLED(CONFIG_HAVE_RELIABLE_STACKTRACE) ||
     !IS_ENABLED(CONFIG_TASKS_RCU)) return -EOPNOTSUPP;
 /* Drain non-task interrupt readers as well, including interrupts from idle. */
 synchronize_rcu();
 synchronize_rcu_tasks();
 check.running = kcalloc(nr_cpu_ids, sizeof(*check.running), GFP_KERNEL);
 if (!check.running) return -ENOMEM;
 cpus_read_lock();
 /* Inspect running tasks on their own CPU, including interrupted frames.
  * This avoids indefinitely refusing a still-running grace-period worker. */
 on_each_cpu(ebpfos_stack_running, &check, 1);
 for_each_online_cpu(cpu)
  if (check.running[cpu].error == -EADDRINUSE || !error) error = check.running[cpu].error;
 rcu_read_lock();
 for_each_process_thread(group, task) {
  int verdict = task_call_func(task, ebpfos_stack_task, &check);
  if (verdict == -EADDRINUSE || !error) error = verdict;
 }
 rcu_read_unlock();
 for_each_online_cpu(cpu) put_task_struct(check.running[cpu].task);
 cpus_read_unlock();
 kfree(check.running);
 return error;
}
/* Only from a stop_machine callback running on every online CPU. Current
 * tasks are the stop workers in that callback, not the interrupted callers;
 * their displaced task stacks and idle stacks are stable until it returns.
 * The caller separately excludes NMI users and the transaction's own code.
 * This scan neither disconnects entries nor establishes an object inventory.
 */
static inline int ebpfos_code_stopped(bool (*contains)(void *, unsigned long), void *owner)
{
 struct ebpfos_stack_check check = { .contains = contains, .owner = owner };
 struct task_struct *group, *task;
 int error = 0, cpu;
 if (!IS_ENABLED(CONFIG_HAVE_RELIABLE_STACKTRACE)) return -EOPNOTSUPP;
 rcu_read_lock();
 for_each_process_thread(group, task) {
  int verdict;
  if (task_curr(task)) continue;
  verdict = ebpfos_stack_walk(task, &check);
  if (verdict == -EADDRINUSE || !error) error = verdict;
 }
 for_each_online_cpu(cpu) {
  int verdict = ebpfos_stack_walk(idle_task(cpu), &check);
  if (verdict == -EADDRINUSE || !error) error = verdict;
 }
 rcu_read_unlock();
 return error;
}
#endif
