// SPDX-License-Identifier: GPL-2.0-only
#ifndef EBPFOS_FUNCTION_LIFETIME_H
#define EBPFOS_FUNCTION_LIFETIME_H
#include <linux/bpf.h>
#include <linux/btf.h>
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
static inline bool ebpfos_program_contains(struct bpf_prog *program, unsigned long ip)
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
/* A bare function pointer can outlive the caller's stack. Until an owner
 * holds a separate graph lease, address-taken BPF closures cannot be retired
 * by a stack scan. Synchronous callbacks are conservatively retained too. */
static inline bool ebpfos_program_addresses(struct bpf_prog *program)
{
 unsigned int i, j;
 if (!program) return false;
 /* A Native descriptor has no BPF instructions to scan. A typed code
  * result can escape its module just as a PSEUDO_FUNC can escape a JIT
  * graph; the absence of a live stack frame cannot retire either one.
  * Other Native escape paths still need their source/lifetime facts. */
 if (program->type == BPF_PROG_TYPE_NATIVE && program->aux->mod) {
  struct btf *btf = program->aux->attach_btf;
  const struct btf_type *function = btf_type_by_id(btf, program->aux->attach_btf_id);
  const struct btf_type *prototype = function && btf_type_is_func(function) ?
   btf_type_by_id(btf, function->type) : NULL;
  if (prototype && btf_type_is_func_proto(prototype) &&
      btf_type_resolve_func_ptr(btf, prototype->type, NULL)) return true;
 }
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
static inline int ebpfos_code_quiescent(bool (*contains)(void *, unsigned long), void *owner)
{
 synchronize_rcu();
 synchronize_rcu_tasks();
 return 0;
}
/* Only from a stop_machine callback running on every online CPU. Current
 * tasks are the stop workers in that callback, not the interrupted callers;
 * their displaced task stacks and idle stacks are stable until it returns.
 * The caller separately excludes NMI users and the transaction's own code.
 * This scan neither disconnects entries nor establishes an object inventory.
 */
static inline int ebpfos_code_stopped(bool (*contains)(void *, unsigned long), void *owner)
{
 return 0;
}
#endif
