// SPDX-License-Identifier: GPL-2.0-only
/* Read-only relations of the operation's context. These run only while a
 * rule resolves; queued work inherits its existing decision instead. */
#include <linux/bpf_kernel_rule.h>
#include <linux/bpf_kernel_rule_context.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/cgroup.h>
#include <linux/init.h>
#include <linux/pid_namespace.h>
#include <linux/sched/signal.h>

__bpf_kfunc_start_defs();
__bpf_kfunc u64 bpf_kernel_rule_task_under(const struct bpf_kernel_rule_ctx *ctx, u64 root)
{
 struct task_struct *task, *parent;
 u64 found = 0;
 if (!ctx->task) return 0;
 rcu_read_lock();read_lock(&tasklist_lock);
 task = find_task_by_pid_ns((pid_t)ctx->task, &init_pid_ns);
 while (task) {
  if ((u64)task_tgid_nr(task) == root) {found = 1;break;}
  parent = rcu_dereference(task->real_parent);
  if (parent == task) break;
  task = parent;
 }
 read_unlock(&tasklist_lock);rcu_read_unlock();return found;
}
__bpf_kfunc u64 bpf_kernel_rule_cgroup_under(const struct bpf_kernel_rule_ctx *ctx, u64 root)
{
#ifdef CONFIG_CGROUPS
 struct cgroup *group = __cgroup_get_from_id(ctx->cgroup), *ancestor;
 u64 found;
 if (IS_ERR(group)) return 0;
 ancestor = __cgroup_get_from_id(root);
 if (IS_ERR(ancestor)) {cgroup_put(group);return 0;}
 found = cgroup_is_descendant(group, ancestor);
 cgroup_put(ancestor);cgroup_put(group);return found;
#else
 return 0;
#endif
}
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(rule_context_ids)
BTF_ID_FLAGS(func, bpf_kernel_rule_task_under)
BTF_ID_FLAGS(func, bpf_kernel_rule_cgroup_under)
BTF_KFUNCS_END(rule_context_ids)

bool bpf_kernel_rule_context_kfunc(u32 id, s16 offset)
{
 /* Offset zero denotes vmlinux. A module's unrelated BTF ID cannot stand
  * in for a context query even when its numeric ID happens to match. */
 return !offset && btf_id_set8_contains(&rule_context_ids, id);
}
static const struct btf_kfunc_id_set rule_context_set = {.set=&rule_context_ids};
static int __init rule_context_register(void)
{ return register_btf_kfunc_id_set(BPF_PROG_TYPE_KERNEL_RULE, &rule_context_set); }
late_initcall(rule_context_register);
