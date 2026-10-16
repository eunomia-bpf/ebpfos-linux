// SPDX-License-Identifier: GPL-2.0-only
/* Typed native entry linking through Linux's existing batch direct ftrace API.
 * Only cold preparation/publication runs here. Ordinary callers execute the
 * installed direct jump and the verified JIT body, with no invocation gate.
 */
#include <linux/anon_inodes.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/filter.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include "syscall_kfuncs.h"
struct ebpfos_function_entry { u32 native_function, compiled_function; };
/* Each symbol may come from a separately admitted object. Program references
 * and all symbol/ABI/context checks belong to cold linking, never invocation.
 */
struct ebpfos_function_link {
 u32 native_function, compiled_function, first, second;
};
struct entry_set {
 struct list_head retained;
 struct bpf_prog **programs;
 struct ftrace_ops operations;
 struct ftrace_hash *hash[2];
 unsigned long *locations;
 unsigned int count, active;
 bool published;
};
static DEFINE_MUTEX(entry_lock);
/* A stopped CPU does not prove every suspended old frame has returned. Keep
 * actual published graphs alive until their owners can prove retirement. */
static LIST_HEAD(entry_retained);
static const struct file_operations entry_operations;
/* Bare native ABI calls have no bpf_run_ctx. These standard helpers depend
 * only on explicit operands or the native CPU/task, not on such a frame.
 * Keep this cold eligibility check outside the call path. */
static bool entry_context(struct bpf_prog *parent)
{
 const enum bpf_func_id helpers[] = { BPF_FUNC_per_cpu_ptr, BPF_FUNC_this_cpu_ptr,
  BPF_FUNC_get_current_task_btf, BPF_FUNC_loop };
 unsigned int i, j, k;
 if (!parent->aux->func || !parent->aux->func_cnt) return false;
 for (i = 0; i < parent->aux->func_cnt; ++i) {
  struct bpf_prog *function = parent->aux->func[i];
  if (!function || !function->jited || function->aux->priv_stack_ptr) return false;
  for (j = 0; j < function->len; ++j) {
   const struct bpf_insn *insn = &function->insnsi[j];
   unsigned long target;
   if (insn->code != (BPF_JMP | BPF_CALL) || insn->src_reg) continue;
   target = (unsigned long)__bpf_call_base + insn->imm;
   /* Stock may_goto fixups use initialized slots in this function's frame,
    * not bpf_run_ctx. Keep their original timeout and escape semantics. */
   if (target == (unsigned long)arch_bpf_timed_may_goto) continue;
   for (k = 0; k < ARRAY_SIZE(helpers); ++k) {
    const struct bpf_func_proto *prototype = bpf_base_func_proto(helpers[k], parent);
    if (prototype && target == (unsigned long)prototype->func) break;
   }
   if (k == ARRAY_SIZE(helpers)) return false;
  }
 }
 return true;
}

#include "function_contract.h"

static int entry_publication_point(void *unused) { return 0; }
static int entry_apply(struct entry_set *set, unsigned int from, unsigned int to)
{
 if (!from) return update_ftrace_direct_add(&set->operations, set->hash[to - 1]);
 if (!to) return update_ftrace_direct_del(&set->operations, set->hash[from - 1]);
 return update_ftrace_direct_mod(&set->operations, set->hash[to - 1], true);
}
static int entry_switch(struct entry_set *set, unsigned int from, unsigned int to)
{
 int error, recovery;
 if (from > 2 || to > 2 || from != set->active) return -ESTALE;
 if (from == to) return 0;
 /* The stock x86 text-poke batch performs its own CPU synchronization and
  * breakpoint-safe instruction update. Never call it with CPUs stopped: its
  * cross-CPU synchronizations must run. One following stop-machine point
  * establishes that the entire installed set is visible before completion.
  * Unchanged layouts and retained old code permit in-flight old frames.
  */
 error = entry_apply(set, from, to);
 if (error) return error;
 set->active = to;set->published |= to != 0;
 error = stop_machine(entry_publication_point, NULL, NULL);
 if (error) {
  recovery = entry_apply(set, to, from);
  if (!recovery) set->active = from;
 }
 return error;
}
static void entry_free(struct entry_set *set)
{
 unsigned int i;
 if (set->programs)
  for (i = 0; i < set->count * 2; ++i)
   if (set->programs[i]) bpf_prog_put(set->programs[i]);
 kvfree(set->programs);
 free_ftrace_hash(set->hash[0]);free_ftrace_hash(set->hash[1]);kvfree(set->locations);kfree(set);
}
static int entry_release(struct inode *inode, struct file *file)
{
 struct entry_set *set = file->private_data;
 int error;
 mutex_lock(&entry_lock);error = entry_switch(set, set->active, 0);
 if (set->published || error) list_add_tail(&set->retained, &entry_retained);
 mutex_unlock(&entry_lock);
 if (!set->published && !error) entry_free(set);
 return error;
}
static const struct file_operations entry_operations = { .release = entry_release, .llseek = noop_llseek };
static int entry_open(const struct ebpfos_function_link *entries,
 unsigned int count)
{
 struct entry_set *set;
 struct btf *btf = bpf_get_btf_vmlinux();
 unsigned int i,j;
 int error = -EINVAL;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (!IS_ENABLED(CONFIG_DYNAMIC_FTRACE_WITH_JMP) ||
     !IS_ENABLED(CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS)) return -EOPNOTSUPP;
 if (!count || IS_ERR_OR_NULL(btf)) return -EINVAL;
 set = kzalloc(sizeof(*set), GFP_KERNEL);
 if (!set) return -ENOMEM;
 set->count = count;
 set->programs = kvcalloc(count, 2 * sizeof(*set->programs), GFP_KERNEL);
 if (!set->programs) {error = -ENOMEM;goto fail;}
 set->locations = kvcalloc(set->count, sizeof(*set->locations), GFP_KERNEL);
 if (!set->locations) {error = -ENOMEM;goto fail;}
 set->hash[0] = alloc_ftrace_hash(FTRACE_HASH_DEFAULT_BITS);
 set->hash[1] = alloc_ftrace_hash(FTRACE_HASH_DEFAULT_BITS);
 if (!set->hash[0] || !set->hash[1]) { error = -ENOMEM;goto fail; }
 for (i = 0; i < set->count; ++i) {
  const struct ebpfos_function_link *entry = &entries[i];
  const struct btf_type *function = btf_type_by_id(btf, entry->native_function);
  unsigned long address,ip,target;
  if (!function || !btf_type_is_func(function)) goto fail;
  address = kallsyms_lookup_name(btf_name_by_offset(btf, function->name_off));
  if (!address || !core_kernel_text(address) || !(ip = ftrace_location(address))) {error = -ENOENT;goto fail;}
  for (j = 0; j < i; ++j) if (set->locations[j] == ip) goto fail;
  set->locations[i] = ip;
  for (j = 0; j < 2; ++j) {
   struct bpf_prog *program = bpf_prog_get_type_dev(j ? entry->second : entry->first,
      BPF_PROG_TYPE_TRACING, false);
   if (IS_ERR(program)) {error = PTR_ERR(program);goto fail;}
   set->programs[i * 2 + j] = program;
   if (program->sleepable || program->expected_attach_type != BPF_TRACE_REPLACE ||
       !program->aux->ebpfos_component || !entry_context(program)) {error = -EOPNOTSUPP;goto fail;}
   if (!cell_callable(btf, function, program, entry->compiled_function, &target)) {error = -EPROTOTYPE;goto fail;}
   if (target & 1) goto fail;
   if (!add_ftrace_hash_entry_direct(set->hash[j], ip, ftrace_jmp_set(target))) {error = -ENOMEM;goto fail;}
  }
 }
 error = anon_inode_getfd("ebpfos-function-entries", &entry_operations, set, O_CLOEXEC | O_RDWR);
 if (error >= 0) return error;
fail:
 entry_free(set);return error;
}
__bpf_kfunc_start_defs();
__bpf_kfunc int bpf_ebpfos_function_entries_open_many(
 const struct ebpfos_function_link *entries, u32 entries__sz)
{
 struct ebpfos_function_link *snapshot;
 int error;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (!entries__sz || entries__sz % sizeof(*entries)) return -EINVAL;
 snapshot = kmemdup(entries, entries__sz, GFP_KERNEL);
 if (!snapshot) return -ENOMEM;
 error = entry_open(snapshot, entries__sz / sizeof(*entries));
 kfree(snapshot);return error;
}
__bpf_kfunc int bpf_ebpfos_function_entries_open(u32 first, u32 second,
 const struct ebpfos_function_entry *entries, u32 entries__sz)
{
 struct ebpfos_function_entry *snapshot;
 struct ebpfos_function_link *links;
 unsigned int i, count;
 int error;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (!entries__sz || entries__sz % sizeof(*entries)) return -EINVAL;
 count = entries__sz / sizeof(*entries);
 snapshot = kmemdup(entries, entries__sz, GFP_KERNEL);
 if (!snapshot) return -ENOMEM;
 links = kvmalloc_array(count, sizeof(*links), GFP_KERNEL);
 if (!links) {kfree(snapshot);return -ENOMEM;}
 for (i = 0; i < count; ++i)
  links[i] = (struct ebpfos_function_link){snapshot[i].native_function,
    snapshot[i].compiled_function, first, second};
 error = entry_open(links, count);
 kvfree(links);kfree(snapshot);return error;
}
__bpf_kfunc int bpf_ebpfos_function_entries_switch(u32 fd, u32 from, u32 to)
{
 struct fd file = fdget(fd);int error;
 if (fd_empty(file)) return -EBADF;
 if (fd_file(file)->f_op != &entry_operations) {fdput(file);return -EINVAL;}
 mutex_lock(&entry_lock);error = entry_switch(fd_file(file)->private_data, from, to);
 mutex_unlock(&entry_lock);fdput(file);return error;
}
__bpf_kfunc int bpf_ebpfos_function_entries_state(u32 fd)
{
 struct fd file = fdget(fd);int active;
 if (fd_empty(file)) return -EBADF;
 if (fd_file(file)->f_op != &entry_operations) {fdput(file);return -EINVAL;}
 mutex_lock(&entry_lock);active = ((struct entry_set *)fd_file(file)->private_data)->active;
 mutex_unlock(&entry_lock);fdput(file);return active;
}
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(entry_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_open, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_open_many, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_switch, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_ebpfos_function_entries_state, KF_SLEEPABLE)
BTF_KFUNCS_END(entry_ids)
static const struct btf_kfunc_id_set entry_kfuncs;
static int entry_filter(const struct bpf_prog *prog, u32 id)
{const struct btf_kfunc_id_set *sets[] = { &entry_kfuncs };return ebpfos_syscall_kfunc_filter(prog,id,sets,ARRAY_SIZE(sets));}
static const struct btf_kfunc_id_set entry_kfuncs = { .set = &entry_ids, .filter = entry_filter };
static int __init entry_init(void)
{return register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC,&entry_kfuncs);}
late_initcall(entry_init);
