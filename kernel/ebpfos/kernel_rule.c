// SPDX-License-Identifier: GPL-2.0-only
/* Rules run on resolution, never on the cached indirect-call path. */
#include <linux/bpf_kernel_rule.h>
#include <linux/bpf_operations.h>
#include <linux/btf.h>
#include <linux/cgroup.h>
#include <linux/ebpfos_operations.h>
#include <linux/ebpfos_rule_cache.h>
#include <linux/ebpfos_task_rule.h>
#include <linux/filter.h>
#include <linux/hash.h>
#include <linux/mutex.h>
#include <linux/nsproxy.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <net/net_namespace.h>

struct rule_generation {
 refcount_t refs;
 struct bpf_prog *program;
 u32 count;
 struct bpf_operations_set *versions[BPF_KERNEL_RULE_MAX_VERSIONS];
 struct ebpfos_task_view_request *tasks[BPF_KERNEL_RULE_MAX_VERSIONS];
 bool has_tasks;
};
struct kernel_rule_link {
 struct bpf_link link;
 struct list_head node;
 struct rule_generation *generation;
 bool attached;
};
struct rule_choice { struct rule_generation *generation; u32 selection; };
struct ebpfos_rule_decision {
 refcount_t refs;
 u64 epoch;
 u32 count;
 struct rule_choice choices[];
};
static DEFINE_MUTEX(rule_mutex);
static DEFINE_RWLOCK(rule_lock);
static u32 rule_count;
static LIST_HEAD(rule_links);
static atomic64_t rule_epoch = ATOMIC64_INIT(1);

/* Rules are pure, bounded scalar computations. In particular they cannot
 * change a selection through a mutable map without advancing the epoch. */
static const struct bpf_func_proto *rule_func_proto(enum bpf_func_id id,
 const struct bpf_prog *prog) { return NULL; }
static bool rule_access(int off, int size, enum bpf_access_type type,
 const struct bpf_prog *prog, struct bpf_insn_access_aux *info)
{
 return type == BPF_READ && off >= 0 && off < sizeof(struct bpf_kernel_rule_ctx) &&
  size <= sizeof(struct bpf_kernel_rule_ctx) - off && IS_ALIGNED(off, size);
}
const struct bpf_verifier_ops bpf_kernel_rule_verifier_ops = {
 .get_func_proto = rule_func_proto, .is_valid_access = rule_access,
};
const struct bpf_prog_ops bpf_kernel_rule_prog_ops = {};

static bool rule_program_allowed(const struct bpf_prog *program)
{
 /* External memory can observe policy state without a link
  * update. The first rule vocabulary is context scalars and the BPF stack.
  * The ordinary verifier has already proved their memory safety. */
 return program->type == BPF_PROG_TYPE_KERNEL_RULE && !program->aux->trusted_kernel &&
  !program->aux->used_map_cnt && !program->aux->used_btf_cnt;
}

static void generation_put(struct rule_generation *generation)
{
 u32 i;
 if (!generation || !refcount_dec_and_test(&generation->refs)) return;
 for (i = 0; i < generation->count; ++i) {
  bpf_operations_set_put(generation->versions[i]);ebpfos_rule_task_put(generation->tasks[i]);
 }
 bpf_prog_put(generation->program);kfree(generation);
}
u64 ebpfos_rule_epoch(void) { return atomic64_read(&rule_epoch); }
EXPORT_SYMBOL_GPL(ebpfos_rule_epoch);
void ebpfos_rule_context(struct bpf_kernel_rule_ctx *ctx, u64 object, u64 binding)
{
 memset(ctx, 0, sizeof(*ctx));
 ctx->object = object;ctx->binding = binding;
 /* Object identities are supplied by their owner. The hash is stable across
  * epochs and independent of unrelated rule changes. */
 ctx->sample_hash = hash_64(object, 32);
 ctx->epoch = ebpfos_rule_epoch();
 if (in_task()) {
  ctx->task = task_pid_nr(current);
  rcu_read_lock();
  ctx->process_subtree = task_tgid_nr(rcu_dereference(current->real_parent));
  ctx->cgroup = cgroup_id(task_dfl_cgroup(current));
  rcu_read_unlock();
  if (current->nsproxy && current->nsproxy->net_ns) ctx->netns = current->nsproxy->net_ns->ns.inum;
 }
}
EXPORT_SYMBOL_GPL(ebpfos_rule_context);

struct ebpfos_rule_decision *ebpfos_rule_resolve(const struct bpf_kernel_rule_ctx *context, gfp_t gfp)
{
 struct kernel_rule_link *link;
 struct ebpfos_rule_decision *decision;
 struct bpf_kernel_rule_ctx ctx = *context;
 u32 count = 0;
 unsigned long flags;
 /* Copy leases under the publication lock; run verified programs after
  * dropping it. GFP_ATOMIC supports an interrupt with no originating task. */
 for (;;) {
  count = READ_ONCE(rule_count);
  decision = kzalloc(struct_size(decision, choices, count), gfp);
  if (!decision) return ERR_PTR(-ENOMEM);
  read_lock_irqsave(&rule_lock, flags);
  if (rule_count > count) {
   read_unlock_irqrestore(&rule_lock, flags);kfree(decision);continue;
  }
  refcount_set(&decision->refs, 1);decision->epoch = ctx.epoch = ebpfos_rule_epoch();
  list_for_each_entry(link, &rule_links, node) {
   struct rule_generation *generation = link->generation;
   struct rule_choice *choice = &decision->choices[decision->count++];
   refcount_inc(&generation->refs);choice->generation = generation;
  }
  read_unlock_irqrestore(&rule_lock, flags);break;
 }
 for (count = 0; count < decision->count; ++count) {
  struct rule_choice *choice = &decision->choices[count];
  choice->selection = bpf_prog_run_pin_on_cpu(choice->generation->program, &ctx);
 }
 return decision;
}
EXPORT_SYMBOL_GPL(ebpfos_rule_resolve);
struct ebpfos_rule_decision *ebpfos_rule_decision_get(struct ebpfos_rule_decision *decision)
{ if (decision) refcount_inc(&decision->refs);return decision; }
EXPORT_SYMBOL_GPL(ebpfos_rule_decision_get);
void ebpfos_rule_decision_put(struct ebpfos_rule_decision *decision)
{
 u32 i;
 if (!decision || !refcount_dec_and_test(&decision->refs)) return;
 for (i = 0; i < decision->count; ++i) generation_put(decision->choices[i].generation);
 kfree(decision);
}
EXPORT_SYMBOL_GPL(ebpfos_rule_decision_put);
struct ebpfos_operations *ebpfos_rule_operations(struct ebpfos_rule_decision *decision,
 const void *original, u32 type, size_t size)
{
 struct ebpfos_operations *operations;
 u32 i;
 for (i = 0; decision && i < decision->count; ++i) {
  struct rule_choice *choice = &decision->choices[i];
  u32 selected = choice->selection;
  if (!selected || selected > choice->generation->count) continue;
  operations = bpf_operations_find(choice->generation->versions[selected - 1], original, type, size);
  if (operations) return operations;
 }
 return NULL;
}
EXPORT_SYMBOL_GPL(ebpfos_rule_operations);

bool ebpfos_rule_task_choices(struct ebpfos_rule_decision *decision)
{
 u32 i;
 for (i = 0; decision && i < decision->count; ++i)
  if (decision->choices[i].generation->has_tasks) return true;
 return false;
}
void ebpfos_rule_task_table(struct ebpfos_rule_decision *decision, void *table)
{
 u32 i;
 for (i = 0; decision && i < decision->count; ++i) {
  struct rule_choice *choice = &decision->choices[i];
  u32 selected = choice->selection;
  if (selected && selected <= choice->generation->count)
   ebpfos_rule_task_copy(choice->generation->tasks[selected - 1], table);
 }
}

void ebpfos_rule_cache_init(struct ebpfos_rule_cache *cache, void **slot,
 const void *original, const void *resolver, u32 type, u32 size,
 const struct bpf_kernel_rule_ctx *context)
{
 memset(cache, 0, sizeof(*cache));
 cache->slot = slot;cache->original = original;cache->resolver = resolver;
 cache->type = type;cache->size = size;cache->context = *context;
 cache->epoch = ebpfos_rule_epoch();
 WRITE_ONCE(*slot, (void *)resolver);
}
EXPORT_SYMBOL_GPL(ebpfos_rule_cache_init);
int ebpfos_rule_cache_resolve(struct ebpfos_rule_cache *cache,
 struct ebpfos_rule_decision *inherited, gfp_t gfp)
{
 struct ebpfos_rule_decision *decision;
 struct ebpfos_operations *operations;
 decision = inherited ? ebpfos_rule_decision_get(inherited) : ebpfos_rule_resolve(&cache->context, gfp);
 if (IS_ERR(decision)) return PTR_ERR(decision);
 operations = ebpfos_rule_operations(decision, cache->original, cache->type, cache->size);
 WRITE_ONCE(*cache->slot, (void *)(operations ? ebpfos_operations_table(operations) : cache->original));
 ebpfos_operations_put(cache->operations);ebpfos_rule_decision_put(cache->decision);
 cache->decision = decision;cache->operations = operations;cache->epoch = decision->epoch;
 return 0;
}
EXPORT_SYMBOL_GPL(ebpfos_rule_cache_resolve);
void ebpfos_rule_cache_quiescent(struct ebpfos_rule_cache *cache)
{
 if (cache->epoch == ebpfos_rule_epoch()) return;
 WRITE_ONCE(*cache->slot, (void *)cache->resolver);
 ebpfos_operations_put(cache->operations);cache->operations = NULL;
 ebpfos_rule_decision_put(cache->decision);cache->decision = NULL;
 cache->epoch = ebpfos_rule_epoch();
}
EXPORT_SYMBOL_GPL(ebpfos_rule_cache_quiescent);
void ebpfos_rule_cache_destroy(struct ebpfos_rule_cache *cache)
{
 ebpfos_operations_put(cache->operations);ebpfos_rule_decision_put(cache->decision);
 cache->operations = NULL;cache->decision = NULL;
}
EXPORT_SYMBOL_GPL(ebpfos_rule_cache_destroy);

static int rule_detach(struct bpf_link *base)
{
 struct kernel_rule_link *link = container_of(base, struct kernel_rule_link, link);
 unsigned long flags;
 bool detached = false;
 mutex_lock(&rule_mutex);
 write_lock_irqsave(&rule_lock, flags);
 if (link->attached) {list_del(&link->node);--rule_count;link->attached = false;detached = true;atomic64_inc(&rule_epoch);}
 write_unlock_irqrestore(&rule_lock, flags);
 mutex_unlock(&rule_mutex);
 if (detached) {
  if (link->generation->has_tasks) ebpfos_task_rule_unclaim(false);
  ebpfos_task_rules_changed();
 }
 return 0;
}
static void rule_release(struct bpf_link *base) { rule_detach(base); }
static void rule_dealloc(struct bpf_link *base)
{
 struct kernel_rule_link *link = container_of(base, struct kernel_rule_link, link);
 generation_put(link->generation);kfree(link);
}
static int rule_update(struct bpf_link *base, struct bpf_prog *program, struct bpf_prog *old)
{
 struct kernel_rule_link *link = container_of(base, struct kernel_rule_link, link);
 struct rule_generation *next, *before;
 u32 i;
 unsigned long flags;
 int error = 0;
 if (!rule_program_allowed(program)) return -EINVAL;
 next = kzalloc(sizeof(*next), GFP_KERNEL);
 if (!next) return -ENOMEM;
 refcount_set(&next->refs, 1);
 mutex_lock(&rule_mutex);
 before = link->generation;
 if (!link->attached) {error = -ENOLINK;goto fail;}
 if (old && old != before->program) {error = -EPERM;goto fail;}
 next->program = program;next->count = before->count;
 next->has_tasks = before->has_tasks;
 for (i = 0; i < next->count; ++i) {
  next->versions[i] = bpf_operations_set_get(before->versions[i]);
  next->tasks[i] = ebpfos_rule_task_get(before->tasks[i]);
 }
 write_lock_irqsave(&rule_lock, flags);
 link->generation = next;
 /* bpf_link owns its own program reference independently of decisions. */
 bpf_prog_inc(program);link->link.prog = program;atomic64_inc(&rule_epoch);
 write_unlock_irqrestore(&rule_lock, flags);
 mutex_unlock(&rule_mutex);
 bpf_prog_put(before->program);generation_put(before);ebpfos_task_rules_changed();return 0;
fail:
 mutex_unlock(&rule_mutex);kfree(next);return error;
}
static int rule_info(const struct bpf_link *base, struct bpf_link_info *info)
{
 const struct kernel_rule_link *link = container_of(base, struct kernel_rule_link, link);
 mutex_lock(&rule_mutex);
 info->kernel_rule.epoch = ebpfos_rule_epoch();
 info->kernel_rule.versions = link->generation->count;
 info->kernel_rule.detached = !link->attached;
 mutex_unlock(&rule_mutex);return 0;
}
static void rule_fdinfo(const struct bpf_link *base, struct seq_file *seq)
{
 struct bpf_link_info info = {};
 rule_info(base, &info);
 seq_printf(seq, "epoch:\t%llu\nversions:\t%u\ndetached:\t%u\n",
  info.kernel_rule.epoch, info.kernel_rule.versions, info.kernel_rule.detached);
}
static const struct bpf_link_ops kernel_rule_link_ops = {
 .release = rule_release, .dealloc = rule_dealloc, .detach = rule_detach,
 .update_prog = rule_update, .fill_link_info = rule_info, .show_fdinfo = rule_fdinfo,
};
static bool rule_targets_overlap(const struct rule_generation *generation)
{
 struct kernel_rule_link *owner;
 u32 i, j;
 lockdep_assert_held(&rule_mutex);
 list_for_each_entry(owner, &rule_links, node)
  for (i = 0; i < generation->count; ++i)
   for (j = 0; j < owner->generation->count; ++j)
    if (bpf_operations_overlap(generation->versions[i], owner->generation->versions[j]) ||
        ebpfos_rule_task_overlap(generation->tasks[i], owner->generation->tasks[j])) return true;
 return false;
}
int bpf_kernel_rule_link_create(const union bpf_attr *attr)
{
 struct bpf_kernel_rule_version *versions;
 struct rule_generation *generation;
 struct kernel_rule_link *link;
 struct bpf_link_primer primer;
 struct bpf_prog *program;
 u32 i, count = attr->link_create.kernel_rule.count;
 unsigned long flags;
 int error;
 if (!capable(CAP_SYS_ADMIN)) return -EPERM;
 if (attr->link_create.target_fd || attr->link_create.flags || !count ||
     count > BPF_KERNEL_RULE_MAX_VERSIONS || attr->link_create.kernel_rule.reserved) return -EINVAL;
 versions = memdup_array_user(u64_to_user_ptr(attr->link_create.kernel_rule.versions),
                             count, sizeof(*versions));
 if (IS_ERR(versions)) return PTR_ERR(versions);
 program = bpf_prog_get_type(attr->link_create.prog_fd, BPF_PROG_TYPE_KERNEL_RULE);
 if (IS_ERR(program)) {error = PTR_ERR(program);kfree(versions);return error;}
 if (!rule_program_allowed(program)) {bpf_prog_put(program);kfree(versions);return -EINVAL;}
 generation = kzalloc(sizeof(*generation), GFP_KERNEL);
 if (!generation) {bpf_prog_put(program);kfree(versions);return -ENOMEM;}
 refcount_set(&generation->refs, 1);generation->program = program;generation->count = count;
 for (i = 0; i < count; ++i) {
  u32 *fds;
  if (versions[i].reserved || versions[i].reserved2) {
   error = -EINVAL;goto fail;
  }
  if (versions[i].function_count) {
   u32 *ids, *programs;
   ids = memdup_array_user(u64_to_user_ptr(versions[i].function_btf_ids),
                          versions[i].function_count, sizeof(u32));
   if (IS_ERR(ids)) {error = PTR_ERR(ids);goto fail;}
   programs = memdup_array_user(u64_to_user_ptr(versions[i].function_prog_fds),
                               versions[i].function_count, sizeof(u32));
   if (IS_ERR(programs)) {error = PTR_ERR(programs);kfree(ids);goto fail;}
   generation->tasks[i] = ebpfos_rule_task_prepare(ids, programs, versions[i].function_count);
   kfree(ids);kfree(programs);
   if (IS_ERR(generation->tasks[i])) {
    error = PTR_ERR(generation->tasks[i]);generation->tasks[i] = NULL;goto fail;
   }
   generation->has_tasks = true;
  }
  if (!versions[i].operations_count) continue;
  fds = memdup_user(u64_to_user_ptr(versions[i].operations_fds), versions[i].operations_count * sizeof(u32));
  if (IS_ERR(fds)) {error = PTR_ERR(fds);goto fail;}
  generation->versions[i] = bpf_operations_prepare(fds, versions[i].operations_count);kfree(fds);
  if (IS_ERR(generation->versions[i])) {
   error = PTR_ERR(generation->versions[i]);generation->versions[i] = NULL;goto fail;
  }
 }
 kfree(versions);versions = NULL;
 link = kzalloc(sizeof(*link), GFP_KERNEL);
 if (!link) {error = -ENOMEM;goto fail;}
 link->generation = generation;
 bpf_prog_inc(program);
 bpf_link_init(&link->link, BPF_LINK_TYPE_KERNEL_RULE, &kernel_rule_link_ops, program, BPF_KERNEL_RULE);
 mutex_lock(&rule_mutex);
 if (rule_targets_overlap(generation)) error = -EBUSY;
 else {
  error = generation->has_tasks ? ebpfos_task_rule_claim(false) : 0;
  if (!error) {
   error = bpf_link_prime(&link->link, &primer);
   if (error && generation->has_tasks) ebpfos_task_rule_unclaim(false);
  }
 }
 if (error) {
  mutex_unlock(&rule_mutex);bpf_prog_put(program);kfree(link);goto fail;
 }
 write_lock_irqsave(&rule_lock, flags);
 list_add_tail(&link->node, &rule_links);++rule_count;link->attached = true;atomic64_inc(&rule_epoch);
 write_unlock_irqrestore(&rule_lock, flags);
 mutex_unlock(&rule_mutex);
 ebpfos_task_rules_changed();
 return bpf_link_settle(&primer);
fail:
 generation_put(generation);kfree(versions);return error;
}
