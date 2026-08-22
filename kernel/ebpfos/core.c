// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/ebpfos.h>
#include <linux/err.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

struct ebpfos_slot {
	struct bpf_prog *prog;
	u64 abi_hash;
	u64 flags;
};

struct ebpfos_state_slot {
	struct bpf_map *map;
	u64 schema_hash;
	u64 flags;
};

struct ebpfos_graph {
	u64 generation;
	u64 hook_mask;
	u64 state_mask;
	struct ebpfos_slot slots[EBPFOS_HOOK_MAX];
	struct ebpfos_state_slot state[EBPFOS_MAX_STATE_SLOTS];
};

struct ebpfos_file {
	struct ebpfos_graph *pending;
	/* Serializes the one file-replacement transaction owned by this FD. */
	struct mutex file_txn_lock;
	void *file_txn;
	/* Independent generated KOperation proof/native transaction. */
	struct mutex koperation_txn_lock;
	void *koperation_txn;
};

static DEFINE_MUTEX(ebpfos_graph_lock);
static struct ebpfos_graph __rcu *ebpfos_active_graph;

static bool ebpfos_graph_has_legacy_binding(const struct ebpfos_graph *graph)
{
	return graph && (graph->hook_mask || graph->state_mask);
}

static int ebpfos_legacy_mutation_check(void)
{
	int error;

	ebpfos_admission_gate_lock();
	error = ebpfos_legacy_mutation_check_locked();
	ebpfos_admission_gate_unlock();
	return error;
}

static const u64 ebpfos_hook_abi[EBPFOS_HOOK_MAX] = {
	[EBPFOS_HOOK_SYSCALL_ENTER] = EBPFOS_ABI_SYSCALL_ENTER,
	[EBPFOS_HOOK_SYSCALL_EXIT] = EBPFOS_ABI_SYSCALL_EXIT,
	[EBPFOS_HOOK_VFS_LOOKUP] = EBPFOS_ABI_VFS_LOOKUP,
	[EBPFOS_HOOK_VFS_READDIR] = EBPFOS_ABI_VFS_READDIR,
	[EBPFOS_HOOK_SCHED_SELECT] = EBPFOS_ABI_SCHED_SELECT,
	[EBPFOS_HOOK_SCHED_ENQUEUE] = EBPFOS_ABI_SCHED_ENQUEUE,
	[EBPFOS_HOOK_MM_RECLAIM] = EBPFOS_ABI_MM_RECLAIM,
	[EBPFOS_HOOK_BLOCK_SUBMIT] = EBPFOS_ABI_BLOCK_SUBMIT,
	[EBPFOS_HOOK_NET_RX] = EBPFOS_ABI_NET_RX,
	[EBPFOS_HOOK_NET_TX] = EBPFOS_ABI_NET_TX,
	[EBPFOS_HOOK_SECURITY] = EBPFOS_ABI_SECURITY,
	[EBPFOS_HOOK_DRIVER_PROBE] = EBPFOS_ABI_DRIVER_PROBE,
	[EBPFOS_HOOK_DRIVER_LIFECYCLE] = EBPFOS_ABI_DRIVER_LIFECYCLE,
};

static void ebpfos_graph_put(struct ebpfos_graph *graph)
{
	unsigned int i;

	if (!graph)
		return;

	for (i = 0; i < EBPFOS_HOOK_MAX; i++) {
		if (graph->slots[i].prog)
			bpf_prog_put(graph->slots[i].prog);
	}
	for (i = 0; i < EBPFOS_MAX_STATE_SLOTS; i++) {
		if (graph->state[i].map)
			bpf_map_put(graph->state[i].map);
	}
	kfree(graph);
}

static struct ebpfos_graph *ebpfos_graph_clone_locked(void)
{
	struct ebpfos_graph *old;
	struct ebpfos_graph *new;
	unsigned int i;

	lockdep_assert_held(&ebpfos_graph_lock);
	old = rcu_dereference_protected(ebpfos_active_graph,
					lockdep_is_held(&ebpfos_graph_lock));
	new = kzalloc_obj(*new, GFP_KERNEL);
	if (!new)
		return NULL;
	if (!old)
		return new;

	new->generation = old->generation;
	new->hook_mask = old->hook_mask;
	new->state_mask = old->state_mask;
	for (i = 0; i < EBPFOS_HOOK_MAX; i++) {
		new->slots[i] = old->slots[i];
		if (new->slots[i].prog)
			bpf_prog_inc(new->slots[i].prog);
	}
	for (i = 0; i < EBPFOS_MAX_STATE_SLOTS; i++) {
		new->state[i] = old->state[i];
		if (new->state[i].map)
			bpf_map_inc(new->state[i].map);
	}
	return new;
}

u32 ebpfos_run_hook(enum ebpfos_hook_id hook, const u64 *args, u32 nr_args)
{
	struct ebpfos_graph *graph;
	struct bpf_prog *prog;
	u64 ctx[3 + EBPFOS_MAX_ARGS] = { 0 };
	u32 result = EBPFOS_ACTION(EBPFOS_VERDICT_CONTINUE, 0);
	u32 i;

	/* Activation proves the legacy graph empty; typed fallbacks stay neutral. */
	if (ebpfos_policy_enforcing()) {
		bool legacy;

		rcu_read_lock();
		graph = rcu_dereference(ebpfos_active_graph);
		legacy = ebpfos_graph_has_legacy_binding(graph);
		rcu_read_unlock();
		if (WARN_ON_ONCE(legacy))
			return EBPFOS_ACTION(EBPFOS_VERDICT_DENY, EPERM);
		return result;
	}
	if ((unsigned int)hook >= EBPFOS_HOOK_MAX)
		return result;
	if (nr_args > EBPFOS_MAX_ARGS)
		nr_args = EBPFOS_MAX_ARGS;

	rcu_read_lock();
	graph = rcu_dereference(ebpfos_active_graph);
	if (!graph || !(graph->hook_mask & BIT_ULL(hook)))
		goto out;
	prog = graph->slots[hook].prog;
	if (!prog)
		goto out;

	ctx[0] = hook;
	ctx[1] = graph->generation;
	ctx[2] = nr_args;
	for (i = 0; i < nr_args; i++)
		ctx[3 + i] = args[i];
	result = bpf_prog_run_pin_on_cpu(prog, ctx);
out:
	rcu_read_unlock();
	return result;
}
EXPORT_SYMBOL_GPL(ebpfos_run_hook);

bool ebpfos_hook_enabled(enum ebpfos_hook_id hook)
{
	struct ebpfos_graph *graph;
	bool enabled = false;

	if (ebpfos_policy_enforcing() ||
	    (unsigned int)hook >= EBPFOS_HOOK_MAX)
		return false;

	rcu_read_lock();
	graph = rcu_dereference(ebpfos_active_graph);
	if (graph)
		enabled = !!(graph->hook_mask & BIT_ULL(hook));
	rcu_read_unlock();
	return enabled;
}
EXPORT_SYMBOL_GPL(ebpfos_hook_enabled);

static int ebpfos_open(struct inode *inode, struct file *file)
{
	struct ebpfos_file *state;

	state = kzalloc_obj(*state, GFP_KERNEL);
	if (!state)
		return -ENOMEM;
	mutex_init(&state->file_txn_lock);
	mutex_init(&state->koperation_txn_lock);
	file->private_data = state;
	return 0;
}

static int ebpfos_release(struct inode *inode, struct file *file)
{
	struct ebpfos_file *state = file->private_data;

	if (state) {
		ebpfos_file_replace_release(&state->file_txn);
		ebpfos_koperation_release(&state->koperation_txn);
		ebpfos_graph_put(state->pending);
		mutex_destroy(&state->koperation_txn_lock);
		mutex_destroy(&state->file_txn_lock);
		kfree(state);
	}
	return 0;
}

static long ebpfos_ioctl_version(void __user *argp)
{
	struct ebpfos_ioc_version version = {
		.uapi_version = EBPFOS_UAPI_VERSION,
		.hook_count = EBPFOS_HOOK_MAX,
	};

	return copy_to_user(argp, &version, sizeof(version)) ? -EFAULT : 0;
}

static long ebpfos_ioctl_begin(struct ebpfos_file *state)
{
	struct ebpfos_graph *pending;
	int error;

	if (state->pending)
		return -EBUSY;
	error = ebpfos_legacy_mutation_check();
	if (error)
		return error;
	mutex_lock(&ebpfos_graph_lock);
	pending = ebpfos_graph_clone_locked();
	mutex_unlock(&ebpfos_graph_lock);
	if (!pending)
		return -ENOMEM;
	state->pending = pending;
	return 0;
}

static long ebpfos_ioctl_set_hook(struct ebpfos_file *state, void __user *argp)
{
	struct ebpfos_ioc_set_hook request;
	struct bpf_prog *prog = NULL;
	struct bpf_prog *old;
	int error;

	if (!state->pending)
		return -EINVAL;
	error = ebpfos_legacy_mutation_check();
	if (error)
		return error;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.hook_id >= EBPFOS_HOOK_MAX)
		return -ERANGE;
	if (request.prog_fd >= 0 &&
	    request.abi_hash != ebpfos_hook_abi[request.hook_id])
		return -EPROTO;

	if (request.prog_fd >= 0) {
		prog = bpf_prog_get_type_dev(request.prog_fd,
					     BPF_PROG_TYPE_RAW_TRACEPOINT,
					     false);
		if (IS_ERR(prog))
			return PTR_ERR(prog);
	}

	old = state->pending->slots[request.hook_id].prog;
	state->pending->slots[request.hook_id].prog = prog;
	state->pending->slots[request.hook_id].abi_hash = request.abi_hash;
	state->pending->slots[request.hook_id].flags = request.flags;
	if (prog)
		state->pending->hook_mask |= BIT_ULL(request.hook_id);
	else
		state->pending->hook_mask &= ~BIT_ULL(request.hook_id);
	if (old)
		bpf_prog_put(old);
	return 0;
}

static long ebpfos_ioctl_set_state(struct ebpfos_file *state,
				   void __user *argp)
{
	struct ebpfos_ioc_set_state request;
	struct bpf_map *map = NULL;
	struct bpf_map *old;
	int error;

	if (!state->pending)
		return -EINVAL;
	error = ebpfos_legacy_mutation_check();
	if (error)
		return error;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.slot >= EBPFOS_MAX_STATE_SLOTS)
		return -ERANGE;

	old = state->pending->state[request.slot].map;
	if (old && request.map_fd >= 0 &&
	    state->pending->state[request.slot].schema_hash != request.schema_hash &&
	    (!(request.flags & EBPFOS_STATE_F_MIGRATED) ||
	     request.previous_schema_hash !=
		state->pending->state[request.slot].schema_hash))
		return -EXDEV;

	if (request.map_fd >= 0) {
		map = bpf_map_get(request.map_fd);
		if (IS_ERR(map))
			return PTR_ERR(map);
	}

	state->pending->state[request.slot].map = map;
	state->pending->state[request.slot].schema_hash = request.schema_hash;
	state->pending->state[request.slot].flags = request.flags;
	if (map)
		state->pending->state_mask |= BIT_ULL(request.slot);
	else
		state->pending->state_mask &= ~BIT_ULL(request.slot);
	if (old)
		bpf_map_put(old);
	return 0;
}

static long ebpfos_ioctl_commit(struct ebpfos_file *state, void __user *argp)
{
	struct ebpfos_ioc_commit request;
	struct ebpfos_graph *old;
	struct ebpfos_graph *new;
	bool new_legacy;
	bool old_legacy;
	int error;

	if (!state->pending)
		return -EINVAL;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;

	ebpfos_admission_gate_lock();
	error = ebpfos_legacy_mutation_check_locked();
	if (error) {
		ebpfos_admission_gate_unlock();
		return error;
	}
	mutex_lock(&ebpfos_graph_lock);
	old = rcu_dereference_protected(ebpfos_active_graph,
					lockdep_is_held(&ebpfos_graph_lock));
	if (request.expected_generation && old &&
	    request.expected_generation != old->generation) {
		mutex_unlock(&ebpfos_graph_lock);
		ebpfos_admission_gate_unlock();
		return -ESTALE;
	}

	new = state->pending;
	old_legacy = ebpfos_graph_has_legacy_binding(old);
	new_legacy = ebpfos_graph_has_legacy_binding(new);
	if (!old_legacy && new_legacy) {
		error = ebpfos_legacy_binding_add_locked();
		if (error) {
			mutex_unlock(&ebpfos_graph_lock);
			ebpfos_admission_gate_unlock();
			return error;
		}
	}
	new->generation = old ? old->generation + 1 : 1;
	state->pending = NULL;
	rcu_assign_pointer(ebpfos_active_graph, new);
	request.new_generation = new->generation;
	mutex_unlock(&ebpfos_graph_lock);

	synchronize_rcu();
	ebpfos_graph_put(old);
	if (old_legacy && !new_legacy)
		ebpfos_legacy_binding_del_locked();
	ebpfos_admission_gate_unlock();
	return copy_to_user(argp, &request, sizeof(request)) ? -EFAULT : 0;
}

static long ebpfos_ioctl_status(void __user *argp)
{
	struct ebpfos_ioc_status status = { 0 };
	struct ebpfos_graph *graph;

	rcu_read_lock();
	graph = rcu_dereference(ebpfos_active_graph);
	if (graph) {
		status.generation = graph->generation;
		status.hook_mask = graph->hook_mask;
		status.state_mask = graph->state_mask;
	}
	rcu_read_unlock();
	return copy_to_user(argp, &status, sizeof(status)) ? -EFAULT : 0;
}

static long ebpfos_ioctl_run(void __user *argp)
{
	struct ebpfos_ioc_run request;
	int error = 0;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.hook_id >= EBPFOS_HOOK_MAX ||
	    request.nr_args > EBPFOS_MAX_ARGS)
		return -ERANGE;
	ebpfos_admission_gate_lock();
	if (ebpfos_policy_enforcing_locked())
		error = -EPERM;
	else
		request.result = ebpfos_run_hook(request.hook_id, request.args,
						request.nr_args);
	ebpfos_admission_gate_unlock();
	if (error)
		return error;
	return copy_to_user(argp, &request, sizeof(request)) ? -EFAULT : 0;
}

static long ebpfos_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ebpfos_file *state = file->private_data;
	void __user *argp = (void __user *)arg;
	long result;

	switch (cmd) {
	case EBPFOS_IOC_VERSION:
		return ebpfos_ioctl_version(argp);
	case EBPFOS_IOC_BEGIN:
		return ebpfos_ioctl_begin(state);
	case EBPFOS_IOC_SET_HOOK:
		return ebpfos_ioctl_set_hook(state, argp);
	case EBPFOS_IOC_COMMIT:
		return ebpfos_ioctl_commit(state, argp);
	case EBPFOS_IOC_ABORT:
		ebpfos_graph_put(state->pending);
		state->pending = NULL;
		return 0;
	case EBPFOS_IOC_STATUS:
		return ebpfos_ioctl_status(argp);
	case EBPFOS_IOC_RUN:
		return ebpfos_ioctl_run(argp);
	case EBPFOS_IOC_SET_STATE:
		return ebpfos_ioctl_set_state(state, argp);
	case EBPFOS_IOC_POLICY_ACTIVATE:
		return ebpfos_policy_activate_ioctl(argp);
	case EBPFOS_IOC_POLICY_STATUS:
		return ebpfos_policy_status_ioctl(argp);
	case EBPFOS_IOC_ADMISSION_SEAL:
		return ebpfos_admission_seal_ioctl(argp);
	case EBPFOS_IOC_ADMISSION_INFO:
		return ebpfos_admission_info_ioctl(argp);
	case EBPFOS_IOC_ADMISSION_RUNTIME_INFO:
		return ebpfos_admission_runtime_info_ioctl(argp);
	case EBPFOS_IOC_STATE_ADAPTER_SEAL:
		return ebpfos_state_adapter_seal_ioctl(argp);
	case EBPFOS_IOC_STATE_ADAPTER_INFO:
		return ebpfos_state_adapter_info_ioctl(argp);
	case EBPFOS_IOC_STATE_ADAPTER_TARGET_PAIR_EXPERIMENTAL:
		return ebpfos_state_adapter_target_pair_ioctl(argp);
	case EBPFOS_IOC_FILE_SPLIT_PRIVATE_CONVERT_EXPERIMENTAL:
		return ebpfos_file_split_private_convert_experimental_ioctl(argp);
	case EBPFOS_IOC_FILE_SPLIT_HOT_PUBLISH_EXPERIMENTAL:
		return ebpfos_file_split_hot_publish_experimental_ioctl(argp);
	case EBPFOS_IOC_OBJECT_CREATE:
		return ebpfos_object_create_ioctl(argp);
	case EBPFOS_IOC_FILE_ENROLL:
		return ebpfos_file_enroll_ioctl(argp);
	case EBPFOS_IOC_FILE_STATUS:
		return ebpfos_file_status_ioctl(argp);
	case EBPFOS_IOC_FILE_REPLACE_BEGIN:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_replace_begin_ioctl(argp,
							 &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_REPLACE_CATCHUP:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_replace_catchup_ioctl(argp,
							   &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_REPLACE_COMMIT:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_replace_commit_ioctl(argp,
							  &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_REPLACE_ABORT:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_replace_abort_ioctl(argp,
							 &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_REPLACE_STATUS:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_replace_status_ioctl(argp,
							  &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_RECOVERY_BEGIN:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_recovery_begin_ioctl(argp,
							  &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_RECOVERY_ARM:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_recovery_arm_ioctl(argp,
							&state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_RECOVERY_ABORT:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_recovery_abort_ioctl(argp,
							  &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_RECOVERY_STATUS:
		return ebpfos_file_recovery_status_ioctl(argp);
	case EBPFOS_IOC_FILE_RECOVERY_RETIRE:
		return ebpfos_file_recovery_retire_ioctl(argp);
	case EBPFOS_IOC_FILE_REPLACE_BEGIN_V2:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_replace_begin_v2_ioctl(argp,
							    &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_RECOVERY_BEGIN_V2:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_recovery_begin_v2_ioctl(
			argp, &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_RECOVERY_ARM_V2:
		mutex_lock(&state->file_txn_lock);
		result = ebpfos_file_recovery_arm_v2_ioctl(argp,
							   &state->file_txn);
		mutex_unlock(&state->file_txn_lock);
		return result;
	case EBPFOS_IOC_FILE_ADMISSION_STATUS:
		return ebpfos_file_admission_status_ioctl(argp);
	case EBPFOS_IOC_FILE_SPLIT_PUBLISH_EXPERIMENTAL:
		return ebpfos_file_split_publish_experimental_ioctl(argp);
	case EBPFOS_IOC_FILE_SPLIT_CONTROL_EXPERIMENTAL:
		return ebpfos_file_split_control_experimental_ioctl(argp);
	case EBPFOS_IOC_FILE_CHECKPOINT_EXPERIMENTAL:
		return ebpfos_file_checkpoint_experimental_ioctl(argp);
	case EBPFOS_IOC_KOPERATION_PREPARE_EXPERIMENTAL:
		mutex_lock(&state->koperation_txn_lock);
		result = ebpfos_koperation_prepare_ioctl(
			argp, &state->koperation_txn);
		mutex_unlock(&state->koperation_txn_lock);
		return result;
	case EBPFOS_IOC_KOPERATION_EXECUTE_EXPERIMENTAL:
		mutex_lock(&state->koperation_txn_lock);
		result = ebpfos_koperation_execute_ioctl(
			argp, &state->koperation_txn);
		mutex_unlock(&state->koperation_txn_lock);
		return result;
	case EBPFOS_IOC_KOPERATION_RESULT_EXPERIMENTAL:
		mutex_lock(&state->koperation_txn_lock);
		result = ebpfos_koperation_result_ioctl(
			argp, &state->koperation_txn);
		mutex_unlock(&state->koperation_txn_lock);
		return result;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations ebpfos_fops = {
	.owner = THIS_MODULE,
	.open = ebpfos_open,
	.release = ebpfos_release,
	.unlocked_ioctl = ebpfos_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = ebpfos_ioctl,
#endif
	.llseek = noop_llseek,
};

static struct miscdevice ebpfos_miscdev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ebpfos",
	.fops = &ebpfos_fops,
	.mode = 0600,
};

static int __init ebpfos_init(void)
{
	struct ebpfos_graph *initial;
	int error;

	initial = kzalloc_obj(*initial, GFP_KERNEL);
	if (!initial)
		return -ENOMEM;
	initial->generation = 1;
	rcu_assign_pointer(ebpfos_active_graph, initial);
	error = misc_register(&ebpfos_miscdev);
	if (error) {
		RCU_INIT_POINTER(ebpfos_active_graph, NULL);
		kfree(initial);
		return error;
	}
	pr_info("ebpfos: composition nucleus ready, generation=1\n");
	return 0;
}
subsys_initcall(ebpfos_init);

MODULE_DESCRIPTION("eBPFOS transactional eBPF component graph");
MODULE_AUTHOR("eunomia-bpf community");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.2");
