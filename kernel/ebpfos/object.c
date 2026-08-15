// SPDX-License-Identifier: GPL-2.0-only
#include <linux/anon_inodes.h>
#include <linux/atomic.h>
#include <linux/bpf.h>
#include <linux/ebpfos.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define EBPFOS_EXEC_FAULT 1

struct ebpfos_delta {
	u64 sequence;
	u64 method_id;
	u64 argument;
	u64 result;
};

struct ebpfos_provider {
	struct list_head node;
	struct bpf_prog *prog;
	u64 id;
	u64 schema_hash;
	u64 required_rights;
	u64 state[2];
	u64 attempts;
	u64 foreground_commits;
	u64 shadow_replays;
	u64 faults;
	u64 activated_epoch;
	u64 deactivated_epoch;
	u32 kind;
	bool active;
};

struct ebpfos_migration {
	struct ebpfos_provider *candidate;
	struct ebpfos_delta *deltas;
	u64 txn_id;
	u64 owner_capability_id;
	u64 snapshot_sequence;
	u32 delta_count;
	bool overflow;
};

struct ebpfos_object {
	struct kref ref;
	struct mutex lock; /* Serializes routing, state, migration, and audit. */
	struct list_head providers;
	struct ebpfos_provider *active;
	struct ebpfos_provider *rollback;
	struct ebpfos_migration migration;
	struct ebpfos_delta *rollback_log;
	struct ebpfos_audit_record *audit;
	struct ebpfos_ioc_provider_stats *provider_history;
	u64 id;
	u64 contract_id;
	u64 rights_ceiling;
	u64 epoch;
	u64 last_sequence;
	u64 committed_calls;
	u64 committed_writes;
	u64 abstract_digest;
	u64 rollback_count;
	u64 fault_count;
	u64 retired_call_violations;
	u64 last_snapshot_sequence;
	u64 last_captured_deltas;
	u32 rollback_log_count;
	u32 provider_history_next;
	u32 provider_history_count;
	bool rollback_valid;
};

struct ebpfos_cap_file {
	struct ebpfos_object *object;
	u64 id;
	u64 rights;
};

struct ebpfos_prepared_call {
	struct ebpfos_provider *provider;
	u64 sequence;
	u64 epoch;
	u64 method_id;
	u64 argument;
	u64 result;
	u32 audit_flags;
};

static atomic64_t ebpfos_next_object_id = ATOMIC64_INIT(0);
static atomic64_t ebpfos_next_capability_id = ATOMIC64_INIT(0);
static atomic64_t ebpfos_next_provider_id = ATOMIC64_INIT(0);
static atomic64_t ebpfos_next_transaction_id = ATOMIC64_INIT(0);

static const struct file_operations ebpfos_object_fops;

static u64 ebpfos_new_id(atomic64_t *counter)
{
	return (u64)atomic64_inc_return(counter);
}

static int ebpfos_cell_decode(const struct ebpfos_provider *provider,
			      u64 *value)
{
	u64 decoded;

	switch (provider->schema_hash) {
	case EBPFOS_SCHEMA_CELL_NATIVE:
		if (provider->state[1])
			return -EUCLEAN;
		decoded = provider->state[0];
		break;
	case EBPFOS_SCHEMA_CELL_V1:
		decoded = provider->state[0];
		if (provider->state[1] != (~decoded & 0xffffffffULL))
			return -EUCLEAN;
		break;
	case EBPFOS_SCHEMA_CELL_V2:
		if (provider->state[0] & ~EBPFOS_CELL_V2_LOW_MASK)
			return -EUCLEAN;
		if ((provider->state[1] & ~EBPFOS_CELL_V2_HIGH_MASK) !=
		    EBPFOS_CELL_V2_TAG)
			return -EUCLEAN;
		decoded = provider->state[0] |
			  ((provider->state[1] & EBPFOS_CELL_V2_HIGH_MASK) << 16);
		break;
	default:
		return -EPROTONOSUPPORT;
	}
	if (decoded > EBPFOS_CELL_VALUE_MASK)
		return -ERANGE;
	*value = decoded;
	return 0;
}

static int ebpfos_cell_encode(struct ebpfos_provider *provider, u64 value)
{
	if (value > EBPFOS_CELL_VALUE_MASK)
		return -ERANGE;

	switch (provider->schema_hash) {
	case EBPFOS_SCHEMA_CELL_NATIVE:
		provider->state[0] = value;
		provider->state[1] = 0;
		break;
	case EBPFOS_SCHEMA_CELL_V1:
		provider->state[0] = value;
		provider->state[1] = (~value) & 0xffffffffULL;
		break;
	case EBPFOS_SCHEMA_CELL_V2:
		provider->state[0] = value & EBPFOS_CELL_V2_LOW_MASK;
		provider->state[1] = EBPFOS_CELL_V2_TAG |
			((value >> 16) & EBPFOS_CELL_V2_HIGH_MASK);
		break;
	default:
		return -EPROTONOSUPPORT;
	}
	return 0;
}

static int ebpfos_cell_expected(u64 current_value, u64 method_id, u64 argument,
				u64 *result)
{
	switch (method_id) {
	case EBPFOS_CELL_GET:
		*result = current_value;
		return 0;
	case EBPFOS_CELL_ADD:
		if (argument > EBPFOS_CELL_VALUE_MASK - current_value)
			return -EOVERFLOW;
		*result = current_value + argument;
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static u64 ebpfos_method_right(u64 method_id)
{
	switch (method_id) {
	case EBPFOS_CELL_GET:
		return EBPFOS_RIGHT_READ;
	case EBPFOS_CELL_ADD:
		return EBPFOS_RIGHT_WRITE;
	default:
		return 0;
	}
}

static int ebpfos_validate_pure_program(const struct bpf_prog *prog)
{
	u32 i;

	if (prog->aux->used_map_cnt || prog->aux->used_btf_cnt)
		return -EACCES;
	if (prog->aux->max_ctx_offset > sizeof(struct ebpfos_bpf_call_ctx))
		return -E2BIG;

	for (i = 0; i < prog->len; i++) {
		const struct bpf_insn *insn = &prog->insnsi[i];
		u8 class = BPF_CLASS(insn->code);

		if ((class == BPF_JMP || class == BPF_JMP32) &&
		    BPF_OP(insn->code) == BPF_CALL)
			return -EACCES;
	}
	return 0;
}

static struct ebpfos_provider *
ebpfos_provider_alloc(u32 kind, u64 schema_hash, u64 required_rights,
		      struct bpf_prog *prog)
{
	struct ebpfos_provider *provider;

	provider = kzalloc_obj(*provider, GFP_KERNEL);
	if (!provider)
		return NULL;
	INIT_LIST_HEAD(&provider->node);
	provider->id = ebpfos_new_id(&ebpfos_next_provider_id);
	provider->kind = kind;
	provider->schema_hash = schema_hash;
	provider->required_rights = required_rights;
	provider->prog = prog;
	return provider;
}

static void ebpfos_provider_free(struct ebpfos_provider *provider)
{
	if (!provider)
		return;
	if (provider->prog)
		bpf_prog_put(provider->prog);
	kfree(provider);
}

static void ebpfos_provider_snapshot(const struct ebpfos_provider *provider,
				     struct ebpfos_ioc_provider_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
	stats->provider_id = provider->id;
	stats->schema_hash = provider->schema_hash;
	stats->attempts = provider->attempts;
	stats->foreground_commits = provider->foreground_commits;
	stats->shadow_replays = provider->shadow_replays;
	stats->faults = provider->faults;
	stats->activated_epoch = provider->activated_epoch;
	stats->deactivated_epoch = provider->deactivated_epoch;
	stats->kind = provider->kind;
	stats->active = provider->active;
}

static void ebpfos_provider_archive_locked(struct ebpfos_object *object,
					   struct ebpfos_provider *provider)
{
	struct ebpfos_ioc_provider_stats *slot;

	lockdep_assert_held(&object->lock);
	if (!provider)
		return;
	slot = &object->provider_history[object->provider_history_next];
	ebpfos_provider_snapshot(provider, slot);
	slot->active = 0;
	object->provider_history_next =
		(object->provider_history_next + 1) %
		EBPFOS_PROVIDER_HISTORY_CAPACITY;
	if (object->provider_history_count < EBPFOS_PROVIDER_HISTORY_CAPACITY)
		object->provider_history_count++;
	list_del(&provider->node);
	ebpfos_provider_free(provider);
}

/*
 * Execute a pure transition. State is changed only by ebpfos_commit_call()
 * or by an explicitly shadowed replay after this function returns success.
 */
static int ebpfos_provider_execute(struct ebpfos_object *object,
				   struct ebpfos_provider *provider,
				   u64 sequence, u64 method_id,
				   u64 argument, u64 effective_rights,
				   u64 flags, u64 *result)
{
	struct ebpfos_bpf_call_ctx context = { 0 };
	u64 current_value;
	u64 expected;
	u32 raw_result;
	u32 status;
	int error;

	if ((flags & EBPFOS_BPF_CALL_F_FOREGROUND) &&
	    (!provider->active || provider != object->active)) {
		object->retired_call_violations++;
		return EBPFOS_EXEC_FAULT;
	}

	provider->attempts++;
	if (flags & EBPFOS_BPF_CALL_F_SHADOW)
		provider->shadow_replays++;

	error = ebpfos_cell_decode(provider, &current_value);
	if (error)
		goto fault;
	error = ebpfos_cell_expected(current_value, method_id, argument, &expected);
	if (error)
		return error;

	if (provider->kind == EBPFOS_PROVIDER_NATIVE) {
		*result = expected;
		return 0;
	}
	if (provider->kind != EBPFOS_PROVIDER_BPF || !provider->prog)
		goto fault;

	context.object_id = object->id;
	context.contract_id = object->contract_id;
	context.epoch = object->epoch;
	context.sequence = sequence;
	context.method_id = method_id;
	context.effective_rights = effective_rights;
	context.state[0] = provider->state[0];
	context.state[1] = provider->state[1];
	context.args[0] = argument;
	context.flags = flags;

	raw_result = bpf_prog_run_pin_on_cpu(provider->prog, &context);
	status = EBPFOS_CALL_RETURN_STATUS(raw_result);
	switch (status) {
	case EBPFOS_CALL_RETURN_OK:
		*result = EBPFOS_CALL_RETURN_PAYLOAD(raw_result);
		if (*result != expected)
			goto fault;
		return 0;
	case EBPFOS_CALL_RETURN_DENY:
		/*
		 * Rights and method legality are nucleus-checked above. A
		 * provider that rejects a legal contract transition does not
		 * refine CELL and must fault/rollback rather than change the API.
		 */
		goto fault;
	case EBPFOS_CALL_RETURN_FAULT:
		goto fault;
	default:
		goto fault;
	}

fault:
	provider->faults++;
	return EBPFOS_EXEC_FAULT;
}

static void ebpfos_migration_reset(struct ebpfos_object *object)
{
	object->migration.candidate = NULL;
	object->migration.deltas = NULL;
	object->migration.txn_id = 0;
	object->migration.owner_capability_id = 0;
	object->migration.snapshot_sequence = 0;
	object->migration.delta_count = 0;
	object->migration.overflow = false;
}

static void ebpfos_migration_abort_locked(struct ebpfos_object *object)
{
	struct ebpfos_provider *candidate = object->migration.candidate;
	struct ebpfos_delta *deltas = object->migration.deltas;

	lockdep_assert_held(&object->lock);
	if (candidate) {
		list_del(&candidate->node);
		ebpfos_provider_free(candidate);
	}
	ebpfos_migration_reset(object);
	kvfree(deltas);
}

static int ebpfos_replay_log(struct ebpfos_object *object,
			     struct ebpfos_provider *provider,
			     const struct ebpfos_delta *log, u32 count)
{
	u32 i;

	for (i = 0; i < count; i++) {
		u64 result;
		int error;

		error = ebpfos_provider_execute(object, provider,
						log[i].sequence,
						log[i].method_id,
						log[i].argument,
						provider->required_rights,
						EBPFOS_BPF_CALL_F_SHADOW,
						&result);
		if (error)
			return error == EBPFOS_EXEC_FAULT ? -EIO : error;
		if (result != log[i].result)
			return -EREMOTEIO;
		if (log[i].method_id == EBPFOS_CELL_ADD) {
			error = ebpfos_cell_encode(provider, result);
			if (error)
				return error;
		}
	}
	return 0;
}

static int ebpfos_rollback_locked(struct ebpfos_object *object)
{
	struct ebpfos_provider *failed = object->active;
	struct ebpfos_provider *rollback = object->rollback;
	u64 active_value;
	u64 rollback_value;
	int error;

	lockdep_assert_held(&object->lock);
	if (!rollback || !object->rollback_valid)
		return -EIO;

	error = ebpfos_replay_log(object, rollback, object->rollback_log,
				  object->rollback_log_count);
	if (error) {
		object->rollback_valid = false;
		return error;
	}
	error = ebpfos_cell_decode(failed, &active_value);
	if (error) {
		object->rollback_valid = false;
		return error;
	}
	error = ebpfos_cell_decode(rollback, &rollback_value);
	if (error || active_value != rollback_value) {
		object->rollback_valid = false;
		return error ? error : -EREMOTEIO;
	}

	if (object->migration.candidate)
		ebpfos_migration_abort_locked(object);

	object->epoch++;
	failed->active = false;
	failed->deactivated_epoch = object->epoch;
	rollback->active = true;
	rollback->activated_epoch = object->epoch;
	rollback->deactivated_epoch = 0;
	object->active = rollback;
	object->rollback = NULL;
	object->rollback_log_count = 0;
	object->rollback_valid = false;
	object->rollback_count++;
	ebpfos_provider_archive_locked(object, failed);
	return 0;
}

static int ebpfos_prepare_call_locked(struct ebpfos_cap_file *cap,
				      u64 method_id, u64 argument,
				      struct ebpfos_prepared_call *call)
{
	struct ebpfos_object *object = cap->object;
	struct ebpfos_provider *provider;
	u64 needed_right;
	int error;

	lockdep_assert_held(&object->lock);
	needed_right = ebpfos_method_right(method_id);
	if (!needed_right)
		return -EOPNOTSUPP;
	if (!(cap->rights & needed_right))
		return -EACCES;
	if (object->last_sequence == ~0ULL)
		return -EOVERFLOW;

	call->sequence = object->last_sequence + 1;
	call->method_id = method_id;
	call->argument = argument;
	call->audit_flags = method_id == EBPFOS_CELL_ADD ?
		EBPFOS_AUDIT_F_MUTATING : 0;

	provider = object->active;
	error = ebpfos_provider_execute(object, provider, call->sequence,
					method_id, argument, cap->rights,
					EBPFOS_BPF_CALL_F_FOREGROUND,
					&call->result);
	if (error == EBPFOS_EXEC_FAULT) {
		object->fault_count++;
		error = ebpfos_rollback_locked(object);
		if (error)
			return error;
		call->audit_flags |= EBPFOS_AUDIT_F_ROLLBACK;
		provider = object->active;
		error = ebpfos_provider_execute(object, provider,
						call->sequence, method_id, argument,
						cap->rights,
						EBPFOS_BPF_CALL_F_FOREGROUND,
						&call->result);
		if (error == EBPFOS_EXEC_FAULT) {
			object->fault_count++;
			return -EIO;
		}
	}
	if (error)
		return error;

	call->provider = provider;
	call->epoch = object->epoch;
	return 0;
}

static void ebpfos_capture_delta(struct ebpfos_object *object,
				 const struct ebpfos_prepared_call *call)
{
	struct ebpfos_delta *delta;

	if (!object->migration.candidate ||
	    call->method_id != EBPFOS_CELL_ADD)
		return;
	if (object->migration.delta_count >= EBPFOS_OBJECT_DELTA_CAPACITY) {
		object->migration.overflow = true;
		return;
	}
	delta = &object->migration.deltas[object->migration.delta_count++];
	delta->sequence = call->sequence;
	delta->method_id = call->method_id;
	delta->argument = call->argument;
	delta->result = call->result;
}

static void ebpfos_capture_rollback(struct ebpfos_object *object,
				    const struct ebpfos_prepared_call *call)
{
	struct ebpfos_delta *delta;

	if (!object->rollback || call->method_id != EBPFOS_CELL_ADD)
		return;
	if (object->rollback_log_count >= EBPFOS_OBJECT_DELTA_CAPACITY) {
		if (ebpfos_replay_log(object, object->rollback,
				      object->rollback_log,
				      object->rollback_log_count)) {
			object->rollback_valid = false;
			return;
		}
		object->rollback_log_count = 0;
	}
	delta = &object->rollback_log[object->rollback_log_count++];
	delta->sequence = call->sequence;
	delta->method_id = call->method_id;
	delta->argument = call->argument;
	delta->result = call->result;
}

static u64 ebpfos_digest_call(u64 digest,
			      const struct ebpfos_prepared_call *call)
{
	digest = EBPFOS_DIGEST_MIX(digest, call->sequence);
	digest = EBPFOS_DIGEST_MIX(digest, call->epoch);
	digest = EBPFOS_DIGEST_MIX(digest, call->method_id);
	digest = EBPFOS_DIGEST_MIX(digest, call->argument);
	return EBPFOS_DIGEST_MIX(digest, call->result);
}

static void ebpfos_commit_call_locked(struct ebpfos_object *object,
				      const struct ebpfos_prepared_call *call)
{
	struct ebpfos_audit_record *record;

	lockdep_assert_held(&object->lock);
	if (WARN_ON_ONCE(call->sequence != object->last_sequence + 1))
		return;
	if (call->method_id == EBPFOS_CELL_ADD)
		WARN_ON_ONCE(ebpfos_cell_encode(call->provider, call->result));

	object->last_sequence = call->sequence;
	object->committed_calls++;
	if (call->method_id == EBPFOS_CELL_ADD)
		object->committed_writes++;
	call->provider->foreground_commits++;
	object->abstract_digest =
		ebpfos_digest_call(object->abstract_digest, call);

	ebpfos_capture_delta(object, call);
	ebpfos_capture_rollback(object, call);

	record = &object->audit[(call->sequence - 1) %
				EBPFOS_OBJECT_AUDIT_CAPACITY];
	record->sequence = call->sequence;
	record->epoch = call->epoch;
	record->provider_id = call->provider->id;
	record->method_id = call->method_id;
	record->argument = call->argument;
	record->result = call->result;
	record->abstract_digest = object->abstract_digest;
	record->status = 0;
	record->flags = call->audit_flags;
}

static void ebpfos_object_release_kref(struct kref *ref)
{
	struct ebpfos_object *object =
		container_of(ref, struct ebpfos_object, ref);
	struct ebpfos_provider *provider;
	struct ebpfos_provider *next;

	list_for_each_entry_safe(provider, next, &object->providers, node) {
		list_del(&provider->node);
		ebpfos_provider_free(provider);
	}
	kvfree(object->migration.deltas);
	kvfree(object->rollback_log);
	kvfree(object->audit);
	kvfree(object->provider_history);
	kfree(object);
}

static void ebpfos_object_put(struct ebpfos_object *object)
{
	kref_put(&object->ref, ebpfos_object_release_kref);
}

static struct ebpfos_object *
ebpfos_object_alloc(u64 contract_id, u64 rights_ceiling, u64 initial_value)
{
	struct ebpfos_provider *native;
	struct ebpfos_object *object;
	int error;

	if (contract_id != EBPFOS_CONTRACT_CELL_V1)
		return ERR_PTR(-EPROTONOSUPPORT);
	if (!rights_ceiling || rights_ceiling & ~EBPFOS_RIGHT_ALL)
		return ERR_PTR(-EINVAL);
	if (initial_value > EBPFOS_CELL_VALUE_MASK)
		return ERR_PTR(-ERANGE);

	object = kzalloc_obj(*object, GFP_KERNEL);
	if (!object)
		return ERR_PTR(-ENOMEM);
	object->audit = kvcalloc(EBPFOS_OBJECT_AUDIT_CAPACITY,
				 sizeof(*object->audit), GFP_KERNEL);
	object->rollback_log = kvcalloc(EBPFOS_OBJECT_DELTA_CAPACITY,
					sizeof(*object->rollback_log), GFP_KERNEL);
	object->provider_history =
		kvcalloc(EBPFOS_PROVIDER_HISTORY_CAPACITY,
			 sizeof(*object->provider_history), GFP_KERNEL);
	if (!object->audit || !object->rollback_log ||
	    !object->provider_history) {
		error = -ENOMEM;
		goto error_object;
	}

	native = ebpfos_provider_alloc(EBPFOS_PROVIDER_NATIVE,
				       EBPFOS_SCHEMA_CELL_NATIVE,
				       rights_ceiling &
				       (EBPFOS_RIGHT_READ | EBPFOS_RIGHT_WRITE),
				       NULL);
	if (!native) {
		error = -ENOMEM;
		goto error_object;
	}
	error = ebpfos_cell_encode(native, initial_value);
	if (error) {
		ebpfos_provider_free(native);
		goto error_object;
	}

	kref_init(&object->ref);
	mutex_init(&object->lock);
	INIT_LIST_HEAD(&object->providers);
	ebpfos_migration_reset(object);
	object->id = ebpfos_new_id(&ebpfos_next_object_id);
	object->contract_id = contract_id;
	object->rights_ceiling = rights_ceiling;
	object->epoch = 1;
	object->abstract_digest = EBPFOS_DIGEST_INITIAL;
	native->active = true;
	native->activated_epoch = object->epoch;
	list_add_tail(&native->node, &object->providers);
	object->active = native;
	return object;

error_object:
	kvfree(object->provider_history);
	kvfree(object->rollback_log);
	kvfree(object->audit);
	kfree(object);
	return ERR_PTR(error);
}

static int ebpfos_object_release(struct inode *inode, struct file *file)
{
	struct ebpfos_cap_file *cap = file->private_data;

	if (cap) {
		mutex_lock(&cap->object->lock);
		if (cap->object->migration.candidate &&
		    cap->object->migration.owner_capability_id == cap->id)
			ebpfos_migration_abort_locked(cap->object);
		mutex_unlock(&cap->object->lock);
		ebpfos_object_put(cap->object);
		kfree(cap);
	}
	return 0;
}

static struct file *ebpfos_cap_getfile(struct ebpfos_object *object,
				       u64 rights, u64 *capability_id)
{
	struct ebpfos_cap_file *cap;
	struct file *file;

	cap = kzalloc_obj(*cap, GFP_KERNEL);
	if (!cap)
		return ERR_PTR(-ENOMEM);
	cap->object = object;
	cap->rights = rights;
	cap->id = ebpfos_new_id(&ebpfos_next_capability_id);
	kref_get(&object->ref);

	file = anon_inode_create_getfile("[ebpfos-cell]", &ebpfos_object_fops,
					 cap, O_RDWR, NULL);
	if (IS_ERR(file)) {
		ebpfos_object_put(object);
		kfree(cap);
		return file;
	}
	file->f_mode |= FMODE_STREAM;
	*capability_id = cap->id;
	return file;
}

static ssize_t ebpfos_object_read(struct file *file, char __user *buffer,
				  size_t count, loff_t *position)
{
	struct ebpfos_cap_file *cap = file->private_data;
	struct ebpfos_object *object = cap->object;
	struct ebpfos_prepared_call call = { 0 };
	int error;

	if (count < sizeof(call.result))
		return -EINVAL;
	mutex_lock(&object->lock);
	error = ebpfos_prepare_call_locked(cap, EBPFOS_CELL_GET, 0, &call);
	if (!error && copy_to_user(buffer, &call.result, sizeof(call.result)))
		error = -EFAULT;
	if (!error)
		ebpfos_commit_call_locked(object, &call);
	mutex_unlock(&object->lock);
	return error ? error : sizeof(call.result);
}

static ssize_t ebpfos_object_write(struct file *file,
				   const char __user *buffer, size_t count,
				   loff_t *position)
{
	struct ebpfos_cap_file *cap = file->private_data;
	struct ebpfos_object *object = cap->object;
	struct ebpfos_prepared_call call = { 0 };
	u64 argument;
	int error;

	if (count != sizeof(argument))
		return -EINVAL;
	if (copy_from_user(&argument, buffer, sizeof(argument)))
		return -EFAULT;
	mutex_lock(&object->lock);
	error = ebpfos_prepare_call_locked(cap, EBPFOS_CELL_ADD, argument,
					   &call);
	if (!error)
		ebpfos_commit_call_locked(object, &call);
	mutex_unlock(&object->lock);
	return error ? error : sizeof(argument);
}

static long ebpfos_cap_derive_ioctl(struct ebpfos_cap_file *cap,
				    void __user *argp)
{
	struct ebpfos_ioc_cap_derive request;
	struct file *new_file;
	u64 capability_id;
	int fd;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags || !request.rights ||
	    request.rights & ~cap->rights)
		return -EACCES;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0)
		return fd;
	new_file = ebpfos_cap_getfile(cap->object, request.rights,
				      &capability_id);
	if (IS_ERR(new_file)) {
		put_unused_fd(fd);
		return PTR_ERR(new_file);
	}
	request.capability_id = capability_id;
	request.new_fd = fd;
	if (copy_to_user(argp, &request, sizeof(request))) {
		fput(new_file);
		put_unused_fd(fd);
		return -EFAULT;
	}
	fd_install(fd, new_file);
	return 0;
}

static long ebpfos_cap_info_ioctl(struct ebpfos_cap_file *cap,
				  void __user *argp)
{
	struct ebpfos_ioc_cap_info request = {
		.object_id = cap->object->id,
		.capability_id = cap->id,
		.contract_id = cap->object->contract_id,
		.rights = cap->rights,
	};

	return copy_to_user(argp, &request, sizeof(request)) ? -EFAULT : 0;
}

static long ebpfos_call_ioctl(struct ebpfos_cap_file *cap, void __user *argp)
{
	struct ebpfos_ioc_call request;
	struct ebpfos_object *object = cap->object;
	struct ebpfos_prepared_call call = { 0 };
	int error;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags)
		return -EINVAL;

	mutex_lock(&object->lock);
	error = ebpfos_prepare_call_locked(cap, request.method_id,
					   request.args[0], &call);
	request.status = error;
	if (!error) {
		request.results[0] = call.result;
		request.sequence = call.sequence;
		request.epoch = call.epoch;
		request.provider_id = call.provider->id;
	}
	if (copy_to_user(argp, &request, sizeof(request))) {
		mutex_unlock(&object->lock);
		return -EFAULT;
	}
	if (!error)
		ebpfos_commit_call_locked(object, &call);
	mutex_unlock(&object->lock);
	return error;
}

static long ebpfos_replace_begin_ioctl(struct ebpfos_cap_file *cap,
				       void __user *argp)
{
	struct ebpfos_ioc_replace_begin request;
	struct ebpfos_object *object = cap->object;
	struct ebpfos_provider *candidate = NULL;
	struct ebpfos_delta *deltas = NULL;
	struct bpf_prog *prog = NULL;
	u64 value;
	u64 result;
	int error;

	if (!(cap->rights & EBPFOS_RIGHT_REPLACE))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags ||
	    request.contract_abi_hash != EBPFOS_ABI_CELL_V1)
		return -EPROTO;
	if (request.required_rights & ~object->rights_ceiling)
		return -EACCES;
	if (request.target_schema_hash != EBPFOS_SCHEMA_CELL_NATIVE &&
	    request.target_schema_hash != EBPFOS_SCHEMA_CELL_V1 &&
	    request.target_schema_hash != EBPFOS_SCHEMA_CELL_V2)
		return -EPROTONOSUPPORT;

	if (request.prog_fd >= 0) {
		prog = bpf_prog_get_type_dev(request.prog_fd,
					     BPF_PROG_TYPE_RAW_TRACEPOINT,
					     false);
		if (IS_ERR(prog))
			return PTR_ERR(prog);
		error = ebpfos_validate_pure_program(prog);
		if (error) {
			bpf_prog_put(prog);
			return error;
		}
	}

	candidate = ebpfos_provider_alloc(prog ? EBPFOS_PROVIDER_BPF :
					  EBPFOS_PROVIDER_NATIVE,
					  request.target_schema_hash,
					  request.required_rights, prog);
	if (!candidate) {
		if (prog)
			bpf_prog_put(prog);
		return -ENOMEM;
	}
	deltas = kvcalloc(EBPFOS_OBJECT_DELTA_CAPACITY, sizeof(*deltas),
			  GFP_KERNEL);
	if (!deltas) {
		ebpfos_provider_free(candidate);
		return -ENOMEM;
	}

	mutex_lock(&object->lock);
	if (object->migration.candidate) {
		error = -EBUSY;
		goto error_locked;
	}
	if (request.expected_epoch && request.expected_epoch != object->epoch) {
		error = -ESTALE;
		goto error_locked;
	}
	if (request.expected_schema_hash &&
	    request.expected_schema_hash != object->active->schema_hash) {
		error = -EXDEV;
		goto error_locked;
	}
	error = ebpfos_cell_decode(object->active, &value);
	if (error)
		goto error_locked;
	error = ebpfos_cell_encode(candidate, value);
	if (error)
		goto error_locked;
	error = ebpfos_provider_execute(object, candidate,
					object->last_sequence + 1,
					EBPFOS_CELL_GET, 0,
					candidate->required_rights,
					EBPFOS_BPF_CALL_F_SHADOW, &result);
	if (error || result != value) {
		error = error == EBPFOS_EXEC_FAULT ? -EIO :
			(error ? error : -EREMOTEIO);
		goto error_locked;
	}

	list_add_tail(&candidate->node, &object->providers);
	object->migration.candidate = candidate;
	object->migration.deltas = deltas;
	object->migration.txn_id =
		ebpfos_new_id(&ebpfos_next_transaction_id);
	object->migration.owner_capability_id = cap->id;
	object->migration.snapshot_sequence = object->last_sequence;
	object->migration.delta_count = 0;
	object->migration.overflow = false;
	request.txn_id = object->migration.txn_id;
	request.snapshot_sequence = object->migration.snapshot_sequence;
	request.target_provider_id = candidate->id;
	if (copy_to_user(argp, &request, sizeof(request))) {
		ebpfos_migration_abort_locked(object);
		mutex_unlock(&object->lock);
		return -EFAULT;
	}
	mutex_unlock(&object->lock);
	return 0;

error_locked:
	mutex_unlock(&object->lock);
	kvfree(deltas);
	ebpfos_provider_free(candidate);
	return error;
}

static long ebpfos_replace_commit_ioctl(struct ebpfos_cap_file *cap,
					void __user *argp)
{
	struct ebpfos_ioc_replace_end request;
	struct ebpfos_object *object = cap->object;
	struct ebpfos_provider *candidate;
	struct ebpfos_provider *old;
	struct ebpfos_delta *deltas;
	u64 active_value;
	u64 candidate_value;
	u32 captured;
	int error;

	if (!(cap->rights & EBPFOS_RIGHT_REPLACE))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;

	mutex_lock(&object->lock);
	candidate = object->migration.candidate;
	if (!candidate || request.txn_id != object->migration.txn_id ||
	    object->migration.owner_capability_id != cap->id) {
		error = -ESTALE;
		goto out_unlock;
	}
	if (object->migration.overflow) {
		error = -EOVERFLOW;
		goto abort_locked;
	}
	error = ebpfos_replay_log(object, candidate,
				  object->migration.deltas,
				  object->migration.delta_count);
	if (error)
		goto abort_locked;
	error = ebpfos_cell_decode(object->active, &active_value);
	if (error)
		goto abort_locked;
	error = ebpfos_cell_decode(candidate, &candidate_value);
	if (error)
		goto abort_locked;
	if (active_value != candidate_value) {
		error = -EREMOTEIO;
		goto abort_locked;
	}

	old = object->active;
	captured = object->migration.delta_count;
	deltas = object->migration.deltas;
	if (object->rollback)
		ebpfos_provider_archive_locked(object, object->rollback);
	object->last_snapshot_sequence = object->migration.snapshot_sequence;
	object->last_captured_deltas = captured;
	ebpfos_migration_reset(object);
	object->epoch++;
	old->active = false;
	old->deactivated_epoch = object->epoch;
	candidate->active = true;
	candidate->activated_epoch = object->epoch;
	candidate->deactivated_epoch = 0;
	object->rollback = old;
	object->rollback_log_count = 0;
	object->rollback_valid = true;
	object->active = candidate;
	mutex_unlock(&object->lock);
	kvfree(deltas);
	return 0;

abort_locked:
	ebpfos_migration_abort_locked(object);
out_unlock:
	mutex_unlock(&object->lock);
	return error;
}

static long ebpfos_replace_abort_ioctl(struct ebpfos_cap_file *cap,
				       void __user *argp)
{
	struct ebpfos_ioc_replace_end request;
	struct ebpfos_object *object = cap->object;
	int error = 0;

	if (!(cap->rights & EBPFOS_RIGHT_REPLACE))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	mutex_lock(&object->lock);
	if (!object->migration.candidate ||
	    request.txn_id != object->migration.txn_id ||
	    object->migration.owner_capability_id != cap->id)
		error = -ESTALE;
	else
		ebpfos_migration_abort_locked(object);
	mutex_unlock(&object->lock);
	return error;
}

static long ebpfos_object_status_ioctl(struct ebpfos_cap_file *cap,
				       void __user *argp)
{
	struct ebpfos_ioc_object_status request = { 0 };
	struct ebpfos_object *object = cap->object;
	u64 value = 0;
	int error;

	if (!(cap->rights & EBPFOS_RIGHT_INSPECT))
		return -EACCES;
	mutex_lock(&object->lock);
	error = ebpfos_cell_decode(object->active, &value);
	if (!error) {
		request.object_id = object->id;
		request.contract_id = object->contract_id;
		request.rights_ceiling = object->rights_ceiling;
		request.epoch = object->epoch;
		request.active_provider_id = object->active->id;
		request.active_schema_hash = object->active->schema_hash;
		request.last_sequence = object->last_sequence;
		request.committed_calls = object->committed_calls;
		request.committed_writes = object->committed_writes;
		request.abstract_value = value;
		request.abstract_digest = object->abstract_digest;
		request.rollback_count = object->rollback_count;
		request.fault_count = object->fault_count;
		request.retired_call_violations =
			object->retired_call_violations;
		request.rollback_log_count = object->rollback_log_count;
		request.audit_first_sequence = object->last_sequence ?
			(object->last_sequence > EBPFOS_OBJECT_AUDIT_CAPACITY ?
			 object->last_sequence - EBPFOS_OBJECT_AUDIT_CAPACITY + 1 :
			 1) : 0;
		request.audit_capacity = EBPFOS_OBJECT_AUDIT_CAPACITY;
		request.delta_capacity = EBPFOS_OBJECT_DELTA_CAPACITY;
		request.provider_history_capacity =
			EBPFOS_PROVIDER_HISTORY_CAPACITY;
		request.rollback_valid = object->rollback_valid;
		if (object->migration.candidate) {
			request.migration_txn_id = object->migration.txn_id;
			request.migration_owner_capability_id =
				object->migration.owner_capability_id;
			request.snapshot_sequence =
				object->migration.snapshot_sequence;
			request.captured_deltas = object->migration.delta_count;
			request.migration_phase = EBPFOS_MIGRATION_CAPTURING;
		} else {
			request.snapshot_sequence =
				object->last_snapshot_sequence;
			request.captured_deltas = object->last_captured_deltas;
			request.migration_phase = EBPFOS_MIGRATION_IDLE;
		}
	}
	mutex_unlock(&object->lock);
	if (error)
		return error;
	return copy_to_user(argp, &request, sizeof(request)) ? -EFAULT : 0;
}

static long ebpfos_provider_stats_ioctl(struct ebpfos_cap_file *cap,
					void __user *argp)
{
	struct ebpfos_ioc_provider_stats request;
	struct ebpfos_object *object = cap->object;
	struct ebpfos_provider *provider;
	u64 provider_id;
	u32 i;
	int error = -ENOENT;

	if (!(cap->rights & EBPFOS_RIGHT_INSPECT))
		return -EACCES;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	provider_id = request.provider_id;
	mutex_lock(&object->lock);
	list_for_each_entry(provider, &object->providers, node) {
		if (provider->id != provider_id)
			continue;
		ebpfos_provider_snapshot(provider, &request);
		request.active = provider == object->active && provider->active;
		error = 0;
		break;
	}
	if (error) {
		for (i = 0; i < EBPFOS_PROVIDER_HISTORY_CAPACITY; i++) {
			if (object->provider_history[i].provider_id != provider_id)
				continue;
			request = object->provider_history[i];
			error = 0;
			break;
		}
	}
	mutex_unlock(&object->lock);
	if (error)
		return error;
	return copy_to_user(argp, &request, sizeof(request)) ? -EFAULT : 0;
}

static long ebpfos_audit_get_ioctl(struct ebpfos_cap_file *cap,
				   void __user *argp)
{
	struct ebpfos_ioc_audit_get request;
	struct ebpfos_object *object = cap->object;
	int error = 0;

	if (!(cap->rights & EBPFOS_RIGHT_INSPECT))
		return -EACCES;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	mutex_lock(&object->lock);
	if (!request.sequence || request.sequence > object->last_sequence ||
	    object->last_sequence - request.sequence >=
		EBPFOS_OBJECT_AUDIT_CAPACITY) {
		error = -ENOENT;
	} else {
		request.record = object->audit[(request.sequence - 1) %
					       EBPFOS_OBJECT_AUDIT_CAPACITY];
		if (request.record.sequence != request.sequence)
			error = -ENOENT;
	}
	mutex_unlock(&object->lock);
	if (error)
		return error;
	return copy_to_user(argp, &request, sizeof(request)) ? -EFAULT : 0;
}

static long ebpfos_object_ioctl(struct file *file, unsigned int command,
				unsigned long argument)
{
	struct ebpfos_cap_file *cap = file->private_data;
	void __user *argp = (void __user *)argument;

	switch (command) {
	case EBPFOS_IOC_CAP_DERIVE:
		return ebpfos_cap_derive_ioctl(cap, argp);
	case EBPFOS_IOC_CAP_INFO:
		return ebpfos_cap_info_ioctl(cap, argp);
	case EBPFOS_IOC_CALL:
		return ebpfos_call_ioctl(cap, argp);
	case EBPFOS_IOC_REPLACE_BEGIN:
		return ebpfos_replace_begin_ioctl(cap, argp);
	case EBPFOS_IOC_REPLACE_COMMIT:
		return ebpfos_replace_commit_ioctl(cap, argp);
	case EBPFOS_IOC_REPLACE_ABORT:
		return ebpfos_replace_abort_ioctl(cap, argp);
	case EBPFOS_IOC_OBJECT_STATUS:
		return ebpfos_object_status_ioctl(cap, argp);
	case EBPFOS_IOC_PROVIDER_STATS:
		return ebpfos_provider_stats_ioctl(cap, argp);
	case EBPFOS_IOC_AUDIT_GET:
		return ebpfos_audit_get_ioctl(cap, argp);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations ebpfos_object_fops = {
	.owner = THIS_MODULE,
	.read = ebpfos_object_read,
	.write = ebpfos_object_write,
	.release = ebpfos_object_release,
	.unlocked_ioctl = ebpfos_object_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = ebpfos_object_ioctl,
#endif
	.llseek = noop_llseek,
};

long ebpfos_object_create_ioctl(void __user *argp)
{
	struct ebpfos_ioc_object_create request;
	struct ebpfos_object *object;
	struct file *file;
	u64 capability_id;
	int fd;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags || request.initial_state[1])
		return -EINVAL;

	object = ebpfos_object_alloc(request.contract_id,
				     request.rights_ceiling,
				     request.initial_state[0]);
	if (IS_ERR(object))
		return PTR_ERR(object);
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		ebpfos_object_put(object);
		return fd;
	}
	file = ebpfos_cap_getfile(object, request.rights_ceiling,
				  &capability_id);
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		ebpfos_object_put(object);
		return PTR_ERR(file);
	}
	request.object_id = object->id;
	request.object_fd = fd;
	if (copy_to_user(argp, &request, sizeof(request))) {
		fput(file);
		put_unused_fd(fd);
		ebpfos_object_put(object);
		return -EFAULT;
	}
	fd_install(fd, file);
	ebpfos_object_put(object);
	return 0;
}
