// SPDX-License-Identifier: GPL-2.0-only
#include <linux/anon_inodes.h>
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/build_bug.h>
#include <linux/capability.h>
#include <linux/ebpfos.h>
#include <linux/file.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/kref.h>
#include <linux/lockdep.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#define EBPFOS_COMPONENT_CALL_PROG_FLAGS 0x410U

#define EBPFOS_ASSERT_OFFSET(_type, _field, _offset) \
	static_assert(offsetof(struct _type, _field) == (_offset))

static_assert(sizeof(struct ebpfos_component_desc_v1) ==
	      EBPFOS_COMPONENT_DESC_V1_SIZE);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, magic, 0);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, format_version, 8);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, header_size, 10);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, total_size, 12);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, reserved_flags, 16);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, domain, 20);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, use, 24);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, reserved_header, 28);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, reserved_identity, 40);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, abi_id, 496);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, abi_version, 504);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, context_size, 508);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, reserved_attributes, 512);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, prog_type, 536);
EBPFOS_ASSERT_OFFSET(ebpfos_component_desc_v1, reserved_payload, 540);

static_assert(sizeof(struct ebpfos_ioc_admission_seal) == 1168);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_seal, map_fds, 16);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_seal, descriptor, 24);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_seal, admission_fd, 1048);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_seal, grant_id, 1056);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_seal, reserved_digests, 1072);
static_assert(sizeof(struct ebpfos_ioc_admission_info) == 1152);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_info, descriptor, 128);
static_assert(sizeof(struct ebpfos_ioc_admission_runtime_info) == 96);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_runtime_info,
		     reserved_rehashes, 24);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_runtime_info,
			     invocation_entries, 32);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_runtime_info,
		     reserved_digest, 40);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_runtime_info, retired_epoch, 72);
EBPFOS_ASSERT_OFFSET(ebpfos_ioc_admission_runtime_info,
		     entries_at_publication, 80);
static_assert(BPF_PROG_TYPE_SYSCALL == 31);
static_assert((BPF_F_EBPFOS_COMPONENT | BPF_F_SLEEPABLE) ==
	      EBPFOS_COMPONENT_CALL_PROG_FLAGS);
static_assert(sizeof(struct ebpfos_component_call_frame) ==
	      EBPFOS_COMPONENT_CALL_CONTEXT_SIZE);
static_assert(EBPFOS_COMPONENT_IRQ_ARG_COUNT == MAX_BPF_FUNC_ARGS);
static_assert(sizeof(struct ebpfos_component_irq_frame) ==
	      EBPFOS_COMPONENT_IRQ_CONTEXT_SIZE);

enum ebpfos_prog_seal_state {
	EBPFOS_PROG_SEALING = 1,
	EBPFOS_PROG_SEALED = 2,
};

struct ebpfos_prog_identity {
	refcount_t refs;
	u32 seal_state;
	struct ebpfos_component_desc_v1 descriptor;
};

struct ebpfos_admission {
	struct kref ref;
	/* Serializes one-shot transitions shared by duplicated grant FDs. */
	spinlock_t state_lock;
	struct ebpfos_binding *binding;
	u32 state;
};

static DEFINE_MUTEX(ebpfos_publish_gate);
static DEFINE_MUTEX(ebpfos_seal_lock);
static u64 ebpfos_staged_grants;

static const struct file_operations ebpfos_admission_fops;

static int ebpfos_validate_component_descriptor(
	const struct ebpfos_component_desc_v1 *descriptor)
{
	u64 abi_id = le64_to_cpu(descriptor->abi_id);
	u32 context_size = le32_to_cpu(descriptor->context_size);
	u32 prog_type = le32_to_cpu(descriptor->prog_type);

	if (prog_type == BPF_PROG_TYPE_SYSCALL &&
	    abi_id == EBPFOS_COMPONENT_CALL_ABI_ID &&
	    le32_to_cpu(descriptor->abi_version) ==
		EBPFOS_COMPONENT_CALL_ABI_VERSION &&
	    context_size == EBPFOS_COMPONENT_CALL_CONTEXT_SIZE)
		return 0;
	if (prog_type == BPF_PROG_TYPE_RAW_TRACEPOINT &&
	    abi_id == EBPFOS_COMPONENT_IRQ_ABI_ID &&
	    le32_to_cpu(descriptor->abi_version) ==
		EBPFOS_COMPONENT_IRQ_ABI_VERSION &&
	    context_size == EBPFOS_COMPONENT_IRQ_CONTEXT_SIZE)
		return 0;
	return -EPROTO;
}

void ebpfos_admission_gate_lock(void)
{
	mutex_lock(&ebpfos_publish_gate);
}

void ebpfos_admission_gate_unlock(void)
{
	mutex_unlock(&ebpfos_publish_gate);
}

static struct ebpfos_prog_identity *
ebpfos_prog_identity_get(struct ebpfos_prog_identity *identity)
{
	if (identity)
		refcount_inc(&identity->refs);
	return identity;
}

void ebpfos_prog_identity_put(struct ebpfos_prog_identity *identity)
{
	if (identity && refcount_dec_and_test(&identity->refs)) {
		kfree(identity);
	}
}

struct ebpfos_binding *ebpfos_binding_get(struct ebpfos_binding *binding)
{
	if (binding)
		refcount_inc(&binding->refs);
	return binding;
}

void ebpfos_binding_put(struct ebpfos_binding *binding)
{
	u32 i;

	if (!binding || !refcount_dec_and_test(&binding->refs))
		return;
	if (binding->prog)
		bpf_prog_put(binding->prog);
	for (i = 0; i < binding->map_count; i++)
		bpf_map_put(binding->maps[i]);
	kfree(binding->maps);
	ebpfos_prog_identity_put(binding->prog_identity);
	kfree(binding);
}

#define EBPFOS_BINDING_ACTIVE_BITS 16
#define EBPFOS_BINDING_ACTIVE_MASK ((1ULL << EBPFOS_BINDING_ACTIVE_BITS) - 1)
#define EBPFOS_BINDING_ENTRY_ONE (1ULL << EBPFOS_BINDING_ACTIVE_BITS)
#define EBPFOS_BINDING_ENTRY_BITS 47
#define EBPFOS_BINDING_ENTRY_MASK \
	(((1ULL << EBPFOS_BINDING_ENTRY_BITS) - 1) << \
	 EBPFOS_BINDING_ACTIVE_BITS)
#define EBPFOS_BINDING_RETIRED BIT_ULL(63)

static void ebpfos_binding_decode_invocation_state(u64 state, u32 *active,
						   u64 *entries)
{
	*active = (u32)(state & EBPFOS_BINDING_ACTIVE_MASK);
	*entries = (state & EBPFOS_BINDING_ENTRY_MASK) >>
		EBPFOS_BINDING_ACTIVE_BITS;
}

int ebpfos_binding_invocation_enter(struct ebpfos_binding *binding)
{
	u64 old, new;

	if (!binding)
		return -EINVAL;
	do {
		old = atomic64_read(&binding->invocation_state);
		if (old & EBPFOS_BINDING_RETIRED)
			return -ESHUTDOWN;
		if ((old & EBPFOS_BINDING_ACTIVE_MASK) ==
		    EBPFOS_BINDING_ACTIVE_MASK ||
		    (old & EBPFOS_BINDING_ENTRY_MASK) ==
		    EBPFOS_BINDING_ENTRY_MASK)
			return -EOVERFLOW;
		new = old + EBPFOS_BINDING_ENTRY_ONE + 1;
	} while (atomic64_cmpxchg(&binding->invocation_state, old, new) != old);
	return 0;
}

void ebpfos_binding_invocation_exit(struct ebpfos_binding *binding)
{
	u64 old, new;

	if (!binding)
		return;
	do {
		old = atomic64_read(&binding->invocation_state);
		if (WARN_ON_ONCE(!(old & EBPFOS_BINDING_ACTIVE_MASK)))
			return;
		new = old - 1;
	} while (atomic64_cmpxchg(&binding->invocation_state, old, new) != old);
}

u32 ebpfos_binding_active_invocations(const struct ebpfos_binding *binding)
{
	return binding ? (u32)(atomic64_read(&binding->invocation_state) &
			       EBPFOS_BINDING_ACTIVE_MASK) : 0;
}

u64 ebpfos_binding_invocation_entries(const struct ebpfos_binding *binding)
{
	return binding ? (atomic64_read(&binding->invocation_state) &
		EBPFOS_BINDING_ENTRY_MASK) >> EBPFOS_BINDING_ACTIVE_BITS : 0;
}

bool ebpfos_binding_is_retired(const struct ebpfos_binding *binding)
{
	return binding && (atomic64_read(&binding->invocation_state) &
			   EBPFOS_BINDING_RETIRED);
}

void ebpfos_binding_retire(struct ebpfos_binding *binding, u64 epoch)
{
	u64 old, new;

	if (!binding || !epoch)
		return;
	do {
		old = atomic64_read(&binding->invocation_state);
		if (WARN_ON_ONCE(old & EBPFOS_BINDING_RETIRED))
			return;
		new = old | EBPFOS_BINDING_RETIRED;
	} while (atomic64_cmpxchg(&binding->invocation_state, old, new) != old);
	/* One immutable pre-retirement word backs both decoded UAPI fields. */
	WRITE_ONCE(binding->retirement_snapshot, old);
	smp_store_release(&binding->retired_epoch, epoch);
}

static void ebpfos_admission_release_kref(struct kref *ref)
{
	struct ebpfos_admission *admission =
		container_of(ref, struct ebpfos_admission, ref);

	mutex_lock(&ebpfos_publish_gate);
	ebpfos_admission_burn_locked(admission);
	mutex_unlock(&ebpfos_publish_gate);
	ebpfos_binding_put(admission->binding);
	kfree(admission);
}

void ebpfos_admission_put(struct ebpfos_admission *admission)
{
	if (admission) {
		lockdep_assert_not_held(&ebpfos_publish_gate);
		kref_put(&admission->ref, ebpfos_admission_release_kref);
	}
}

static int ebpfos_admission_release(struct inode *inode, struct file *file)
{
	ebpfos_admission_put(file->private_data);
	return 0;
}

static const struct file_operations ebpfos_admission_fops = {
	.owner = THIS_MODULE,
	.release = ebpfos_admission_release,
	.llseek = noop_llseek,
};

struct ebpfos_admission *ebpfos_admission_get_from_fd(int fd)
{
	struct ebpfos_admission *admission;
	struct file *file;

	file = fget(fd);
	if (!file)
		return ERR_PTR(-EBADF);
	if (file->f_op != &ebpfos_admission_fops) {
		fput(file);
		return ERR_PTR(-EINVAL);
	}
	admission = file->private_data;
	kref_get(&admission->ref);
	fput(file);
	return admission;
}

static struct ebpfos_binding *
ebpfos_binding_alloc_bpf(struct bpf_prog *prog, struct bpf_map **maps,
			 u32 map_count, struct ebpfos_prog_identity *identity)
{
	struct ebpfos_binding *binding;

	binding = kzalloc_obj(*binding, GFP_KERNEL);
	if (!binding)
		return NULL;
	refcount_set(&binding->refs, 1);
	atomic64_set(&binding->invocation_state, 0);
	binding->prog = prog;
	binding->maps = maps;
	binding->map_count = map_count;
	binding->map = map_count ? maps[0] : NULL;
	binding->prog_identity = ebpfos_prog_identity_get(identity);
	binding->prog_id = prog->aux->id;
	binding->map_id = binding->map ? binding->map->id : 0;
	return binding;
}

const struct ebpfos_component_desc_v1 *
ebpfos_binding_descriptor(const struct ebpfos_binding *binding)
{
	return binding && binding->prog_identity ?
	       &binding->prog_identity->descriptor : NULL;
}

struct bpf_prog *ebpfos_binding_prog(const struct ebpfos_binding *binding)
{
	return binding ? binding->prog : NULL;
}

struct bpf_map *ebpfos_binding_map(const struct ebpfos_binding *binding)
{
	return binding ? binding->map : NULL;
}

static bool ebpfos_map_owner_matches(struct bpf_prog *prog,
				     struct bpf_map *map)
{
	bool matches;

	spin_lock_bh(&map->owner_lock);
	matches = map->ebpfos_component_owner == prog->aux &&
		  map->ebpfos_prog_users == 1 &&
		  !map->ebpfos_external_writers &&
		  !map->ebpfos_user_mmaps &&
		  !atomic64_read(&map->writecnt) &&
		  !map->ebpfos_external_gp_refs &&
		  !map->ebpfos_external_next_refs &&
		  !map->ebpfos_external_gp_queued;
	spin_unlock_bh(&map->owner_lock);
	return matches;
}

static int ebpfos_check_program(struct bpf_prog *prog,
				struct bpf_map *const *maps, u32 map_count,
				struct ebpfos_prog_identity *expected_identity)
{
	u32 i, j;
	bool externally_reachable;
	int error = 0;

	if (!prog->aux->ebpfos_component ||
	    !((prog->type == BPF_PROG_TYPE_SYSCALL && prog->sleepable) ||
	      (prog->type == BPF_PROG_TYPE_RAW_TRACEPOINT && !prog->sleepable)))
		return -EKEYREJECTED;
	mutex_lock(&prog->aux->used_maps_mutex);
	if (prog->aux->used_map_cnt != map_count ||
	    (expected_identity &&
	     READ_ONCE(prog->aux->ebpfos_identity) != expected_identity)) {
		error = -EXDEV;
		goto out_unlock_maps;
	}
	for (i = 0; i < map_count; i++) {
		struct bpf_map *map = maps[i];
		bool found = false;

		/* Nested maps and program arrays need package-wide leases. */
		if (map->inner_map_meta || map->map_type == BPF_MAP_TYPE_PROG_ARRAY ||
		    !ebpfos_map_owner_matches(prog, map)) {
			error = -EXDEV;
			goto out_unlock_maps;
		}
		for (j = 0; j < map_count; j++)
			if (prog->aux->used_maps[j] == map) {
				found = true;
				break;
			}
		if (!found) {
			error = -EXDEV;
			goto out_unlock_maps;
		}
		for (j = 0; j < i; j++)
			if (maps[j] == map) {
				error = -EINVAL;
				goto out_unlock_maps;
			}
	}
	mutex_lock(&prog->aux->ext_mutex);
	externally_reachable = prog->aux->is_extended ||
			       prog->aux->prog_array_member_cnt;
	mutex_unlock(&prog->aux->ext_mutex);
	if (externally_reachable)
		error = -EBUSY;
out_unlock_maps:
	mutex_unlock(&prog->aux->used_maps_mutex);
	return error;
}

static struct ebpfos_prog_identity *
ebpfos_prog_identity_alloc(const struct ebpfos_component_desc_v1 *descriptor)
{
	struct ebpfos_prog_identity *identity;

	identity = kzalloc_obj(*identity, GFP_KERNEL);
	if (!identity)
		return NULL;
	refcount_set(&identity->refs, 1);
	identity->seal_state = EBPFOS_PROG_SEALING;
	identity->descriptor = *descriptor;
	return identity;
}

static struct ebpfos_admission *
ebpfos_admission_alloc(struct ebpfos_binding *binding)
{
	struct ebpfos_admission *admission;

	admission = kzalloc_obj(*admission, GFP_KERNEL);
	if (!admission)
		return NULL;
	kref_init(&admission->ref);
	spin_lock_init(&admission->state_lock);
	admission->binding = binding;
	admission->state = EBPFOS_ADMISSION_FRESH;
	return admission;
}

long ebpfos_admission_seal_ioctl(void __user *argp)
{
	struct ebpfos_ioc_admission_seal request;
	struct ebpfos_prog_identity *identity = NULL;
	struct ebpfos_admission *admission = NULL;
	struct ebpfos_binding *binding = NULL;
	struct bpf_prog *prog = NULL;
	struct bpf_map **maps = NULL;
	struct file *admission_file = NULL;
	int *map_fds = NULL;
	u32 map_count, i;
	int fd = -1;
	int error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.map_count > MAX_USED_MAPS ||
	    (request.map_count && !request.map_fds))
		return -EINVAL;
	error = ebpfos_validate_component_descriptor(&request.descriptor);
	if (error)
		return error;
	prog = bpf_prog_get_type_dev(request.prog_fd,
		le32_to_cpu(request.descriptor.prog_type), false);
	if (IS_ERR(prog))
		return PTR_ERR(prog);
	map_count = request.map_count ? request.map_count :
		    (request.map_fd >= 0 ? 1 : 0);
	if (request.map_count) {
		map_fds = memdup_user(u64_to_user_ptr(request.map_fds),
				      sizeof(*map_fds) * map_count);
		if (IS_ERR(map_fds)) {
			error = PTR_ERR(map_fds);
			map_fds = NULL;
			goto out_put_prog;
		}
	}
	if (map_count) {
		maps = kcalloc(map_count, sizeof(*maps), GFP_KERNEL);
		if (!maps) {
			error = -ENOMEM;
			goto out_put_map;
		}
		for (i = 0; i < map_count; i++) {
			maps[i] = bpf_map_get(map_fds ? map_fds[i] : request.map_fd);
			if (IS_ERR(maps[i])) {
				error = PTR_ERR(maps[i]);
				maps[i] = NULL;
				goto out_put_map;
			}
		}
	}
	kfree(map_fds);
	map_fds = NULL;
	error = ebpfos_check_program(prog, maps, map_count, NULL);
	if (error)
		goto out_put_map;
	identity = ebpfos_prog_identity_alloc(&request.descriptor);
	if (!identity) {
		error = -ENOMEM;
		goto out_put_map;
	}
	binding = ebpfos_binding_alloc_bpf(prog, maps, map_count, identity);
	if (!binding) {
		error = -ENOMEM;
		goto out_put_identity;
	}
	/* Binding owns the program and all map references. */
	prog = NULL;
	maps = NULL;
	admission = ebpfos_admission_alloc(binding);
	if (!admission) {
		error = -ENOMEM;
		goto out_put_binding;
	}
	binding = NULL;
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		error = fd;
		goto out_put_admission;
	}
	admission_file = anon_inode_getfile("[ebpfos-admission]",
					    &ebpfos_admission_fops,
					    admission, O_RDWR);
	if (IS_ERR(admission_file)) {
		error = PTR_ERR(admission_file);
		admission_file = NULL;
		goto out_put_fd;
	}
	request.admission_fd = fd;
	request.admission_state = EBPFOS_ADMISSION_FRESH;
	request.grant_id = 0;
	request.prog_id = admission->binding->prog_id;
	request.map_id = admission->binding->map_id;
	memset(request.reserved_digests, 0, sizeof(request.reserved_digests));

	mutex_lock(&ebpfos_publish_gate);
	mutex_lock(&ebpfos_seal_lock);
	prog = admission->binding->prog;
	maps = admission->binding->maps;
	if (READ_ONCE(prog->aux->ebpfos_identity)) {
		error = -EALREADY;
		goto out_unlock_seal;
	}
	error = ebpfos_check_program(prog, maps, map_count, NULL);
	if (error)
		goto out_unlock_seal;
	WRITE_ONCE(prog->aux->ebpfos_identity, identity);
	mutex_unlock(&ebpfos_seal_lock);
	mutex_unlock(&ebpfos_publish_gate);

	if (copy_to_user(argp, &request, sizeof(request))) {
		mutex_lock(&ebpfos_seal_lock);
		if (WARN_ON_ONCE(READ_ONCE(prog->aux->ebpfos_identity) !=
				 identity)) {
			mutex_unlock(&ebpfos_seal_lock);
			error = -EUCLEAN;
			goto out_release_file;
		}
		WRITE_ONCE(prog->aux->ebpfos_identity, NULL);
		mutex_unlock(&ebpfos_seal_lock);
		error = -EFAULT;
		goto out_release_file;
	}
	mutex_lock(&ebpfos_seal_lock);
	if (WARN_ON_ONCE(READ_ONCE(prog->aux->ebpfos_identity) != identity)) {
		mutex_unlock(&ebpfos_seal_lock);
		error = -EUCLEAN;
		goto out_release_file;
	}
	WRITE_ONCE(identity->seal_state, EBPFOS_PROG_SEALED);
	mutex_unlock(&ebpfos_seal_lock);
	fd_install(fd, admission_file);
	return 0;

out_unlock_seal:
	mutex_unlock(&ebpfos_seal_lock);
	mutex_unlock(&ebpfos_publish_gate);
out_release_file:
	prog = NULL;
	maps = NULL;
	fput(admission_file);
	admission_file = NULL;
	admission = NULL;
out_put_fd:
	put_unused_fd(fd);
out_put_admission:
	if (admission)
		ebpfos_admission_put(admission);
out_put_binding:
	ebpfos_binding_put(binding);
out_put_identity:
	ebpfos_prog_identity_put(identity);
out_put_map:
	if (maps) {
		for (i = 0; i < map_count; i++)
			if (maps[i])
				bpf_map_put(maps[i]);
		kfree(maps);
	}
	kfree(map_fds);
out_put_prog:
	if (prog)
		bpf_prog_put(prog);
	return error;
}

static u32 ebpfos_admission_effective_state_locked(
	struct ebpfos_admission *admission)
{
	u32 state;

	lockdep_assert_held(&ebpfos_publish_gate);
	spin_lock(&admission->state_lock);
	state = admission->state;
	spin_unlock(&admission->state_lock);
	return state;
}

struct ebpfos_binding *
ebpfos_admission_binding_get(struct ebpfos_admission *admission)
{
	return admission ? ebpfos_binding_get(admission->binding) : NULL;
}

long ebpfos_admission_info_ioctl(void __user *argp)
{
	struct ebpfos_ioc_admission_info request;
	struct ebpfos_admission *admission;
	struct ebpfos_binding *binding;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	admission = ebpfos_admission_get_from_fd(request.admission_fd);
	if (IS_ERR(admission))
		return PTR_ERR(admission);
	binding = admission->binding;
	mutex_lock(&ebpfos_publish_gate);
	request.grant_id = 0;
	request.admission_state =
		ebpfos_admission_effective_state_locked(admission);
	request.prog_id = binding->prog_id;
	request.map_id = binding->map_id;
	request.flags = 0;
	request.reserved0 = 0;
	memset(request.reserved_digests, 0, sizeof(request.reserved_digests));
	request.descriptor = binding->prog_identity->descriptor;
	mutex_unlock(&ebpfos_publish_gate);
	ebpfos_admission_put(admission);
	return copy_to_user(argp, &request, sizeof(request)) ? -EFAULT : 0;
}

long ebpfos_admission_runtime_info_ioctl(void __user *argp)
{
	struct ebpfos_ioc_admission_runtime_info request;
	struct ebpfos_admission *admission;
	struct ebpfos_binding *binding;

	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	admission = ebpfos_admission_get_from_fd(request.admission_fd);
	if (IS_ERR(admission))
		return PTR_ERR(admission);
	binding = admission->binding;
	request.version = EBPFOS_ADMISSION_RUNTIME_INFO_VERSION;
	request.flags = 0;
	request.prog_id = binding->prog_id;
	request.map_id = binding->map_id;
	request.reserved_rehashes = 0;
	/* Both values are decoded from one atomic snapshot. */
	{
		u64 state = atomic64_read(&binding->invocation_state);

		ebpfos_binding_decode_invocation_state(
			state, &request.active_invocations,
			&request.invocation_entries);
	}
	memset(request.reserved_digest, 0, sizeof(request.reserved_digest));
	request.retired_epoch = smp_load_acquire(&binding->retired_epoch);
	request.entries_at_publication = 0;
	request.active_at_publication = 0;
	request.reserved2 = 0;
	if (request.retired_epoch) {
		u64 snapshot = READ_ONCE(binding->retirement_snapshot);

		request.active_at_publication =
			(u32)(snapshot & EBPFOS_BINDING_ACTIVE_MASK);
		request.entries_at_publication =
			(snapshot & EBPFOS_BINDING_ENTRY_MASK) >>
			EBPFOS_BINDING_ACTIVE_BITS;
	}
	ebpfos_admission_put(admission);
	return copy_to_user(argp, &request, sizeof(request)) ? -EFAULT : 0;
}

static int ebpfos_admission_owner_recheck(struct ebpfos_admission *admission)
{
	struct ebpfos_binding *binding = admission->binding;

	if (READ_ONCE(binding->prog_identity->seal_state) !=
	    EBPFOS_PROG_SEALED)
		return -EKEYREJECTED;
	return ebpfos_check_program(binding->prog, binding->maps,
				    binding->map_count,
				    binding->prog_identity);
}

int ebpfos_admission_stage_bundle_locked(
	struct ebpfos_admission **grants, unsigned int count)
{
	unsigned int index, prior;
	u64 staged_grants;
	int error;

	lockdep_assert_held(&ebpfos_publish_gate);
	if (!grants || !count || count > EBPFOS_EXECUTOR_ROOT_MAX_ROLES)
		return -EINVAL;
	for (index = 0; index < count; index++) {
		struct ebpfos_admission *grant = grants[index];
		u32 state;

		if (!grant || !grant->binding)
			return -EINVAL;
		if (!!grant->binding->map_count != !!grant->binding->map)
			return -EUCLEAN;
		for (prior = 0; prior < index; prior++)
			if (grant == grants[prior])
				return -EUCLEAN;
		spin_lock(&grant->state_lock);
		state = grant->state;
		spin_unlock(&grant->state_lock);
		if (state != EBPFOS_ADMISSION_FRESH)
			return state == EBPFOS_ADMISSION_STAGED ? -EBUSY : -EALREADY;
		/* Recheck the state lease immediately before publication. */
		error = ebpfos_admission_owner_recheck(grant);
		if (error)
			return error;
	}
	if (check_add_overflow(ebpfos_staged_grants, (u64)count,
			       &staged_grants))
		return -EOVERFLOW;
	ebpfos_staged_grants = staged_grants;
	/*
	 * The admission gate excludes every state transition, so after the full
	 * validation pass these individual state locks cannot expose a partial
	 * bundle to another admission operation.
	 */
	for (index = 0; index < count; index++) {
		spin_lock(&grants[index]->state_lock);
		WARN_ON_ONCE(grants[index]->state != EBPFOS_ADMISSION_FRESH);
		grants[index]->state = EBPFOS_ADMISSION_STAGED;
		spin_unlock(&grants[index]->state_lock);
	}
	return 0;
}

int ebpfos_admission_consume_bundle_locked(
	struct ebpfos_admission **grants, unsigned int count)
{
	unsigned int index;
	u32 state;

	lockdep_assert_held(&ebpfos_publish_gate);
	if (!grants || !count || count > EBPFOS_EXECUTOR_ROOT_MAX_ROLES)
		return -EINVAL;
	for (index = 0; index < count; index++) {
		if (!grants[index])
			return -EINVAL;
		spin_lock(&grants[index]->state_lock);
		state = grants[index]->state;
		spin_unlock(&grants[index]->state_lock);
		if (state != EBPFOS_ADMISSION_STAGED)
			return -ESTALE;
	}
	if (ebpfos_staged_grants < count)
		return -EUCLEAN;
	for (index = 0; index < count; index++) {
		spin_lock(&grants[index]->state_lock);
		grants[index]->state = EBPFOS_ADMISSION_CONSUMED;
		spin_unlock(&grants[index]->state_lock);
	}
	ebpfos_staged_grants -= count;
	return 0;
}

void ebpfos_admission_burn_locked(struct ebpfos_admission *admission)
{
	lockdep_assert_held(&ebpfos_publish_gate);
	if (!admission)
		return;
	spin_lock(&admission->state_lock);
	if (admission->state == EBPFOS_ADMISSION_STAGED ||
	    admission->state == EBPFOS_ADMISSION_STAGED_RECOVERY) {
		admission->state = EBPFOS_ADMISSION_BURNED;
		if (WARN_ON_ONCE(!ebpfos_staged_grants)) {
			/* Preserve the terminal grant state despite bad accounting. */
		} else {
			ebpfos_staged_grants--;
		}
	}
	spin_unlock(&admission->state_lock);
}

void ebpfos_admission_burn_set_locked(struct ebpfos_admission **grants,
				      unsigned int count)
{
	unsigned int index;

	lockdep_assert_held(&ebpfos_publish_gate);
	if (!grants)
		return;
	/*
	 * Cleanup is deliberately tolerant where consume is atomic and strict:
	 * nulls, duplicate pointers, duplicate IDs, and a partially invalid set
	 * must still drive every reachable staged grant to a terminal state.  A
	 * grant is locked separately, so duplicates never cause recursive locks.
	 */
	for (index = 0; index < count; index++)
		ebpfos_admission_burn_locked(grants[index]);
}
