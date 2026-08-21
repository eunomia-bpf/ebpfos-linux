// SPDX-License-Identifier: GPL-2.0-only
#include <crypto/sha2.h>
#include <linux/anon_inodes.h>
#include <linux/capability.h>
#include <linux/ebpfos.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#define EBPFOS_ASSERT_OFFSET(_type, _field, _offset) \
	static_assert(offsetof(struct _type, _field) == (_offset))

static_assert(sizeof(struct ebpfos_state_adapter_role_v1) ==
	      EBPFOS_STATE_ADAPTER_ROLE_V1_SIZE);
static_assert(sizeof(struct ebpfos_state_adapter_program_v1) ==
	      EBPFOS_STATE_ADAPTER_PROGRAM_V1_SIZE);
static_assert(sizeof(struct ebpfos_state_adapter_record_v1) ==
	      EBPFOS_STATE_ADAPTER_RECORD_V1_SIZE);
EBPFOS_ASSERT_OFFSET(ebpfos_state_adapter_record_v1, realm_id, 32);
EBPFOS_ASSERT_OFFSET(ebpfos_state_adapter_record_v1, policy_generation, 48);
EBPFOS_ASSERT_OFFSET(ebpfos_state_adapter_record_v1,
		     policy_record_digest, 56);
EBPFOS_ASSERT_OFFSET(ebpfos_state_adapter_record_v1, adapter_id, 120);
EBPFOS_ASSERT_OFFSET(ebpfos_state_adapter_record_v1,
		     source_runtime_schema_u64, 144);
EBPFOS_ASSERT_OFFSET(ebpfos_state_adapter_record_v1, target_reader, 224);
EBPFOS_ASSERT_OFFSET(ebpfos_state_adapter_record_v1, target_writer, 320);
EBPFOS_ASSERT_OFFSET(ebpfos_state_adapter_record_v1, program, 432);
EBPFOS_ASSERT_OFFSET(ebpfos_state_adapter_record_v1, program_sha256, 488);
EBPFOS_ASSERT_OFFSET(ebpfos_state_adapter_record_v1, reserved, 536);

static const u8 ebpfos_state_adapter_content_domain[] =
	"eBPFOS-state-adapter-content-v1";
static const u8 ebpfos_state_adapter_program_domain[] =
	"eBPFOS-adapter-program-v1";
static const u8 ebpfos_state_adapter_role_domain[] =
	"eBPFOS-adapter-target-role-v1";
static const u8 ebpfos_split_adapter_id[16] = "split-v1-to-v2";

struct ebpfos_state_adapter {
	struct ebpfos_state_adapter_record_v1 record;
	u8 content_digest[SHA256_DIGEST_SIZE];
};

static const struct file_operations ebpfos_state_adapter_fops;

static bool ebpfos_state_adapter_all_zero(const void *data, size_t size)
{
	return !memchr_inv(data, 0, size);
}

static bool ebpfos_state_adapter_nonzero(const void *data, size_t size)
{
	return !!memchr_inv(data, 0, size);
}

static void ebpfos_state_adapter_hash(const u8 *domain, size_t domain_size,
				      const void *record, size_t record_size,
				      u8 digest[SHA256_DIGEST_SIZE])
{
	struct sha256_ctx context;

	sha256_init(&context);
	sha256_update(&context, domain, domain_size);
	sha256_update(&context, record, record_size);
	sha256_final(&context, digest);
}

static void ebpfos_state_adapter_role_digest(
	const struct ebpfos_state_adapter_role_v1 *role,
	u8 digest[SHA256_DIGEST_SIZE])
{
	struct ebpfos_state_adapter_role_v1 canonical = *role;

	memset(canonical.role_digest, 0, sizeof(canonical.role_digest));
	ebpfos_state_adapter_hash(ebpfos_state_adapter_role_domain,
				  sizeof(ebpfos_state_adapter_role_domain),
				  &canonical, sizeof(canonical), digest);
}

static int ebpfos_state_adapter_validate_role(
	const struct ebpfos_state_adapter_role_v1 *role, u32 expected_role,
	u64 expected_provider_type, u64 expected_capabilities, u64 target_schema)
{
	u8 digest[SHA256_DIGEST_SIZE];

	if (le32_to_cpu(role->role) != expected_role ||
	    le32_to_cpu(role->reserved0) ||
	    le64_to_cpu(role->provider_type_id) != expected_provider_type ||
	    le64_to_cpu(role->transition_id) !=
		EBPFOS_STATE_ADAPTER_SPLIT_TRANSITION_ID ||
	    le64_to_cpu(role->runtime_schema_u64) != target_schema ||
	    !ebpfos_state_adapter_all_zero(role->reserved,
					  sizeof(role->reserved)))
		return -EPROTOTYPE;
	if (le64_to_cpu(role->capability_mask) != expected_capabilities)
		return -EACCES;
	ebpfos_state_adapter_role_digest(role, digest);
	return memcmp(role->role_digest, digest, sizeof(digest)) ?
		-EBADMSG : 0;
}

static int ebpfos_state_adapter_validate_record(
	const struct ebpfos_state_adapter_record_v1 *record)
{
	u8 program_digest[SHA256_DIGEST_SIZE];
	u64 target_schema = le64_to_cpu(record->target_runtime_schema_u64);
	int error;

	if (memcmp(record->magic, EBPFOS_STATE_ADAPTER_RECORD_V1_MAGIC,
		   sizeof(record->magic)) ||
	    le16_to_cpu(record->format_version) !=
		EBPFOS_ADMISSION_FORMAT_VERSION ||
	    le16_to_cpu(record->header_size) != sizeof(*record) ||
	    le32_to_cpu(record->total_size) != sizeof(*record))
		return -EPROTO;
	if (le32_to_cpu(record->flags) !=
		EBPFOS_STATE_ADAPTER_F_TEST_ONLY ||
	    le32_to_cpu(record->domain) != EBPFOS_COMPONENT_DOMAIN_FILE ||
	    le32_to_cpu(record->adapter_kind) !=
		EBPFOS_STATE_ADAPTER_BOUNDED_COPY ||
	    le32_to_cpu(record->reserved0) ||
	    memcmp(record->adapter_id, ebpfos_split_adapter_id,
		   sizeof(record->adapter_id)) ||
	    le64_to_cpu(record->adapter_version) != 1)
		return -EACCES;
	if (!le64_to_cpu(record->policy_generation) ||
	    !ebpfos_state_adapter_nonzero(record->policy_record_digest,
					  SHA256_DIGEST_SIZE) ||
	    !ebpfos_state_adapter_nonzero(record->host_policy_sha256,
					  SHA256_DIGEST_SIZE) ||
	    le64_to_cpu(record->source_runtime_schema_u64) !=
		EBPFOS_FILE_SCHEMA_V2 ||
	    !ebpfos_state_adapter_nonzero(record->source_reader_content_digest,
					  SHA256_DIGEST_SIZE) ||
	    !ebpfos_state_adapter_nonzero(record->source_writer_content_digest,
					  SHA256_DIGEST_SIZE) ||
	    !memcmp(record->source_reader_content_digest,
		    record->source_writer_content_digest, SHA256_DIGEST_SIZE) ||
	    target_schema != EBPFOS_STATE_ADAPTER_SPLIT_V2_SCHEMA ||
	    target_schema == le64_to_cpu(record->source_runtime_schema_u64))
		return -EPROTO;
	error = ebpfos_state_adapter_validate_role(
		&record->target_reader, EBPFOS_STATE_ADAPTER_ROLE_READER,
		EBPFOS_STATE_ADAPTER_SPLIT_READER_PROVIDER_TYPE,
		EBPFOS_CAP_FILE_READ | EBPFOS_CAP_FILE_MIGRATE, target_schema);
	if (error)
		return error;
	error = ebpfos_state_adapter_validate_role(
		&record->target_writer, EBPFOS_STATE_ADAPTER_ROLE_WRITER,
		EBPFOS_STATE_ADAPTER_SPLIT_WRITER_PROVIDER_TYPE,
		EBPFOS_CAP_FILE_APPEND | EBPFOS_CAP_FILE_MIGRATE, target_schema);
	if (error)
		return error;
	if (!memcmp(record->target_reader.role_digest,
		    record->target_writer.role_digest, SHA256_DIGEST_SIZE) ||
	    !memcmp(record->target_reader.role_digest,
		    record->source_reader_content_digest, SHA256_DIGEST_SIZE) ||
	    !memcmp(record->target_reader.role_digest,
		    record->source_writer_content_digest, SHA256_DIGEST_SIZE) ||
	    !memcmp(record->target_writer.role_digest,
		    record->source_reader_content_digest, SHA256_DIGEST_SIZE) ||
	    !memcmp(record->target_writer.role_digest,
		    record->source_writer_content_digest, SHA256_DIGEST_SIZE))
		return -EKEYREJECTED;
	if (le64_to_cpu(record->capability_mask) !=
		EBPFOS_CAP_FILE_MIGRATE ||
	    le64_to_cpu(record->effect_mask) !=
		EBPFOS_STATE_ADAPTER_MIGRATE_EFFECTS)
		return -EACCES;
	if (le32_to_cpu(record->program.format) !=
		EBPFOS_STATE_ADAPTER_PROGRAM_BOUNDED_COPY_V1 ||
	    le32_to_cpu(record->program.operation_count) != 1 ||
	    le64_to_cpu(record->program.max_input_bytes) !=
		EBPFOS_STATE_ADAPTER_SPLIT_MAX_BYTES ||
	    le64_to_cpu(record->program.max_output_bytes) !=
		EBPFOS_STATE_ADAPTER_SPLIT_MAX_BYTES ||
	    le32_to_cpu(record->program.operation) !=
		EBPFOS_STATE_ADAPTER_OP_COPY_INPUT ||
	    le32_to_cpu(record->program.reserved0) ||
	    le64_to_cpu(record->program.source_offset) ||
	    le64_to_cpu(record->program.target_offset) ||
	    le64_to_cpu(record->program.max_length) !=
		EBPFOS_STATE_ADAPTER_SPLIT_MAX_BYTES)
		return -EPROTO;
	ebpfos_state_adapter_hash(ebpfos_state_adapter_program_domain,
				  sizeof(ebpfos_state_adapter_program_domain),
				  &record->program, sizeof(record->program),
				  program_digest);
	if (memcmp(record->program_sha256, program_digest,
		   sizeof(program_digest)))
		return -EBADMSG;
	if (le32_to_cpu(record->refinement_rule) !=
		EBPFOS_STATE_ADAPTER_REFINES_VISIBLE_BYTES ||
	    le32_to_cpu(record->source_abstraction) !=
		EBPFOS_STATE_ADAPTER_ALPHA_VISIBLE_BYTES_V1 ||
	    le32_to_cpu(record->target_abstraction) !=
		EBPFOS_STATE_ADAPTER_ALPHA_VISIBLE_BYTES_V1 ||
	    le32_to_cpu(record->reserved1) ||
	    !ebpfos_state_adapter_all_zero(record->reserved,
					  sizeof(record->reserved)))
		return -EPROTO;
	return 0;
}

static int ebpfos_state_adapter_validate_sources_locked(
	const struct ebpfos_state_adapter_record_v1 *record,
	struct ebpfos_admission *reader, struct ebpfos_admission *writer)
{
	struct ebpfos_binding *reader_binding;
	struct ebpfos_binding *writer_binding;
	const struct ebpfos_component_desc_v1 *reader_descriptor;
	const struct ebpfos_component_desc_v1 *writer_descriptor;
	int error;

	error = ebpfos_policy_identity_validate_locked(
		le64_to_cpu(record->policy_generation), record->realm_id,
		record->policy_record_digest, record->host_policy_sha256,
		EBPFOS_POLICY_F_TEST_ONLY);
	if (error)
		return error;
	if (!reader || !writer || reader == writer ||
	    ebpfos_admission_state_locked(reader) != EBPFOS_ADMISSION_FRESH ||
	    ebpfos_admission_state_locked(writer) != EBPFOS_ADMISSION_FRESH)
		return -ESTALE;
	reader_binding = ebpfos_admission_binding_get(reader);
	writer_binding = ebpfos_admission_binding_get(writer);
	if (!reader_binding || !writer_binding) {
		error = -EINVAL;
		goto out;
	}
	reader_descriptor = ebpfos_binding_descriptor(reader_binding);
	writer_descriptor = ebpfos_binding_descriptor(writer_binding);
	if (!reader_descriptor || !writer_descriptor ||
	    ebpfos_binding_use(reader_binding) !=
		EBPFOS_COMPONENT_USE_SPLIT_READER ||
	    ebpfos_binding_use(writer_binding) !=
		EBPFOS_COMPONENT_USE_SPLIT_WRITER ||
	    ebpfos_binding_runtime_schema(reader_binding) !=
		le64_to_cpu(record->source_runtime_schema_u64) ||
	    ebpfos_binding_runtime_schema(writer_binding) !=
		le64_to_cpu(record->source_runtime_schema_u64)) {
		error = -EPROTOTYPE;
		goto out;
	}
	if (!ebpfos_binding_content_matches(
			reader_binding, record->source_reader_content_digest) ||
	    !ebpfos_binding_content_matches(
			writer_binding, record->source_writer_content_digest) ||
	    le64_to_cpu(reader_descriptor->policy_generation) !=
		le64_to_cpu(record->policy_generation) ||
	    le64_to_cpu(writer_descriptor->policy_generation) !=
		le64_to_cpu(record->policy_generation) ||
	    memcmp(reader_descriptor->policy_record_digest,
		   record->policy_record_digest, SHA256_DIGEST_SIZE) ||
	    memcmp(writer_descriptor->policy_record_digest,
		   record->policy_record_digest, SHA256_DIGEST_SIZE)) {
		error = -ESTALE;
		goto out;
	}
	error = 0;
out:
	ebpfos_binding_put(writer_binding);
	ebpfos_binding_put(reader_binding);
	return error;
}

static int ebpfos_state_adapter_release(struct inode *inode, struct file *file)
{
	kfree_sensitive(file->private_data);
	return 0;
}

static const struct file_operations ebpfos_state_adapter_fops = {
	.owner = THIS_MODULE,
	.release = ebpfos_state_adapter_release,
	.llseek = noop_llseek,
};

static struct ebpfos_state_adapter *
ebpfos_state_adapter_get_from_fd(int fd, struct file **file_out)
{
	struct file *file;

	file = fget(fd);
	if (!file)
		return ERR_PTR(-EBADF);
	if (file->f_op != &ebpfos_state_adapter_fops) {
		fput(file);
		return ERR_PTR(-EINVAL);
	}
	*file_out = file;
	return file->private_data;
}

long ebpfos_state_adapter_seal_ioctl(void __user *argp)
{
	struct ebpfos_ioc_state_adapter_seal request;
	struct ebpfos_state_adapter *adapter = NULL;
	struct ebpfos_admission *reader = NULL;
	struct ebpfos_admission *writer = NULL;
	struct file *adapter_file = NULL;
	void *signature = NULL;
	int fd = -1;
	int error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags || !request.signature || !request.signature_size ||
	    request.signature_size > EBPFOS_ADMISSION_MAX_SIGNATURE)
		return -EINVAL;
	error = ebpfos_state_adapter_validate_record(&request.record);
	if (error)
		return error;
	reader = ebpfos_admission_get_from_fd(
		request.source_reader_admission_fd);
	if (IS_ERR(reader))
		return PTR_ERR(reader);
	writer = ebpfos_admission_get_from_fd(
		request.source_writer_admission_fd);
	if (IS_ERR(writer)) {
		error = PTR_ERR(writer);
		writer = NULL;
		goto out;
	}
	signature = memdup_user(u64_to_user_ptr(request.signature),
				request.signature_size);
	if (IS_ERR(signature)) {
		error = PTR_ERR(signature);
		signature = NULL;
		goto out;
	}
	error = ebpfos_state_adapter_verify_signature(
		&request.record, signature, request.signature_size);
	if (error)
		goto out;
	adapter = kzalloc(sizeof(*adapter), GFP_KERNEL);
	if (!adapter) {
		error = -ENOMEM;
		goto out;
	}
	adapter->record = request.record;
	ebpfos_state_adapter_hash(ebpfos_state_adapter_content_domain,
				  sizeof(ebpfos_state_adapter_content_domain),
				  &adapter->record, sizeof(adapter->record),
				  adapter->content_digest);
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		error = fd;
		goto out;
	}
	adapter_file = anon_inode_getfile("[ebpfos-state-adapter]",
					  &ebpfos_state_adapter_fops,
					  adapter, O_RDONLY);
	if (IS_ERR(adapter_file)) {
		error = PTR_ERR(adapter_file);
		adapter_file = NULL;
		goto out;
	}
	adapter = NULL;
	ebpfos_admission_gate_lock();
	error = ebpfos_state_adapter_validate_sources_locked(
		&request.record, reader, writer);
	ebpfos_admission_gate_unlock();
	if (error)
		goto out;
	request.adapter_fd = fd;
	request.adapter_state = EBPFOS_STATE_ADAPTER_SEALED;
	memcpy(request.content_digest,
	       ((struct ebpfos_state_adapter *)adapter_file->private_data)->content_digest,
	       sizeof(request.content_digest));
	memcpy(request.target_reader_role_digest,
	       request.record.target_reader.role_digest,
	       sizeof(request.target_reader_role_digest));
	memcpy(request.target_writer_role_digest,
	       request.record.target_writer.role_digest,
	       sizeof(request.target_writer_role_digest));
	if (copy_to_user(argp, &request, sizeof(request))) {
		error = -EFAULT;
		goto out;
	}
	fd_install(fd, adapter_file);
	adapter_file = NULL;
	fd = -1;
	error = 0;
out:
	if (fd >= 0)
		put_unused_fd(fd);
	if (adapter_file)
		fput(adapter_file);
	kfree_sensitive(adapter);
	kfree_sensitive(signature);
	ebpfos_admission_put(writer);
	ebpfos_admission_put(reader);
	return error;
}

long ebpfos_state_adapter_info_ioctl(void __user *argp)
{
	struct ebpfos_ioc_state_adapter_info request;
	struct ebpfos_state_adapter *adapter;
	struct file *file = NULL;
	int error;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, argp, sizeof(request)))
		return -EFAULT;
	if (request.flags || request.reserved0)
		return -EINVAL;
	adapter = ebpfos_state_adapter_get_from_fd(request.adapter_fd, &file);
	if (IS_ERR(adapter))
		return PTR_ERR(adapter);
	ebpfos_admission_gate_lock();
	error = ebpfos_policy_identity_validate_locked(
		le64_to_cpu(adapter->record.policy_generation),
		adapter->record.realm_id, adapter->record.policy_record_digest,
		adapter->record.host_policy_sha256, EBPFOS_POLICY_F_TEST_ONLY);
	ebpfos_admission_gate_unlock();
	request.adapter_state = error ? EBPFOS_STATE_ADAPTER_STALE :
		EBPFOS_STATE_ADAPTER_SEALED;
	request.reserved0 = 0;
	memcpy(request.content_digest, adapter->content_digest,
	       sizeof(request.content_digest));
	request.record = adapter->record;
	fput(file);
	return copy_to_user(argp, &request, sizeof(request)) ? -EFAULT : 0;
}
