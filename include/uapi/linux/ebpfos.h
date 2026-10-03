/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_EBPFOS_H
#define _UAPI_EBPFOS_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define EBPFOS_UAPI_VERSION 11
#define EBPFOS_IOC_MAGIC 0xe7

struct ebpfos_ioc_version {
	__u32 uapi_version;
	__u32 feature_flags;
};

#define EBPFOS_IOC_VERSION \
	_IOR(EBPFOS_IOC_MAGIC, 0x00, struct ebpfos_ioc_version)

#define EBPFOS_COMPONENT_DESC_V1_SIZE 1024U

#define EBPFOS_COMPONENT_DESC_V1_MAGIC "EBPFDES1"
#define EBPFOS_ADMISSION_FORMAT_VERSION 1U

enum ebpfos_component_domain {
	EBPFOS_COMPONENT_DOMAIN_COMPONENT = 3,
};

enum ebpfos_admission_state {
	EBPFOS_ADMISSION_NONE = 0,
	EBPFOS_ADMISSION_FRESH = 1,
	EBPFOS_ADMISSION_STAGED = 2,
	EBPFOS_ADMISSION_STAGED_RECOVERY = 3,
	EBPFOS_ADMISSION_CONSUMED = 4,
	EBPFOS_ADMISSION_BURNED = 5,
	EBPFOS_ADMISSION_STALE = 6,
};

struct ebpfos_component_desc_v1 {
	/* Retained wire slots; admission uses the typed ABI fields below. */
	__u8 magic[8];
	__le16 format_version;
	__le16 header_size;
	__le32 total_size;
	__le32 reserved_flags;
	/* Legacy metadata; the typed ABI determines admission. */
	__le32 domain;
	__le32 use;
	__u8 reserved_header[12];
	/* Retained wire space from the original descriptor format. */
	__u8 reserved_identity[456];
	__le64 abi_id;
	__le32 abi_version;
	__le32 context_size;
	__u8 reserved_attributes[24];
	__le32 prog_type;
	__u8 reserved_payload[484];
};

struct ebpfos_ioc_admission_seal {
	__s32 prog_fd;
	__s32 map_fd;
	__u32 flags;
	/* Zero keeps the legacy map_fd path; otherwise map_fds names every map. */
	__u32 map_count;
	__aligned_u64 map_fds;
	struct ebpfos_component_desc_v1 descriptor;
	__s32 admission_fd;
	__u32 admission_state;
	/* Retained wire slot; always zero. */
	__u64 grant_id;
	__u32 prog_id;
	__u32 map_id;
	__u8 reserved_digests[96];
};

struct ebpfos_ioc_admission_info {
	__s32 admission_fd;
	__u32 flags;
	/* Retained wire slot; always zero. */
	__u64 grant_id;
	__u32 admission_state;
	__u32 prog_id;
	__u32 map_id;
	__u32 reserved0;
	__u8 reserved_digests[96];
	struct ebpfos_component_desc_v1 descriptor;
};

#define EBPFOS_ADMISSION_RUNTIME_INFO_VERSION 1U

struct ebpfos_ioc_admission_runtime_info {
	__s32 admission_fd;
	/* Output layout version; the ioctl command fixes the request size. */
	__u32 version;
	__u32 flags;
	__u32 prog_id;
	__u32 map_id;
	__u32 active_invocations;
	__u64 reserved_rehashes;
	__u64 invocation_entries;
	__u8 reserved_digest[32];
	__u64 retired_epoch;
	__u64 entries_at_publication;
	__u32 active_at_publication;
	__u32 reserved2;
};

struct ebpfos_ioc_root_quiesce {
	__u64 object_id;
	__u64 expected_epoch;
};

#define EBPFOS_IOC_ADMISSION_SEAL \
	_IOWR(EBPFOS_IOC_MAGIC, 0x32, struct ebpfos_ioc_admission_seal)
#define EBPFOS_IOC_ADMISSION_INFO \
	_IOWR(EBPFOS_IOC_MAGIC, 0x33, struct ebpfos_ioc_admission_info)
#define EBPFOS_IOC_ADMISSION_RUNTIME_INFO \
	_IOWR(EBPFOS_IOC_MAGIC, 0x38, struct ebpfos_ioc_admission_runtime_info)
#define EBPFOS_IOC_ROOT_QUIESCE \
	_IOW(EBPFOS_IOC_MAGIC, 0x39, struct ebpfos_ioc_root_quiesce)
#define EBPFOS_IOC_ROOT_RESUME _IO(EBPFOS_IOC_MAGIC, 0x3a)

/* A BTF-generated typed stub must be registered for symbol before enable. */
struct ebpfos_ioc_function_route {
	char symbol[64];
	__u64 object_id;
	__u64 role_type;
	__u64 component_calls;
	__u64 native_fallbacks;
	__u64 last_epoch;
	__u32 last_provider_id;
	__u32 enable;
};

#define EBPFOS_IOC_FUNCTION_ROUTE \
	_IOWR(EBPFOS_IOC_MAGIC, 0x3b, struct ebpfos_ioc_function_route)

#endif /* _UAPI_EBPFOS_H */
