/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_BPF_KERNEL_RULE_H
#define _UAPI_BPF_KERNEL_RULE_H
#include <linux/types.h>

/* Scalar identities, never dereferenceable addresses. Context is read-only. */
struct bpf_kernel_rule_ctx {
 __u64 task, cgroup, process_subtree, netns;
 __u64 object, sample_hash, binding, epoch;
};

/* Zero returns the empty set; result i selects prepared set i-1. A set
 * contains versions through generated operations tables and syscall graphs. Alternative
 * sets may replace the same table; separate rules own disjoint tables. */
#define BPF_KERNEL_RULE_MAX_VERSIONS 32
#define BPF_KERNEL_RULE_SCOPED_FUNCTIONS (1U << 0)
struct bpf_kernel_rule_function {
 __u32 btf_obj_fd; /* Zero denotes vmlinux; otherwise the target's BTF FD. */
 __u32 btf_id;
 __u32 prog_fd;
};
struct bpf_kernel_rule_version {
 __u32 operations_count;
 __u32 reserved;
 __aligned_u64 operations_fds;
 /* With SCOPED_FUNCTIONS, function_btf_ids points to function records and
  * function_prog_fds is zero. Otherwise these are the legacy vmlinux ID
  * and program-FD arrays. The version's load context never names a target. */
 __u32 function_count;
 union { __u32 function_flags; __u32 reserved2; };
 __aligned_u64 function_btf_ids;
 __aligned_u64 function_prog_fds;
};
#endif
