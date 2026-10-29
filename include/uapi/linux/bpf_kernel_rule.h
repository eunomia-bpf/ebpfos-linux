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
struct bpf_kernel_rule_version {
 __u32 operations_count;
 __u32 reserved;
 __aligned_u64 operations_fds;
 /* Actual vmlinux function IDs and matching program FDs. Syscall roots
  * publish into the task table; private graph members retain their code. */
 __u32 function_count;
 __u32 reserved2;
 __aligned_u64 function_btf_ids;
 __aligned_u64 function_prog_fds;
};
#endif
