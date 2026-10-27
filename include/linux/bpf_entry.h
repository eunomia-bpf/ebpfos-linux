/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_BPF_ENTRY_H
#define _LINUX_BPF_ENTRY_H
#include <linux/bpf.h>
#ifdef CONFIG_EBPFOS_ENTRY_LINK
int bpf_entry_program_address(struct btf *, u32, struct bpf_prog *, bool, unsigned long *);
int bpf_native_prog_init(struct bpf_prog *prog, const union bpf_attr *attr);
int bpf_entry_link_create(const union bpf_attr *attr, bool kernel);
int bpf_entry_link_update(struct bpf_link *link, const union bpf_attr *attr);
#else
static inline int bpf_native_prog_init(struct bpf_prog *prog, const union bpf_attr *attr)
{ return -EOPNOTSUPP; }
static inline int bpf_entry_link_create(const union bpf_attr *attr, bool kernel)
{ return -EOPNOTSUPP; }
static inline int bpf_entry_link_update(struct bpf_link *link, const union bpf_attr *attr)
{ return -EOPNOTSUPP; }
#endif
#endif
