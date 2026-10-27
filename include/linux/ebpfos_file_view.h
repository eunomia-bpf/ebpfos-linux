/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LINUX_EBPFOS_FILE_VIEW_H
#define LINUX_EBPFOS_FILE_VIEW_H
struct file;
struct bpf_insn;
#if defined(CONFIG_EBPFOS_ENTRY_LINK) && defined(CONFIG_X86_64)
/* Resolve read operations once, before the opened file becomes visible. */
int ebpfos_file_view_open(struct file *file);
void ebpfos_file_view_free(struct file *file);
#else
static inline int ebpfos_file_view_open(struct file *file) { return 0; }
static inline void ebpfos_file_view_free(struct file *file) {}
#endif
#endif
