/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LINUX_EBPFOS_FILE_VIEW_H
#define LINUX_EBPFOS_FILE_VIEW_H
struct file;
#if defined(CONFIG_EBPFOS) && defined(CONFIG_X86_64)
/* Resolve read operations once, before the opened file becomes visible. */
int ebpfos_file_view_open(struct file *file);
int ebpfos_object_view_select(int descriptor);
#else
static inline int ebpfos_file_view_open(struct file *file) { return 0; }
#endif
#endif
