/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_ENTRIES_H
#define EBPFOS_FUNCTION_ENTRIES_H
#include <linux/types.h>
struct ebpfos_function_link { u32 native_function, compiled_function, first, second; };
/* Cold kernel C interfaces. A journal owns all text, BTF and module leases.
 * source_btf_fd is U32_MAX for built-in kernel text, or a module BTF fd.
 * These native source journals require reserved entries and stopped epochs
 * from creation. compiled_function encodes target BTF fd + 1.
 * The caller supplies the complete source unit, as for ordinary journals.
 */
int ebpfos_function_entries_open_epoch(u32 source_btf_fd,
 const struct ebpfos_function_link *, unsigned int count);
/* Reserved entries only. The update/undo contract is that of the stopped
 * text transaction: caller closes every live object/user and excludes NMI,
 * MCE and transaction users. Ordinary switches refuse from journal creation;
 * restore through another epoch before closing. An active close retains code
 * and its journal instead of separating old text from new-layout data.
 * No normal entry/call path is added here.
 */
int ebpfos_function_entries_epoch(u32 fd, u32 from, u32 to,
 int (*update)(void *), void (*undo)(void *), void *data);
#endif
