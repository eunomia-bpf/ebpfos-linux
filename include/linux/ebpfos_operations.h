/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LINUX_EBPFOS_OPERATIONS_H
#define LINUX_EBPFOS_OPERATIONS_H
#include <linux/types.h>

struct ebpfos_operations;
/* Cold preparation only. The caller owns the immutable original table and supplies its
 * vmlinux BTF struct ID and C size. Nothing is installed in a live object.
 * Publish the returned table only while the object is still private; retain
 * the lease until its last possible callback has returned. The original
 * table must remain live too (including its module, when applicable).
 *
 * A copied table is not interchangeable with an address used as an identity
 * or order key. Such owners must keep that identity separate from dispatch.
 */
struct ebpfos_operations *ebpfos_operations_prepare(u32 descriptor,
 const void *original, u32 type_id, size_t size);
const void *ebpfos_operations_table(const struct ebpfos_operations *operations);
u32 ebpfos_operations_bound(const struct ebpfos_operations *operations);
void ebpfos_operations_put(struct ebpfos_operations *operations);
#endif
