/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LINUX_EBPFOS_OPERATIONS_H
#define LINUX_EBPFOS_OPERATIONS_H
#include <linux/types.h>
#include <linux/gfp_types.h>

struct ebpfos_operations;
struct ebpfos_operations_owner;
struct module;
#define EBPFOS_OPERATIONS_NAME_LEN 128
struct ebpfos_operations_table_source {
 u32 type;
 char symbol[EBPFOS_OPERATIONS_NAME_LEN];
};
/* Cold preparation only. The caller owns the immutable original table and supplies its
 * vmlinux BTF struct ID and C size. Nothing is installed in a live object.
 * Publish the returned table only while the object is still private; retain
 * the lease until its last possible callback has returned. The original
 * table must remain live too (including its module, when applicable).
 *
 * A copied table is not interchangeable with an address used as an identity
 * or order key. Such owners must keep that identity separate from dispatch.
 */
#ifdef CONFIG_EBPFOS_ENTRY_LINK
const void *ebpfos_operations_table(const struct ebpfos_operations *operations);
u32 ebpfos_operations_bound(const struct ebpfos_operations *operations);
void ebpfos_operations_put(struct ebpfos_operations *operations);
struct ebpfos_operations *ebpfos_operations_get(struct ebpfos_operations *operations);
/* Resolve only tables admitted by the linker's complete-image address-use
 * analysis. NULL means the object keeps its global operations. */
struct ebpfos_operations *ebpfos_operations_current(const void *original,
 u32 type_id, size_t size, struct module *original_owner);
/* Reserve during fallible object allocation. Resolve later, without
 * allocation or sleeping, before the object is first published. The owner
 * serializes resolve with its existing publication lock. Put after the last
 * ordinary reference; the independent record retains code through RCU. */
struct ebpfos_operations_owner *ebpfos_operations_reserve(u32 type_id, gfp_t gfp);
const void *ebpfos_operations_resolve(struct ebpfos_operations_owner *owner,
 const void *original);
void ebpfos_operations_owner_put(struct ebpfos_operations_owner *owner);
#else
static inline const void *ebpfos_operations_table(const struct ebpfos_operations *ops) { return NULL; }
static inline u32 ebpfos_operations_bound(const struct ebpfos_operations *ops) { return 0; }
static inline void ebpfos_operations_put(struct ebpfos_operations *ops) {}
static inline struct ebpfos_operations *ebpfos_operations_get(struct ebpfos_operations *ops) { return NULL; }
static inline struct ebpfos_operations *ebpfos_operations_current(const void *original,
 u32 type, size_t size, struct module *owner) { return NULL; }
static inline struct ebpfos_operations_owner *ebpfos_operations_reserve(u32 type, gfp_t gfp) { return NULL; }
static inline const void *ebpfos_operations_resolve(struct ebpfos_operations_owner *owner,
 const void *original) { return original; }
static inline void ebpfos_operations_owner_put(struct ebpfos_operations_owner *owner) {}
#endif
#endif
