/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_PTVIEW_H
#define _LINUX_EBPFOS_PTVIEW_H
#include <linux/types.h>
struct mm_struct;
struct ebpfos_ptview;
struct module;
struct ebpfos_ptview_nmi_state { unsigned long cr3; struct mm_struct *loaded; };
struct ebpfos_ptview_change {
 unsigned long address;
 const void *bytes;
 size_t size;
};
typedef int (*ebpfos_ptview_visit)(unsigned long, const void *, size_t, void *);
int ebpfos_ptview_pointer_change(unsigned long, const void *, ebpfos_ptview_visit, void *);
#ifdef CONFIG_EBPFOS_PTVIEW
/* Cold preparation reads the original kernel, independent of the caller's view. */
int ebpfos_ptview_read_native(void *, const void *, size_t);
/* Architecture patchers own text_mutex, or KGDB's full stop. */
void ebpfos_ptview_text_poke(unsigned long, const void *, size_t,
 void (*)(void *, const void *, size_t), bool);
/* Cold preparation and owner-serialized binding. No entry dispatch helper.
 * This prototype requires four-level paging, no PCID, and one mm user.
 * The caller retains referenced code and serializes changes against its work.
 * Text changes cover complete instruction regions. The architecture patcher
 * propagates changes outside the selected regions to prepared/bound views. */
struct ebpfos_ptview *ebpfos_ptview_prepare(const struct ebpfos_ptview_change *, unsigned int, struct module *);
void ebpfos_ptview_put(struct ebpfos_ptview *);
int ebpfos_ptview_bind(struct ebpfos_ptview *);
void ebpfos_ptview_mm_retain(struct mm_struct *, void (*)(void *), void *);
struct ebpfos_ptview *ebpfos_ptview_get(struct ebpfos_ptview *);
struct ebpfos_ptview *ebpfos_ptview_compose(struct ebpfos_ptview **, unsigned int);
bool ebpfos_ptview_overlap(struct ebpfos_ptview *, struct ebpfos_ptview *);
void ebpfos_ptview_mm_free(struct mm_struct *);
bool ebpfos_ptview_mm(const struct mm_struct *);
unsigned long ebpfos_ptview_symbol(const char *);
unsigned long ebpfos_ptview_entry(unsigned long);
u64 ebpfos_ptview_leaf(struct mm_struct *, unsigned long);
void ebpfos_ptview_nmi_enter(struct ebpfos_ptview_nmi_state *);
void ebpfos_ptview_nmi_exit(const struct ebpfos_ptview_nmi_state *);
unsigned long ebpfos_ptview_work_enter(struct mm_struct *);
unsigned long ebpfos_ptview_global_enter(void);
void ebpfos_ptview_global_exit(unsigned long);
void ebpfos_ptview_irq_enter(void);
void ebpfos_ptview_irq_exit(void);
#else
#include <linux/uaccess.h>
static inline int ebpfos_ptview_read_native(void *to, const void *from, size_t size)
{ return copy_from_kernel_nofault(to, from, size); }
static inline void ebpfos_ptview_text_poke(unsigned long at, const void *bytes,
 size_t size, void (*write)(void *, const void *, size_t), bool stopped) {}
static inline bool ebpfos_ptview_mm(const struct mm_struct *mm) { return false; }
static inline void ebpfos_ptview_mm_free(struct mm_struct *mm) {}
static inline void ebpfos_ptview_nmi_enter(struct ebpfos_ptview_nmi_state *state) {}
static inline void ebpfos_ptview_nmi_exit(const struct ebpfos_ptview_nmi_state *state) {}
static inline unsigned long ebpfos_ptview_global_enter(void) { return 0; }
static inline void ebpfos_ptview_global_exit(unsigned long cr3) {}
static inline void ebpfos_ptview_irq_enter(void) {}
static inline void ebpfos_ptview_irq_exit(void) {}
#endif
#endif
