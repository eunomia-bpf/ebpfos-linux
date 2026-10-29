// SPDX-License-Identifier: GPL-2.0-only
/* Per-mm kernel mappings. Only changed leaves and their page-table paths are
 * private. Ordinary data, table addresses and direct callers stay shared. */
#include <linux/ebpfos_ptview.h>
#include <linux/export.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <asm/pgalloc.h>
#include <asm/mmu_context.h>
#include <asm/set_memory.h>
#include <asm/tlbflush.h>

struct ptview_page { unsigned long address; struct page *copy; };
struct ebpfos_ptview {
 struct module *owner;
 refcount_t refs;
 unsigned int count;
 struct ptview_page pages[];
};
struct ptview_table { struct list_head node; void *page; };
struct ptview_mm {
 struct ebpfos_ptview *view;
 struct list_head tables;
 pgd_t *root;
 DECLARE_BITMAP(changed, PTRS_PER_PGD);
 pgd_t original[PTRS_PER_PGD];
};

unsigned long ebpfos_ptview_symbol(const char *name) { return kallsyms_lookup_name(name); }
EXPORT_SYMBOL_GPL(ebpfos_ptview_symbol);
unsigned long ebpfos_ptview_entry(unsigned long address) { return ftrace_location(address); }
EXPORT_SYMBOL_GPL(ebpfos_ptview_entry);

void ebpfos_ptview_put(struct ebpfos_ptview *view)
{
 unsigned int i;
 if (!view || !refcount_dec_and_test(&view->refs)) return;
 for (i = 0; i < view->count; ++i) __free_page(view->pages[i].copy);
 kfree(view);
}
EXPORT_SYMBOL_GPL(ebpfos_ptview_put);

struct ebpfos_ptview *ebpfos_ptview_prepare(const struct ebpfos_ptview_change *changes, unsigned int count, struct module *owner)
{
 struct ebpfos_ptview *view;
 unsigned int i, j;
 int error = -EINVAL;
 /* These are admission restrictions, not checks in the replaced code. */
 if (!count || count > 64 || pgtable_l5_enabled() ||
     boot_cpu_has(X86_FEATURE_PCID)) return ERR_PTR(-EOPNOTSUPP);
 view = kzalloc(struct_size(view, pages, count), GFP_KERNEL);
 if (!view) return ERR_PTR(-ENOMEM);
 refcount_set(&view->refs, 1);view->owner = owner;
 for (i = 0; i < count; ++i) {
  unsigned long address = changes[i].address & PAGE_MASK;
  size_t offset = offset_in_page(changes[i].address);
  unsigned int level;
  pte_t *pte;
  if (address < PAGE_OFFSET || !changes[i].size || changes[i].size > PAGE_SIZE - offset) {error = -EINVAL;goto fail;}
  for (j = 0; j < view->count; ++j) if (view->pages[j].address == address) break;
  if (j == view->count) {
   /* CPA splits only the containing large mapping, retaining the global bit
    * on every unchanged neighbour. It also invalidates existing global TLBs. */
   error = set_memory_4k(address, 1);
   if (error) goto fail;
   error = set_memory_nonglobal(address, 1);
   if (error) goto fail;
   pte = lookup_address(address, &level);
   if (!pte || level != PG_LEVEL_4K || !pte_present(*pte)) {error = -EINVAL;goto fail;}
   view->pages[j].copy = alloc_page(GFP_KERNEL);
   if (!view->pages[j].copy) {error = -ENOMEM;goto fail;}
   view->pages[j].address = address;
   /* Preparation is independent of the preparing task's current view. */
   memcpy(page_address(view->pages[j].copy), page_address(pfn_to_page(pte_pfn(*pte))), PAGE_SIZE);
   ++view->count;
  }
  memcpy(page_address(view->pages[j].copy) + offset, changes[i].bytes, changes[i].size);
 }
 return view;
fail:
 ebpfos_ptview_put(view);return ERR_PTR(error);
}
EXPORT_SYMBOL_GPL(ebpfos_ptview_prepare);

static void free_mapping(struct ptview_mm *binding)
{
 struct ptview_table *table, *next;
 struct module *owner;
 if (!binding) return;
 list_for_each_entry_safe(table, next, &binding->tables, node) {
  free_page((unsigned long)table->page);kfree(table);
 }
 free_page((unsigned long)binding->root);
 owner = binding->view->owner;
 ebpfos_ptview_put(binding->view);kfree(binding);module_put(owner);
}

static void *copy_table(struct ptview_mm *binding, void *source)
{
 struct ptview_table *table;
 /* Reuse a previously copied path when changes share a page-table page. */
 list_for_each_entry(table, &binding->tables, node) if (table->page == source) return source;
 table = kmalloc(sizeof(*table), GFP_KERNEL);
 if (!table) return NULL;
 table->page = (void *)__get_free_page(GFP_KERNEL);
 if (!table->page) {kfree(table);return NULL;}
 memcpy(table->page, source, PAGE_SIZE);list_add(&table->node, &binding->tables);
 return table->page;
}

static int map_page(struct ptview_mm *binding, const struct ptview_page *page)
{
 unsigned long address = page->address;
 pgd_t *pgd = binding->root + pgd_index(address);
 pud_t *pud;
 pmd_t *pmd;
 pte_t *pte;
 void *copy;
 /* Four levels, folded p4d. Upper permission bits stay exactly as before. */
 copy = copy_table(binding, (void *)pgd_page_vaddr(*pgd));
 if (!copy) return -ENOMEM;
 set_pgd(pgd, __pgd(__pa(copy) | (pgd_val(*pgd) & ~PTE_PFN_MASK)));
 pud = (pud_t *)copy + pud_index(address);
 copy = copy_table(binding, (void *)pud_pgtable(*pud));
 if (!copy) return -ENOMEM;
 set_pud(pud, __pud(__pa(copy) | (pud_val(*pud) & ~PTE_PFN_MASK)));
 pmd = (pmd_t *)copy + pmd_index(address);
 copy = copy_table(binding, (void *)pmd_page_vaddr(*pmd));
 if (!copy) return -ENOMEM;
 set_pmd(pmd, __pmd(__pa(copy) | (pmd_val(*pmd) & ~PTE_PFN_MASK)));
 pte = (pte_t *)copy + pte_index(address);
 set_pte(pte, pfn_pte(page_to_pfn(page->copy),
  __pgprot(pte_val(*pte) & ~(PTE_PFN_MASK | _PAGE_GLOBAL))));
 __set_bit(pgd_index(address), binding->changed);
 return 0;
}

bool ebpfos_ptview_mm(const struct mm_struct *mm)
{ return mm && READ_ONCE(mm->context.ptview); }

static void evict_lazy_borrower(void *opaque)
{
 struct mm_struct *mm = opaque;
 if (this_cpu_read(cpu_tlbstate.loaded_mm) == mm &&
     this_cpu_read(cpu_tlbstate_shared.is_lazy))
  switch_mm_irqs_off(mm, &init_mm, current);
}

int ebpfos_ptview_bind(struct ebpfos_ptview *view)
{
 struct mm_struct *mm = current->mm;
 struct ptview_mm *old, *next = NULL;
 unsigned int i;
 int error = 0;
 if (!mm) return -EINVAL;
 mmap_write_lock(mm);
 old = mm->context.ptview;
 if ((old ? old->view : NULL) == view) goto out;
 /* Different thread choices need different mms. The prototype refuses to
  * mutate a shared mm, and the owner drains its queued work before rebinding. */
 if (atomic_read(&mm->mm_users) != 1) {error = -EBUSY;goto out;}
 if (view) {
  next = kzalloc(sizeof(*next), GFP_KERNEL);
  if (!next) {error = -ENOMEM;goto out;}
  INIT_LIST_HEAD(&next->tables);
  next->root = (pgd_t *)__get_free_page(GFP_KERNEL);
  if (!next->root) {kfree(next);next = NULL;error = -ENOMEM;goto out;}
  refcount_inc(&view->refs);__module_get(view->owner);next->view = view;
  memcpy(next->root, mm->pgd, PAGE_SIZE);
  /* Prepare from this mm's original kernel half, never another view's. */
  if (old) for_each_set_bit(i, old->changed, PTRS_PER_PGD) next->root[i] = old->original[i];
  memcpy(next->original, next->root, PAGE_SIZE);
  for (i = 0; i < view->count; ++i) {
   error = map_page(next, &view->pages[i]);if (error) {free_mapping(next);goto out;}
  }
 }
 /* A kernel thread may already have borrowed this formerly-global mm.
  * Mark it private before draining lazy CPUs so no new borrower can enter.
  * This is cold publication work, never an ordinary call-path test. */
 if (next && !old) {
  WRITE_ONCE(mm->context.ptview, next);
  on_each_cpu_mask(mm_cpumask(mm), evict_lazy_borrower, mm, true);
 }
 /* Only root slots for changed kernel paths are published. User mappings
  * and all unaffected leaves remain the very same mappings. */
 if (old) for_each_set_bit(i, old->changed, PTRS_PER_PGD) set_pgd(mm->pgd + i, old->original[i]);
 if (next) for_each_set_bit(i, next->changed, PTRS_PER_PGD) set_pgd(mm->pgd + i, next->root[i]);
 WRITE_ONCE(mm->context.ptview, next);
 flush_tlb_mm(mm);
 free_mapping(old);
out:
 mmap_write_unlock(mm);return error;
}
EXPORT_SYMBOL_GPL(ebpfos_ptview_bind);

void ebpfos_ptview_mm_free(struct mm_struct *mm)
{
 struct ptview_mm *old = mm->context.ptview;
 unsigned int i;
 if (!old) return;
 for_each_set_bit(i, old->changed, PTRS_PER_PGD) set_pgd(mm->pgd + i, old->original[i]);
 mm->context.ptview = NULL;free_mapping(old);
}

/* IRQ and softirq work is non-scheduling and cannot access user memory.
 * Use the architecture's temporary-mm path so Linux's loaded-mm and TLB
 * generation bookkeeping continue to agree with the hardware CR3. */
unsigned long ebpfos_ptview_work_enter(struct mm_struct *target)
{
 struct mm_struct *loaded = this_cpu_read(cpu_tlbstate.loaded_mm);
 struct ptview_mm *a = loaded->context.ptview, *b = target->context.ptview;
 if ((a ? a->view : NULL) == (b ? b->view : NULL)) return 0;
 return (unsigned long)use_temporary_mm(target);
}
EXPORT_SYMBOL_GPL(ebpfos_ptview_work_enter);
unsigned long notrace ebpfos_ptview_global_enter(void)
{
 struct mm_struct *loaded = this_cpu_read(cpu_tlbstate.loaded_mm);
 if (!ebpfos_ptview_mm(loaded)) return 0;
 return (unsigned long)use_temporary_mm(&init_mm);
}
EXPORT_SYMBOL_GPL(ebpfos_ptview_global_enter);
void notrace ebpfos_ptview_global_exit(unsigned long token)
{ if (token) unuse_temporary_mm((struct mm_struct *)token); }
EXPORT_SYMBOL_GPL(ebpfos_ptview_global_exit);

/* NMI may interrupt switch_mm's own bookkeeping. It changes only hardware
 * CR3 and restores it before returning; it neither schedules nor flushes
 * another task's mappings. */
void notrace ebpfos_ptview_nmi_enter(struct ebpfos_ptview_nmi_state *state)
{
 unsigned long cr3;
 pgd_t *root;
 unsigned int i;
 state->cr3 = 0;
 cr3 = __native_read_cr3();root = __va(cr3 & CR3_ADDR_MASK);
 if (root == init_mm.pgd) return;
 /* NMI can land between the CR3 write and loaded_mm publication. Inspect
  * the actual kernel half, ignoring hardware accessed bits. In this
  * four-level prototype all default mms share these upper page tables. */
 for (i = PTRS_PER_PGD / 2; i < PTRS_PER_PGD; ++i)
  if ((pgd_val(root[i]) ^ pgd_val(init_mm.pgd[i])) & PTE_PFN_MASK) break;
 if (i == PTRS_PER_PGD) return;
 state->cr3 = cr3;state->loaded = this_cpu_read(cpu_tlbstate.loaded_mm);
 /* Existing nmi_uaccess_okay must see the same unavailable-user-mm state
  * as during switch_mm itself, while the global root has no user half. */
 this_cpu_write(cpu_tlbstate.loaded_mm, LOADED_MM_SWITCHING);
 barrier();native_write_cr3(__pa(init_mm.pgd));
}
void notrace ebpfos_ptview_nmi_exit(const struct ebpfos_ptview_nmi_state *state)
{
 if (!state->cr3) return;
 native_write_cr3(state->cr3);barrier();
 this_cpu_write(cpu_tlbstate.loaded_mm, state->loaded);
}

u64 ebpfos_ptview_leaf(struct mm_struct *mm, unsigned long address)
{
 pgd_t *pgd = pgd_offset(mm ? mm : &init_mm, address);
 p4d_t *p4d = p4d_offset(pgd, address);
 pud_t *pud = pud_offset(p4d, address);
 pmd_t *pmd;
 if (pud_leaf(*pud)) return pud_val(*pud);
 pmd = pmd_offset(pud, address);
 if (pmd_leaf(*pmd)) return pmd_val(*pmd);
 return pte_val(*pte_offset_kernel(pmd, address));
}
EXPORT_SYMBOL_GPL(ebpfos_ptview_leaf);

struct ptview_irq_stack { unsigned int depth; unsigned long roots[16]; };
static DEFINE_PER_CPU(struct ptview_irq_stack, irq_stack);
void ebpfos_ptview_irq_enter(void)
{
 struct ptview_irq_stack *stack = this_cpu_ptr(&irq_stack);
 stack->roots[stack->depth++] = ebpfos_ptview_global_enter();
}
void ebpfos_ptview_irq_exit(void)
{
 struct ptview_irq_stack *stack = this_cpu_ptr(&irq_stack);
 ebpfos_ptview_global_exit(stack->roots[--stack->depth]);
}
