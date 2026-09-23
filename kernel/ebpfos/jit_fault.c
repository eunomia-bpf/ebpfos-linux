// SPDX-License-Identifier: GPL-2.0-only
/* Faults inside placed native code, resolved on either side of a handoff.
 *
 * Placement copies a verified and JITed program's image to a second address
 * and rebuilds its fault fixups there.  In the donor kernel those fixups are
 * reachable because the region owns a kallsyms-visible bpf_prog, so
 * search_exception_tables() -> search_bpf_extables() -> bpf_prog_ksym_find()
 * finds them.  That stops working at handoff: a successor image carries
 * exc_page_fault, fixup_exception and search_exception_tables, but it carries
 * neither CONFIG_BPF_SYSCALL nor kallsyms, so that arm compiles to the inline
 * stub in linux/extable.h and answers NULL.  A placed region that faulted
 * after handoff would have nowhere to land.
 *
 * This registry is the arm that does survive.  It needs no BPF and no
 * kallsyms, which is why it is a configuration of its own rather than part of
 * the placement mechanism: the donor selects it along with placement, and a
 * successor image that must resolve its own placed code's faults selects it
 * alone, without taking any of the donor's component runtime with it.
 *
 * Fault context reads the list, so it is RCU-walked and a region is only ever
 * published once its entries are complete.
 */
#include <linux/ebpfos.h>
#include <linux/extable.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

/* The list head and a small array of records are both global, because a
 * region has to be resolvable after handoff as well as before it.
 *
 * Before handoff the donor adds records at run time, from the placement
 * ioctl.  After handoff there is no donor to do that: the successor executes
 * its own image, with its own copy of this list, which nothing running would
 * ever populate.  So a region placed into an image is published there
 * statically -- the image builder fills a record and links the head to it,
 * exactly as it fills the other typed objects it materializes.  Both symbols
 * are global so the builder can find them; where records are only ever added
 * at run time the array is simply unused.
 */
LIST_HEAD(ebpfos_jit_fault_regions);
static DEFINE_SPINLOCK(ebpfos_jit_fault_lock);

struct ebpfos_jit_fault_region
	ebpfos_jit_static_fault_regions[EBPFOS_JIT_STATIC_FAULT_REGIONS];

/* Consulted by search_exception_tables() after the kernel, module and BPF
 * tables.  Returns the entry covering addr, or NULL.
 */
const struct exception_table_entry *ebpfos_jit_search_extables(unsigned long addr)
{
	const struct exception_table_entry *entry = NULL;
	struct ebpfos_jit_fault_region *region;

	rcu_read_lock();
	list_for_each_entry_rcu(region, &ebpfos_jit_fault_regions, node) {
		if (addr < region->start || addr >= region->end)
			continue;
		entry = search_extable(region->extable, region->num_exentries,
				       addr);
		break;
	}
	rcu_read_unlock();
	return entry;
}

int ebpfos_jit_record_fault_region(void *image, u32 image_len,
				   const struct exception_table_entry *extable,
				   u32 num_exentries)
{
	struct ebpfos_jit_fault_region *region;

	if (!num_exentries)
		return 0;
	region = kzalloc(sizeof(*region), GFP_KERNEL);
	if (!region)
		return -ENOMEM;
	region->start = (unsigned long)image;
	region->end = region->start + image_len;
	region->extable = extable;
	region->num_exentries = num_exentries;
	spin_lock(&ebpfos_jit_fault_lock);
	list_add_rcu(&region->node, &ebpfos_jit_fault_regions);
	spin_unlock(&ebpfos_jit_fault_lock);
	return 0;
}

void ebpfos_jit_forget_fault_region(void *image)
{
	struct ebpfos_jit_fault_region *region;

	spin_lock(&ebpfos_jit_fault_lock);
	list_for_each_entry(region, &ebpfos_jit_fault_regions, node)
		if (region->start == (unsigned long)image) {
			list_del_rcu(&region->node);
			spin_unlock(&ebpfos_jit_fault_lock);
			kfree_rcu(region, rcu);
			return;
		}
	spin_unlock(&ebpfos_jit_fault_lock);
}
