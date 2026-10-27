// SPDX-License-Identifier: GPL-2.0-only
/* Cold publication with code and data hidden until every CPU resumes. */
#include <linux/cpu.h>
#include <linux/export.h>
#include <linux/memory.h>
#include <linux/mutex.h>
#include <linux/stop_machine.h>
#include <linux/uaccess.h>
#include <asm/text-patching.h>
#include <asm/sync_core.h>

struct text_poke_quiescent_transaction {
	const struct text_poke_pair *pairs;
	unsigned int count, leader;
	int (*update)(void *);
	void (*undo)(void *);
	void *data;
	int error, finished;
};

static int text_poke_quiescent_update(void *opaque)
{
	struct text_poke_quiescent_transaction *transaction = opaque;
	unsigned int i;

	/* stop_machine calls every online CPU only after all have disabled IRQs.
	 * The non-leaders remain stopped until both data and text are complete.
	 */
	if (smp_processor_id() == transaction->leader) {
		transaction->error = transaction->update(transaction->data);
		if (transaction->error) {
			transaction->undo(transaction->data);
		} else {
			for (i = 0; i < transaction->count; ++i)
				text_poke(transaction->pairs[i].addr,
					  transaction->pairs[i].after, 5);
		}
		smp_store_release(&transaction->finished, 1);
	} else {
		while (!smp_load_acquire(&transaction->finished))
			cpu_relax();
	}
	/* No IPI is sent while CPUs are stopped. Each CPU serializes its own
	 * instruction stream before stop_machine permits normal execution.
	 */
	sync_core();
	return transaction->error;
}

static int text_poke_quiescent_transaction_locked(const struct text_poke_pair *pairs,
	unsigned int count, int (*update)(void *), void (*undo)(void *), void *data)
{
	struct text_poke_quiescent_transaction transaction = {
		.pairs = pairs, .count = count, .update = update, .undo = undo,
		.data = data, .leader = cpumask_first(cpu_online_mask),
	};
	unsigned int i;

	lockdep_assert_cpus_held();
	lockdep_assert_held(&text_mutex);
	if (!update || !undo || (count && !pairs))
		return -EINVAL;
	/* Validate every instruction before the callback can write live data.
	 * text_mutex keeps these bytes stable through the stopped transaction.
	 */
	for (i = 0; i < count; ++i) {
		unsigned long address = (unsigned long)pairs[i].addr;
		u8 actual[5];

		if (i && address < (unsigned long)pairs[i - 1].addr + 5)
			return -EINVAL;
		if (copy_from_kernel_nofault(actual, pairs[i].addr, sizeof(actual)) ||
		    memcmp(actual, pairs[i].before, sizeof(actual)))
			return -ESTALE;
	}
	return stop_machine_cpuslocked(text_poke_quiescent_update, &transaction,
				      cpu_online_mask);
}

int smp_text_poke_quiescent_transaction(const struct text_poke_pair *pairs,
	unsigned int count, int (*update)(void *), void (*undo)(void *), void *data)
{
	int error;

	cpus_read_lock();
	mutex_lock(&text_mutex);
	error = text_poke_quiescent_transaction_locked(pairs, count, update, undo, data);
	mutex_unlock(&text_mutex);
	cpus_read_unlock();
	return error;
}
EXPORT_SYMBOL_GPL(smp_text_poke_quiescent_transaction);
