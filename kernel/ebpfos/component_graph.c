// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/sched.h>

#include "component_graph.h"

void ebpfos_component_gate_init(struct ebpfos_component_gate *gate)
{
	spin_lock_init(&gate->lock);
	init_waitqueue_head(&gate->waitq);
	gate->acquired = 0;
	gate->draining = false;
}

void ebpfos_component_gate_enter(struct ebpfos_component_gate *gate)
{
	unsigned long flags;

	for (;;) {
		spin_lock_irqsave(&gate->lock, flags);
		if (!gate->draining) {
			gate->acquired++;
			spin_unlock_irqrestore(&gate->lock, flags);
			return;
		}
		spin_unlock_irqrestore(&gate->lock, flags);
		wait_event(gate->waitq, !READ_ONCE(gate->draining));
	}
}

bool ebpfos_component_gate_try_enter(struct ebpfos_component_gate *gate)
{
	unsigned long flags;
	bool acquired;

	spin_lock_irqsave(&gate->lock, flags);
	acquired = !gate->draining;
	if (acquired)
		gate->acquired++;
	spin_unlock_irqrestore(&gate->lock, flags);
	return acquired;
}

void ebpfos_component_gate_exit(struct ebpfos_component_gate *gate)
{
	unsigned long flags;

	spin_lock_irqsave(&gate->lock, flags);
	if (WARN_ON_ONCE(!gate->acquired)) {
		spin_unlock_irqrestore(&gate->lock, flags);
		return;
	}
	gate->acquired--;
	spin_unlock_irqrestore(&gate->lock, flags);
	wake_up_all(&gate->waitq);
}
int ebpfos_component_gate_engage(struct ebpfos_component_gate *gate)
{
	unsigned long flags;

	spin_lock_irqsave(&gate->lock, flags);
	if (gate->draining) {
		spin_unlock_irqrestore(&gate->lock, flags);
		return -EBUSY;
	}
	gate->draining = true;
	spin_unlock_irqrestore(&gate->lock, flags);
	wait_event(gate->waitq, !READ_ONCE(gate->acquired));
	return 0;
}

void ebpfos_component_gate_abort(struct ebpfos_component_gate *gate)
{
	unsigned long flags;

	spin_lock_irqsave(&gate->lock, flags);
	gate->draining = false;
	spin_unlock_irqrestore(&gate->lock, flags);
	wake_up_all(&gate->waitq);
}
