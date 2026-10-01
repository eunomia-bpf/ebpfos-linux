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
	for (;;) {
		spin_lock(&gate->lock);
		if (!gate->draining) {
			gate->acquired++;
			spin_unlock(&gate->lock);
			return;
		}
		spin_unlock(&gate->lock);
		wait_event(gate->waitq, !READ_ONCE(gate->draining));
	}
}

void ebpfos_component_gate_exit(struct ebpfos_component_gate *gate)
{
	spin_lock(&gate->lock);
	if (WARN_ON_ONCE(!gate->acquired)) {
		spin_unlock(&gate->lock);
		return;
	}
	gate->acquired--;
	spin_unlock(&gate->lock);
	wake_up_all(&gate->waitq);
}
int ebpfos_component_gate_engage(struct ebpfos_component_gate *gate)
{
	spin_lock(&gate->lock);
	if (gate->draining) {
		spin_unlock(&gate->lock);
		return -EBUSY;
	}
	gate->draining = true;
	spin_unlock(&gate->lock);
	wait_event(gate->waitq, !READ_ONCE(gate->acquired));
	return 0;
}

void ebpfos_component_gate_abort(struct ebpfos_component_gate *gate)
{
	spin_lock(&gate->lock);
	gate->draining = false;
	spin_unlock(&gate->lock);
	wake_up_all(&gate->waitq);
}
