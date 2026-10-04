// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/sched.h>

#include "component_graph.h"

void ebpfos_component_gate_init(struct ebpfos_component_gate *gate)
{
	atomic_long_set(&gate->state, 0);
	init_waitqueue_head(&gate->waitq);
}

void ebpfos_component_gate_enter(struct ebpfos_component_gate *gate)
{
	while (!ebpfos_component_gate_try_enter(gate))
		wait_event(gate->waitq,
			   !ebpfos_component_gate_is_draining(gate));
}

bool ebpfos_component_gate_try_enter(struct ebpfos_component_gate *gate)
{
	long state = atomic_long_read(&gate->state);

	for (;;) {
		if (state & EBPFOS_GATE_DRAINING)
			return false;
		/* Admission and drain closure linearize on the same word. */
		if (atomic_long_try_cmpxchg(&gate->state, &state,
					  state + EBPFOS_GATE_ACQUIRED))
			return true;
	}
}

void ebpfos_component_gate_exit(struct ebpfos_component_gate *gate)
{
	long state = atomic_long_read(&gate->state);

	for (;;) {
		if (WARN_ON_ONCE(!(state & ~EBPFOS_GATE_DRAINING)))
			return;
		if (atomic_long_try_cmpxchg(&gate->state, &state,
					  state - EBPFOS_GATE_ACQUIRED))
			break;
	}
	/*
	 * An aborted drain can still be waiting for the final acquisition.
	 * The successful fully ordered cmpxchg supplies the barrier between
	 * updating the count and inspecting the wait queue.
	 */
	if (!((state - EBPFOS_GATE_ACQUIRED) & ~EBPFOS_GATE_DRAINING) &&
	    waitqueue_active(&gate->waitq))
		wake_up_all(&gate->waitq);
}

int ebpfos_component_gate_engage(struct ebpfos_component_gate *gate)
{
	if (atomic_long_fetch_or(EBPFOS_GATE_DRAINING, &gate->state) &
	    EBPFOS_GATE_DRAINING)
		return -EBUSY;
	wait_event(gate->waitq,
		   !(atomic_long_read_acquire(&gate->state) &
		     ~EBPFOS_GATE_DRAINING));
	return 0;
}

void ebpfos_component_gate_abort(struct ebpfos_component_gate *gate)
{
	/* Fully ordered RMW publishes the drained provider before readmission. */
	atomic_long_fetch_andnot(EBPFOS_GATE_DRAINING, &gate->state);
	wake_up_all(&gate->waitq);
}
