/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _EBPFOS_COMPONENT_GRAPH_H
#define _EBPFOS_COMPONENT_GRAPH_H

#include <linux/atomic.h>
#include <linux/types.h>
#include <linux/wait.h>

#define EBPFOS_COMPONENT_GRAPH_MAX_ROLES 4U

/* Bit 0 closes admission; the remaining bits count acquired calls. */
#define EBPFOS_GATE_DRAINING 1L
#define EBPFOS_GATE_ACQUIRED 2L

/* Policy-free acquisition gate shared by component routes. */
struct ebpfos_component_gate {
	atomic_long_t state;
	wait_queue_head_t waitq;
};

static inline bool ebpfos_component_gate_is_draining(
	const struct ebpfos_component_gate *gate)
{
	return atomic_long_read(&gate->state) & EBPFOS_GATE_DRAINING;
}

void ebpfos_component_gate_init(struct ebpfos_component_gate *gate);
void ebpfos_component_gate_enter(struct ebpfos_component_gate *gate);
bool ebpfos_component_gate_try_enter(struct ebpfos_component_gate *gate);
void ebpfos_component_gate_exit(struct ebpfos_component_gate *gate);
int ebpfos_component_gate_engage(struct ebpfos_component_gate *gate);
void ebpfos_component_gate_abort(struct ebpfos_component_gate *gate);

#endif /* _EBPFOS_COMPONENT_GRAPH_H */
