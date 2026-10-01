/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _EBPFOS_COMPONENT_GRAPH_H
#define _EBPFOS_COMPONENT_GRAPH_H

#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>

#define EBPFOS_COMPONENT_GRAPH_MAX_ROLES 4U

/* Policy-free acquisition gate shared by component routes. */
struct ebpfos_component_gate {
	spinlock_t lock;
	wait_queue_head_t waitq;
	unsigned int acquired;
	bool draining;
};

void ebpfos_component_gate_init(struct ebpfos_component_gate *gate);
void ebpfos_component_gate_enter(struct ebpfos_component_gate *gate);
bool ebpfos_component_gate_try_enter(struct ebpfos_component_gate *gate);
void ebpfos_component_gate_exit(struct ebpfos_component_gate *gate);
int ebpfos_component_gate_engage(struct ebpfos_component_gate *gate);
void ebpfos_component_gate_abort(struct ebpfos_component_gate *gate);

#endif /* _EBPFOS_COMPONENT_GRAPH_H */
