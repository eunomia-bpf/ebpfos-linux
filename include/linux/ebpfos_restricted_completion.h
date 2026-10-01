/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_RESTRICTED_COMPLETION_H
#define _LINUX_EBPFOS_RESTRICTED_COMPLETION_H
#include <linux/completion.h>
#include <linux/types.h>

typedef void (*ebpfos_completion_native_t)(void *queue);
typedef void *(*ebpfos_completion_consume_t)(void *queue, unsigned int *len);

void ebpfos_restricted_completion_register(void *queue, void *owner);
void ebpfos_restricted_completion_unregister(void *owner);
void ebpfos_restricted_completion(
	void *queue, ebpfos_completion_native_t native,
	ebpfos_completion_consume_t consume, unsigned int *published,
	struct completion *done);
#endif
