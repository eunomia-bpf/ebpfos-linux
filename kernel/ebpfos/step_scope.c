// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/string.h>
#include "step_scope.h"

int ebpfos_step_read(const struct ebpfos_step_scope *scope, void *dst, u32 size)
{
	if (!scope || !dst || !scope->valid || scope->size != size)
	 return -EINVAL;
	memcpy(dst, scope->state, size);
	return 0;
}

int ebpfos_step_save(struct ebpfos_step_scope *scope, const void *src, u32 size)
{
	if (!scope || !src || !size || size > sizeof(scope->state))
	 return -EINVAL;
	memcpy(scope->state, src, size);
	scope->size = size;
	scope->valid = true;
	scope->pending = true;
	return 0;
}
