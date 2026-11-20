// SPDX-License-Identifier: GPL-2.0-only
#ifndef EBPFOS_FUNCTION_LIFETIME_H
#define EBPFOS_FUNCTION_LIFETIME_H
#include <linux/rcupdate.h>
/* Preserve the existing retirement grace periods without an extra scan gate. */
static inline void ebpfos_code_quiescent(void)
{
 synchronize_rcu();
 synchronize_rcu_tasks();
}
#endif
