/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_RESTRICTED_BLOCK_H
#define _LINUX_EBPFOS_RESTRICTED_BLOCK_H
#include <linux/blk_types.h>
#include <linux/hrtimer.h>

struct request;
enum hrtimer_restart ebpfos_restricted_block_timer(
	struct request *rq, struct hrtimer *timer,
	enum hrtimer_restart (*native)(struct hrtimer *), blk_status_t status);
#endif
