/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_EBPFOS_OPS_H
#define _LINUX_EBPFOS_OPS_H

#include <linux/types.h>
#include <uapi/linux/ebpfos.h>

/* Stable scalar-only subsystem ABIs. Hardware primitives remain in Linux. */
struct ebpfos_fs_ops {
	u32 (*lookup)(u64 name_hash, u32 name_len, u32 walk_flags, u32 nd_flags);
	u32 (*readdir)(u64 file, u64 inode, u64 pos, u32 f_mode);
};

struct ebpfos_mm_ops {
	u32 (*reclaim)(u64 nr_to_reclaim, s32 priority, u64 gfp_mask, s32 nid);
};

struct ebpfos_block_ops {
	u32 (*submit)(u64 sector, u32 bytes, u32 opf, u64 bdev);
};

struct ebpfos_net_ops {
	u32 (*rx)(u64 skb, u32 len, u32 protocol, u32 ifindex);
	u32 (*tx)(u64 skb, u32 len, u32 protocol, u32 ifindex);
};

struct ebpfos_driver_ops {
	u32 (*probe)(u64 dev, u64 drv, u64 bus, u64 owner);
	u32 (*unbind)(u64 dev, u64 drv, u64 reserved0, u64 reserved1);
};

u32 ebpfos_fs_lookup(u64 name_hash, u32 name_len, u32 walk_flags, u32 nd_flags);
u32 ebpfos_fs_readdir(u64 file, u64 inode, u64 pos, u32 f_mode);
u32 ebpfos_mm_reclaim(u64 nr_to_reclaim, s32 priority, u64 gfp_mask, s32 nid);
u32 ebpfos_block_submit(u64 sector, u32 bytes, u32 opf, u64 bdev);
u32 ebpfos_net_rx(u64 skb, u32 len, u32 protocol, u32 ifindex);
u32 ebpfos_net_tx(u64 skb, u32 len, u32 protocol, u32 ifindex);
u32 ebpfos_driver_probe(u64 dev, u64 drv, u64 bus, u64 owner);
u32 ebpfos_driver_unbind(u64 dev, u64 drv);

/* Dispatch a source boundary through typed struct_ops if one is live. */
u32 ebpfos_component_run_hook(enum ebpfos_hook_id hook,
			      const u64 *args, u32 nr_args);

#endif
