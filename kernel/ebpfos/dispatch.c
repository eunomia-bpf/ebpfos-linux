// SPDX-License-Identifier: GPL-2.0-only
#include <linux/ebpfos.h>
#include <linux/ebpfos_ops.h>
#include <linux/export.h>

u32 ebpfos_component_run_hook(enum ebpfos_hook_id hook,
			      const u64 *args, u32 nr_args)
{
	switch (hook) {
	case EBPFOS_HOOK_VFS_LOOKUP:
		if (nr_args >= 4)
			return ebpfos_fs_lookup(args[0], args[1], args[2], args[3]);
		break;
	case EBPFOS_HOOK_VFS_READDIR:
		if (nr_args >= 4)
			return ebpfos_fs_readdir(args[0], args[1], args[2], args[3]);
		break;
	case EBPFOS_HOOK_MM_RECLAIM:
		if (nr_args >= 4)
			return ebpfos_mm_reclaim(args[0], args[1], args[2], args[3]);
		break;
	case EBPFOS_HOOK_BLOCK_SUBMIT:
		if (nr_args >= 4)
			return ebpfos_block_submit(args[0], args[1], args[2], args[3]);
		break;
	case EBPFOS_HOOK_NET_RX:
		if (nr_args >= 4)
			return ebpfos_net_rx(args[0], args[1], args[2], args[3]);
		break;
	case EBPFOS_HOOK_NET_TX:
		if (nr_args >= 4)
			return ebpfos_net_tx(args[0], args[1], args[2], args[3]);
		break;
	case EBPFOS_HOOK_DRIVER_PROBE:
		if (nr_args >= 4)
			return ebpfos_driver_probe(args[0], args[1], args[2], args[3]);
		break;
	case EBPFOS_HOOK_DRIVER_LIFECYCLE:
		if (nr_args >= 3)
			return ebpfos_driver_unbind(args[1], args[2]);
		break;
	default:
		break;
	}
	return ebpfos_run_hook(hook, args, nr_args);
}
EXPORT_SYMBOL_GPL(ebpfos_component_run_hook);
