// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/ebpfos.h>
#include <linux/ebpfos_ops.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>

static DEFINE_MUTEX(ebpfos_ops_lock);
static struct ebpfos_fs_ops __rcu *active_fs;
static struct ebpfos_mm_ops __rcu *active_mm;
static struct ebpfos_block_ops __rcu *active_block;
static struct ebpfos_net_ops __rcu *active_net;
static struct ebpfos_driver_ops __rcu *active_driver;

static bool ebpfos_ops_is_valid_access(int off, int size,
				       enum bpf_access_type type,
				       const struct bpf_prog *prog,
				       struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static const struct bpf_verifier_ops ebpfos_ops_verifier_ops = {
	.is_valid_access = ebpfos_ops_is_valid_access,
};

static int ebpfos_ops_init(struct btf *btf)
{
	return 0;
}

#define DEFINE_EBPFOS_REGISTRY(_name, _type, _active)                         \
static int ebpfos_##_name##_reg(void *kdata, struct bpf_link *link)           \
{                                                                              \
	int ret = 0;                                                              \
	mutex_lock(&ebpfos_ops_lock);                                             \
	if (rcu_access_pointer(_active))                                          \
		ret = -EBUSY;                                                       \
	else                                                                       \
		rcu_assign_pointer(_active, (struct _type *)kdata);                  \
	mutex_unlock(&ebpfos_ops_lock);                                           \
	return ret;                                                                \
}                                                                                \
static void ebpfos_##_name##_unreg(void *kdata, struct bpf_link *link)         \
{                                                                              \
	bool removed = false;                                                     \
	mutex_lock(&ebpfos_ops_lock);                                             \
	if (rcu_access_pointer(_active) == (struct _type *)kdata) {               \
		RCU_INIT_POINTER(_active, NULL);                                     \
		removed = true;                                                      \
	}                                                                          \
	mutex_unlock(&ebpfos_ops_lock);                                           \
	if (removed)                                                               \
		synchronize_rcu();                                                   \
}                                                                                \
static int ebpfos_##_name##_update(void *kdata, void *old_kdata,               \
				   struct bpf_link *link)                         \
{                                                                              \
	int ret = 0;                                                              \
	mutex_lock(&ebpfos_ops_lock);                                             \
	if (rcu_access_pointer(_active) != (struct _type *)old_kdata)             \
		ret = -ESTALE;                                                      \
	else                                                                       \
		rcu_assign_pointer(_active, (struct _type *)kdata);                  \
	mutex_unlock(&ebpfos_ops_lock);                                           \
	if (!ret)                                                                  \
		synchronize_rcu();                                                   \
	return ret;                                                                \
}

DEFINE_EBPFOS_REGISTRY(fs, ebpfos_fs_ops, active_fs)
DEFINE_EBPFOS_REGISTRY(mm, ebpfos_mm_ops, active_mm)
DEFINE_EBPFOS_REGISTRY(block, ebpfos_block_ops, active_block)
DEFINE_EBPFOS_REGISTRY(net, ebpfos_net_ops, active_net)
DEFINE_EBPFOS_REGISTRY(driver, ebpfos_driver_ops, active_driver)

static u32 fs_lookup_stub(u64 h, u32 l, u32 w, u32 n)
{
	return EBPFOS_ACTION(EBPFOS_VERDICT_CONTINUE, 0);
}

static u32 fs_readdir_stub(u64 f, u64 i, u64 p, u32 m)
{
	return EBPFOS_ACTION(EBPFOS_VERDICT_CONTINUE, 0);
}

static u32 mm_reclaim_stub(u64 n, s32 p, u64 g, s32 nid)
{
	return EBPFOS_ACTION(EBPFOS_VERDICT_CONTINUE, 0);
}

static u32 block_submit_stub(u64 s, u32 b, u32 o, u64 d)
{
	return EBPFOS_ACTION(EBPFOS_VERDICT_CONTINUE, 0);
}

static u32 net_rx_stub(u64 s, u32 l, u32 p, u32 i)
{
	return EBPFOS_ACTION(EBPFOS_VERDICT_CONTINUE, 0);
}

static u32 net_tx_stub(u64 s, u32 l, u32 p, u32 i)
{
	return EBPFOS_ACTION(EBPFOS_VERDICT_CONTINUE, 0);
}

static u32 driver_probe_stub(u64 d, u64 r, u64 b, u64 o)
{
	return EBPFOS_ACTION(EBPFOS_VERDICT_CONTINUE, 0);
}

static u32 driver_unbind_stub(u64 d, u64 r, u64 z0, u64 z1)
{
	return EBPFOS_ACTION(EBPFOS_VERDICT_CONTINUE, 0);
}

static struct ebpfos_fs_ops fs_cfi_stubs = {
	.lookup = fs_lookup_stub,
	.readdir = fs_readdir_stub,
};
static struct ebpfos_mm_ops mm_cfi_stubs = {
	.reclaim = mm_reclaim_stub,
};
static struct ebpfos_block_ops block_cfi_stubs = {
	.submit = block_submit_stub,
};
static struct ebpfos_net_ops net_cfi_stubs = {
	.rx = net_rx_stub,
	.tx = net_tx_stub,
};
static struct ebpfos_driver_ops driver_cfi_stubs = {
	.probe = driver_probe_stub,
	.unbind = driver_unbind_stub,
};

#define EBPFOS_STRUCT_OPS(_name, _type, _stubs) {                             \
	.verifier_ops = &ebpfos_ops_verifier_ops,                                \
	.init = ebpfos_ops_init,                                                  \
	.reg = ebpfos_##_name##_reg,                                             \
	.unreg = ebpfos_##_name##_unreg,                                         \
	.update = ebpfos_##_name##_update,                                       \
	.cfi_stubs = &_stubs,                                                    \
	.owner = THIS_MODULE,                                                     \
	.name = #_type,                                                          \
}

static struct bpf_struct_ops bpf_ebpfos_fs_ops =
	EBPFOS_STRUCT_OPS(fs, ebpfos_fs_ops, fs_cfi_stubs);
static struct bpf_struct_ops bpf_ebpfos_mm_ops =
	EBPFOS_STRUCT_OPS(mm, ebpfos_mm_ops, mm_cfi_stubs);
static struct bpf_struct_ops bpf_ebpfos_block_ops =
	EBPFOS_STRUCT_OPS(block, ebpfos_block_ops, block_cfi_stubs);
static struct bpf_struct_ops bpf_ebpfos_net_ops =
	EBPFOS_STRUCT_OPS(net, ebpfos_net_ops, net_cfi_stubs);
static struct bpf_struct_ops bpf_ebpfos_driver_ops =
	EBPFOS_STRUCT_OPS(driver, ebpfos_driver_ops, driver_cfi_stubs);

static u32 fallback(enum ebpfos_hook_id hook, const u64 *args, u32 nr_args)
{
	return ebpfos_run_hook(hook, args, nr_args);
}

u32 ebpfos_fs_lookup(u64 name_hash, u32 name_len, u32 walk_flags, u32 nd_flags)
{
	struct ebpfos_fs_ops *ops;
	u64 args[4] = { name_hash, name_len, walk_flags, nd_flags };
	u32 action;

	rcu_read_lock();
	ops = rcu_dereference(active_fs);
	action = ops && ops->lookup ?
		ops->lookup(name_hash, name_len, walk_flags, nd_flags) :
		fallback(EBPFOS_HOOK_VFS_LOOKUP, args, 4);
	rcu_read_unlock();
	return action;
}
EXPORT_SYMBOL_GPL(ebpfos_fs_lookup);

u32 ebpfos_fs_readdir(u64 file, u64 inode, u64 pos, u32 f_mode)
{
	struct ebpfos_fs_ops *ops;
	u64 args[4] = { file, inode, pos, f_mode };
	u32 action;

	rcu_read_lock();
	ops = rcu_dereference(active_fs);
	action = ops && ops->readdir ?
		ops->readdir(file, inode, pos, f_mode) :
		fallback(EBPFOS_HOOK_VFS_READDIR, args, 4);
	rcu_read_unlock();
	return action;
}
EXPORT_SYMBOL_GPL(ebpfos_fs_readdir);

u32 ebpfos_mm_reclaim(u64 nr, s32 priority, u64 gfp, s32 nid)
{
	struct ebpfos_mm_ops *ops;
	u64 args[4] = { nr, priority, gfp, nid };
	u32 action;

	rcu_read_lock();
	ops = rcu_dereference(active_mm);
	action = ops && ops->reclaim ? ops->reclaim(nr, priority, gfp, nid) :
		fallback(EBPFOS_HOOK_MM_RECLAIM, args, 4);
	rcu_read_unlock();
	return action;
}
EXPORT_SYMBOL_GPL(ebpfos_mm_reclaim);

u32 ebpfos_block_submit(u64 sector, u32 bytes, u32 opf, u64 bdev)
{
	struct ebpfos_block_ops *ops;
	u64 args[4] = { sector, bytes, opf, bdev };
	u32 action;

	rcu_read_lock();
	ops = rcu_dereference(active_block);
	action = ops && ops->submit ? ops->submit(sector, bytes, opf, bdev) :
		fallback(EBPFOS_HOOK_BLOCK_SUBMIT, args, 4);
	rcu_read_unlock();
	return action;
}
EXPORT_SYMBOL_GPL(ebpfos_block_submit);

u32 ebpfos_net_rx(u64 skb, u32 len, u32 protocol, u32 ifindex)
{
	struct ebpfos_net_ops *ops;
	u64 args[4] = { skb, len, protocol, ifindex };
	u32 action;

	rcu_read_lock();
	ops = rcu_dereference(active_net);
	action = ops && ops->rx ? ops->rx(skb, len, protocol, ifindex) :
		fallback(EBPFOS_HOOK_NET_RX, args, 4);
	rcu_read_unlock();
	return action;
}
EXPORT_SYMBOL_GPL(ebpfos_net_rx);

u32 ebpfos_net_tx(u64 skb, u32 len, u32 protocol, u32 ifindex)
{
	struct ebpfos_net_ops *ops;
	u64 args[4] = { skb, len, protocol, ifindex };
	u32 action;

	rcu_read_lock();
	ops = rcu_dereference(active_net);
	action = ops && ops->tx ? ops->tx(skb, len, protocol, ifindex) :
		fallback(EBPFOS_HOOK_NET_TX, args, 4);
	rcu_read_unlock();
	return action;
}
EXPORT_SYMBOL_GPL(ebpfos_net_tx);

u32 ebpfos_driver_probe(u64 dev, u64 drv, u64 bus, u64 owner)
{
	struct ebpfos_driver_ops *ops;
	u64 args[4] = { dev, drv, bus, owner };
	u32 action;

	rcu_read_lock();
	ops = rcu_dereference(active_driver);
	action = ops && ops->probe ? ops->probe(dev, drv, bus, owner) :
		fallback(EBPFOS_HOOK_DRIVER_PROBE, args, 4);
	rcu_read_unlock();
	return action;
}
EXPORT_SYMBOL_GPL(ebpfos_driver_probe);

u32 ebpfos_driver_unbind(u64 dev, u64 drv)
{
	struct ebpfos_driver_ops *ops;
	u64 args[3] = { 1, dev, drv };
	u32 action;

	rcu_read_lock();
	ops = rcu_dereference(active_driver);
	action = ops && ops->unbind ? ops->unbind(dev, drv, 0, 0) :
		fallback(EBPFOS_HOOK_DRIVER_LIFECYCLE, args, 3);
	rcu_read_unlock();
	return action;
}
EXPORT_SYMBOL_GPL(ebpfos_driver_unbind);

static int __init ebpfos_struct_ops_init(void)
{
	int ret;

	ret = register_bpf_struct_ops(&bpf_ebpfos_fs_ops, ebpfos_fs_ops);
	if (ret)
		return ret;
	ret = register_bpf_struct_ops(&bpf_ebpfos_mm_ops, ebpfos_mm_ops);
	if (ret)
		return ret;
	ret = register_bpf_struct_ops(&bpf_ebpfos_block_ops, ebpfos_block_ops);
	if (ret)
		return ret;
	ret = register_bpf_struct_ops(&bpf_ebpfos_net_ops, ebpfos_net_ops);
	if (ret)
		return ret;
	return register_bpf_struct_ops(&bpf_ebpfos_driver_ops, ebpfos_driver_ops);
}
late_initcall(ebpfos_struct_ops_init);
