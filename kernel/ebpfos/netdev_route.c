// SPDX-License-Identifier: GPL-2.0-only
/* Generated net_device_ops boundary; transmit runs in a sleepable worker. */
#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/ebpfos.h>
#include <linux/ebpfos_fops_route.h>
#include <linux/ebpfos_services.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/netdevice.h>
#include <linux/notifier.h>
#include <linux/nsproxy.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <uapi/linux/ebpfos_netdev_route.h>

#include "netdev-route-generated.h"

struct ebpfos_netdev_route {
	struct list_head list;
	struct net_device *dev;
	const struct net_device_ops *original;
	struct net_device_ops routed;
	spinlock_t lock;
	wait_queue_head_t drained;
	atomic_t active;
	atomic64_t linux_entries;
	atomic64_t component_entries;
	atomic64_t faults;
	atomic64_t method_entries[7];
	bool draining;
	bool component;
	u64 handle;
	u64 role;
	u64 method_mask;
};

struct ebpfos_netdev_work {
	struct work_struct work;
	struct ebpfos_netdev_route *route;
	struct sk_buff *skb;
};

static LIST_HEAD(ebpfos_netdev_routes); /* RTNL protects the list. */

static void ebpfos_netdev_route_finish(struct ebpfos_netdev_route *route)
{
	if (atomic_dec_and_test(&route->active))
		wake_up_all(&route->drained);
}

static netdev_tx_t ebpfos_netdev_route_linux_xmit(
	struct ebpfos_netdev_route *route, struct sk_buff *skb)
{
	netdev_tx_t result;

	atomic64_inc(&route->linux_entries);
	result = route->original->ndo_start_xmit(skb, route->dev);
	return result;
}

static void ebpfos_netdev_route_work(struct work_struct *work)
{
	struct ebpfos_netdev_work *item =
		container_of(work, struct ebpfos_netdev_work, work);
	struct ebpfos_netdev_route *route = item->route;
	struct ebpfos_component_call_frame frame = {};
	struct ebpfos_effect_scope *scope;
	u64 epoch = 0;
	u32 provider_id = 0, provider_status = 0;
	u64 bytes = item->skb->len;
	bool pending = true;
	int error;

	frame.version = EBPFOS_COMPONENT_CALL_ABI_VERSION;
	frame.method_id = 1;
	frame.object_id = route->handle;
	frame.input_size = sizeof(bytes);
	memcpy(frame.input, &bytes, sizeof(bytes));
	scope = ebpfos_effect_net_scope_enter(route->handle, route->dev, item->skb);
	if (IS_ERR(scope)) {
		error = PTR_ERR(scope);
	} else {
		error = ebpfos_fops_route_call(route->handle, route->role, &frame,
					       &epoch, &provider_id,
					       &provider_status);
		pending = ebpfos_effect_net_skb_pending(scope);
		if (ebpfos_effect_scope_exit(scope) && !error)
			error = -EPROTO;
		if (!error && (provider_status || frame.status ||
			      frame.output_size || pending))
			error = -EPROTO;
	}
	if (error) {
		netdev_tx_t fallback;

		atomic64_inc(&route->faults);
		WRITE_ONCE(route->component, false);
		if (pending) {
			local_bh_disable();
			fallback = ebpfos_netdev_route_linux_xmit(route,
							  item->skb);
			local_bh_enable();
			if (fallback == NETDEV_TX_BUSY)
				dev_queue_xmit(item->skb);
		}
	} else {
		atomic64_inc(&route->component_entries);
		atomic64_inc(&route->method_entries[1]);
	}
	kfree(item);
	ebpfos_netdev_route_finish(route);
}

static netdev_tx_t ebpfos_netdev_route_start_xmit(struct sk_buff *skb,
						   struct net_device *dev)
{
	struct ebpfos_netdev_route *route = READ_ONCE(dev->ebpfos_route);
	struct ebpfos_netdev_work *item;
	netdev_tx_t result;
	bool component;

	if (WARN_ON_ONCE(!route))
		return NETDEV_TX_BUSY;
	spin_lock_bh(&route->lock);
	if (route->draining || atomic_read(&route->active) >= 1024) {
		spin_unlock_bh(&route->lock);
		return NETDEV_TX_BUSY;
	}
	atomic_inc(&route->active);
	component = READ_ONCE(route->component);
	spin_unlock_bh(&route->lock);
	if (!component) {
		result = ebpfos_netdev_route_linux_xmit(route, skb);
		ebpfos_netdev_route_finish(route);
		return result;
	}
	item = kmalloc(sizeof(*item), GFP_ATOMIC);
	if (!item) {
		ebpfos_netdev_route_finish(route);
		return NETDEV_TX_BUSY;
	}
	item->route = route;
	item->skb = skb;
	INIT_WORK(&item->work, ebpfos_netdev_route_work);
	queue_work(system_unbound_wq, &item->work);
	return NETDEV_TX_OK;
}

static bool ebpfos_netdev_route_config_begin(struct ebpfos_netdev_route *route)
{
	bool component;

	spin_lock_bh(&route->lock);
	atomic_inc(&route->active);
	component = route->component && !route->draining;
	spin_unlock_bh(&route->lock);
	return component && in_task() && preemptible() && !irqs_disabled();
}

static int ebpfos_netdev_route_config_call(struct ebpfos_netdev_route *route,
		u64 method, const void *input, u32 input_size, void *addr,
		struct rtnl_link_stats64 *stats, s32 *status)
{
	struct ebpfos_component_call_frame frame = {};
	struct ebpfos_effect_scope *scope;
	u64 epoch = 0;
	u32 provider_id = 0, provider_status = 0;
	int error;

	if (input_size > sizeof(frame.input))
		return -E2BIG;
	frame.version = EBPFOS_COMPONENT_CALL_ABI_VERSION;
	frame.method_id = method;
	frame.object_id = route->handle;
	frame.input_size = input_size;
	if (input_size)
		memcpy(frame.input, input, input_size);
	scope = ebpfos_effect_net_config_scope_enter(route->handle,
						 route->dev, addr, stats);
	if (IS_ERR(scope)) {
		error = PTR_ERR(scope);
	} else {
		error = ebpfos_fops_route_call(route->handle, route->role, &frame,
					       &epoch, &provider_id,
					       &provider_status);
		if (ebpfos_effect_scope_exit(scope) && !error)
			error = -EPROTO;
		if (!error && (provider_status || frame.output_size))
			error = -EPROTO;
	}
	if (error) {
		atomic64_inc(&route->faults);
		WRITE_ONCE(route->component, false);
	} else {
		atomic64_inc(&route->component_entries);
		atomic64_inc(&route->method_entries[method]);
		*status = frame.status;
	}
	return error;
}

static int ebpfos_netdev_route_validate_addr(struct net_device *dev)
{
	struct ebpfos_netdev_route *route = READ_ONCE(dev->ebpfos_route);
	s32 status = 0;
	int result;

	if (ebpfos_netdev_route_config_begin(route) &&
	    !ebpfos_netdev_route_config_call(route, 2, NULL, 0, NULL, NULL,
					     &status))
		result = status;
	else {
		atomic64_inc(&route->linux_entries);
		result = route->original->ndo_validate_addr(dev);
	}
	ebpfos_netdev_route_finish(route);
	return result;
}

static void ebpfos_netdev_route_set_rx_mode_async(struct net_device *dev,
		struct netdev_hw_addr_list *uc, struct netdev_hw_addr_list *mc)
{
	struct ebpfos_netdev_route *route = READ_ONCE(dev->ebpfos_route);
	s32 status = 0;

	if (!ebpfos_netdev_route_config_begin(route) ||
	    ebpfos_netdev_route_config_call(route, 3, NULL, 0, NULL, NULL,
					    &status)) {
		atomic64_inc(&route->linux_entries);
		route->original->ndo_set_rx_mode_async(dev, uc, mc);
	}
	ebpfos_netdev_route_finish(route);
}

static int ebpfos_netdev_route_set_mac_address(struct net_device *dev,
					       void *addr)
{
	struct ebpfos_netdev_route *route = READ_ONCE(dev->ebpfos_route);
	s32 status = 0;
	int result;

	if (ebpfos_netdev_route_config_begin(route) &&
	    !ebpfos_netdev_route_config_call(route, 4, addr,
					     sizeof(struct sockaddr), addr,
					     NULL, &status))
		result = status;
	else {
		atomic64_inc(&route->linux_entries);
		result = route->original->ndo_set_mac_address(dev, addr);
	}
	ebpfos_netdev_route_finish(route);
	return result;
}

static void ebpfos_netdev_route_get_stats64(struct net_device *dev,
					    struct rtnl_link_stats64 *stats)
{
	struct ebpfos_netdev_route *route = READ_ONCE(dev->ebpfos_route);
	s32 status = 0;

	if (!ebpfos_netdev_route_config_begin(route) ||
	    ebpfos_netdev_route_config_call(route, 5, NULL, 0, NULL, stats,
					    &status)) {
		atomic64_inc(&route->linux_entries);
		route->original->ndo_get_stats64(dev, stats);
	}
	ebpfos_netdev_route_finish(route);
}

static int ebpfos_netdev_route_change_carrier(struct net_device *dev,
					      bool new_carrier)
{
	struct ebpfos_netdev_route *route = READ_ONCE(dev->ebpfos_route);
	u8 input = new_carrier;
	s32 status = 0;
	int result;

	if (ebpfos_netdev_route_config_begin(route) &&
	    !ebpfos_netdev_route_config_call(route, 6, &input, sizeof(input),
					     NULL, NULL, &status))
		result = status;
	else {
		atomic64_inc(&route->linux_entries);
		result = route->original->ndo_change_carrier(dev, new_carrier);
	}
	ebpfos_netdev_route_finish(route);
	return result;
}

static struct ebpfos_netdev_route *ebpfos_netdev_route_get(
						 struct net_device *dev)
{
	struct ebpfos_netdev_route *route;

	list_for_each_entry(route, &ebpfos_netdev_routes, list)
		if (route->dev == dev)
			return route;
	return NULL;
}

static int ebpfos_netdev_route_quiesce(struct ebpfos_netdev_route *route)
{
	spin_lock_bh(&route->lock);
	if (route->draining) {
		spin_unlock_bh(&route->lock);
		return -EBUSY;
	}
	route->draining = true;
	spin_unlock_bh(&route->lock);
	wait_event(route->drained, !atomic_read(&route->active));
	return 0;
}

static void ebpfos_netdev_route_resume(struct ebpfos_netdev_route *route)
{
	spin_lock_bh(&route->lock);
	route->draining = false;
	spin_unlock_bh(&route->lock);
	netif_tx_wake_all_queues(route->dev);
}

static int ebpfos_netdev_route_attach(struct net_device *dev,
					     u64 handle, u64 role, u64 method_mask)
{
	struct ebpfos_netdev_route *route;
	int error;

	if (!handle || !role || ebpfos_netdev_route_get(dev))
		return -EINVAL;
	if (!method_mask)
		method_mask = 0x7e;
	if (method_mask & ~0x7eULL)
		return -EINVAL;
	route = kzalloc(sizeof(*route), GFP_KERNEL);
	if (!route)
		return -ENOMEM;
	error = ebpfos_effect_handle_get(handle);
	if (error)
		goto out_free;
	route->original = READ_ONCE(dev->netdev_ops);
	if (!route->original || !route->original->ndo_start_xmit) {
		error = -EOPNOTSUPP;
		goto out_put;
	}
	route->routed = *route->original;
#define EBPFOS_INSTALL_NETDEV(name, method_id) \
	if ((method_mask & (1ULL << method_id)) && route->original->ndo_##name) \
		route->routed.ndo_##name = ebpfos_netdev_route_##name;
	EBPFOS_NETDEV_ROUTE_METHODS(EBPFOS_INSTALL_NETDEV)
#undef EBPFOS_INSTALL_NETDEV
	route->dev = dev;
	dev_hold(dev);
	route->handle = handle;
	route->role = role;
	route->method_mask = method_mask;
	spin_lock_init(&route->lock);
	init_waitqueue_head(&route->drained);
	atomic_set(&route->active, 0);
	for (int method = 1; method <= 6; ++method)
		atomic64_set(&route->method_entries[method], 0);
	list_add(&route->list, &ebpfos_netdev_routes);
	WRITE_ONCE(dev->ebpfos_route, route);
	smp_wmb();
	WRITE_ONCE(dev->netdev_ops, &route->routed);
	synchronize_net();
	return 0;
out_put:
	ebpfos_effect_handle_put(handle);
out_free:
	kfree(route);
	return error;
}

static int ebpfos_netdev_route_detach(struct ebpfos_netdev_route *route)
{
	int error;

	error = ebpfos_netdev_route_quiesce(route);
	if (error)
		return error;
	WRITE_ONCE(route->dev->netdev_ops, route->original);
	synchronize_net();
	WRITE_ONCE(route->dev->ebpfos_route, NULL);
	list_del(&route->list);
	ebpfos_effect_handle_put(route->handle);
	dev_put(route->dev);
	kfree(route);
	return 0;
}

static long ebpfos_netdev_route_ioctl(struct file *control,
				     unsigned int command, unsigned long argument)
{
	struct ebpfos_netdev_route_request request;
	struct ebpfos_netdev_route *route;
	struct net_device *dev;
	long result = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (copy_from_user(&request, (void __user *)argument, sizeof(request)))
		return -EFAULT;
	if (request.flags & ~EBPFOS_NETDEV_ROUTE_F_COMPONENT)
		return -EINVAL;
	dev = dev_get_by_index(current->nsproxy->net_ns, request.ifindex);
	if (!dev)
		return -ENODEV;
	rtnl_lock();
	route = ebpfos_netdev_route_get(dev);
	switch (command) {
	case EBPFOS_NETDEV_ROUTE_IOC_ATTACH:
		result = ebpfos_netdev_route_attach(dev, request.handle,
					    request.role, request.method_mask);
		break;
	case EBPFOS_NETDEV_ROUTE_IOC_DETACH:
		result = route ? ebpfos_netdev_route_detach(route) : -ENOENT;
		break;
	case EBPFOS_NETDEV_ROUTE_IOC_QUIESCE:
		result = route ? ebpfos_netdev_route_quiesce(route) : -ENOENT;
		break;
	case EBPFOS_NETDEV_ROUTE_IOC_SWITCH:
		if (!route || !READ_ONCE(route->draining))
			result = -EINVAL;
		else
			WRITE_ONCE(route->component,
				request.flags & EBPFOS_NETDEV_ROUTE_F_COMPONENT);
		break;
	case EBPFOS_NETDEV_ROUTE_IOC_RESUME:
		if (!route)
			result = -ENOENT;
		else
			ebpfos_netdev_route_resume(route);
		break;
	case EBPFOS_NETDEV_ROUTE_IOC_STATS:
		if (!route) {
			result = -ENOENT;
			break;
		}
		request.linux_entries = atomic64_read(&route->linux_entries);
		request.component_entries = atomic64_read(&route->component_entries);
		request.faults = atomic64_read(&route->faults);
		request.method_mask = route->method_mask;
		for (int method = 1; method <= 6; ++method)
			request.method_entries[method] =
				atomic64_read(&route->method_entries[method]);
		result = copy_to_user((void __user *)argument, &request,
				      sizeof(request)) ? -EFAULT : 0;
		break;
	default:
		result = -ENOTTY;
	}
	rtnl_unlock();
	dev_put(dev);
	return result;
}

static const struct file_operations ebpfos_netdev_route_control_ops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ebpfos_netdev_route_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_ptr_ioctl,
#endif
};

static struct miscdevice ebpfos_netdev_route_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "ebpfos-netdev-route",
	.fops = &ebpfos_netdev_route_control_ops,
};

static int ebpfos_netdev_route_netdev_event(struct notifier_block *block,
					    unsigned long event, void *data)
{
	struct net_device *dev = netdev_notifier_info_to_dev(data);
	struct ebpfos_netdev_route *route;

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;
	route = ebpfos_netdev_route_get(dev);
	if (route)
		ebpfos_netdev_route_detach(route);
	return NOTIFY_DONE;
}

static struct notifier_block ebpfos_netdev_route_notifier = {
	.notifier_call = ebpfos_netdev_route_netdev_event,
};

static int __init ebpfos_netdev_route_init(void)
{
	int error = register_netdevice_notifier(&ebpfos_netdev_route_notifier);

	if (error)
		return error;
	error = misc_register(&ebpfos_netdev_route_device);
	if (error)
		unregister_netdevice_notifier(&ebpfos_netdev_route_notifier);
	return error;
}
device_initcall(ebpfos_netdev_route_init);
