/* SPDX-License-Identifier: GPL-2.0-only */
/* Generated from file_operations BTF by generate-fops-route.py. */
#ifndef _EBPFOS_FOPS_ROUTE_GENERATED_H
#define _EBPFOS_FOPS_ROUTE_GENERATED_H
#define EBPFOS_FOPS_ROUTE_ITER_METHODS(X) \
	X(read_iter, 1) \
	X(write_iter, 2)
#define EBPFOS_FOPS_ROUTE_WRITE_METHODS(X) X(write, 3)
#define EBPFOS_FOPS_ROUTE_POLL_METHODS(X) X(poll, 4)
#define EBPFOS_FOPS_ROUTE_RELEASE_METHODS(X) X(release, 5)
#define EBPFOS_FOPS_ROUTE_READ_METHODS(X) X(read, 6)
#define EBPFOS_FOPS_ROUTE_LLSEEK_METHODS(X) X(llseek, 7)
/* Keep the original iterator-only route source compatible. */
#define EBPFOS_FOPS_ROUTE_METHODS(X) EBPFOS_FOPS_ROUTE_ITER_METHODS(X)
#endif
