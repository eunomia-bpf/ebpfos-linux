/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/init.h>

	__INITRODATA

	.align 8
	.globl ebpfos_certificate_list
ebpfos_certificate_list:
	.incbin "kernel/ebpfos/ebpfos_x509_certificate_list"
	.globl ebpfos_certificate_list_end
ebpfos_certificate_list_end:
