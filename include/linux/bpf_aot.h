/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_BPF_AOT_H
#define _LINUX_BPF_AOT_H

#include <linux/types.h>
#include <uapi/linux/bpf_aot.h>

struct bpf_prog;
int bpf_jit_aot(struct bpf_prog *prog, struct bpf_aot_request *request,
	       void **object, u32 *size);

#endif
