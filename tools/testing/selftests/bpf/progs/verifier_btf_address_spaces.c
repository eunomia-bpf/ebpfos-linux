// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

extern struct rq runqueues __ksym;

__noinline int read_rq(struct rq *p __arg_untrusted)
{
	return p->nr_running;
}

SEC("?raw_tp")
__failure __msg("arg#0 has incompatible address space")
int untrusted_global_percpu_template(void *ctx)
{
	return read_rq(&runqueues);
}

SEC("?raw_tp")
__success
int untrusted_global_selected_cpu(void *ctx)
{
	return read_rq(bpf_this_cpu_ptr(&runqueues));
}

char _license[] SEC("license") = "GPL";
