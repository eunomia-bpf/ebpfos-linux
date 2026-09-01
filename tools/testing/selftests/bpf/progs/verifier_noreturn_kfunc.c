// SPDX-License-Identifier: GPL-2.0

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"
#include "../test_kmods/bpf_testmod_kfunc.h"

extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

struct bpf_spin_lock lock SEC(".bss.noreturn_lock") __hidden
	__aligned(8);

SEC("?tc")
__description("no-return kfunc is a final CFG instruction")
__success
__naked void noreturn_kfunc_no_fallthrough(void)
{
	asm volatile("call %[bpf_kfunc_noreturn_test];"
	:
	: __imm(bpf_kfunc_noreturn_test)
	: __clobber_all);
}

SEC("?tc")
__description("ordinary infinite loop remains rejected")
__failure __msg("infinite loop detected")
__naked void noreturn_kfunc_does_not_admit_loop(void)
{
	asm volatile("l0_%=: goto l0_%=;"
	:
	:
	: __clobber_all);
}

SEC("?tc")
__description("no-return kfunc rejects active lock")
__failure __msg("function calls are not allowed while holding a lock")
int noreturn_kfunc_reject_lock(struct __sk_buff *ctx)
{
	bpf_spin_lock(&lock);
	if (ctx->len)
		bpf_kfunc_noreturn_test();
	bpf_spin_unlock(&lock);
	return 0;
}

SEC("?tc")
__description("no-return kfunc rejects active RCU critical section")
__failure __msg("terminal kfunc cannot be used inside bpf_rcu_read_lock-ed region")
int noreturn_kfunc_reject_rcu(struct __sk_buff *ctx)
{
	bpf_rcu_read_lock();
	if (ctx->len)
		bpf_kfunc_noreturn_test();
	bpf_rcu_read_unlock();
	return 0;
}

SEC("?tc")
__description("no-return kfunc rejects unreleased reference")
__failure __msg("Unreleased reference")
int noreturn_kfunc_reject_reference(struct __sk_buff *ctx)
{
	struct prog_test_ref_kfunc *ref;
	unsigned long scalar = 0;

	ref = bpf_kfunc_call_test_acquire(&scalar);
	if (!ref)
		return 0;
	if (ctx->len)
		bpf_kfunc_noreturn_test();
	bpf_kfunc_call_test_release(ref);
	return 0;
}

char _license[] SEC("license") = "GPL";
