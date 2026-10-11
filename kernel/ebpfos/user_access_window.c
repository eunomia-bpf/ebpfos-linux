// SPDX-License-Identifier: GPL-2.0-only
/* AC transitions. The reference tracks an owed CLAC, not memory authority. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include <asm/cpufeature.h>
#include "koperation_user_window.generated.h"

/* No fields, destructor or transfer API: this object cannot be dereferenced. */
struct bpf_ebpfos_user_access_window {};
static struct bpf_ebpfos_user_access_window window_cookie;

__bpf_kfunc_start_defs();
__bpf_kfunc struct bpf_ebpfos_user_access_window *
bpf_ebpfos_x86_user_access_open(void)
{
	asm volatile("stac" : : : "memory");
	return &window_cookie;
}
__bpf_kfunc void bpf_ebpfos_x86_user_access_close(
		struct bpf_ebpfos_user_access_window *window)
{
	asm volatile("clac" : : : "memory");
}
__bpf_kfunc u64 bpf_ebpfos_kop_user_access_open(void)
{
	return 0; /* Replaced by the checked proof or single-instruction emission. */
}
__bpf_kfunc u64 bpf_ebpfos_kop_user_access_close(
		void *window)
{
	return 0;
}
__bpf_kfunc_end_defs();

BTF_KFUNCS_START(window_open_services)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_user_access_open, KF_ACQUIRE)
BTF_KFUNCS_END(window_open_services)
BTF_KFUNCS_START(window_close_services)
BTF_ID_FLAGS(func, bpf_ebpfos_x86_user_access_close, KF_RELEASE)
BTF_KFUNCS_END(window_close_services)
BTF_KFUNCS_START(window_open_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_user_access_open)
BTF_KFUNCS_END(window_open_ids)
BTF_KFUNCS_START(window_close_ids)
BTF_ID_FLAGS(func, bpf_ebpfos_kop_user_access_close)
BTF_KFUNCS_END(window_close_ids)

static int window_open_proof(u64 payload, struct bpf_insn *insns)
{
	if (!insns || payload != window_open_ids.pairs[0].id)
		return -EINVAL;
	insns[0] = BPF_CALL_KFUNC(0, window_open_services.pairs[0].id);
	return 1;
}
static int window_close_proof(u64 payload, struct bpf_insn *insns)
{
	if (!insns || payload != window_close_ids.pairs[0].id)
		return -EINVAL;
	insns[0] = BPF_CALL_KFUNC(0, window_close_services.pairs[0].id);
	return 1;
}
static int window_open_emit(u8 *image, u32 *offset, bool emit, u64 payload,
		const struct bpf_prog *prog, const u8 *final_ip)
{
	/* STAC, then a flag-preserving return of the stable opaque token. */
	u8 native[] = { 0x0f, 0x01, 0xcb, 0x48, 0xb8,
		0, 0, 0, 0, 0, 0, 0, 0 };
	u64 cookie = (unsigned long)&window_cookie;
	static const u8 instruction[] = EBPFOS_USER_STAC_INSN;
	if (!offset || (emit && !image) || payload != window_open_ids.pairs[0].id)
		return -EINVAL;
	memcpy(native + 5, &cookie, sizeof(cookie));
	memcpy(native, instruction, sizeof(instruction));
	if (emit)
		memcpy(image + *offset, native, sizeof(native));
	*offset += sizeof(native);
	return sizeof(native);
}
static int window_close_emit(u8 *image, u32 *offset, bool emit, u64 payload,
		const struct bpf_prog *prog, const u8 *final_ip)
{
	/* CLAC, then MOV (not XOR) to preserve the source arithmetic flags. */
	u8 native[] = { 0x0f, 0x01, 0xca, 0xb8, 0, 0, 0, 0 };
	static const u8 instruction[] = EBPFOS_USER_CLAC_INSN;
	if (!offset || (emit && !image) || payload != window_close_ids.pairs[0].id)
		return -EINVAL;
	memcpy(native, instruction, sizeof(instruction));
	if (emit)
		memcpy(image + *offset, native, sizeof(native));
	*offset += sizeof(native);
	return sizeof(native);
}
static struct bpf_kop window_open_kop = {
	.max_insn_cnt = 1, .max_emit_bytes = 13,
	.instantiate_insn = window_open_proof, .emit_x86 = window_open_emit,
	.semantic_sha256 = EBPFOS_USER_STAC_SHA256,
};
static struct bpf_kop window_close_kop = {
	.max_insn_cnt = 1, .max_emit_bytes = 8,
	.instantiate_insn = window_close_proof, .emit_x86 = window_close_emit,
	.semantic_sha256 = EBPFOS_USER_CLAC_SHA256,
};
/* Each singleton owns its exact semantic descriptor; BTF sets are sorted. */
static const struct bpf_kop * const window_open_descriptors[] = { &window_open_kop };
static const struct bpf_kop * const window_close_descriptors[] = { &window_close_kop };
static const struct btf_kfunc_id_set window_open_service_set = { .set = &window_open_services };
static const struct btf_kfunc_id_set window_close_service_set = { .set = &window_close_services };
static const struct btf_kfunc_id_set window_open_set = {
	.set = &window_open_ids, .kop_descs = window_open_descriptors,
};
static const struct btf_kfunc_id_set window_close_set = {
	.set = &window_close_ids, .kop_descs = window_close_descriptors,
};
static int __init window_register(void)
{
	int error;
	/* An absent configured source alternative is not a requested opcode. */
	if (!boot_cpu_has(X86_FEATURE_SMAP))
		return 0;
	window_open_kop.proof_kfunc_id = window_open_services.pairs[0].id;
	window_close_kop.proof_kfunc_id = window_close_services.pairs[0].id;
	error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &window_open_service_set);
	if (error)
		return error;
	error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &window_close_service_set);
	if (error)
		return error;
	error = register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &window_open_set);
	if (error)
		return error;
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_SYSCALL, &window_close_set);
}
late_initcall(window_register);
