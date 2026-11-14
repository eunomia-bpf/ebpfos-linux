// SPDX-License-Identifier: GPL-2.0-only
/* AC transitions. The reference tracks an owed CLAC, not memory authority. */
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <linux/init.h>
#include "syscall_kfuncs.h"
#include <asm/cpufeature.h>
#include "koperation_user_window.generated.h"

/* No fields, destructor or transfer API: this object cannot be dereferenced.
 * The token is global: an AOT body carries its address as a relocation, so
 * the image that runs the body supplies its own address. */
struct bpf_ebpfos_user_access_window {};
struct bpf_ebpfos_user_access_window ebpfos_user_access_window_cookie;

__bpf_kfunc_start_defs();
__bpf_kfunc struct bpf_ebpfos_user_access_window *
bpf_ebpfos_x86_user_access_open(void)
{
	asm volatile("stac" : : : "memory");
	return &ebpfos_user_access_window_cookie;
}
__bpf_kfunc void bpf_ebpfos_x86_user_access_close(
		struct bpf_ebpfos_user_access_window *window)
{
	asm volatile("clac" : : : "memory");
}
__bpf_kfunc __attribute__((btf_decl_tag("bpf_kop_payload_id:0"))) u64 bpf_ebpfos_kop_user_access_open(void)
{
	return 0; /* Replaced by the checked proof or single-instruction emission. */
}
__bpf_kfunc __attribute__((btf_decl_tag("bpf_kop_payload_id:0"))) u64 bpf_ebpfos_kop_user_access_close(
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

	insns[0] = BPF_CALL_KFUNC(0, window_open_services.pairs[0].id);
	return 1;
}
static int window_close_proof(u64 payload, struct bpf_insn *insns)
{

	insns[0] = BPF_CALL_KFUNC(0, window_close_services.pairs[0].id);
	return 1;
}
static int window_open_emit(u8 *image, u32 *offset, bool emit, u64 payload,
		const struct bpf_prog *prog, const u8 *final_ip)
{
	/* STAC, then a flag-preserving return of the stable opaque token. */
	u8 native[] = { 0x0f, 0x01, 0xcb, 0x48, 0xb8,
		0, 0, 0, 0, 0, 0, 0, 0 };
	u64 cookie = (unsigned long)&ebpfos_user_access_window_cookie;
	static const u8 instruction[] = EBPFOS_USER_STAC_INSN;

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

	memcpy(native, instruction, sizeof(instruction));
	if (emit)
		memcpy(image + *offset, native, sizeof(native));
	*offset += sizeof(native);
	return sizeof(native);
}
static int window_open_reloc(u64 payload, unsigned int index,
		struct bpf_kop_reloc *reloc)
{
	/* The MOVABS immediate after STAC and its REX.W B8 opcode. */
	*reloc = (struct bpf_kop_reloc) {
		.offset = sizeof((u8[])EBPFOS_USER_STAC_INSN) + 2, .size = 8,
		.symbol = "ebpfos_user_access_window_cookie",
	};
	return 0;
}
static struct bpf_kop window_open_kop = {
	.num_x86_relocs = 1, .x86_reloc = window_open_reloc,
	.max_insn_cnt = 1, .max_emit_bytes = 13,
	.instantiate_insn = window_open_proof, .emit_x86 = window_open_emit,

};
static struct bpf_kop window_close_kop = {
	.max_insn_cnt = 1, .max_emit_bytes = 8,
	.instantiate_insn = window_close_proof, .emit_x86 = window_close_emit,

};
/* Each singleton owns its exact semantic descriptor; BTF sets are sorted. */
static const struct bpf_kop * const window_open_descriptors[] = { &window_open_kop };
static const struct bpf_kop * const window_close_descriptors[] = { &window_close_kop };
static int window_context_filter(const struct bpf_prog *prog, u32 id);
static const struct btf_kfunc_id_set window_open_service_set = { .set = &window_open_services, .filter = window_context_filter };
static const struct btf_kfunc_id_set window_close_service_set = { .set = &window_close_services, .filter = window_context_filter };
static const struct btf_kfunc_id_set window_open_set = {
	.set = &window_open_ids, .kop_descs = window_open_descriptors,
 .filter = window_context_filter,
};
static const struct btf_kfunc_id_set window_close_set = {
	.set = &window_close_ids, .kop_descs = window_close_descriptors,
 .filter = window_context_filter,
};
static const struct btf_kfunc_id_set * const window_sets[] = {
 &window_open_service_set,
 &window_close_service_set,
 &window_open_set,
 &window_close_set,
};
static int window_context_filter(const struct bpf_prog *prog, u32 id)
{
 return ebpfos_syscall_kfunc_filter(prog, id, window_sets,
                                    ARRAY_SIZE(window_sets));
}
static int __init window_register(void)
{
 /* An absent configured source alternative is not a requested opcode. */
 if (!boot_cpu_has(X86_FEATURE_SMAP)) return 0;
 window_open_kop.proof_kfunc_id = window_open_services.pairs[0].id;
 window_close_kop.proof_kfunc_id = window_close_services.pairs[0].id;
 return ebpfos_register_syscall_kfuncs(window_sets, ARRAY_SIZE(window_sets));
}

late_initcall(window_register);
