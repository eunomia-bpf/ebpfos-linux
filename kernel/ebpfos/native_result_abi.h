/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_NATIVE_RESULT_ABI_H
#define EBPFOS_NATIVE_RESULT_ABI_H
struct bpf_prog;
#if defined(CONFIG_X86) && defined(CONFIG_EBPFOS_KOPERATION)
bool ebpfos_prog_native_result2(const struct bpf_prog *prog);
#else
static inline bool ebpfos_prog_native_result2(const struct bpf_prog *prog) { return false; }
#endif
#endif
