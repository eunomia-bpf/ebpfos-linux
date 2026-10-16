/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_BINDING_H
#define EBPFOS_FUNCTION_BINDING_H
struct bpf_prog;
/* A prepared function address owns the entire independently verified graph. */
struct ebpfos_function_binding {
 struct bpf_prog *program;
 unsigned long address;
};
#endif
