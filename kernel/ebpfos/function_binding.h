/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_BINDING_H
#define EBPFOS_FUNCTION_BINDING_H
struct bpf_prog;
struct module;
/* A prepared address owns its verified graph or trusted native module. */
struct ebpfos_function_binding {
 struct bpf_prog *program;
 struct module *module;
 unsigned long address;
};
#endif
