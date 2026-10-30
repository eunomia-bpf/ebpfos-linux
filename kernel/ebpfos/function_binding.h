/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_BINDING_H
#define EBPFOS_FUNCTION_BINDING_H
#include <linux/btf.h>

/* Consume one BTF reference and return the defining provider for a binding
 * ID. A shared prototype or record does not determine storage/code ownership. */
static inline struct btf *ebpfos_binding_btf_owner(struct btf *types, u32 id)
{
 struct btf *owner = types, *base;
 while ((base = btf_base_btf(owner)) && id < btf_nr_types(base))
  owner = base;
 if (owner != types) {btf_get(owner);btf_put(types);}
 return owner;
}
struct bpf_prog;
struct module;
/* A prepared address owns its verified graph or trusted native module. */
struct ebpfos_function_binding {
 struct bpf_prog *program;
 struct module *module;
 struct module *source_module;
 unsigned long address;
 unsigned long native_address;
};
#endif
