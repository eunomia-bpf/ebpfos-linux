/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_NATIVE_H
#define EBPFOS_FUNCTION_NATIVE_H
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/rcupdate.h>
#include <linux/ftrace.h>
#include <asm/ibt.h>
/* Only Linux's existing function-trace entry; no compiler reservations. */
static inline unsigned long ebpfos_ftrace_entry(unsigned long address)
{
 return ftrace_location(address);
}
/* Private page views need an instruction address, not reserved patch space. */
static inline unsigned long ebpfos_view_entry(unsigned long address)
{
 unsigned long ip = ebpfos_ftrace_entry(address);
 return ip ? ip : address + (is_endbr((u32 *)address) ? ENDBR_INSN_SIZE : 0);
}
/* Module BTF may label C globals STATIC. Global and weak ELF definitions
 * retain the public callable ABI; private definitions may have specialized
 * arguments not described by source BTF. Init/exit text is not resident. */
static inline unsigned long ebpfos_module_symbol(struct module *module, const char *name,
 bool text, u32 min_size)
{
#if defined(CONFIG_MODULES) && defined(CONFIG_KALLSYMS)
 return find_kallsyms_symbol_value(module, name);
#else
 return 0;
#endif
}
static inline unsigned long ebpfos_module_function(struct module *module, const char *name)
{ return ebpfos_module_symbol(module, name, true, 0); }
static inline unsigned long ebpfos_core_symbol_address(const char *name, bool text)
{
 return kallsyms_lookup_name(name);
}
/* Resolve one resident definition in its owning image, never a same-named
 * symbol in another module. The caller holds the module through publication. */
static inline unsigned long ebpfos_native_function(struct btf *btf, u32 id, struct module *module)
{
 const struct btf_type *function = btf_type_by_id(btf, id);
 unsigned long address;
 if (!function || !btf_type_is_func(function)) return 0;
 address = module ? ebpfos_module_function(module, btf_name_by_offset(btf, function->name_off)) :
  ebpfos_core_symbol_address(btf_name_by_offset(btf, function->name_off), true);
 return address;
}
#endif
