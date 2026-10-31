/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_NATIVE_H
#define EBPFOS_FUNCTION_NATIVE_H
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/rcupdate.h>
#include <linux/ftrace.h>
/* Only Linux's existing function-trace entry; no compiler reservations. */
static inline unsigned long ebpfos_ftrace_entry(unsigned long address)
{
 unsigned long ip = ftrace_location(address);
#ifdef FTRACE_MCOUNT_MAX_OFFSET
 if (ip && (ip < address || ip - address > FTRACE_MCOUNT_MAX_OFFSET)) return 0;
#endif
 return ip;
}
/* Module BTF may label C globals STATIC. Global and weak ELF definitions
 * retain the public callable ABI; private definitions may have specialized
 * arguments not described by source BTF. Init/exit text is not resident. */
static inline unsigned long ebpfos_module_function(struct module *module, const char *name)
{
 unsigned long target = 0;
#if defined(CONFIG_MODULES) && defined(CONFIG_KALLSYMS)
 struct mod_kallsyms *symbols;
 unsigned int i;
 rcu_read_lock();
 symbols = rcu_dereference(module->kallsyms);
 for (i = 0; symbols && i < symbols->num_symtab; ++i) {
  const Elf_Sym *symbol = &symbols->symtab[i];
  if (strcmp(name, symbols->strtab + symbol->st_name)) continue;
  if (target || (ELF_ST_BIND(symbol->st_info) != STB_GLOBAL &&
                 ELF_ST_BIND(symbol->st_info) != STB_WEAK) ||
      ELF_ST_TYPE(symbol->st_info) != STT_FUNC ||
      symbol->st_shndx == SHN_UNDEF) {
   target = 0;break;
  }
  target = kallsyms_symbol_value(symbol);
 }
 rcu_read_unlock();
 if (!within_module_mem_type(target, module, MOD_TEXT)) target = 0;
#endif
 return target;
}
struct ebpfos_core_symbol { unsigned long address; bool found, ambiguous, text; };
static int ebpfos_core_match(void *opaque, unsigned long address)
{
 struct ebpfos_core_symbol *symbol = opaque;
 if (symbol->text && !core_kernel_text(address)) return 0;
 if (symbol->found && symbol->address != address) {symbol->ambiguous = true;return 1;}
 symbol->address = address;symbol->found = true;return 0;
}
static inline unsigned long ebpfos_core_symbol_address(const char *name, bool text)
{
 struct ebpfos_core_symbol symbol = {.text=text};
 kallsyms_on_each_match_symbol(ebpfos_core_match, name, &symbol);
 return symbol.ambiguous ? 0 : symbol.address;
}
/* Resolve one resident definition in its owning image, never a same-named
 * symbol in another module. The caller holds the module through publication. */
static inline unsigned long ebpfos_native_function(struct btf *btf, u32 id, struct module *module)
{
 const struct btf_type *function = btf_type_by_id(btf, id);
 unsigned long address;
 if (!function || !btf_type_is_func(function) ||
     (module && id < btf_nr_types(bpf_get_btf_vmlinux()))) return 0;
 address = module ? ebpfos_module_function(module, btf_name_by_offset(btf, function->name_off)) :
  ebpfos_core_symbol_address(btf_name_by_offset(btf, function->name_off), true);
 return address && (module || core_kernel_text(address)) ? address : 0;
}
#endif
