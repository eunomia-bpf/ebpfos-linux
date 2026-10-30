/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_NATIVE_H
#define EBPFOS_FUNCTION_NATIVE_H
#include <linux/btf.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/rcupdate.h>
/* Module BTF may label C globals STATIC. Require a unique global ELF FUNC
 * in ordinary module text; init/exit text cannot outlive preparation. */
static unsigned long ebpfos_module_function(struct module *module, const char *name)
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
  if (target || ELF_ST_BIND(symbol->st_info) != STB_GLOBAL ||
      ELF_ST_TYPE(symbol->st_info) != STT_FUNC || symbol->st_shndx == SHN_UNDEF) {
   target = 0;break;
  }
  target = kallsyms_symbol_value(symbol);
 }
 rcu_read_unlock();
 if (!within_module_mem_type(target, module, MOD_TEXT)) target = 0;
#endif
 return target;
}
struct ebpfos_core_symbol { unsigned long address; bool ambiguous; };
static int ebpfos_core_match(void *opaque, unsigned long address)
{
 struct ebpfos_core_symbol *symbol = opaque;
 if (!core_kernel_text(address)) return 0;
 if (symbol->address && symbol->address != address) {symbol->ambiguous = true;return 1;}
 symbol->address = address;return 0;
}
static unsigned long ebpfos_core_function(const char *name)
{
 struct ebpfos_core_symbol symbol = {};
 kallsyms_on_each_match_symbol(ebpfos_core_match, name, &symbol);
 return symbol.ambiguous ? 0 : symbol.address;
}
/* Resolve one resident definition in its owning image, never a same-named
 * symbol in another module. The caller holds the module through publication. */
static unsigned long ebpfos_native_function(struct btf *btf, u32 id, struct module *module)
{
 const struct btf_type *function = btf_type_by_id(btf, id);
 unsigned long address;
 if (!function || !btf_type_is_func(function) ||
     (module && id < btf_nr_types(bpf_get_btf_vmlinux()))) return 0;
 address = module ? ebpfos_module_function(module, btf_name_by_offset(btf, function->name_off)) :
  ebpfos_core_function(btf_name_by_offset(btf, function->name_off));
 return address && (module || core_kernel_text(address)) ? address : 0;
}
#endif
