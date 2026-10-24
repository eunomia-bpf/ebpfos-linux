/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_FUNCTION_NATIVE_H
#define EBPFOS_FUNCTION_NATIVE_H
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
#endif
