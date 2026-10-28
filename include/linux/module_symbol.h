/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_MODULE_SYMBOL_H
#define _LINUX_MODULE_SYMBOL_H

#include <linux/types.h>

struct module;
#if defined(CONFIG_MODULES) && defined(CONFIG_KALLSYMS)
/* Caller holds a reference to the live module. */
bool module_address_is_exported(const struct module *mod, unsigned long address);
#else
static inline bool module_address_is_exported(const struct module *mod, unsigned long address)
{
 return false;
}
#endif

/* Kernel symbol flags bitset. */
enum ksym_flags {
	KSYM_FLAG_GPL_ONLY	= 1 << 0,
};

/* This ignores the intensely annoying "mapping symbols" found in ELF files. */
static inline bool is_mapping_symbol(const char *str)
{
	if (str[0] == '.' && str[1] == 'L')
		return true;
	if (str[0] == 'L' && str[1] == '0')
		return true;
	return str[0] == '$';
}

#endif /* _LINUX_MODULE_SYMBOL_H */
