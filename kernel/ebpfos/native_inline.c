// SPDX-License-Identifier: GPL-2.0-only
/* Retain only declared original inline bodies through their actual C address.
 * The configured source headers supply the body and ABI; no wrapper, prototype
 * or assembly is rewritten. This LTO object is also the compiler's template.
 */
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <asm/archrandom.h>
#include <asm/checksum.h>
#include <asm/cpuid/api.h>
#include <asm/desc.h>
#include <asm/fsgsbase.h>
#include <asm/gsseg.h>
#include <asm/io.h>
#include <asm/irqflags.h>
#include <asm/msr.h>
#include <asm/mwait.h>
#include <asm/nospec-branch.h>
#include <asm/special_insns.h>
#include <asm/tsc.h>

#define NATIVE_INLINE_FUNCTION(source, native, flags) \
	static __typeof__(&source) const __used ebpfos_native_inline_##native = &source;
#define NATIVE_FUNCTION(source, native, flags)
#define NATIVE_STATIC_CALL(source, native, record, field, flags)
#define NATIVE_ALIAS(source, native)
#define NATIVE_ARG(native, index, tag)
#define NATIVE_ENUM_MAX(native, index, record, sentinel)
#define NATIVE_POINTEE_TAG(native, index, tag)
#include <linux/ebpfos_native_set.def>
#undef NATIVE_INLINE_FUNCTION
#undef NATIVE_FUNCTION
#undef NATIVE_STATIC_CALL
#undef NATIVE_ALIAS
#undef NATIVE_ARG
#undef NATIVE_ENUM_MAX
#undef NATIVE_POINTEE_TAG
