// SPDX-License-Identifier: GPL-2.0-only
/* Retain only declared original inline bodies through their actual C address.
 * The configured source headers supply the body and ABI; no wrapper, prototype
 * or assembly is rewritten. This LTO object is also the compiler's template.
 */
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <asm/alternative.h>
#include <asm/archrandom.h>
#include <asm/page.h>
#include <asm/paravirt.h>
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
#include <asm/sync_core.h>
#include <asm/tsc.h>

/* C-callable boundaries for Linux's original checked dual-result macro.
 * The .S entries keep their RAX/RDX convention; the macro performs that call.
 */
#define RETAIN_GET_USER(width, type) \
	noinline __used int ebpfos_native_get_user_##width(const type __user *source, type *value) \
	{ return do_get_user_call(get_user, *value, source); }
RETAIN_GET_USER(1, u8)
RETAIN_GET_USER(2, u16)
RETAIN_GET_USER(4, u32)
RETAIN_GET_USER(8, u64)
#undef RETAIN_GET_USER

#define NATIVE_INLINE_FUNCTION(source, native, flags) \
	static __typeof__(&source) const __used ebpfos_native_inline_##native = &source;
/* Retain a source-only assembly declaration as a typed record member. */
#define NATIVE_PROTOTYPE(source) \
	struct ebpfos_native_proto_##source { __typeof__(&source) fn; }; \
	static const struct ebpfos_native_proto_##source __used \
		ebpfos_native_proto_capture_##source = { .fn = &source };
#define NATIVE_FUNCTION(source, native, flags)
#define NATIVE_STATIC_CALL(source, native, record, field, flags)
#define NATIVE_ALIAS(source, native)
#define NATIVE_ARG(native, index, tag)
#define NATIVE_ENUM_MAX(native, index, record, sentinel)
#define NATIVE_COUNT_MAX(native, index, count)
#define NATIVE_POINTEE_TAG(native, index, tag)
#include <linux/ebpfos_native_set.def>
#undef NATIVE_INLINE_FUNCTION
#undef NATIVE_PROTOTYPE
#undef NATIVE_FUNCTION
#undef NATIVE_STATIC_CALL
#undef NATIVE_ALIAS
#undef NATIVE_ARG
#undef NATIVE_ENUM_MAX
#undef NATIVE_COUNT_MAX
#undef NATIVE_POINTEE_TAG
