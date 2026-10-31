/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _LINUX_BTF_CONTEXT_H
#define _LINUX_BTF_CONTEXT_H

/* One decoder for source and compiled BTF context annotations. Decoding a
 * declaration supplies no capability or implementation proof. Consumers must
 * still bind its resource expression and enforce their own effect policy.
 * No kernel types are needed: compiler tools use this same decoder.
 */
enum btf_context_operation {
	BTF_CONTEXT_UNKNOWN,
	BTF_CONTEXT_ACQUIRE,
	BTF_CONTEXT_RELEASE,
	BTF_CONTEXT_REQUIRE,
	BTF_CONTEXT_ASSERT,
	BTF_CONTEXT_EXCLUDE,
	BTF_CONTEXT_TRY_ACQUIRE,
};

struct btf_context_tag {
	enum btf_context_operation operation;
	unsigned int shared;
	unsigned long resource_offset;
};

static inline struct btf_context_tag
btf_context_decode(const char *text, unsigned long length)
{
	struct btf_context_tag tag = { BTF_CONTEXT_UNKNOWN, 0, 0 };
	unsigned long end, size;
	if (length < 8 || __builtin_memcmp(text, "context_", 8))
		return tag;
	for (end = 8; end < length && text[end] != ':'; end++) { }
	if (end == length)
		return tag;
	size = end - 8;
	if (size >= 7 && !__builtin_memcmp(text + end - 7, "_shared", 7)) {
		tag.shared = 1;
		size -= 7;
	}
#define BTF_CONTEXT_OPERATION(name, value) \
	if (size == sizeof(name) - 1 && \
	    !__builtin_memcmp(text + 8, name, sizeof(name) - 1)) \
		tag.operation = value
	BTF_CONTEXT_OPERATION("acquire", BTF_CONTEXT_ACQUIRE);
	BTF_CONTEXT_OPERATION("release", BTF_CONTEXT_RELEASE);
	BTF_CONTEXT_OPERATION("require", BTF_CONTEXT_REQUIRE);
	BTF_CONTEXT_OPERATION("assert", BTF_CONTEXT_ASSERT);
	BTF_CONTEXT_OPERATION("exclude", BTF_CONTEXT_EXCLUDE);
	BTF_CONTEXT_OPERATION("try_acquire", BTF_CONTEXT_TRY_ACQUIRE);
#undef BTF_CONTEXT_OPERATION
	/* There is no shared exclusion spelling in the source protocol. */
	if (tag.operation == BTF_CONTEXT_EXCLUDE && tag.shared)
		tag.operation = BTF_CONTEXT_UNKNOWN;
	tag.resource_offset = end + 1;
	return tag;
}

static inline int btf_context_transfer(enum btf_context_operation operation)
{
	return operation == BTF_CONTEXT_ACQUIRE ||
	       operation == BTF_CONTEXT_RELEASE ||
	       operation == BTF_CONTEXT_TRY_ACQUIRE;
}

static inline int btf_context_precondition(enum btf_context_operation operation)
{
	return operation == BTF_CONTEXT_REQUIRE || operation == BTF_CONTEXT_EXCLUDE;
}

static inline const char *
btf_context_operation_name(enum btf_context_operation operation)
{
	switch (operation) {
	case BTF_CONTEXT_ACQUIRE: return "acquire";
	case BTF_CONTEXT_RELEASE: return "release";
	case BTF_CONTEXT_REQUIRE:
	case BTF_CONTEXT_ASSERT: return "require";
	case BTF_CONTEXT_EXCLUDE: return "exclude";
	case BTF_CONTEXT_TRY_ACQUIRE: return "try_acquire";
	default: return "unresolved";
	}
}
#endif
