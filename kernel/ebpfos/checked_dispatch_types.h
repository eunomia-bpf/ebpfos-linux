/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _EBPFOS_CHECKED_DISPATCH_TYPES_H
#define _EBPFOS_CHECKED_DISPATCH_TYPES_H

/* Same-image BTF only. Records/enums keep their nominal IDs; two different
 * records never become interchangeable merely because their layouts match.
 * Accessors make these exact checks executable in the compiler's host controls
 * with libbpf, without maintaining a second prototype comparison algorithm.
 */
struct ebpfos_checked_types {
	const void *context;
	const struct btf_type *(*type)(const void *context, unsigned int id);
	const char *(*name)(const void *context, unsigned int offset);
};

static inline bool ebpfos_checked_type_equal(const struct ebpfos_checked_types *btf,
	unsigned int left, unsigned int right, unsigned int depth)
{
	const struct btf_type *a, *b;
	unsigned int i;

	/* This is a refusal bound, never permission to ignore a deeper type. */
	if (depth > 64)
		return false;
	if (!left || !right)
		return left == right;
	a = btf->type(btf->context, left);
	b = btf->type(btf->context, right);
	if (!a || !b)
		return false;
	if (BTF_INFO_KIND(a->info) == BTF_KIND_TYPEDEF)
		return ebpfos_checked_type_equal(btf, a->type, right, depth + 1);
	if (BTF_INFO_KIND(b->info) == BTF_KIND_TYPEDEF)
		return ebpfos_checked_type_equal(btf, left, b->type, depth + 1);
	if (BTF_INFO_KIND(a->info) != BTF_INFO_KIND(b->info))
		return false;
	switch (BTF_INFO_KIND(a->info)) {
	case BTF_KIND_PTR:
	case BTF_KIND_CONST:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
		return ebpfos_checked_type_equal(btf, a->type, b->type, depth + 1);
	case BTF_KIND_TYPE_TAG:
		return !strcmp(btf->name(btf->context, a->name_off),
			btf->name(btf->context, b->name_off)) &&
			ebpfos_checked_type_equal(btf, a->type, b->type, depth + 1);
	case BTF_KIND_FUNC_PROTO: {
		const struct btf_param *pa = (const struct btf_param *)(a + 1);
		const struct btf_param *pb = (const struct btf_param *)(b + 1);

		if (BTF_INFO_VLEN(a->info) != BTF_INFO_VLEN(b->info) ||
		    !ebpfos_checked_type_equal(btf, a->type, b->type, depth + 1))
			return false;
		for (i = 0; i < BTF_INFO_VLEN(a->info); i++) {
			const char *na = btf->name(btf->context, pa[i].name_off);
			const char *nb = btf->name(btf->context, pb[i].name_off);

			/* Variadic calls do not have a complete checked ABI. */
			if (!pa[i].type || !pb[i].type ||
			    !ebpfos_checked_type_equal(btf, pa[i].type, pb[i].type, depth + 1))
				return false;
			/* Ordinary parameter names are immaterial. Names carrying
			 * verifier contracts cannot be silently interchanged.
			 */
			if ((strstr(na, "__") || strstr(nb, "__")) && strcmp(na, nb))
				return false;
		}
		return true;
	}
	default:
		return left == right;
	}
}
#endif
