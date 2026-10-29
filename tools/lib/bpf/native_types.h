/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __LIBBPF_NATIVE_TYPES_H
#define __LIBBPF_NATIVE_TYPES_H
#include "btf.h"
#ifdef __cplusplus
extern "C" {
#endif
#include "relo_core.h"
#ifdef __cplusplus
}
#endif

/* DWARF producers can flatten a multidimensional C array into one BTF
 * array. Its contiguous storage is unchanged. This is for native variable
 * binding, not CO-RE field access or a relaxation of pointer element types.
 */
static inline bool btf_native_array_elements(const struct btf *btf, __u32 id,
					    __u64 *count, __u32 *element)
{
	const struct btf_type *type;
	bool array = false;
	int depth, resolved;

	*count = 1;
	for (depth = 0; depth < 32; depth++) {
		resolved = btf__resolve_type(btf, id);
		if (resolved <= 0)
			return false;
		type = btf__type_by_id(btf, resolved);
		if (!type || !btf_is_array(type)) {
			*element = resolved;
			return type && array;
		}
		if (!btf_array(type)->nelems ||
		    *count > ~(__u64)0 / btf_array(type)->nelems)
			return false;
		*count *= btf_array(type)->nelems;
		id = btf_array(type)->type;
		array = true;
	}
	return false;
}

static inline bool btf_native_array_storage_match(const struct btf *local, __u32 local_id,
						 const struct btf *kern, __u32 kern_id)
{
	__u64 local_count, kern_count;
	__u32 local_element, kern_element;
	__s64 local_size, kern_size;

	if (!btf_native_array_elements(local, local_id, &local_count, &local_element) ||
	    !btf_native_array_elements(kern, kern_id, &kern_count, &kern_element) ||
	    local_count != kern_count)
		return false;
	local_size = btf__resolve_size(local, local_id);
	kern_size = btf__resolve_size(kern, kern_id);
	return local_size > 0 && local_size == kern_size &&
		bpf_core_types_match(local, local_element, kern, kern_element) > 0;
}

/* Physical scalar C ABI only; this supplies no pointer safety contract. */
static inline bool btf_native_scalar_abi_match(const struct btf *local, __u32 local_id,
				 const struct btf *kern, __u32 kern_id)
{
	const struct btf_type *l, *k;
	bool l_signed, k_signed;
	int lid, kid;

	if (!local_id || !kern_id)
		return local_id == kern_id;
	lid = btf__resolve_type(local, local_id);
	kid = btf__resolve_type(kern, kern_id);
	if (lid < 0 || kid < 0)
		return false;
	l = btf__type_by_id(local, lid);
	k = btf__type_by_id(kern, kid);
	if (btf_is_ptr(l) || btf_is_ptr(k))
		return btf_is_ptr(l) && btf_is_ptr(k) &&
		       btf__pointer_size(local) == btf__pointer_size(kern);
	if (!(btf_is_int(l) || btf_is_any_enum(l)) ||
	    !(btf_is_int(k) || btf_is_any_enum(k)))
		return false;
	l_signed = btf_is_int(l) ? btf_int_encoding(l) & BTF_INT_SIGNED : btf_kflag(l);
	k_signed = btf_is_int(k) ? btf_int_encoding(k) & BTF_INT_SIGNED : btf_kflag(k);
	return l->size && l->size == k->size && l->size <= 8 && l_signed == k_signed;
}

static inline bool btf_native_scalar_proto_match(const struct btf *local, __u32 local_id,
						 const struct btf *kern, __u32 kern_id)
{
	const struct btf_type *l = btf__type_by_id(local, local_id);
	const struct btf_type *k = btf__type_by_id(kern, kern_id);
	const struct btf_param *lp, *kp;
	int i;

	if (!l || !k || !btf_is_func_proto(l) || !btf_is_func_proto(k) ||
	    btf_vlen(l) != btf_vlen(k) ||
	    !btf_native_scalar_abi_match(local, l->type, kern, k->type))
		return false;
	lp = btf_params(l);
	kp = btf_params(k);
	for (i = 0; i < btf_vlen(l); i++)
		if (!lp[i].type || !btf_native_scalar_abi_match(local, lp[i].type, kern, kp[i].type))
			return false;
	return true;
}
#endif
