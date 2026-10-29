/* SPDX-License-Identifier: GPL-2.0-only */
/* Source invariant B for one integer output object at a native entry.
 * The compiler describes an original mandatory access. Kernel BTF supplies
 * the actual scalar layout; a tag cannot invent a region or erase a type.
 */
static u32 btf_scalar_context_size(const struct bpf_prog *prog,
				  struct btf *btf, u32 declared, int off)
{
	const struct bpf_prog_aux *aux = prog->aux;
	const struct btf_type *t, *fn;
	const char *tag;
	char key[64];
	u32 bytes;

	if (!aux->ebpfos_component || !capable(CAP_SYS_ADMIN) ||
	    !aux->btf || !aux->func_info || !aux->func_info_cnt ||
	    (prog->expected_attach_type != BPF_TRACE_FENTRY &&
	     prog->expected_attach_type != BPF_TRACE_REPLACE))
		return 0;
	/* Qualifiers on either the address or its object remain significant.
	 * In particular, const and type tags never become writable memory.
	 */
	t = btf_type_by_id(btf, declared);
	while (t && (btf_type_is_typedef(t) || btf_type_is_volatile(t) ||
		     BTF_INFO_KIND(t->info) == BTF_KIND_RESTRICT))
		t = btf_type_by_id(btf, t->type);
	if (!t || !btf_type_is_ptr(t))
		return 0;
	t = btf_type_by_id(btf, t->type);
	while (t && (btf_type_is_typedef(t) || btf_type_is_volatile(t) ||
		     BTF_INFO_KIND(t->info) == BTF_KIND_RESTRICT))
		t = btf_type_by_id(btf, t->type);
	if (!t || (!btf_type_is_int(t) && !btf_is_any_enum(t)))
		return 0;
	bytes = t->size;
	if (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8)
		return 0;
	snprintf(key, sizeof(key), "ctx:scalar_rw:%d:%u", off, bytes);
	fn = btf_type_by_id(aux->btf, aux->func_info[0].type_id);
	tag = btf_find_decl_tag_value(aux->btf, fn, -1, key);
	return !IS_ERR(tag) && !*tag ? bytes : 0;
}
