/* SPDX-License-Identifier: GPL-2.0-only */
/* Native scalar globals keep their BTF VAR identity, rather than becoming an
 * untyped writable byte buffer. Only permanent writable core storage qualifies.
 * Each store needs the current function's compiler-described symbol and span.
 */
/* Preserve native pointer-cell identity, including homogeneous arrays.
 * The cell is readable; the value has no lifetime or write capability.
 */
static bool btf_pointer_global(const struct btf *btf, u32 id)
{
	const struct btf_type *t = btf_type_skip_modifiers(btf, id, NULL);

	while (t && btf_type_is_array(t))
		t = btf_type_skip_modifiers(btf, btf_array(t)->type, NULL);
	return t && btf_type_is_ptr(t);
}

static int check_btf_pointer_global(struct bpf_verifier_env *env,
				    struct bpf_reg_state *regs, int regno,
				    int off, int size, enum bpf_access_type atype,
				    int value_regno)
{
	struct bpf_reg_state *reg = &regs[regno];
	const struct btf_type *var = btf_type_by_id(reg->btf, reg->btf_id), *type;
	enum bpf_type_flag flags = 0;
	u32 bytes, id = 0;
	int ret;

	if (!btf_is_kernel(reg->btf) ||
	    base_type(reg->type) != PTR_TO_BTF_ID ||
	    reg->type & (PTR_UNTRUSTED | PTR_MAYBE_NULL | MEM_USER | MEM_PERCPU |
			 MEM_RCU | MEM_ALLOC) || reg->ref_obj_id ||
	    atype != BPF_READ)
		return -EACCES;
	type = btf_type_skip_modifiers(reg->btf, var->type, NULL);
	if (IS_ERR(btf_resolve_size(reg->btf, type, &bytes)))
		return -EINVAL;
	ret = check_mem_region_access(env, regno, off, size, bytes, false);
	if (ret || value_regno < 0)
		return ret;
	/* Partial or overlapping pointer words stay ordinary scalar bits.
	 * No arithmetic on such fragments can reconstruct pointer provenance.
	 */
	if (size != sizeof(void *) ||
	    ((reg->var_off.value + off) & (sizeof(void *) - 1)) ||
	    (reg->var_off.mask & (sizeof(void *) - 1))) {
		mark_reg_unknown(env, regs, value_regno);
		return 0;
	}
	/* The bounds and alignment above cover every possible array index.
	 * Classify its uniform element at zero, without assuming an index value.
	 */
	ret = btf_struct_access(&env->log, reg, 0, size, atype, &id, &flags, NULL);
	if (ret < 0)
		return ret;
	flags |= PTR_UNTRUSTED;
	if (ret == PTR_TO_BTF_ID || ret == PTR_TO_BTF_FUNC)
		flags |= PTR_MAYBE_NULL;
	return mark_btf_ld_reg(env, regs, value_regno, ret, reg->btf, id, flags);
}

static bool btf_plain_scalar_global(const struct btf *btf, u32 id)
{
	const struct btf_type *type;
	int depth;

	/* Records keep their field ranges, pointer and managed-field rules.
	 * This rule covers scalars and arrays of scalars only, including through
	 * ordinary qualifiers, and never removes const at an array element.
	 */
	for (depth = 0; depth < 32; depth++) {
		type = btf_type_by_id(btf, id);
		if (!type)
			return false;
		switch (btf_kind(type)) {
		case BTF_KIND_TYPEDEF:
		case BTF_KIND_VOLATILE:
		case BTF_KIND_RESTRICT:
			id = type->type;
			break;
		case BTF_KIND_ARRAY:
			id = btf_array(type)->type;
			break;
		case BTF_KIND_INT:
		case BTF_KIND_ENUM:
		case BTF_KIND_ENUM64:
		case BTF_KIND_FLOAT:
			return true;
		default:
			return false;
		}
	}
	return false;
}

static bool btf_writable_scalar_global(struct btf *btf, u32 id, u64 addr)
{
	const struct btf_type *var = btf_type_by_id(btf, id), *type;
	unsigned long end;
	u32 bytes;

	if (!btf_is_vmlinux(btf) || !var || !btf_type_is_var(var))
		return false;
	if (!btf_plain_scalar_global(btf, var->type))
		return false;
	type = btf_type_skip_modifiers(btf, var->type, NULL);
	if (!type || IS_ERR(btf_resolve_size(btf, type, &bytes)) || !bytes ||
	    !btf_type_is_scalar_region(btf, var->type, 0, bytes))
		return false;
	if (addr >= (unsigned long)_sdata && addr < (unsigned long)_edata)
		end = (unsigned long)_edata;
	else if (addr >= (unsigned long)__bss_start && addr < (unsigned long)__bss_stop)
		end = (unsigned long)__bss_stop;
	else
		return false;
	if (bytes > end - addr)
		return false;
	end = addr + bytes;
	return !(addr < (unsigned long)__end_rodata && end > (unsigned long)__start_rodata) &&
	       !(addr < (unsigned long)__end_ro_after_init &&
		 end > (unsigned long)__start_ro_after_init);
}

static int check_btf_global_access(struct bpf_verifier_env *env,
				  struct bpf_reg_state *regs, int regno,
				  int off, int size, enum bpf_access_type atype,
				  int value_regno)
{
	struct bpf_reg_state *reg = &regs[regno];
	const struct bpf_prog_aux *aux = env->prog->aux;
	const struct btf_type *var = btf_type_by_id(reg->btf, reg->btf_id), *type;
	u32 owner = cur_func(env)->subprogno, bytes;
	const char *tag;
	char key[KSYM_NAME_LEN + 80];
	int len, err;

	if (btf_pointer_global(reg->btf, var->type))
		return check_btf_pointer_global(env, regs, regno, off, size, atype, value_regno);

	/* No reference, nullable, user, RCU or per-CPU capability can become a
	 * writable global. VAR pointers originate only at checked symbol loads.
	 */
	if (reg->type != (PTR_TO_BTF_ID | PTR_TRUSTED) ||
	    !env->prog->aux->ebpfos_component ||
	    !btf_is_vmlinux(reg->btf))
		return -EACCES;
	type = btf_type_skip_modifiers(reg->btf, var->type, NULL);
	if (IS_ERR(btf_resolve_size(reg->btf, type, &bytes)))
		return -EINVAL;
	err = check_mem_region_access(env, regno, off, size, bytes, false);
	if (err)
		return err;
	if (atype == BPF_WRITE) {
		if (!tnum_is_const(reg->var_off) || !aux->btf || !aux->func_info ||
		    owner >= aux->func_info_cnt ||
		    (value_regno >= 0 && regs[value_regno].type != SCALAR_VALUE)) {
			verbose(env, "kernel global store requires a fixed scalar span\n");
			return -EACCES;
		}
		len = snprintf(key, sizeof(key), "write:kernel_global:%s:%llu:%d",
			btf_name_by_offset(reg->btf, var->name_off),
			(unsigned long long)(off + reg->var_off.value), size);
		if (len < 0 || len >= sizeof(key))
			return -EINVAL;
		tag = btf_find_decl_tag_value(aux->btf,
			btf_type_by_id(aux->btf, aux->func_info[owner].type_id), -1, key);
		if (IS_ERR(tag) || *tag) {
			verbose(env, "kernel global store lacks source authority: %s\n", key);
			return -EACCES;
		}
	} else if (value_regno >= 0) {
		mark_reg_unknown(env, regs, value_regno);
	}
	return 0;
}
