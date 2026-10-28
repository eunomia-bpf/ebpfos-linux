/* SPDX-License-Identifier: GPL-2.0-only */
/* Compiler-proved constructors and all writers establish field:umax:N.
 * This is a declaration contract, not a value sampled from a live object.
 * Every verified write preserves it; typed pointer/lifetime checks still run.
 */
/* Kernel BTF deliberately omits the user-BTF resolved-id/size caches. */
static const struct btf_type *btf_field_range_type(const struct btf *btf,
						 u32 *id, u32 *bytes)
{
	const struct btf_type *type = btf_type_skip_modifiers(btf, *id, id);

	return !type || IS_ERR(btf_resolve_size(btf, type, bytes)) ? NULL : type;
}

static int btf_scalar_field_max(struct bpf_verifier_env *env,
			      const struct btf *btf, u32 id, u32 member,
			      u64 *maximum)
{
	const struct btf_type *record = btf_type_by_id(btf, id), *field;
	const struct btf *program = env->prog->aux->btf;
	const char *tag;
	u32 field_id = btf_members(record)[member].type;
	u32 bytes;
	s32 local;

	tag = btf_find_decl_tag_value(btf, record, member, "field:umax:");
	if (IS_ERR(tag) && PTR_ERR(tag) == -ENOENT && program && program != btf) {
		local = btf_find_by_name_kind(program,
			btf_name_by_offset(btf, record->name_off), BTF_KIND_STRUCT);
		if (local > 0 && btf_same_scalar_layout(btf, id, program, local))
			tag = btf_find_decl_tag_value(program,
				btf_type_by_id(program, local), member, "field:umax:");
	}
	if (IS_ERR(tag))
		return PTR_ERR(tag) == -ENOENT ? 0 : PTR_ERR(tag);
	field = btf_field_range_type(btf, &field_id, &bytes);
	if (!field || !btf_type_is_int(field) || btf_int_encoding(field) & BTF_INT_SIGNED ||
	    !bytes || bytes > 8 || !is_power_of_2(bytes) ||
	    btf_member_bitfield_size(record, member) ||
	    btf_member_bit_offset(record, member) % 8 || kstrtou64(tag, 10, maximum) ||
	    (bytes < 8 && *maximum >= (1ULL << (bytes * 8))))
		return -EINVAL;
	return bytes;
}

/* Read only an exact field; a short or signed access keeps the stock range.
 * Writes spanning fields, atomics and helper destinations with unknown values
 * cannot silently break a contract. Nested by-value objects are visited too.
 */
static int btf_field_ranges(struct bpf_verifier_env *env, struct bpf_reg_state *regs,
			    int regno, const struct btf *btf, u32 id, s64 base,
			    s64 off, int size, enum bpf_access_type access,
			    int value_regno, unsigned int depth)
{
	const struct btf_type *type;
	u32 bytes, i;
	int err;

	if (depth > 32)
		return access == BPF_WRITE ? -E2BIG : 0;
	type = btf_field_range_type(btf, &id, &bytes);
	if (!type)
		return 0;
	if (btf_type_is_array(type)) {
		const struct btf_array *array = btf_array(type);
		u32 element_id = array->type, element_bytes;
		s64 first, last;

		if (!array->nelems || !btf_field_range_type(btf, &element_id, &element_bytes) ||
		    !element_bytes)
			return 0;
		/* All elements have the same declaration contracts. Visit the
		 * boundary elements and one fully covered middle element; a large
		 * plain byte buffer must not acquire a new access-size limit.
		 */
		first = off < 0 ? 0 : max_t(s64, 0, (off - base) / element_bytes);
		last = off < 0 ? first :
			min_t(s64, array->nelems - 1, (off + size - 1 - base) / element_bytes);
		if (first > last)
			return 0;
		err = btf_field_ranges(env, regs, regno, btf, array->type,
			base + first * element_bytes, off, size, access, value_regno, depth + 1);
		if (err || first == last)
			return err;
		err = btf_field_ranges(env, regs, regno, btf, array->type,
			base + last * element_bytes, off, size, access, value_regno, depth + 1);
		if (err || first + 1 == last)
			return err;
		return btf_field_ranges(env, regs, regno, btf, array->type,
			base + (first + 1) * element_bytes, -1, size, access, value_regno, depth + 1);
	}
	if (!btf_type_is_struct(type))
		return 0;
	for (i = 0; i < btf_type_vlen(type); i++) {
		const struct btf_member *member = &btf_members(type)[i];
		u32 member_id = member->type, member_bytes;
		s64 start = base + btf_member_bit_offset(type, i) / 8;
		u64 maximum;
		int width;

		if (!btf_field_range_type(btf, &member_id, &member_bytes))
			continue;
		if (off >= 0 && (off >= start + member_bytes || off + size <= start))
			continue;
		width = btf_scalar_field_max(env, btf, id, i, &maximum);
		if (width < 0)
			return width;
		if (width && access == BPF_WRITE) {
			const struct bpf_insn *insn = &env->prog->insnsi[env->insn_idx];
			u64 value;

			if (off != start || size != width ||
			    (BPF_CLASS(insn->code) == BPF_STX && BPF_MODE(insn->code) == BPF_ATOMIC))
				goto invalid;
			if (value_regno >= 0 && regs[value_regno].type == SCALAR_VALUE)
				value = width <= 4 ? regs[value_regno].u32_max_value :
					regs[value_regno].umax_value;
			else if (value_regno < 0 && BPF_CLASS(insn->code) == BPF_ST &&
				 BPF_MODE(insn->code) == BPF_MEM)
				value = (s64)insn->imm;
			else
				goto invalid;
			if (width < 8)
				value = value_regno >= 0 ? min_t(u64, value, (1ULL << (width * 8)) - 1) :
					value & ((1ULL << (width * 8)) - 1);
			if (value > maximum)
				goto invalid;
			if (value_regno >= 0) {
				err = mark_chain_precision(env, value_regno);
				if (err)
					return err;
			}
		} else if (width && access == BPF_READ && value_regno >= 0 &&
			   off == start && size == width && regs[value_regno].type == SCALAR_VALUE) {
			struct bpf_reg_state *value = &regs[value_regno];

			value->umax_value = min(value->umax_value, maximum);
			value->var_off = tnum_intersect(value->var_off, tnum_range(0, maximum));
			reg_bounds_sync(value);
		}
		err = btf_field_ranges(env, regs, regno, btf, member->type, start,
				      off, size, access, value_regno, depth + 1);
		if (err)
			return err;
	}
	return 0;
invalid:
	verbose(env, "scalar field store does not preserve field:umax contract\n");
	return -EACCES;
}

static int check_btf_field_ranges(struct bpf_verifier_env *env,
				 struct bpf_reg_state *regs, int regno, int off,
				 int size, enum bpf_access_type access, int value_regno,
				 const struct bpf_reg_state *source)
{
	const struct bpf_reg_state *reg = source ? source : &regs[regno];
	s64 address;

	if (size <= 0 || (access == BPF_READ && value_regno < 0))
		return 0;
	if (access == BPF_READ &&
	    (!is_trusted_reg(reg) || reg->type & (PTR_UNTRUSTED | PTR_MAYBE_NULL | MEM_USER | MEM_PERCPU) ||
	     (reg->type & MEM_RCU && !in_rcu_cs(env)) ||
	     (type_is_alloc(reg->type) && !reg->ref_obj_id) ||
	     (reg->ref_obj_id && !find_reference_state(env->cur_state, reg->ref_obj_id))))
		return 0;
	address = tnum_is_const(reg->var_off) ? off + (s64)reg->var_off.value : -1;
	if (address < 0 && access == BPF_READ)
		return 0;
	return btf_field_ranges(env, regs, regno, reg->btf, reg->btf_id,
				0, address, size, access, value_regno, 0);
}
