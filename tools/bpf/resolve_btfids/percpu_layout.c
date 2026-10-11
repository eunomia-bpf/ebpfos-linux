// SPDX-License-Identifier: GPL-2.0-only
/* A type view of existing storage, without replacing or allocating any data. */
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "percpu_layout.h"

static int by_offset(const void *left, const void *right)
{
	const struct btf_var_secinfo *a = left, *b = right;

	return (a->offset > b->offset) - (a->offset < b->offset);
}

struct btf *btf_percpu_layout(const struct btf *source, const char *alias)
{
	const struct btf_type *section, *variable;
	struct btf_var_secinfo *fields = NULL;
	struct btf *result = NULL;
	unsigned int count = btf__type_cnt(source), nr, size, end = 0, i;
	int section_id, root_id = count, alias_id = count + 1;
	int err = -EINVAL;

	if (btf__base_btf(source) ||
	    btf__find_by_name_kind(source, alias, BTF_KIND_VAR) > 0 ||
	    btf__find_by_name_kind(source, "__percpu_layout", BTF_KIND_STRUCT) > 0)
		goto out;
	section_id = btf__find_by_name_kind(source, ".data..percpu", BTF_KIND_DATASEC);
	if (section_id < 1)
		goto out;
	section = btf__type_by_id(source, section_id);
	nr = btf_vlen(section);
	size = section->size;
	/* BTF member offsets use 24 bits, measured in bits. */
	if (!nr || nr == BTF_MAX_VLEN || !size || size > 0x1fffff)
		goto out;
	fields = malloc(nr * sizeof(*fields));
	if (!fields) {
		err = -ENOMEM;
		goto out;
	}
	memcpy(fields, btf_var_secinfos(section), nr * sizeof(*fields));
	qsort(fields, nr, sizeof(*fields), by_offset);
	for (i = 0; i < nr; i++) {
		variable = btf__type_by_id(source, fields[i].type);
		if (!variable || !btf_is_var(variable) || !fields[i].size ||
		    fields[i].offset < end || fields[i].offset > size ||
		    fields[i].size > size - fields[i].offset ||
		    btf__resolve_size(source, variable->type) != fields[i].size)
			goto out;
		end = fields[i].offset + fields[i].size;
	}
	result = btf__new_empty();
	if (!result) {
		err = -ENOMEM;
		goto out;
	}
	err = btf__set_endianness(result, btf__endianness(source));
	if (err)
		goto out;
	err = btf__set_pointer_size(result, btf__pointer_size(source));
	if (err)
		goto out;
	/* Preserve every original type ID. DATASEC describes the area once;
	 * describing the alias alongside its members would overlap storage and
	 * violate the stock DATASEC validator. Original VARs retain their types;
	 * the layout's members provide their offsets in the single area object.
	 */
	for (i = 1; i < count; i++) {
		if (i != section_id) {
			err = btf__add_type(result, source, btf__type_by_id(source, i));
			if (err != i)
				goto out;
			continue;
		}
		err = btf__add_datasec(result, ".data..percpu", size);
		if (err != i)
			goto out;
		err = btf__add_datasec_var_info(result, alias_id, 0, size);
		if (err)
			goto out;
	}
	err = btf__add_struct(result, "__percpu_layout", size);
	if (err != root_id)
		goto out;
	for (i = 0; i < nr; i++) {
		variable = btf__type_by_id(source, fields[i].type);
		err = btf__add_field(result, btf__name_by_offset(source, variable->name_off),
				     variable->type, fields[i].offset * 8, 0);
		if (err)
			goto out;
	}
	err = btf__add_var(result, alias, BTF_VAR_GLOBAL_ALLOCATED, root_id);
	if (err != alias_id)
		goto out;
	free(fields);
	return result;
out:
	fprintf(stderr, "per-CPU BTF layout refused: %s (%d)\n", strerror(-err), err);
	btf__free(result);
	free(fields);
	return NULL;
}
