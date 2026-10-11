/* SPDX-License-Identifier: GPL-2.0-only */
struct btf;
struct btf *btf_percpu_layout(const struct btf *source, const char *alias);
int btf_field_obligations(struct btf *btf, const char *path);
