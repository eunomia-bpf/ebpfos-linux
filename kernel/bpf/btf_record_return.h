/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _BPF_BTF_RECORD_RETURN_H
#define _BPF_BTF_RECORD_RETURN_H

struct btf;
bool btf_scalar_record_return(struct btf *btf, u32 id);
unsigned int btf_record_return_words(struct btf *btf, u32 id);

#endif
