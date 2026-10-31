/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BPF_NATIVE_ABI_H
#define BPF_NATIVE_ABI_H
#include <linux/btf.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/bpf_native_abi.h>
#include "../ebpfos/function_layout.h"
/* The x86 integer ABI assigns whole aggregate arguments to registers or to
 * the caller's argument area. This is load-time layout, with no call adapter.
 */
static inline int bpf_native_classes(struct btf *btf, u32 id, u32 offset,
 enum bpf_native_class classes[2], u32 depth)
{
 const struct btf_type *t = btf_type_skip_modifiers(btf, id, NULL);
 u32 i, kind;
 if (!t || depth > 32) return -EINVAL;
 kind = BTF_INFO_KIND(t->info);
 if (kind == BTF_KIND_INT || kind == BTF_KIND_ENUM || kind == BTF_KIND_ENUM64 ||
     kind == BTF_KIND_PTR || kind == BTF_KIND_FLOAT) {
  u32 size = kind == BTF_KIND_PTR ? sizeof(void *) : t->size;
  enum bpf_native_class cls = kind == BTF_KIND_FLOAT ? BPF_NC_SSE : BPF_NC_INTEGER;
  if (!size || size > 16 || !is_power_of_2(size)) return -EINVAL;
  if (offset % size || offset > 16 - size) return 1;
  for (i = offset / 8; i <= (offset + size - 1) / 8; i++)
   classes[i] = max(classes[i], cls);
  return 0;
 }
 if (kind == BTF_KIND_ARRAY) {
  const struct btf_array *a = btf_array(t);
  u32 size;
  const struct btf_type *element = btf_type_skip_modifiers(btf, a->type, NULL);
  element = btf_resolve_size(btf, element, &size);
  if (IS_ERR(element) || (a->nelems && (!size || size > 16 / a->nelems))) return -EINVAL;
  for (i = 0; i < a->nelems; i++) {
   int err = bpf_native_classes(btf, a->type, offset + i * size, classes, depth + 1);
   if (err) return err;
  }
  return 0;
 }
 if (!btf_type_is_struct(t)) return -EOPNOTSUPP;
 if (t->size > 16) return 1;
 for (i = 0; i < btf_type_vlen(t); i++) {
  const struct btf_member *m = &btf_members(t)[i];
  u32 bits = btf_member_bit_offset(t, i), width = btf_member_bitfield_size(t, i);
  int err;
  if (width) {
   const struct btf_type *leaf = btf_type_skip_modifiers(btf, m->type, NULL);
   if (!leaf || (!btf_type_is_int(leaf) && !btf_is_any_enum(leaf)) ||
       offset * 8 + bits >= 128 || width > 128 - offset * 8 - bits) return -EINVAL;
   for (u32 word = (offset * 8 + bits) / 64;
        word <= (offset * 8 + bits + width - 1) / 64; word++)
    classes[word] = BPF_NC_INTEGER;
   continue;
  }
  if (bits % 8) return 1;
  err = bpf_native_classes(btf, m->type, offset + bits / 8, classes, depth + 1);
  if (err) return err;
 }
 return 0;
}
static inline int bpf_native_classify(struct btf *btf, u32 id, u32 *size, u8 *words)
{
 const struct btf_type *t = btf_type_skip_modifiers(btf, id, NULL);
 enum bpf_native_class classes[2] = {};
 int err;
 *words = 0;
 if (!t) return -EINVAL;
 if (btf_type_is_ptr(t)) *size = sizeof(void *);
 else {
  t = btf_resolve_size(btf, t, size);
  if (IS_ERR(t)) return PTR_ERR(t);
 }
 if (*size > 16) return 1;
 err = bpf_native_classes(btf, id, 0, classes, 0);
 if (err) return err;
 for (u32 i = 0; i < 2; i++) {
  if (classes[i] == BPF_NC_SSE) return -EOPNOTSUPP;
  *words += classes[i] == BPF_NC_INTEGER;
 }
 return 0;
}
bool btf_native_scalar_storage(struct btf *btf, u32 id, u32 depth)
{
 const struct btf_type *t = btf_type_skip_modifiers(btf, id, NULL);
 if (!t || depth > 32) return false;
 if (btf_type_is_int(t) || btf_is_any_enum(t)) return true;
 if (btf_type_is_array(t)) return btf_native_scalar_storage(btf, btf_array(t)->type, depth + 1);
 if (!btf_type_is_struct(t)) return false;
 for (u32 i = 0; i < btf_type_vlen(t); i++)
  if (!btf_native_scalar_storage(btf, btf_members(t)[i].type, depth + 1)) return false;
 return true;
}
static int native_pointer_word(struct btf *btf, u32 id, u32 offset, u32 *pointer, u32 depth)
{
 const struct btf_type *t = btf_type_skip_modifiers(btf, id, &id);
 u32 size;
 if (!t || depth > 32) return -EINVAL;
 if (btf_native_scalar_storage(btf, id, depth)) return 0;
 if (btf_type_is_ptr(t)) {
  if (offset) return -EOPNOTSUPP;
  if (*pointer && *pointer != id) return -EOPNOTSUPP;
  *pointer = id;
  return 0;
 }
 if (btf_type_is_int(t) || btf_is_any_enum(t)) return 0;
 if (btf_type_is_array(t)) {
  const struct btf_array *a = btf_array(t);
  const struct btf_type *e = btf_type_skip_modifiers(btf, a->type, NULL);
  if (IS_ERR(btf_resolve_size(btf, e, &size)) || !size) return -EINVAL;
  for (u32 i = 0; i < a->nelems && i * size <= offset + 7; i++) {
   if (i * size + size <= offset) continue;
   if (i * size > offset) return -EOPNOTSUPP;
   int err = native_pointer_word(btf, a->type, offset - i * size, pointer, depth + 1);
   if (err) return err;
  }
  return 0;
 }
 if (!btf_type_is_struct(t)) return -EOPNOTSUPP;
 for (u32 i = 0; i < btf_type_vlen(t); i++) {
  const struct btf_member *m = &btf_members(t)[i];
  u32 bit = btf_member_bit_offset(t, i);
  const struct btf_type *child = btf_type_skip_modifiers(btf, m->type, NULL);
  if (btf_native_scalar_storage(btf, m->type, depth + 1)) continue;
  if (btf_member_bitfield_size(t, i)) continue;
  if (IS_ERR(btf_resolve_size(btf, child, &size))) return -EINVAL;
  if (bit >= (offset + 8) * 8 || bit + size * 8 <= offset * 8) continue;
  if (bit % 8 || bit / 8 > offset) return -EOPNOTSUPP;
  u32 before = *pointer;
  int err = native_pointer_word(btf, m->type, offset - bit / 8, pointer, depth + 1);
  if (err) return err;
  if ((BTF_INFO_KIND(t->info) == BTF_KIND_UNION) && (*pointer || before)) return -EOPNOTSUPP;
 }
 return 0;
}
int btf_native_pointer_word(struct btf *btf, u32 id, u32 offset, u32 *pointer)
{
 *pointer = 0;
 return native_pointer_word(btf, id, offset, pointer, 0);
}
bool btf_native_value_storage(struct btf *btf, u32 id)
{
 const struct btf_type *t = btf_type_skip_modifiers(btf, id, NULL);
 u32 size, pointer;
 if (!t || IS_ERR(btf_resolve_size(btf, t, &size)) || size > MAX_BPF_STACK) return false;
 for (u32 off = 0; off < size; off += 8)
  if (btf_native_pointer_word(btf, id, off, &pointer)) return false;
 return true;
}
static u8 native_word_mask(struct btf *btf, u32 id)
{
 enum bpf_native_class classes[2] = {};
 if (bpf_native_classes(btf, id, 0, classes, 0)) return 0;
 return (classes[0] == BPF_NC_INTEGER) | ((classes[1] == BPF_NC_INTEGER) << 1);
}
int bpf_native_abi_plan(struct btf *btf, const struct btf_type *proto,
 struct bpf_native_abi *abi, bool trusted_native)
{
 const struct btf_param *params;
 u32 size = 0, next_reg = 0, nargs;
 bool variadic;
 u8 words = 0;
 int err;
 memset(abi, 0, sizeof(*abi));
 if (!cell_function_parameters(proto, &nargs, &variadic)) return -EINVAL;
 if (variadic && !IS_ENABLED(CONFIG_X86_64)) return -EOPNOTSUPP;
 /* An ellipsis describes no named argument or incoming fixed storage.
  * This layout grants no register or memory capability to a variadic tail;
  * normal verification must still prove every actual operand read.
  */
 if (nargs > MAX_BPF_FUNC_ARGS && !trusted_native) return -E2BIG;
 if (proto->type) {
  err = bpf_native_classify(btf, proto->type, &size, &words);
  if (err < 0) return err;
  if (err) {
   abi->result_buffer = true;
   abi->args[abi->nr_args++] = (struct bpf_native_arg) {
    .type_id = proto->type, .size = size, .reg = 0, .words = 1, .result_buffer = true,
   };
   next_reg = 1;
  } else {
   abi->result_words = words;
   abi->result_word_mask = native_word_mask(btf, proto->type);
  }
 }
 params = btf_params(proto);
 for (u32 i = 0; i < nargs; i++) {
  struct bpf_native_arg temporary = {};
  /* Trusted preparation needs the complete stack layout, not per-argument
   * proof records. Keep the existing records without imposing the tracing
   * model capacity on native frames. Normal verification requires them all.
   */
  struct bpf_native_arg *arg = abi->nr_args < ARRAY_SIZE(abi->args) ?
   &abi->args[abi->nr_args++] : &temporary;
  if (!params[i].type) return -EOPNOTSUPP;
  err = bpf_native_classify(btf, params[i].type, &size, &words);
  if (err < 0) return err;
  arg->type_id = params[i].type;arg->size = size;arg->words = words;
  arg->word_mask = err ? 0 : native_word_mask(btf, params[i].type);
  if (!err && next_reg + words <= MAX_BPF_NATIVE_REG_ARGS) {
   arg->reg = next_reg;next_reg += words;
  } else {
   arg->reg = -1;
   const struct btf_type *value = btf_type_skip_modifiers(btf, params[i].type, NULL);
   u32 alignment = cell_abi_type_alignment(btf, params[i].type);
   if (alignment == ~0U) return -EINVAL;
   if (!btf_type_is_struct(value)) alignment = 0;
   if (!alignment) alignment = size == 16 && !err ? 16 : 8;
   alignment = max(alignment, 8u);
   if (alignment > MAX_BPF_STACK) return -E2BIG;
   abi->stack_size = round_up(abi->stack_size, alignment);
   arg->stack_offset = abi->stack_size;
   if (size > MAX_BPF_STACK - abi->stack_size) return -E2BIG;
   abi->stack_size += round_up(size, 8u);
#if defined(CONFIG_CC_IS_CLANG) && CONFIG_CLANG_VERSION < 200000
   /* The native Clang 18/19 x86 convention shadows R9 when a scalar
    * i128 cannot start in the remaining register slot. Record arguments
    * use the frontend's byval convention and do not consume that slot.
    */
   const struct btf_type *type = btf_type_skip_modifiers(btf, params[i].type, NULL);
   if (!err && size == 16 && words == 2 && btf_type_is_int(type))
    next_reg = MAX_BPF_NATIVE_REG_ARGS;
#endif
  }
 }
 abi->next_reg = next_reg;
 abi->tail_stack_start = abi->stack_size;
 return 0;
}
/* Continue the named ABI instead of reclassifying or shifting its holes. */
struct bpf_native_arg bpf_native_tail_arg(const struct bpf_native_abi *abi, u32 index)
{
 u32 slot = abi->next_reg + index;
 struct bpf_native_arg arg = {.words=1, .word_mask=1,
  .size=abi->tail_types[index * 4 + 1] == '6' ? 8 : 4};
 arg.reg = slot < MAX_BPF_NATIVE_REG_ARGS ? slot : -1;
 if (arg.reg < 0)
  arg.stack_offset = abi->tail_stack_start + (slot - MAX_BPF_NATIVE_REG_ARGS) * 8;
 return arg;
}
int bpf_native_abi_tail(struct btf *btf, const struct btf_type *function,
 struct bpf_native_abi *abi)
{
 const char prefix[] = "native:variadic_scalar_tail:";
 const char *types;
 u32 count = cell_variadic_scalar_tail_info(btf, function, &types);
 u32 registers = MAX_BPF_NATIVE_REG_ARGS - abi->next_reg;
 u32 overflow;
 if (count == ~0U) return -EINVAL;
 if (!count) return 0;
 overflow = count > registers ? count - registers : 0;
 if (overflow > (MAX_BPF_STACK - abi->stack_size) / 8) return -E2BIG;
 abi->tail_types = types + sizeof(prefix) - 1;
 abi->tail_count = count;
 abi->stack_size += overflow * 8;
 return 0;
}
#endif
