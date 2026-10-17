// SPDX-License-Identifier: GPL-2.0-only
#ifndef EBPFOS_FUNCTION_NATIVE_CONTEXT_H
#define EBPFOS_FUNCTION_NATIVE_CONTEXT_H
static bool entry_context(struct bpf_prog *parent, unsigned long entry)
{
 const enum bpf_func_id helpers[] = { BPF_FUNC_per_cpu_ptr, BPF_FUNC_this_cpu_ptr,
  BPF_FUNC_get_current_task_btf, BPF_FUNC_loop };
 struct bpf_prog_aux *aux = parent->aux;
 unsigned int count = aux->func_cnt, head = 0, tail = 0, i, j, k;
 unsigned int *queue;
 bool *seen, allowed = false;
 if (!aux->func || !count || aux->real_func_cnt != count ||
     aux->exception_boundary) return false;
 queue = kvmalloc_array(count, sizeof(*queue), GFP_KERNEL);
 seen = kvcalloc(count, sizeof(*seen), GFP_KERNEL);
 if (!queue || !seen) goto out;
 for (i = 1; i < count; ++i)
  if (aux->func[i] && (unsigned long)aux->func[i]->bpf_func == entry) break;
 if (i == count) goto out;
 seen[i] = true;queue[tail++] = i;
 /* jit_subprogs retains the stock-resolved subprogram index in off for
  * both pseudo calls and function addresses. Walk those immutable edges,
  * including every address-taken callback, starting at the callable export.
  * The diagnostic loader entry is irrelevant unless reachable from it.
  * This is a native-context restriction after verification, not a verifier.
  */
 while (head < tail) {
  struct bpf_prog *function = aux->func[queue[head++]];
  if (!function || !function->jited || function->aux->priv_stack_ptr ||
      function->aux->tail_call_reachable || function->aux->exception_cb) goto out;
  for (j = 0; j < function->len; ++j) {
   const struct bpf_insn *insn = &function->insnsi[j];
   unsigned long target;
   if (bpf_pseudo_func(insn) ||
       (insn->code == (BPF_JMP | BPF_CALL) && insn->src_reg == BPF_PSEUDO_CALL)) {
    int callee = insn->off;
    if (callee < 0 || callee >= count) goto out;
    if (!seen[callee]) {seen[callee] = true;queue[tail++] = callee;}
    continue;
   }
   /* Tail calls and register calls do not name an immutable local closure. */
   if (insn->code == (BPF_JMP | BPF_TAIL_CALL) ||
       insn->code == (BPF_JMP | BPF_CALL | BPF_X)) goto out;
   if (insn->code != (BPF_JMP | BPF_CALL)) continue;
   if (insn->src_reg == BPF_PSEUDO_KFUNC_CALL ||
       insn->src_reg == BPF_PSEUDO_KOP_CALL) continue;
   if (insn->src_reg) goto out;
   target = (unsigned long)__bpf_call_base + insn->imm;
   /* Stock may_goto fixups use initialized slots in this function's frame,
    * not bpf_run_ctx. Keep their original timeout and escape semantics. */
   if (target == (unsigned long)arch_bpf_timed_may_goto) continue;
   for (k = 0; k < ARRAY_SIZE(helpers); ++k) {
    const struct bpf_func_proto *prototype = bpf_base_func_proto(helpers[k], parent);
    if (prototype && target == (unsigned long)prototype->func) break;
   }
   if (k == ARRAY_SIZE(helpers)) goto out;
  }
 }
 allowed = true;
out:
 kvfree(seen);kvfree(queue);return allowed;
}

#endif
