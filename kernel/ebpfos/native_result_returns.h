/* SPDX-License-Identifier: GPL-2.0-only */
/* The second result lives in native RDX, which is caller-clobbered in BPF.
 * Keep its writer in every straight-line return block, followed only by
 * first-result moves/loads and EXIT. No jump may bypass that writer. This
 * checks the native calling convention; stock verification still checks all
 * instructions, scalar arguments, memory accesses and loop bounds.
 */
static bool ebpfos_result2_returns(const struct bpf_prog *prog)
{
 u32 i, j, writer = U32_MAX, exits = 0; bool first = false;
 for (i = 0; i < prog->len; i++) {
  const struct bpf_insn *insn = &prog->insnsi[i];
  if (ebpfos_result2_call(prog, insn)) { writer = i; first = false; continue; }
  if (insn->code == (BPF_JMP | BPF_EXIT)) {
   if (writer == U32_MAX || !first) return false;
   for (j = 0; j < prog->len; j++) {
    const struct bpf_insn *jump = &prog->insnsi[j]; s64 target;
    u8 cls = BPF_CLASS(jump->code), op = BPF_OP(jump->code);
    if ((cls != BPF_JMP && cls != BPF_JMP32) || op == BPF_CALL || op == BPF_EXIT) continue;
    target = (s64)j + 1 + (cls == BPF_JMP32 && op == BPF_JA ? jump->imm : jump->off);
    if (target > writer && target <= i) return false;
   }
   exits++; writer = U32_MAX; continue;
  }
  if (writer == U32_MAX) continue;
  if (insn->dst_reg == BPF_REG_0 &&
      ((BPF_OP(insn->code) == BPF_MOV &&
        (BPF_CLASS(insn->code) == BPF_ALU || BPF_CLASS(insn->code) == BPF_ALU64)) ||
       insn->code == (BPF_LDX | BPF_MEM | BPF_DW))) { first = true; continue; }
  if (insn->code == (BPF_LD | BPF_DW | BPF_IMM) && insn->dst_reg == BPF_REG_0) {
   if (++i >= prog->len) return false;
   first = true; continue;
  }
  return false;
 }
 return exits != 0 && writer == U32_MAX;
}

