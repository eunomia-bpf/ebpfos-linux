/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BPF_NATIVE_RCU_REQUIREMENTS_H
#define BPF_NATIVE_RCU_REQUIREMENTS_H

/* Close the already recorded implicit-RCU duties over the immutable local
 * graph. Stock verification has finished. A direct call discharges its
 * callee's duty only if every verifier visit held an explicit stock scope.
 * Taking a function address supplies no invocation-context guarantee.
 * No verifier answer, instruction or JIT call path changes here.
 *
 * jit_subprogs has resolved pseudo-call/function targets into insn->off.
 * Missing call-site evidence remains an unprotected edge (including calls
 * introduced by subsequent stock fixups).
 */
static void bpf_native_rcu_requirements(struct bpf_verifier_env *env)
{
	bool changed;
	u32 i, j;

	do {
		changed = false;
		for (i = 0; i < env->subprog_cnt; i++) {
			if (env->subprog_info[i].requires_rcu)
				continue;
			for (j = env->subprog_info[i].start;
			     j < env->subprog_info[i + 1].start; j++) {
				const struct bpf_insn *insn = &env->prog->insnsi[j];
				const struct bpf_insn_aux_data *aux = &env->insn_aux_data[j];
				bool address = bpf_pseudo_func(insn);

				if (!address && !bpf_pseudo_call(insn))
					continue;
				if (insn->off < 0 || insn->off >= env->subprog_cnt ||
				    (env->subprog_info[insn->off].requires_rcu &&
				     (address || !aux->rcu_call_seen || aux->rcu_call_unprotected))) {
					env->subprog_info[i].requires_rcu = true;
					changed = true;
					break;
				}
			}
		}
	} while (changed);
}
#endif
