/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef BPF_NATIVE_CALL_RESOURCES_H
#define BPF_NATIVE_CALL_RESOURCES_H

struct native_call_edge {
	u32 caller;
	u32 next;
};

/* Independent global checking starts without the caller's resources. Close
 * the native-call requirement over visited local calls and explicit callback
 * addresses before accepting any global call made with those resources held.
 * This is a verifier effect summary, not indirect target-set resolution.
 */
static int check_native_call_resources(struct bpf_verifier_env *env)
{
	struct native_call_edge *edges = NULL;
	u32 *heads = NULL, *queue = NULL;
	u32 i, j, count = 0, first = 0, last = 0;
	bool native = false;
	int err = 0;

	for (i = 0; i < env->subprog_cnt; i++)
		native |= env->subprog_info[i].has_native_call;
	if (!native)
		return 0;
	for (i = 0; i < env->prog->len; i++)
		if (env->insn_aux_data[i].seen &&
		    (bpf_pseudo_call(&env->prog->insnsi[i]) ||
		     bpf_pseudo_func(&env->prog->insnsi[i])))
			count++;
	if (!count)
		return 0;

	heads = kvmalloc_objs(*heads, env->subprog_cnt, GFP_KERNEL_ACCOUNT);
	queue = kvmalloc_objs(*queue, env->subprog_cnt, GFP_KERNEL_ACCOUNT);
	edges = kvmalloc_objs(*edges, count, GFP_KERNEL_ACCOUNT);
	if (!heads || !queue || !edges) {
		err = -ENOMEM;
		goto out;
	}
	for (i = 0; i < env->subprog_cnt; i++) {
		heads[i] = U32_MAX;
		if (env->subprog_info[i].has_native_call)
			queue[last++] = i;
	}
	count = 0;
	for (i = 0; i < env->subprog_cnt; i++) {
		for (j = env->subprog_info[i].start;
		     j < env->subprog_info[i + 1].start; j++) {
			struct bpf_insn *insn = &env->prog->insnsi[j];
			int callee;

			if (!env->insn_aux_data[j].seen ||
			    (!bpf_pseudo_call(insn) && !bpf_pseudo_func(insn)))
				continue;
			callee = bpf_find_subprog(env, j + insn->imm + 1);
			if (callee < 0) {
				err = -EFAULT;
				goto out;
			}
			edges[count].caller = i;
			edges[count].next = heads[callee];
			heads[callee] = count++;
		}
	}
	/* Each node enters the queue once, including callback cycles. */
	while (first < last) {
		u32 callee = queue[first++];

		for (j = heads[callee]; j != U32_MAX; j = edges[j].next) {
			u32 caller = edges[j].caller;

			if (env->subprog_info[caller].has_native_call)
				continue;
			env->subprog_info[caller].has_native_call = true;
			queue[last++] = caller;
		}
	}
	for (i = 0; i < env->subprog_cnt; i++) {
		for (j = env->subprog_info[i].start;
		     j < env->subprog_info[i + 1].start; j++) {
			struct bpf_insn *insn = &env->prog->insnsi[j];
			int callee;

			if (!env->insn_aux_data[j].native_call_resource_held ||
			    !bpf_pseudo_call(insn))
				continue;
			callee = bpf_find_subprog(env, j + insn->imm + 1);
			if (callee < 0) {
				err = -EFAULT;
				goto out;
			}
			if (env->subprog_info[callee].has_native_call) {
				verbose(env, "global function %s cannot call native code with modeled resources held\n",
					subprog_name(env, callee));
				err = -EACCES;
				goto out;
			}
		}
		if (env->subprog_info[i].has_native_call) {
			verbose(env, "func#%u relies on verifier option C; name='%s'\n",
				i, bpf_verifier_subprog_name(env, i));
			verbose(env, "func#%u relies on verifier option D; name='%s'\n",
				i, bpf_verifier_subprog_name(env, i));
		}
	}
out:
	kvfree(edges);
	kvfree(queue);
	kvfree(heads);
	return err;
}
#endif
