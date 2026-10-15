/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _EBPFOS_COMPONENT_CONTEXT_H
#define _EBPFOS_COMPONENT_CONTEXT_H
#include <linux/bpf.h>
/* These instruction proofs preserve the original native caller's context.
 * Ordinary observers do not acquire component instruction/write authority. */
static inline bool ebpfos_non_sleepable_component(const struct bpf_prog *prog)
{
 return prog && prog->aux && prog->aux->ebpfos_component && !prog->sleepable &&
  (prog->type == BPF_PROG_TYPE_RAW_TRACEPOINT ||
   (prog->type == BPF_PROG_TYPE_TRACING && prog->expected_attach_type == BPF_TRACE_REPLACE));
}
#endif
