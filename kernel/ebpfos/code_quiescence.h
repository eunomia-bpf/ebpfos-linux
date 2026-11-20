/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_CODE_QUIESCENCE_H
#define EBPFOS_CODE_QUIESCENCE_H
struct ebpfos_code_range { unsigned long begin, end; };
/* Non-refusing compatibility entry for the removed stack-scan admission. */
int ebpfos_code_stopped_ranges(const struct ebpfos_code_range *, unsigned int);
#endif
