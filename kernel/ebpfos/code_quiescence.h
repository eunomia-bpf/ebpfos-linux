/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef EBPFOS_CODE_QUIESCENCE_H
#define EBPFOS_CODE_QUIESCENCE_H
struct ebpfos_code_range { unsigned long begin, end; };
/* Cold stop_machine callback only. Code ranges must include every layout
 * user; their owners retain the code and exclude NMI and transaction users.
 * The scan rejects suspended frames, not future entry outside that stop.
 */
int ebpfos_code_stopped_ranges(const struct ebpfos_code_range *, unsigned int);
#endif
