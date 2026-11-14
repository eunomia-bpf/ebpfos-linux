# SPDX-License-Identifier: GPL-2.0-only
# Component publication and declared native-set registration.
obj-y += native_set.o native_inline.o
obj-y += views.o
# Bare C-to-BPF entry linking currently uses x86-64 register ABI and no CFI
# signature prefix. Never bypass another configuration's CFI entry contract.
obj-$(CONFIG_EBPFOS_ENTRY_LINK) += function_entries.o code_quiescence.o operations.o kernel_rule.o rule_tasks.o rule_context.o
obj-$(CONFIG_EBPFOS_PTVIEW) += ptview.o
