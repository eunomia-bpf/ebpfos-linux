# SPDX-License-Identifier: GPL-2.0-only
# Component publication and declared native-set registration.
obj-y += admission.o component_graph.o executor_root.o core.o
obj-y += native_set.o native_inline.o
obj-y += checked_dispatch.o views.o
# Bare C-to-BPF entry linking currently uses x86-64 register ABI and no CFI
# signature prefix. Never bypass another configuration's CFI entry contract.
ifeq ($(CONFIG_X86_64)$(CONFIG_DYNAMIC_FTRACE_WITH_JMP)$(CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS)$(CONFIG_CFI),yyy)
obj-y += function_entries.o code_quiescence.o
endif
obj-$(CONFIG_EBPFOS_KOPERATION) += koperation.o pointer_tag.o fault_loads.o fault_rep.o fault_stores.o sfence.o
obj-$(CONFIG_EBPFOS_KOPERATION) += fault_movzx.o
obj-$(CONFIG_EBPFOS_KOPERATION) += buffer_stos.o buffer_mov.o
obj-$(CONFIG_EBPFOS_KOPERATION) += fault_prefetch.o
obj-$(CONFIG_EBPFOS_KOPERATION) += rdmsr.o
obj-$(CONFIG_EBPFOS_KOPERATION) += wrmsr.o
obj-$(CONFIG_EBPFOS_KOPERATION) += percpu_stores.o
obj-$(CONFIG_EBPFOS_KOPERATION) += percpu_arithmetic.o
obj-$(CONFIG_EBPFOS_KOPERATION) += percpu_xadd.o
obj-$(CONFIG_EBPFOS_KOPERATION) += percpu_cmpxchg.o
obj-$(CONFIG_EBPFOS_KOPERATION) += locked_bits.o
obj-$(CONFIG_EBPFOS_KOPERATION) += locked_xchg.o
obj-$(CONFIG_EBPFOS_KOPERATION) += user_access_window.o
obj-$(CONFIG_EBPFOS_KOPERATION) += irq_restore_if.o
obj-$(CONFIG_EBPFOS_KOPERATION) += fault_call.o
obj-$(CONFIG_EBPFOS_KOPERATION) += invalid_opcode.o
