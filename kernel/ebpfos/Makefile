# SPDX-License-Identifier: GPL-2.0-only
# Component publication algorithms; no native function or object routes.
obj-y += admission.o component_graph.o executor_root.o core.o step_scope.o
obj-$(CONFIG_EBPFOS_KOPERATION) += koperation.o pointer_tag.o fault_loads.o fault_rep.o fault_stores.o sfence.o
obj-$(CONFIG_EBPFOS_KOPERATION) += fault_movzx.o
obj-$(CONFIG_EBPFOS_KOPERATION) += fault_prefetch.o
obj-$(CONFIG_EBPFOS_KOPERATION) += rdmsr.o
obj-$(CONFIG_EBPFOS_KOPERATION) += wrmsr.o
obj-$(CONFIG_EBPFOS_KOPERATION) += percpu_stores.o
