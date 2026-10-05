# SPDX-License-Identifier: GPL-2.0-only
obj-y += admission.o component_graph.o executor_root.o core.o
obj-y += fops_route_dispatch.o
obj-y += irq_route_dispatch.o component_entry.o
obj-y += step_scope.o
obj-y += typed_entry.o
obj-$(CONFIG_FUNCTION_TRACER) += function_route.o function_stubs_generated.o
obj-y += services.o
obj-y += atomic_byte.o
obj-y += imports-generated.o
ifneq ($(EBPFOS_CUT_IMPORTS_INCLUDE),)
CFLAGS_imports-generated.o += -DEBPFOS_CUT_IMPORTS_INCLUDE=\"$(EBPFOS_CUT_IMPORTS_INCLUDE)\"
endif
ifneq ($(EBPFOS_CUT_TRACING_IMPORTS_INCLUDE),)
CFLAGS_imports-generated.o += -DEBPFOS_CUT_TRACING_IMPORTS_INCLUDE=\"$(EBPFOS_CUT_TRACING_IMPORTS_INCLUDE)\"
endif
obj-y += fops_route.o
obj-$(CONFIG_NET) += netdev_route.o
obj-$(CONFIG_BLOCK) += bops_route.o mqops_route.o restricted_block.o
obj-y += restricted_irq_event.o
obj-y += restricted_completion.o
obj-$(CONFIG_VIRTIO) += restricted_vq_drain.o
obj-y += restricted_work.o
obj-$(CONFIG_NET) += restricted_napi.o
obj-$(CONFIG_EBPFOS_KOPERATION) += koperation.o
obj-$(CONFIG_EBPFOS_KOPERATION) += pointer_tag.o
obj-y += typed_args.o
